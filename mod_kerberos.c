// Package dependancies: apr-devel apr-util-devel krb5-devel
// Link with: libapr-1.so libaprutil-1.so libgssapi_krb5.so

#include <gssapi/gssapi_krb5.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <apr_hooks.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_base64.h>

#include <stdio.h>

static const char* keytab_location;

const char* set_keytab_location(cmd_parms* command, void* configuration, const char* argument)
{
	keytab_location = argument;
	return NULL;
}

static int verify_keytab_is_readable(apr_pool_t* configuration_pool, apr_pool_t* log_pool, apr_pool_t* temp_pool, server_rec* server)
{
	apr_file_t* file_handle = NULL;
	apr_status_t result = apr_file_open(&file_handle, keytab_location, APR_FOPEN_READ, 0, temp_pool);
	if(result == APR_SUCCESS)
		apr_file_close(file_handle);
	else
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, server, "Unable to open keytab %s", keytab_location);
	return OK;
}

static const command_rec directives[] = {
	AP_INIT_TAKE1("Keytab", set_keytab_location, NULL, OR_AUTHCFG, "The absolute file path of the web server's Kerberos keytab."),
	{ NULL }
};

static void decode_error(FILE* output, char* title, OM_uint32 major_error, OM_uint32 minor_error)
{
	if(title)
		fprintf(output, "%s", title);
	if(major_error == GSS_S_COMPLETE)
	{
		fprintf(output, "Success\n");
		return;
	}
	OM_uint32 minor_status = 0;
	gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;
	OM_uint32 context = 0;
	// Only check the major error if it isn't GSS_S_FAILURE. Running gss_display_status
	// on a major error code of GSS_S_FAILURE produces a completely useless error message.
	if(major_error != GSS_S_FAILURE)
	{
		do {
			gss_display_status(&minor_status, major_error, GSS_C_GSS_CODE, GSS_C_NULL_OID, &context, &status_string);
			fprintf(output, "GSS error: %s\n", (char*)status_string.value);
			gss_release_buffer(&minor_status, &status_string);
		} while(context);
	}
	do {
		gss_display_status(&minor_status, minor_error, GSS_C_MECH_CODE, GSS_C_NULL_OID, &context, &status_string);
		fprintf(output, "Kerberos error: %s\n", (char*)status_string.value);
		gss_release_buffer(&minor_status, &status_string);
	} while(context);
}

static gss_cred_id_t read_keytab(FILE* f)
{
	OM_uint32 major_status = 0;
	OM_uint32 minor_status = 0;

	gss_key_value_element_desc keytab;
	keytab.key = "keytab";
	keytab.value = keytab_location;

	gss_key_value_set_desc credential_store;
	credential_store.count = 1;
	credential_store.elements = &keytab;

	gss_cred_id_t server_credentials = GSS_C_NO_CREDENTIAL;
	major_status = gss_acquire_cred_from(&minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &credential_store, &server_credentials, NULL, NULL);

	decode_error(f, "Read keytab result:\n", major_status, minor_status);

	return server_credentials;
}

static int kerberos_handler(request_rec* request)
{
	// The incoming HTTP request should contain an "Authorization" header with the
	// value "Negotiate" to indicate the user intends to use Kerberos.
	// If it does not we can reply with a "WWW-Authenticate" header set to "Negotiate"
	// to indicate that the server accepts Kerberos authentication.
	const char* authorization_header = apr_table_get(request->headers_in, "Authorization");
	if(authorization_header == NULL)
	{
		apr_table_set(request->err_headers_out, "WWW-Authenticate", "Negotiate");
		return HTTP_UNAUTHORIZED;
	}

	char** tokens = NULL;
	apr_tokenize_to_argv(authorization_header, &tokens, request->pool);

	// Parse the user's Kerberos credentials (also known as a service ticket).
	// There must be exactly two tokens followed by a null terminator.
	// The first token should always be "Negotiate".
	// The second token is the base 64 encoded Kerberos service ticket from the user (sent by web browser).
	if(!tokens || !tokens[0] || !tokens[1] || tokens[2])
		return HTTP_UNAUTHORIZED;

	// The user must specify authentication method "Negotiate" to indicate the use of Kerberos.
	if(strcmp(tokens[0], "Negotiate"))
		return HTTP_UNAUTHORIZED;

	// For debugging:
	FILE* f = fopen("/tmp/kerberos.txt", "w");

	// Decode the base 64 service ticket.
	gss_buffer_desc service_ticket = GSS_C_EMPTY_BUFFER;
	service_ticket.value = apr_pcalloc(request->pool, apr_base64_decode_len(tokens[1]));
	service_ticket.length = apr_base64_decode(service_ticket.value, tokens[1]);

	OM_uint32 minor_status = 0;
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	gss_name_t client_name = GSS_C_NO_NAME;
	gss_buffer_desc response = GSS_C_EMPTY_BUFFER;
	gss_cred_id_t server_credentials = read_keytab(f);

	if(server_credentials == GSS_C_NO_CREDENTIAL)
	{
		fclose(f);
		return HTTP_UNAUTHORIZED;
	}

	// Verify the user's credentials.
	OM_uint32 major_status = gss_accept_sec_context(&minor_status, &context, server_credentials, &service_ticket, GSS_C_NO_CHANNEL_BINDINGS, &client_name, NULL, &response, NULL, NULL, NULL);

	decode_error(f, "Accept security context result:\n", major_status, minor_status);

	gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
	gss_release_name(&minor_status, &client_name);

	fclose(f);

	// If the credentials were invalid then tell the user they're not authorized.
	if(major_status != GSS_S_COMPLETE)
	{
		gss_release_buffer(&minor_status, &response);
		return HTTP_UNAUTHORIZED;
	}

	// The user has successfully authenticated when this point is reached.
	// Encode the authentication response into base 64 and send it to the user.
	int length = apr_base64_encode_len(response.length);
	char* encoded_response = apr_pcalloc(request->pool, length);
	apr_base64_encode(encoded_response, response.value, response.length);
	const char* header = apr_pstrcat(request->pool, "Negotiate ", encoded_response, NULL);
	apr_table_set(request->err_headers_out, "WWW-Authenticate", header);
	gss_release_buffer(&minor_status, &response);
	return OK; // TODO: figure out if we need to return OK or DECLINED. Ask Apache community.
}

static void register_hooks(apr_pool_t* pool)
{
	ap_hook_check_authn(kerberos_handler, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_hook_post_config(verify_keytab_is_readable, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA kerberos_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	NULL,
	NULL,
	directives,
	register_hooks
};
