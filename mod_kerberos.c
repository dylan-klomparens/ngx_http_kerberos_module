// Package dependancies: apr-devel apr-util-devel krb5-devel
// Link with: libapr-1.so libaprutil-1.so libgssapi_krb5.so

#include <gssapi/gssapi.h>
#include <httpd.h>
#include <http_config.h>
#include <apr_hooks.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_base64.h>

#include <stdio.h>

static void decode_error(FILE* output, OM_uint32 error, int type)
{
	OM_uint32 major_status = 0;
	OM_uint32 minor_status = 0;
	gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;
	OM_uint32 context = 0;
	do {
		major_status = gss_display_status(&minor_status, error, type, GSS_C_NULL_OID, &context, &status_string);
		if(type == GSS_C_GSS_CODE)
			fprintf(output, "GSS ");
		if(type == GSS_C_MECH_CODE)
			fprintf(output, "Kerberos ");
		fprintf(output, "error: %s\n", (char*)status_string.value);
		gss_release_buffer(&minor_status, &status_string);
	} while(context);
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
	service_ticket.length = apr_base64_decode_len(tokens[1]);
	service_ticket.value = apr_pcalloc(request->pool, service_ticket.length);
	apr_base64_decode(service_ticket.value, tokens[1]);

	OM_uint32 minor_status = 0;
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	gss_name_t client_name = GSS_C_NO_NAME;
	gss_buffer_desc response = GSS_C_EMPTY_BUFFER;
	putenv("KRB5_KTNAME=/etc/krb5.keytab");

	// Verify the user's credentials.
	OM_uint32 major_status = gss_accept_sec_context(&minor_status, &context, GSS_C_NO_CREDENTIAL, &service_ticket, GSS_C_NO_CHANNEL_BINDINGS, &client_name, NULL, &response, NULL, NULL, NULL);

	fprintf(f, "Accept security context result:\n");
	decode_error(f, major_status, GSS_C_GSS_CODE);
	decode_error(f, minor_status, GSS_C_MECH_CODE);

	gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
	gss_release_name(&minor_status, &client_name);

	fclose(f);

	// If the credentials were invalid then tell the user they're not authorized.
	if(major_status != GSS_S_COMPLETE)
	{
		gss_release_buffer(&minor_status, &response);
		return HTTP_CONFLICT; // Currently set for debugging. Change back to HTTP_UNAUTHORIZED
	}

	// The user has successfully authenticated when this point is reached.
	// Encode the authentication response into base 64 and send it to the user.
	int length = apr_base64_encode_len(response.length);
	char* encoded_response = apr_pcalloc(request->pool, length);
	apr_base64_encode(encoded_response, response.value, response.length);
	const char* header = apr_pstrcat(request->pool, "Negotiate ", encoded_response, NULL);
	apr_table_set(request->err_headers_out, "WWW-Authenticate", header);
	gss_release_buffer(&minor_status, &response);
	return OK;
}

static void register_hooks(apr_pool_t* pool)
{
	ap_hook_handler(kerberos_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA kerberos_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	register_hooks
};