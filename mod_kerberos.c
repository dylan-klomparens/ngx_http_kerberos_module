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

struct configuration
{
	int enabled;
	const char* keytab_location;
};

static int verify_keytab_is_readable(apr_pool_t* configuration_pool, apr_pool_t* log_pool, apr_pool_t* temp_pool, server_rec* server)
{
/*	apr_file_t* file_handle = NULL;
	apr_status_t result = apr_file_open(&file_handle, keytab_location, APR_FOPEN_READ, 0, temp_pool);
	if(result == APR_SUCCESS)
		apr_file_close(file_handle);
	else
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, server, "Unable to open keytab %s", keytab_location);*/
	return OK;
}

static void decode_error(request_rec* request, const char* title, OM_uint32 major_error, OM_uint32 minor_error)
{
	if(major_error == GSS_S_COMPLETE)
		return;
	if(title)
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "%s", title);
	OM_uint32 minor_status = 0;
	gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;
	OM_uint32 context = 0;
	// Only check the major error if it isn't GSS_S_FAILURE. Running gss_display_status
	// on a major error code of GSS_S_FAILURE produces a completely useless error message.
	if(major_error != GSS_S_FAILURE)
	{
		do {
			gss_display_status(&minor_status, major_error, GSS_C_GSS_CODE, GSS_C_NULL_OID, &context, &status_string);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "GSS error: %s", (char*)status_string.value);
			gss_release_buffer(&minor_status, &status_string);
		} while(context);
	}
	do {
		gss_display_status(&minor_status, minor_error, GSS_C_MECH_CODE, GSS_C_NULL_OID, &context, &status_string);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "Kerberos error: %s", (char*)status_string.value);
		gss_release_buffer(&minor_status, &status_string);
	} while(context);
}

static gss_cred_id_t read_keytab(request_rec* request)
{
	const char* keytab_location = "/etc/combined.keytab";

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

	if(major_status == GSS_S_COMPLETE)
	{
		gss_name_t server_credential_name = GSS_C_NO_NAME;
		gss_inquire_cred(&minor_status, server_credentials, &server_credential_name, NULL, NULL, NULL);
		gss_buffer_desc display_name = GSS_C_EMPTY_BUFFER;
		gss_display_name(&minor_status, server_credential_name, &display_name, NULL);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "Successfully obtained server credentials named %s from keytab %s", (char*)display_name.value, keytab_location);
		gss_release_name(&minor_status, &server_credential_name);
		gss_release_buffer(&minor_status, &display_name);
	}
	else
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "Could not read server credentials from keytab %s", keytab_location);
		decode_error(request, NULL, major_status, minor_status);
	}

	return server_credentials;
}

static void release_resources(gss_ctx_id_t context, gss_name_t client_name, gss_buffer_desc response, gss_buffer_desc display_name, gss_cred_id_t server_credentials)
{
	OM_uint32 minor_status;
	gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
	gss_release_name(&minor_status, &client_name);
	gss_release_buffer(&minor_status, &response);
	gss_release_buffer(&minor_status, &display_name);
	gss_release_cred(&minor_status, &server_credentials);
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

	// Decode the base 64 service ticket.
	gss_buffer_desc service_ticket = GSS_C_EMPTY_BUFFER;
	service_ticket.value = apr_pcalloc(request->pool, apr_base64_decode_len(tokens[1]));
	service_ticket.length = apr_base64_decode(service_ticket.value, tokens[1]);

	OM_uint32 minor_status = 0;
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	gss_name_t client_name = GSS_C_NO_NAME;
	gss_buffer_desc response = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc display_name = GSS_C_EMPTY_BUFFER;
	gss_cred_id_t server_credentials = read_keytab(request);

	if(server_credentials == GSS_C_NO_CREDENTIAL)
		return HTTP_INTERNAL_SERVER_ERROR;

	// Verify the user's credentials.
	OM_uint32 major_status = gss_accept_sec_context(&minor_status, &context, server_credentials, &service_ticket, GSS_C_NO_CHANNEL_BINDINGS, &client_name, NULL, &response, NULL, NULL, NULL);

	// If the credentials were invalid then tell the user they're not authorized.
	if(major_status != GSS_S_COMPLETE)
	{
		decode_error(request, "Kerberos authentication failed for this user.", major_status, minor_status);
		release_resources(context, client_name, display_name, response, server_credentials);
		return HTTP_UNAUTHORIZED;
	}

	// The user has successfully authenticated when this point is reached.

	// Get the user's name and inform HTTPD that the user has successfully authenticated.
	major_status = gss_display_name(&minor_status, client_name, &display_name, NULL);
	if(major_status != GSS_S_COMPLETE)
	{
		decode_error(request, "The user successfully authenticated, but the user's display name could not be obtained from GSSAPI.", major_status, minor_status);
		release_resources(context, client_name, display_name, response, server_credentials);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	request->user = apr_pstrdup(request->pool, display_name.value);
	request->ap_auth_type = "Kerberos";

	// Encode the authentication response into base 64 and send it to the user.
	int length = apr_base64_encode_len(response.length);
	char* encoded_response = apr_pcalloc(request->pool, length);
	apr_base64_encode(encoded_response, response.value, response.length);
	const char* header = apr_pstrcat(request->pool, "Negotiate ", encoded_response, NULL);
	apr_table_set(request->err_headers_out, "WWW-Authenticate", header);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "Kerberos authentication for %s was successful!", request->user);
	release_resources(context, client_name, display_name, response, server_credentials);
	return OK;
}

static void* allocate_server_configuration(apr_pool_t* pool, server_rec* server_configuration)
{
	return apr_pcalloc(pool, sizeof(struct configuration));
}

const char* set_enabled(cmd_parms* command, void* config, int argument);
const char* set_keytab_location(cmd_parms* command, void* config, const char* argument);

static const command_rec directives[] = {
	AP_INIT_FLAG("Kerberos", set_enabled, NULL, OR_AUTHCFG, "Determines if Kerberos authentication is enabled or disabled."),
	AP_INIT_TAKE1("Keytab", set_keytab_location, NULL, RSRC_CONF, "The absolute file path of the web server's Kerberos keytab."),
	{ NULL }
};

static void register_hooks(apr_pool_t* pool)
{
	ap_hook_check_authn(kerberos_handler, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_hook_post_config(verify_keytab_is_readable, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(kerberos) =
{
	STANDARD20_MODULE_STUFF,
	NULL, // Per-directory configuration allocator
	NULL, // Per-directory configuration merge handler
	allocate_server_configuration,
	NULL, // Per-server configuration merge handler
	directives,
	register_hooks
};

const char* set_enabled(cmd_parms* command, void* config, int argument)
{
	struct configuration* c = ap_get_module_config(command->server->module_config, &kerberos_module);
	c->enabled = argument;
	return NULL;
}

const char* set_keytab_location(cmd_parms* command, void* config, const char* argument)
{
	struct configuration* c = ap_get_module_config(command->server->module_config, &kerberos_module);
	c->keytab_location = argument;
	return NULL;
}
