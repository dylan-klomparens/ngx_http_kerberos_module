#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <gssapi/gssapi_krb5.h>

typedef struct
{
	ngx_flag_t enabled;
	ngx_str_t keytab;
} module_configuration;

static ngx_command_t directives[] =
{
	{
		ngx_string("kerberos"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(module_configuration, enabled),
		NULL
	},
	{
		ngx_string("keytab"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(module_configuration, keytab),
		NULL
	},
	ngx_null_command
};

static ngx_int_t initialize(ngx_conf_t* nginx_configuration);
static void* create_location_configuration(ngx_conf_t* nginx_configuration);
static char* merge_location_configuration(ngx_conf_t* nginx_configuration, void* parent, void* child);

static ngx_http_module_t context =
{
	NULL,
	initialize,
	NULL,
	NULL,
	NULL,
	NULL,
	create_location_configuration,
	merge_location_configuration
};

// Module definition
ngx_module_t ngx_http_kerberos_module =
{
	NGX_MODULE_V1,
	&context,
	directives,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};
/*
static int verify_keytab_is_readable()
{
	return 0;
}
*/
static void decode_error(ngx_log_t* log, OM_uint32 major_error, OM_uint32 minor_error)
{
	if(major_error == GSS_S_COMPLETE)
		return;
	OM_uint32 minor_status = 0;
	gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;
	OM_uint32 context = 0;
	// Only check the major error if it isn't GSS_S_FAILURE. Running gss_display_status
	// on a major error code of GSS_S_FAILURE produces a completely useless error message.
	if(major_error != GSS_S_FAILURE)
	{
		do {
			gss_display_status(&minor_status, major_error, GSS_C_GSS_CODE, GSS_C_NULL_OID, &context, &status_string);
			ngx_log_error(NGX_LOG_ERR, log, 0, "GSS error: %s", (char*)status_string.value);
			gss_release_buffer(&minor_status, &status_string);
		} while(context);
	}
	do {
		gss_display_status(&minor_status, minor_error, GSS_C_MECH_CODE, GSS_C_NULL_OID, &context, &status_string);
		ngx_log_error(NGX_LOG_ERR, log, 0, "Kerberos error: %s", (char*)status_string.value);
		gss_release_buffer(&minor_status, &status_string);
	} while(context);
}

static gss_cred_id_t read_keytab(ngx_log_t* log)
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
		ngx_log_error(NGX_LOG_DEBUG, log, 0, "Successfully obtained server credentials named %s from keytab %s", (char*)display_name.value, keytab_location);
		gss_release_name(&minor_status, &server_credential_name);
		gss_release_buffer(&minor_status, &display_name);
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, log, 0, "Could not read server credentials from keytab %s", keytab_location);
		decode_error(log, major_status, minor_status);
	}

	return server_credentials;
}

static gss_buffer_desc decode_service_ticket(ngx_str_t encoded_service_ticket)
{
	if(ngx_strncasecmp(encoded_service_ticket.data, (u_char *)"Negotiate", sizeof("Negotiate")))
		return GSS_C_EMPTY_BUFFER;
	encoded_service_ticket.len -= sizeof("Negotiate");
	encoded_service_ticket.data += sizeof("Negotiate");
	while(encoded_service_ticket.len && encoded_service_ticket.data[0] == ' ')
	{
		encoded_service_ticket.len--;
		encoded_service_ticket.data++;
	}
	ngx_str_t decoded_service_ticket;
	decoded_service_ticket.len = ngx_base64_decoded_length(encoded_service_ticket.len);
	decoded_service_ticket.data = ngx_pcalloc(request->pool, decoded_service_ticket.len);
	ngx_decode_base64(&decoded_service_ticket, &encoded_service_ticket);
	gss_buffer_desc service_ticket = { .value = decoded_service_ticket.data, .length = decoded_service_ticket.len };
	return service_ticket;
}

static gss_buffer_desc authenticate(server_credentials, service_ticket)
{
	OM_uint32 minor_status = 0;
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	gss_name_t client_name = GSS_C_NO_NAME;
	gss_buffer_desc response = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc display_name = GSS_C_EMPTY_BUFFER;

	// Verify the user's credentials.
	OM_uint32 major_status = gss_accept_sec_context(&minor_status, &context, server_credentials, &service_ticket, GSS_C_NO_CHANNEL_BINDINGS, &client_name, NULL, &response, NULL, NULL, NULL);

	// If the credentials were invalid then tell the user they're not authenticated.
	if(major_status != GSS_S_COMPLETE)
	{
		ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Kerberos authentication failed for this user");
		decode_error(request->connection->log, major_status, minor_status);
		release_resources(context, client_name, display_name, response, server_credentials);
		return NGX_HTTP_UNAUTHORIZED;
	}

	// The user has successfully authenticated when this point is reached.

	// Get the user's name and inform Nginx that the user has successfully authenticated.
	major_status = gss_display_name(&minor_status, client_name, &display_name, NULL);
	if(major_status != GSS_S_COMPLETE)
	{
		ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "The user successfully authenticated, but the user's display name could not be obtained from GSSAPI");
		decode_error(request->connection->log, major_status, minor_status);
		release_resources(context, client_name, display_name, response, server_credentials);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return response;
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

static ngx_int_t handle_request(ngx_http_request_t* request)
{
	module_configuration* contextual_configuration = ngx_http_get_module_loc_conf(request, ngx_http_kerberos_module);
	if(!contextual_configuration->enabled)
		return NGX_DECLINED;

	// The incoming HTTP request should contain an "Authorization" header with the
	// value "Negotiate" to indicate the user intends to use Kerberos.
	// If it does not we can reply with a "WWW-Authenticate" header set to "Negotiate"
	// to indicate that the server accepts Kerberos authentication.
	if(!request->headers_in.authorization)
	{
		request->headers_out.www_authenticate = ngx_list_push(&request->headers_out.headers);
		request->headers_out.www_authenticate->hash = 1;
		ngx_str_set(&request->headers_out.www_authenticate->key, "WWW-Authenticate");
		ngx_str_set(&request->headers_out.www_authenticate->value, "Negotiate");
		return NGX_OK;
	}

	gss_cred_id_t server_credentials = read_keytab(request->connection->log);
	if(server_credentials == GSS_C_NO_CREDENTIAL)
		return NGX_ERROR;

	gss_buffer_desc service_ticket = decode_service_ticket(request->headers_in.authorization->value);
	if(service_ticket == GSS_C_EMPTY_BUFFER)
		return NGX_DECLINED;



	// Encode the authentication response into base 64 and send it to the user.
	ngx_str_t encoded_response;
	encoded_response.len = ngx_base64_encoded_length(response.length);
	encoded_response.data = ngx_pcalloc(request->pool, encoded_response.len);
	ngx_encode_base64(&encoded_response, &response);
	request->headers_out.www_authenticate = ngx_list_push(&request->headers_out.headers);
	request->headers_out.www_authenticate->hash = 1;
	ngx_str_set(&request->headers_out.www_authenticate->key, "WWW-Authenticate");
	request->headers_out.www_authenticate = encoded_response;
	ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Kerberos authentication for %s was successful!", request->user);
	release_resources(context, client_name, display_name, response, server_credentials);

	return NGX_OK;
}

static ngx_int_t initialize(ngx_conf_t* nginx_configuration)
{
	ngx_http_core_main_conf_t* c = ngx_http_conf_get_module_main_conf(nginx_configuration, ngx_http_core_module);
	ngx_http_handler_pt* h = ngx_array_push(&c->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	*h = handle_request;
	return NGX_OK;
}

static void* create_location_configuration(ngx_conf_t* nginx_configuration)
{
	module_configuration* c = ngx_pcalloc(nginx_configuration->pool, sizeof(module_configuration));
	c->enabled = NGX_CONF_UNSET;
	return c;
}

static char* merge_location_configuration(ngx_conf_t* nginx_configuration, void* parent, void* child)
{
	module_configuration* prev = parent;
	module_configuration* conf = child;
	ngx_conf_merge_off_value(conf->enabled, prev->enabled, 0);
	ngx_conf_merge_str_value(conf->keytab, prev->keytab, "/etc/krb5.keytab");
	return NGX_CONF_OK;
}