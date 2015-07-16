#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "context_interface.h"
#include "nss_getdns.h"
#include "logger.h"
#include "query.h"
#include "config.h"
#include "services/http.h"
#include "browsers.h"

int resolve_with_new_ctx(char *query, int reverse, int af, response_bundle **result)
{
	getdns_context *context = NULL;
	getdns_dict *extensions = NULL;
	if(load_context(&context, &extensions) == GETDNS_RETURN_GOOD)
	{
		getdns_dict *response = NULL;
		do_query(query, af, reverse, context, extensions, &response);
		if(response)
		{
			parse_addr_bundle(response, result, reverse, af);
			getdns_dict_destroy(response);
		}else{
			err_log("resolve_with_new_ctx < NULL RESPONSE >");
		}
		getdns_context_destroy(context);
		getdns_dict_destroy(extensions);
		if(result == NULL)
		{
			err_log("resolve_with_new_ctx < RESPONSE IS EMPTY>");
			return -1;
		}
	}else{
		err_log("resolve_with_new_ctx < context initialization failed>");
		return -1;
	}			
	return 0;
}

#if defined(HAVE_CONTEXT_PROXY) && HAVE_CONTEXT_PROXY == 1
	extern getdns_context_proxy ctx_proxy;
#else
	getdns_context_proxy ctx_proxy = &resolve_with_new_ctx;
#endif

int resolve_with_managed_ctx(char *query, int is_reverse, int af, response_bundle **result)
{
	if(strlen(query) == 0)
	{
		err_log("resolve_with_managed_ctx< Invalid argument: %s >", query);
		return -1;
	}
	int ret = -1;
	if(getgid() == 0 || getuid() == 0)
	{
		ret = resolve_with_new_ctx(query, is_reverse, af, result);
	}else{
		ret = ctx_proxy(query, is_reverse, af, result);
	}
	if((ret == -1) 
	|| (*result != NULL && ((*result)->respstatus != GETDNS_RESPSTATUS_GOOD)
		|| ((*result)->dnssec_status == GETDNS_DNSSEC_BOGUS)))
	{
		int preserve_respstatus = 0;
		response_bundle *local_redirect = NULL;
		if(strncmp(query, GETDNS_CONFIG_LOCALNAME, sizeof(GETDNS_CONFIG_LOCALNAME))==0
			|| strncmp(query, GETDNS_CONFIG_IPV4+5, sizeof(GETDNS_CONFIG_IPV4)-5)==0
			|| strncmp(query, GETDNS_CONFIG_IPV6+5, sizeof(GETDNS_CONFIG_IPV6)-5)==0)
		{
			local_redirect = &RESP_BUNDLE_LOCAL_CONFIG;
		}else if(strncmp(query, GETDNS_ERR_LOCALNAME, sizeof(GETDNS_ERR_LOCALNAME))==0
			|| strncmp(query, GETDNS_ERR_IPV4+5, sizeof(GETDNS_ERR_IPV4)-5)==0
			|| strncmp(query, GETDNS_ERR_IPV6+5, sizeof(GETDNS_ERR_IPV6)-5)==0)
		{
			local_redirect = &RESP_BUNDLE_LOCAL_ERR;
		}else if((((*result)->respstatus == GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS) || ((*result)->dnssec_status == GETDNS_DNSSEC_BOGUS)
				|| ((*result)->respstatus == GETDNS_RESPSTATUS_NO_SECURE_ANSWERS)))
		{
			if(browser_check(af)){
				preserve_respstatus = 1;
				local_redirect = &RESP_BUNDLE_LOCAL_ERR;
			}else{
				local_redirect = &RESP_BUNDLE_EMPTY;
			}
		}else{
			return ret;
		}
		if(local_redirect){
			check_service();
			if(!preserve_respstatus)
			{
				(*result)->respstatus = local_redirect->respstatus;
				(*result)->dnssec_status = local_redirect->dnssec_status;
			}
			(*result)->ipv4_count = 1;
			(*result)->ipv6_count = 1;
			(*result)->ipv4 = strdup(local_redirect->ipv4);
			(*result)->ipv6 = strdup(local_redirect->ipv6);
			(*result)->ttl = 0;
			(*result)->cname = strdup(local_redirect->cname);
			return 0;
		}
	}
	return ret;
}

const char *get_dnssec_code_description(int code)
{
	return getdns_get_errorstr_by_id(code);
}
