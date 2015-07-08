#include <unistd.h>
#include "context_interface.h"
#include "nss_getdns.h"
#include "logger.h"
#include "query.h"
#include "config.h"

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
	if(getgid() == 0 || getuid() == 0)
	{
		return resolve_with_new_ctx(query, is_reverse, af, result);
	}else{
		return ctx_proxy(query, is_reverse, af, result);
	}
	
}
