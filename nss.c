#include "addr_utils.h"
#include <resolv.h>
#include <sys/types.h>
#include <unistd.h>
#include "logger.h"
#include "nss_getdns.h"
#include "opt_parse.h"
#include "browsers.h"

#define  UNUSED_PARAM(x) ((void)(x))
        
struct context_holder
{
	getdns_context *ctx;
	int pid;
};

//static getdns_context *context = NULL;
//getdns_dict *extensions = NULL;
/*
*Create/load context.
*The context should be reused per process.
*It must therefore be safe to be used for multiple threads.
*/
getdns_return_t load_context(getdns_context **ctx, getdns_dict **ext)
{
	getdns_return_t return_code = GETDNS_RETURN_GOOD;
	static getdns_dict *extensions = NULL;
	static struct context_holder *ctx_holder = NULL;
	/*
	*Initialize library configuration from config file (getdns.conf)
	*/
	int options = 0; 
	parse_options(CONFIG_FILE, &options);
	if(!extensions)
	{
		extensions = getdns_dict_create();
		/*
		Getdns extensions for doing both IPv4 and IPv6
    	*/
		return_code = getdns_dict_set_int(extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
		return_code &= getdns_dict_set_int(extensions, "dnssec_return_status", GETDNS_EXTENSION_TRUE);
		return_code &= getdns_dict_set_int(extensions, "dnssec_return_validation_chain", GETDNS_EXTENSION_TRUE);
		if(options & DNSSEC_SECURE_ONLY)
		{
			return_code &= getdns_dict_set_int(extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE);
		}
		if(return_code != GETDNS_RETURN_GOOD){
		    err_log("Failed setting (IPv4/IPv6) extension  <ERR_CODE: %d>.\n", return_code);
		    if(extensions != NULL)
		    	getdns_dict_destroy(extensions);
		    return return_code;
		}
	}
	if(!ctx_holder)
	{
		ctx_holder = malloc(sizeof(struct context_holder));
		assert(ctx_holder);
		ctx_holder->pid = -1;
		ctx_holder->ctx = NULL;
	}
	//if(ctx_holder->ctx == NULL || ctx_holder->pid != getpid())
	{
		ctx_holder->pid = getpid();
		return_code = getdns_context_create(&(ctx_holder->ctx), 1);
		if(return_code != GETDNS_RETURN_GOOD){
			err_log("Failed creating dns context <ERR_CODE: %d>.\n", return_code);
			if(extensions != NULL)
		    	getdns_dict_destroy(extensions);
			if(ctx_holder->ctx != NULL)
				getdns_context_destroy(ctx_holder->ctx);
			return return_code;
		}
		getdns_context_set_resolution_type(ctx_holder->ctx, GETDNS_RESOLUTION_RECURSING);
		getdns_context_set_use_threads(ctx_holder->ctx, 1);
	}
	assert(ctx_holder->ctx != NULL && extensions != NULL);
	*ctx = ctx_holder->ctx;
	*ext = extensions;
	return return_code;
}

int __nss_mod_init()
{
	/*
	*Note: These local variables are wasted, just like that?!
	*This function was build on an assumption that the context could be reused between multiple calls, but that may not be the case anymore.
	*/
	getdns_context *context = NULL;
	getdns_dict *extensions = NULL;
	return load_context(&context, &extensions) == GETDNS_RETURN_GOOD ? 0 : -1;
}

void __nss_mod_destroy()
{
	/*
	*Note: This function was build on an assumption that the context could be reused between multiple calls, but that may not be the case anymore.
	*/
	/*if(context != NULL)
		getdns_context_destroy(context);
	
	if(extensions != NULL)
		getdns_dict_destroy(extensions);
	*/
}  
  
enum nss_status _nss_getdns_gethostbyaddr2_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    getdns_return_t return_code;
    uint32_t respstatus = GETDNS_RESPSTATUS_NO_SECURE_ANSWERS, dnssec_status = GETDNS_DNSSEC_NOT_PERFORMED;
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=REV_HOSTENT, .addr_entry={.p_hostent=result}};
    return_code = getdns_gethostinfo(addr, af, &result_ptr, buffer, buflen, ttlp, NULL, &respstatus, &dnssec_status);
    getdns_process_statcode(return_code, respstatus, &status, errnop, h_errnop);
    debug_log("GETDNS: gethostbyaddr2_r: STATUS: %d (RESPSTATUS: %d; errnop: %d, h_errnop: %d)\n", status, respstatus, *errnop, *h_errnop);
    UNUSED_PARAM(len);
    return status;
}

enum nss_status _nss_getdns_gethostbyaddr_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	debug_log("GETDNS: gethostbyaddr_r!\n");
    return _nss_getdns_gethostbyaddr2_r (addr, len, af, result, buffer, buflen, errnop, h_errnop, NULL);
}

/*
*gethostbyname4_r sends out parallel A and AAAA queries
*Documented somewhere for being problematic with some "cheap"/buggy modems...
*TODO: how to test for and use the AI_ADDRCONFIG flag (necessary for determining whether IPv6 addresses should be tried).
*/
enum nss_status _nss_getdns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    assert(name);
    assert(pat);
    assert(buffer);
    assert(errnop);
    assert(h_errnop);
    getdns_return_t return_code;
    uint32_t respstatus = GETDNS_RESPSTATUS_NO_SECURE_ANSWERS, dnssec_status = GETDNS_DNSSEC_NOT_PERFORMED;
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=ADDR_GAIH, .addr_entry={.p_gaih=pat}};
    return_code = getdns_gethostinfo(name, AF_UNSPEC, &result_ptr, buffer, buflen, ttlp, NULL, &respstatus, &dnssec_status);
    getdns_process_statcode(return_code, respstatus, &status, errnop, h_errnop);
    debug_log("GETDNS: %d.gethostbyname4_r(%s): STATUS: %d, ERRNO: %d, h_errno: %d\n", getppid(), name, status, *errnop, *h_errnop);
    return status;
}

enum nss_status _nss_getdns_gethostbyname3_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
	assert(name);
    assert(result);
    assert(buffer);
    assert(errnop);
    assert(h_errnop); 
    getdns_return_t return_code;
    uint32_t respstatus = GETDNS_RESPSTATUS_NO_SECURE_ANSWERS, dnssec_status = GETDNS_DNSSEC_NOT_PERFORMED;
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=ADDR_HOSTENT, .addr_entry={.p_hostent=result}};
    return_code = getdns_gethostinfo(name, af, &result_ptr, buffer, buflen, ttlp, canonp, &respstatus, &dnssec_status);
    getdns_process_statcode(return_code, respstatus, &status, errnop, h_errnop);
    debug_log("GETDNS: gethostbyname3_r <%s>: STATUS: %d; GETDNS_RESPSTATUS: %d\n", name, status, respstatus);
    return status;
}

enum nss_status _nss_getdns_gethostbyname2_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	debug_log("GETDNS: gethostbyname2_r!\n");
    return _nss_getdns_gethostbyname3_r (name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_getdns_gethostbyname_r (const char *name, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	debug_log("GETDNS: gethostbyname_r!\n");
    enum nss_status status = NSS_STATUS_NOTFOUND;
    if (_res.options & RES_USE_INET6)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET6, result, buffer, 
        			buflen, errnop, h_errnop, NULL, NULL);
    if (status == NSS_STATUS_NOTFOUND)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);
    return status;
}
