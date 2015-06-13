#include "addr_utils.h"
#include <resolv.h>
#include "logger.h"
#include "nss_getdns.h"

#define  UNUSED_PARAM(x) ((void)(x))

/*
Convert getdns status codes & return values to NSS status codes, and set errno values
*/
extern void getdns_process_statcode(getdns_return_t, uint32_t, enum nss_status *nss_code, int *errnop, int *h_errnop);
/*
*NSS wrapper around getdns!
*/
extern getdns_return_t getdns_gethostinfo(const char *name, int af, struct addr_param *result_ptr, 
        char *buffer, size_t buflen, int32_t *ttlp, char **canonp, uint32_t *respstatus);
        
static getdns_context *context = NULL;
static getdns_dict *extensions = NULL;
extern struct __res_state _res;

getdns_return_t load_context(getdns_context **ctx, getdns_dict **ext)
{
	getdns_return_t return_code = GETDNS_RETURN_GOOD; 
	if(!context)
	{	
		/*
		*Initialize resolver configuration from conf files (resolv.conf)
		*/
		if(res_init() == -1)
			return GETDNS_RETURN_BAD_CONTEXT;
		/*
		Create and check getdns context
		*/
		return_code = getdns_context_create(&context, 1);
		if(return_code != GETDNS_RETURN_GOOD){
		    err_log("Failed creating dns context <ERR_CODE: %d>.\n", return_code);
		    return return_code;
		}
	}
	if(!extensions)
	{
		extensions = getdns_dict_create();
		/*
		Getdns extensions for doing both IPv4 and IPv6
    	*/
		return_code = getdns_dict_set_int(extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
		if(return_code != GETDNS_RETURN_GOOD){
		    err_log("Failed setting (IPv4/IPv6) extension  <ERR_CODE: %d>.\n", return_code);
		    return return_code;
		}
	}
	assert(context != NULL && extensions != NULL);
	*ctx = context;
	*ext = extensions;
	return return_code;
}

int __nss_mod_init()
{
	return load_context(&context, &extensions) == GETDNS_RETURN_GOOD ? 0 : -1;
}

void __nss_mod_destroy()
{
	if(context != NULL)
		getdns_context_destroy(context);
	if(extensions != NULL)
		getdns_dict_destroy(extensions);
}  
  
enum nss_status _nss_getdns_gethostbyaddr2_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    getdns_return_t return_code;
    uint32_t respstatus;
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=REV_HOSTENT, .addr_entry={.p_hostent=result}};
    return_code = getdns_gethostinfo(addr, af, &result_ptr, buffer, buflen, ttlp, NULL, &respstatus);
    getdns_process_statcode(return_code, respstatus, &status, errnop, h_errnop);
    debug_log("GETDNS: gethostbyaddr2: STATUS: %d\n", status);
    UNUSED_PARAM(len);
    return status;
}

enum nss_status _nss_getdns_gethostbyaddr_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	debug_log("GETDNS: gethostbyaddr!\n");
    return _nss_getdns_gethostbyaddr2_r (addr, len, af, result, buffer, buflen, errnop, h_errnop, NULL);
}

/*gethostbyname4_r sends out parallel A and AAAA queries*/
enum nss_status _nss_getdns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    getdns_return_t return_code;
    uint32_t respstatus;
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=ADDR_GAIH, .addr_entry={.p_gaih=pat}};
    return_code = getdns_gethostinfo(name, AF_UNSPEC, &result_ptr, buffer, buflen, ttlp, NULL, &respstatus);
    getdns_process_statcode(return_code, respstatus, &status, errnop, h_errnop);
    debug_log("GETDNS: gethostbyname4 <%s>: STATUS: %d\n", name, status);
    return status;
}

enum nss_status _nss_getdns_gethostbyname3_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    getdns_return_t return_code;
    uint32_t respstatus;
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=ADDR_HOSTENT, .addr_entry={.p_hostent=result}};
    return_code = getdns_gethostinfo(name, af, &result_ptr, buffer, buflen, ttlp, canonp, &respstatus);
    getdns_process_statcode(return_code, respstatus, &status, errnop, h_errnop);
    debug_log("GETDNS: gethostbyname3 <%s>: STATUS: %d; GETDNS_RESPSTATUS: %d\n", name, status, respstatus);
    return status;
}

enum nss_status _nss_getdns_gethostbyname2_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	debug_log("GETDNS: gethostbyname2!\n");
    return _nss_getdns_gethostbyname3_r (name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_getdns_gethostbyname_r (const char *name, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	debug_log("GETDNS: gethostbyname!\n");
    enum nss_status status = NSS_STATUS_NOTFOUND;
    if (_res.options & RES_USE_INET6)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET6, result, buffer, 
        			buflen, errnop, h_errnop, NULL, NULL);
    if (status == NSS_STATUS_NOTFOUND)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);
    return status;
}
