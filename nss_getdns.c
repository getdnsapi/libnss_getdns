#include "logger.h"
#include "nss_getdns.h"

static getdns_context *context = NULL;
static getdns_dict *extensions = NULL;

getdns_return_t load_context(getdns_context **ctx, getdns_dict **ext)
{
	getdns_return_t return_code = GETDNS_RETURN_GOOD; 
	if(!context)
	{
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

extern enum nss_status getdns_gethostinfo(const char *name, int af, struct addr_param *result_ptr, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp);
  
  
enum nss_status _nss_getdns_gethostbyaddr2_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=REV_HOSTENT, .addr_entry={.p_hostent=result}};
    status = getdns_gethostinfo(addr, af, &result_ptr, buffer, buflen, errnop, h_errnop, ttlp, NULL);
    debug_log("GETDNS: gethostbyaddr2: STATUS: %d\n", status);
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
	
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=ADDR_GAIH, .addr_entry={.p_gaih=pat}};
    status = getdns_gethostinfo(name, AF_UNSPEC, &result_ptr, buffer, buflen, errnop, h_errnop, ttlp, NULL);
    debug_log("GETDNS: gethostbyname4 <%s>: STATUS: %d\n", name, status);
    return status;
}

enum nss_status _nss_getdns_gethostbyname3_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    enum nss_status status;
    struct addr_param result_ptr = {.addr_type=ADDR_HOSTENT, .addr_entry={.p_hostent=result}};
    status = getdns_gethostinfo(name, af, &result_ptr, buffer, buflen, errnop, h_errnop, ttlp, canonp);
    debug_log("GETDNS: gethostbyname3 <%s>: STATUS: %d\n", name, status);
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
    /*if (_res.options & RES_USE_INET6)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET6, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);*/
    if (status == NSS_STATUS_NOTFOUND)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);
    return status;
}

/*
enum nss_status _nss_getdns_getservbyname_r (const char *name, const char *protocol,
			  struct servent *serv, char *buffer, size_t buflen, int *errnop)
{
	enum nss_status status;
    struct addr_param result_ptr = {.addr_type=ADDR_SERVENT, .addr_entry={.p_servent=serv}};
    int mock_h_errno;
    int mock_ttl;
    status = getdns_gethostinfo(name, AF_UNSPEC, &result_ptr, buffer, buflen, errnop, &mock_h_errno, &mock_ttl, NULL);
    debug_log("GETDNS: getservbyname!\n");
    return status;
}

enum nss_status _nss_getdns_getservbyport_r (int port, const char *protocol, struct servent *serv, 
		char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	debug_log("GETDNS: getservbyport!\n");
	*errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}*/
