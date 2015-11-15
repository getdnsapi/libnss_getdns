// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <resolv.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "logger.h"
#include "nss_getdns.h"
#include "opt_parse.h"
#include "addr_utils.h"

#define  UNUSED_PARAM(x) ((void)(x))

extern int log_level;

/*
*This indicates that all interfaces has an IPv6 address.
*Otherwise, we assume IPv6 is not supported if one or more interfaces do not have an IPv6.
*/
extern int has_ipv6_addresses();
int getdns_options;

/*
*Create/load context.
*The context should be reused per process.
*It must therefore be safe to be used for multiple threads.
*If given a non-NULL context, no other context will be created. So a request for a new context must pass in a NULL ctx
*If a non-NULL extensions is given, a new one will be created only if the configuration file has changed.
*NOTE: This context is maintained by one process. Not safe for forks.
*/
getdns_return_t load_context(getdns_context **ctx, getdns_dict **ext, time_t *last_check)
{
	getdns_return_t return_code = GETDNS_RETURN_GOOD;
	getdns_dict *extensions = NULL;
	getdns_context *context = NULL;
	static getdns_transport_list_t tls_require_l[] = { GETDNS_TRANSPORT_TLS };
	static getdns_transport_list_t tls_prefer_l[] = { GETDNS_TRANSPORT_TLS, GETDNS_TRANSPORT_TCP, GETDNS_TRANSPORT_UDP };


	int config_update = 0;
	if((*ctx != NULL) && (*ext != NULL) && (last_check != NULL))
	{
		struct stat st;
		char config_file[256];
		snprintf(config_file, 256, "%s/%s/%s.conf", getenv("HOME"), ".getdns", CONFIG_FILE_LOCAL);
		if(stat(config_file, &st) != 0)
		{
			log_warning("load_context< %s >", strerror(errno));
		}else if(difftime(st.st_mtime, *last_check) > 0){
			log_info("load_context< loading new settings from %s >", config_file);
			*last_check = st.st_mtime;
			config_update = 1;
		}
		UNUSED_PARAM(st);
	}
	/*
	*Initialize library configuration from config file (getdns.conf or user's local preferences)
	*/
	if( (*ext == NULL) || config_update )
	{
		getdns_options = get_local_defaults(CONFIG_FILE_LOCAL);
		if(!getdns_options)
		{	
			parse_options(CONFIG_FILE, &getdns_options);
		}
		set_log_level(getdns_options, &log_level);
		getdns_options |= has_ipv6_addresses();
		extensions = getdns_dict_create();
		/*
		Getdns extensions for doing both IPv4 and IPv6
		*/
		return_code = getdns_dict_set_int(extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
		return_code |= getdns_dict_set_int(extensions, "dnssec_return_status", GETDNS_EXTENSION_TRUE);
		return_code |= getdns_dict_set_int(extensions, "dnssec_return_validation_chain", GETDNS_EXTENSION_TRUE);
		if(getdns_options & DNSSEC_SECURE_ONLY)
		{
			return_code |= getdns_dict_set_int(extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE);
		}
		if(getdns_options & DNSSEC_ROADBLOCK_AVOIDANCE)
		{
			return_code |= getdns_dict_set_int(extensions, "dnssec_roadblock_avoidance", GETDNS_EXTENSION_TRUE);
		}
		if(return_code != GETDNS_RETURN_GOOD)
		{
			log_warning("Failed setting (IPv4/IPv6) extension  <ERR_CODE: %d>.\n", return_code);
			if(extensions != NULL)
				getdns_dict_destroy(extensions);
			return return_code;
		}
		if(*ext != NULL)
		{
			getdns_dict_destroy(*ext);
		}
		*ext = extensions;
	}
	if(*ctx == NULL)
	{
		return_code = getdns_context_create(&context, 1);
		if(return_code != GETDNS_RETURN_GOOD)
		{
			log_critical("Failed creating dns context <ERR_CODE: %d>.\n", return_code);
			if(extensions != NULL)
				getdns_dict_destroy(extensions);
			if(context != NULL)
				getdns_context_destroy(context);
			return return_code;
		}
		if(getdns_options & TLS_REQUIRE){
		    /*
		    TLS used in STUB mode only
		    */
		    getdns_context_set_resolution_type(context, GETDNS_RESOLUTION_STUB);
		    getdns_context_set_dns_transport_list(context,
		        sizeof(tls_require_l) / sizeof(*tls_require_l), tls_require_l);
		}else if (getdns_options & TLS_PREFER){
		    getdns_context_set_resolution_type(context, GETDNS_RESOLUTION_STUB);
		    getdns_context_set_dns_transport_list(context,
		        sizeof(tls_prefer_l) / sizeof(*tls_prefer_l), tls_prefer_l);
		}else{
		    getdns_context_set_resolution_type(context, GETDNS_RESOLUTION_RECURSING);
		}
		//getdns_context_set_use_threads(context, 1);
		*ctx = context;
	}
	return return_code;
}

int __nss_mod_init()
{
	return 0;
}

void __nss_mod_destroy()
{
	
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
    log_debug("GETDNS: gethostbyaddr2_r: STATUS: %d (RESPSTATUS: %d; errnop: %d, h_errnop: %d)\n", status, respstatus, *errnop, *h_errnop);
    return status;
}

enum nss_status _nss_getdns_gethostbyaddr_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	log_debug("GETDNS: gethostbyaddr_r!\n");
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
    log_debug("GETDNS: %d.gethostbyname4_r(%s): STATUS: %d, ERRNO: %d, h_errno: %d\n", getppid(), name, status, *errnop, *h_errnop);
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
    log_debug("GETDNS: gethostbyname3_r <%s>: STATUS: %d; GETDNS_RESPSTATUS: %d\n", name, status, respstatus);
    return status;
}

enum nss_status _nss_getdns_gethostbyname2_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	log_debug("GETDNS: gethostbyname2_r!\n");
    return _nss_getdns_gethostbyname3_r (name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_getdns_gethostbyname_r (const char *name, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	log_debug("GETDNS: gethostbyname_r!\n");
    enum nss_status status = NSS_STATUS_NOTFOUND;	
    /* XXX: libc thinks: If we are looking for an IPv6 address and mapping is enabled
	 by having the RES_USE_INET6 bit in _res.options set, so...  */
    if (_res.options & RES_USE_INET6)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET6, result, buffer, 
        			buflen, errnop, h_errnop, NULL, NULL);
    if (status == NSS_STATUS_NOTFOUND)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);
    return status;
}
