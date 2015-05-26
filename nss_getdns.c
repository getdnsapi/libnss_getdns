#include <arpa/inet.h>
#include <netdb.h>
#include <nss.h>
#include <errno.h>
#include <getdns/getdns.h>
#include "logger.h"

extern enum nss_status getdns_getaddrinfo(const char *name, int af, struct hostent *result, 
        struct gaih_addrtuple **result_addrtuple, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp);
        
enum nss_status _nss_getdns_gethostbyaddr2_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_getdns_gethostbyaddr_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    return _nss_getdns_gethostbyaddr2_r (addr, len, af, result, buffer, buflen, errnop, h_errnop, NULL);
}

/*gethostbyname4_r sends out parallel A and AAAA queries*/
enum nss_status _nss_getdns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    enum nss_status status = getdns_getaddrinfo(name, AF_UNSPEC, NULL, pat, buffer, buflen, errnop, h_errnop, ttlp, NULL);
    debug_log("GETDNS: gethostbyname4 <%s>: STATUS: %d\n", name, status);
    return status;
}

enum nss_status _nss_getdns_gethostbyname3_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    enum nss_status status;
    status = getdns_getaddrinfo(name, af, result, NULL, buffer, buflen, errnop, h_errnop, ttlp, canonp);
    debug_log("GETDNS: gethostbyname3 <%s>: STATUS: %d\n", name, status);
    return status;
}

enum nss_status _nss_getdns_gethostbyname2_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    return _nss_getdns_gethostbyname3_r (name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_getdns_gethostbyname_r (const char *name, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    /*if (_res.options & RES_USE_INET6)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET6, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);*/
    if (status == NSS_STATUS_NOTFOUND)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);
    return status;
}
