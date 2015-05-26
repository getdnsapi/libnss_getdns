

#ifndef _GETDNS_NSS_ADDRINFO_H_
#define _GETDNS_NSS_ADDRINFO_H_
enum nss_status getdns_getaddrinfo(const char *name, int af, struct hostent *result, 
        struct gaih_addrtuple **result_addrtuple, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp);
        
#endif /*_GETDNS_NSS_ADDRINFO_H_*/
