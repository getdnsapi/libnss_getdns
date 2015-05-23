#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "nsswitch.h"
#include "logger.h"

enum nss_status _nss_dns_gethostbyaddr2_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_dns_gethostbyaddr_r (const void *addr, socklen_t len, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    return _nss_dns_gethostbyaddr2_r (addr, len, af, result, buffer, buflen, errnop, h_errnop, NULL);
}

