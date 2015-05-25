#include <netdb.h>
#include "nsswitch.h"

/*
Convert getdns status codes & return values to NSS status codes, and set errno values
*/
void getdns_process_statcode(uint32_t status, enum nss_status *nss_code, int *errnop, int *h_errnop){
    switch(status)
    {
        case GETDNS_RETURN_MEMORY_ERROR:
            *h_errnop = TRY_AGAIN;
            *errnop = ERANGE;
            *nss_code = NSS_STATUS_TRYAGAIN;
            break;
        case GETDNS_RETURN_GENERIC_ERROR:
            *h_errnop = NO_RECOVERY;
            *errnop = EAGAIN;
            *nss_code = NSS_STATUS_UNAVAIL;
            break;
        case GETDNS_RESPSTATUS_GOOD:
        case GETDNS_RETURN_GOOD: 
            *h_errnop = 0;
            *errnop = 0;
            *nss_code = NSS_STATUS_SUCCESS;
            break;
        case GETDNS_RESPSTATUS_NO_NAME:
            *h_errnop = NO_DATA;
            *errnop = ENOENT;
            *nss_code = NSS_STATUS_NOTFOUND;
            break;
        case GETDNS_RETURN_WRONG_TYPE_REQUESTED:
            *h_errnop = NO_DATA;
            *errnop = EAFNOSUPPORT;
            *nss_code = NSS_STATUS_TRYAGAIN;
            break;
        case GETDNS_RESPSTATUS_ALL_TIMEOUT:
            *h_errnop = NO_DATA;
            *errnop = EAGAIN;
            *nss_code = NSS_STATUS_TRYAGAIN;
            break;
        case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
        case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
            *h_errnop = NO_DATA;
            *errnop = ENOENT;
            *nss_code = NSS_STATUS_NOTFOUND;
  }

}
