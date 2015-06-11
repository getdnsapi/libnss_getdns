#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <nss.h>
#include <getdns/getdns.h>
#include <errno.h>

const char *getdns_mirror_gai_strerror(int ecode)
{
	return "Not implemented!";
}

enum nss_status eai2nss_code(int err, int *status)
{
	switch(err)
	{
		case EAI_AGAIN:
		case EAI_MEMORY:
		case EAI_OVERFLOW:
			*status = NSS_STATUS_TRYAGAIN;
			break;
		case EAI_SYSTEM:
		case EAI_FAIL:
			*status = NSS_STATUS_UNAVAIL;
			break;
		case EAI_FAMILY:
		case EAI_BADFLAGS:
		case EAI_SERVICE:
		case EAI_SOCKTYPE:
		case EAI_NONAME:
			*status = NSS_STATUS_NOTFOUND;
			break;
		default:
			*status = NSS_STATUS_SUCCESS;
			break;
	}
	return err;
}

int getdns_eai_error_code(uint32_t status)
{
	 switch(status)
    {
        case GETDNS_RETURN_MEMORY_ERROR:
            return EAI_MEMORY;
        case GETDNS_RETURN_GENERIC_ERROR:
            return EAI_SYSTEM;
        case GETDNS_RESPSTATUS_GOOD:
        case GETDNS_RETURN_GOOD: 
            return 0;
        case GETDNS_RESPSTATUS_NO_NAME:
            return EAI_NONAME;
        case GETDNS_RETURN_WRONG_TYPE_REQUESTED:
            return EAI_FAMILY;
        case GETDNS_RESPSTATUS_ALL_TIMEOUT:
            return EAI_AGAIN;
        case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
        case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
            return EAI_NONAME;
  }
  return EAI_FAIL;
}


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
