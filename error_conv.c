#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getdns/getdns.h>
#include <errno.h>
#include "nss_getdns.h"

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

int getdns_eai_error_code(getdns_return_t return_code, uint32_t status)
{
	/*
	*The response status has to be parsed first because there may be a negative response without any errors
	*/
	 switch(status)
    {
        case GETDNS_RESPSTATUS_GOOD:
        case GETDNS_RESPSTATUS_NO_NAME:
            return EAI_NONAME;
        case GETDNS_RESPSTATUS_ALL_TIMEOUT:
            return EAI_AGAIN;
        case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
        case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
            return EAI_NONAME;
	}
	switch(return_code)
	{
	case GETDNS_RETURN_GOOD: 
    	return 0;
    case GETDNS_RETURN_BAD_DOMAIN_NAME:
    	return EAI_NONAME;
	case GETDNS_RETURN_MEMORY_ERROR:
		return EAI_MEMORY;
	case GETDNS_RETURN_WRONG_TYPE_REQUESTED:
	case GETDNS_RETURN_INVALID_PARAMETER:
		return EAI_FAMILY;
	case GETDNS_RETURN_GENERIC_ERROR:
		return EAI_FAIL;
	default:
		return EAI_SYSTEM;
	}
}


/*
Convert getdns status codes & return values to NSS status codes, and set errno values
*/
void getdns_process_statcode(getdns_return_t return_code, uint32_t status, enum nss_status *nss_code, int *errnop, int *h_errnop){
    /*
	*The response status has to be parsed first because there may be a negative response without any errors
	*/
    switch(status)
    {
        case GETDNS_RESPSTATUS_GOOD: 
            *h_errnop = 0;
            *errnop = 0;
            *nss_code = NSS_STATUS_SUCCESS;
            return;
        case GETDNS_RESPSTATUS_NO_NAME:
            *h_errnop = NO_DATA;
            *errnop = ENOENT;
            *nss_code = NSS_STATUS_NOTFOUND;
            return;
        case GETDNS_RESPSTATUS_ALL_TIMEOUT:
            *h_errnop = NO_DATA;
            *errnop = EAGAIN;
            *nss_code = NSS_STATUS_TRYAGAIN;
            return;
        case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
        case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
            *h_errnop = NO_DATA;
            *errnop = ENOENT;
            *nss_code = NSS_STATUS_NOTFOUND;
  	}
  	switch(return_code)
  	{
  		case GETDNS_RETURN_GOOD:
  			*h_errnop = 0;
            *errnop = 0;
            *nss_code = NSS_STATUS_SUCCESS;
            return;
  		case GETDNS_RETURN_MEMORY_ERROR:
            *h_errnop = TRY_AGAIN;
            *errnop = ERANGE;
            *nss_code = NSS_STATUS_TRYAGAIN;
            return;
        case GETDNS_RETURN_WRONG_TYPE_REQUESTED:
        case GETDNS_RETURN_BAD_DOMAIN_NAME:
            *h_errnop = NO_DATA;
            *errnop = EAFNOSUPPORT;
            *nss_code = NSS_STATUS_TRYAGAIN;
            return;
         default:
            *h_errnop = NO_RECOVERY;
            *errnop = EAGAIN;
            *nss_code = NSS_STATUS_UNAVAIL;
  	}
}
