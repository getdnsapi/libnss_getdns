#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <nss.h>

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
