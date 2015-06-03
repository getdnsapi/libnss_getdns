#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <nss.h>

const char *getdns_mirror_gai_strerror(int ecode)
{
	return "Not implemented!";
}

enum nss_status eai2nss_code(int err)
{
	return NSS_STATUS_NOTFOUND;
}
