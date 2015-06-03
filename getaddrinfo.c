/*

Supported ERRORS:
	   EAI_AGAIN	 temporary failure in name resolution
	   EAI_BADFLAGS  invalid value for ai_flags
	   EAI_BADHINTS  invalid value for hints
	   EAI_FAIL	 non-recoverable failure in name resolution
	   EAI_FAMILY	 ai_family not supported
	   EAI_MEMORY	 memory allocation failure
	   EAI_NONAME	 hostname or servname not provided, or not known
	   EAI_OVERFLOW  argument buffer overflow
	   EAI_PROTOCOL  resolved protocol is unknown
	   EAI_SERVICE	 servname not supported for ai_socktype
	   EAI_SOCKTYPE  ai_socktype not supported
	   EAI_SYSTEM	 system error returned in errno
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int getdns_mirror_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints,
	struct addrinfo **res)
{
	return EAI_FAMILY;
}

void getdns_mirror_freeaddrinfo(struct addrinfo *ai)
{

}
