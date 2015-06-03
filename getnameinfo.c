#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int getdns_mirror_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen,
	char *serv, size_t servlen, int flags)
{
	return EAI_SERVICE;
}
