#define __USE_GNU
#include "config.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <dlfcn.h>

extern int getdns_mirror_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints,	struct addrinfo **res);
extern void __freeaddrinfo(struct addrinfo *ai);
extern const char *getdns_module_strerror(int);
extern int getdns_mirror_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen,
	char *serv, size_t servlen, int flags);


/*char * this_gai_strerror(int errcode)
{
	static char* (*gai_strerror_libc)(int)=NULL;
	if(!gai_strerror_libc)
	{
		gai_strerror_libc = dlsym(RTLD_NEXT, "gai_strerror");
	}
	switch(errcode)
	{
		case EAI_SYSTEM:
			return getdns_get_errorstr_by_id(errcode);	
		default:
			return gai_strerror_libc(errcode);
	}
}*/

const char * module_gai_strerror(int errcode)
{
	switch(errcode)
	{
		case EAI_AGAIN:
		case EAI_BADFLAGS:
		case EAI_FAIL:
		case EAI_FAMILY:
		case EAI_MEMORY:
		case EAI_NONAME:
		case EAI_OVERFLOW:
		case EAI_SYSTEM:
			return gai_strerror(errcode);	
		default:
			return getdns_module_strerror(errcode);
	}
}

#ifdef HAVE_CONFIG_H
	#ifdef ENABLE_API_INTERCEPT
		#define getaddrinfo(hostname, servname, hints, res) getdns_mirror_getaddrinfo(hostname, servname, hints, res)
		#define getnameinfo(sa, salen, host, hostlen, serv, servlen, flags) getdns_mirror_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags)
		#define freeaddrinfo(ai) __freeaddrinfo(ai)
		#define gai_strerror(errcode) module_gai_strerror(errcode)
		//#define strerror(errcode) module_gai_strerror(errcode)
	#endif
#endif
