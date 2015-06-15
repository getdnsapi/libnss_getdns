#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "addr_utils.h"

/*Convert IPv4 to a IPv6 (IPv4-mapped address).*/
void v42v6_map(char *addr)
{
	struct in6_addr *a6 = (struct in6_addr*)addr;
	memmove(a6->s6_addr+12, a6->s6_addr, 4);
	memset(a6->s6_addr+10, 0xff, 2);
	memset(a6->s6_addr, 0, 10);
}

void *addr_data_ptr(struct sockaddr_storage *arg)
{
	switch(arg->ss_family)
	{
		case AF_INET:
			return &((struct sockaddr_in*)arg)->sin_addr;
		default:
			return &((struct sockaddr_in6*)arg)->sin6_addr;
	}
}

/*
 * Allocate an addrinfo structure its ai_addr member
 */
struct addrinfo *_allocaddrinfo(int family) {
	struct addrinfo *ret;
	size_t addrlen = ((family == AF_INET6) ? sizeof(struct sockaddr_storage) : sizeof(struct sockaddr_storage));
	ret = (struct addrinfo *)calloc(1, sizeof(*ret));
	if (ret == NULL)
	{
		return NULL;
	}
	ret->ai_addr = (struct sockaddr*)calloc(1, addrlen);
	if (ret->ai_addr == NULL) {
		free(ret);
		return NULL;
	}
	ret->ai_addrlen = addrlen;
	ret->ai_family = family;
	ret->ai_addr->sa_family = family;
	return ret;
}

void __freeaddrinfo(struct addrinfo *ai){
	struct addrinfo *ai_next;
	while (ai != NULL){
		ai_next = ai->ai_next;
		if (ai->ai_addr != NULL)
		{
			free(ai->ai_addr);
			ai->ai_addr = NULL;
		}
		if (ai->ai_canonname)
		{
			free(ai->ai_canonname);
			ai->ai_canonname = NULL;
		}
		free(ai);
		ai = ai_next;
	}
}
