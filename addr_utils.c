#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define COPY_ADDssRINFO_PARAMS(res, flags, family, socktype, protocol, addr, addrlen, canonname) {\
do{	\
	(res)->ai_flags = flags;	\
    (res)->ai_family = family;	\
    (res)->ai_socktype = socktype;	\
    (res)->ai_protocol = protocol;	\
    (res)->ai_addrlen = addrlen;	\
    (res)->ai_addr = addr;	\
    (res)->ai_canonname = canonname;	\
    (res)->ai_next = NULL;	\
}while (0)	\
}

/*Convert v4 to a V6 (v4-mapped address).*/
void v42v6_map(char *addr)
{
	struct in6_addr *a6 = (struct in6_addr *)addr;
	memmove(&a6->s6_addr[12], &a6->s6_addr[0], 4);
	memset(&a6->s6_addr[10], 0xff, 2);
	memset(&a6->s6_addr[0], 0, 10);
}
