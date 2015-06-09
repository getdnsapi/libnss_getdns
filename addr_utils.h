#ifndef _NSS_GETDNS_ADDR_UTILS_H_
#define _NSS_GETDNS_ADDR_UTILS_H_

#define AI_MASK (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG)
#define SET_AF_PORT(sa, port)	\
do{	\
	if(sa->sa_family == AF_INET)	\
		((struct sockaddr_in *)(sa))->sin_port = port;	\
	else	\
		((struct sockaddr_in6 *)(sa))->sin6_port = port;	\
}while (0)
#define COPY_ADDRINFO_PARAMS(res, flags, family, socktype, protocol, addr, addrlen, canonname)  \
do{	\
	(res)->ai_flags = flags;	\
    (res)->ai_family = family;	\
    (res)->ai_socktype = socktype;	\
    (res)->ai_protocol = protocol;	\
    (res)->ai_addrlen = addrlen;	\
    (res)->ai_addr = addr;	\
    (res)->ai_canonname = canonname;	\
    (res)->ai_next = NULL;	\
}while (0)

struct addrinfo *_allocaddrinfo(int);
void _freeaddrinfo(struct addrinfo*);

#endif
