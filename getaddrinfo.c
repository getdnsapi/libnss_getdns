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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#define  UNUSED_PARAM(x) ((void)(x))

#define AI_MASK (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG)
#define SOCKADDR(addr)	((struct sockaddr *)(addr))
#define SOCKADDR_IN(addr)	((struct sockaddr_in *)(addr))
#define SOCKADDR_IN6(addr)	((struct sockaddr_in6 *)(addr))
#define IN6(addr)	((struct in6_addr *)(addr))

#define COPY_ADDRINFO_PARAMS(res, flags, family, socktype, protocol, addr, addrlen, canonname) /* \
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
*/
void getdns_mirror_freeaddrinfo(struct addrinfo*);
extern void v42v6_map(char*);

int parse_addrtype_hints(const struct addrinfo *hints, const char *protocol, int *hint_err)
{
	if(hints == NULL)return -1;
	if ((hints->ai_flags & ~(AI_MASK)) != 0)
	{
		*hint_err = EAI_BADFLAGS;
		return -1;
	}
	if (hints->ai_addrlen || hints->ai_canonname || hints->ai_addr || hints->ai_next)
	{
			errno = EINVAL;
			*hint_err = EAI_SYSTEM;
			return -1;
	}
	switch (hints->ai_family)
	{
		case AF_INET:
		case AF_INET6:
		case AF_UNSPEC:
			break;
		default:
			*hint_err = EAI_FAMILY;
			return -1;
	}
	switch (hints->ai_socktype)
	{
		case SOCK_STREAM:
			protocol = "tcp";
			break;
		case SOCK_DGRAM:
			protocol = "udp";
			break;
		case SOCK_RAW:
			break;
		default:
			*hint_err = EAI_SOCKTYPE;
			return -1;
	}	
	return 0;
}

int service_lookup(const char *servname, const char *protocol, int *port, struct servent **srvptr, int *err)
{
	if(servname == NULL)
	{
		*port = 0;
		return 0;
	}
	char *endptr;
	*port = strtol(servname, &endptr, 10);
	if (*endptr != '\0') {
		*srvptr = getservbyname(servname, protocol);
		if (srvptr == NULL)
		{
			*err = EAI_SERVICE;
			return -1;
		}
		*port = (*srvptr)->s_port;
	}else{
		if (*port < 0 || *port > 65535)
		{
			*err = EAI_SERVICE;
			return -1;
		}
		*port = htons((unsigned short) (*port));
	}
	return 0;
}

int getdns_mirror_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints,
	struct addrinfo **res)
{
	
	struct servent *service_ptr;
	const char *proto;
	int family, socktype, flags, protocol;
	struct addrinfo *temp_ai;
	int err = 0;
	int port;
	temp_ai = NULL;
	proto = NULL; 
	if(hints == NULL)
	{
		protocol = 0;
		family = 0;
		socktype = 0;
		flags = 0;
	}else if(parse_addrtype_hints(hints, proto, &err) == 0)
	{
		family = hints->ai_family;
		socktype = hints->ai_socktype;
		protocol = hints->ai_protocol;
		flags = hints->ai_flags;
	}else{
		return err;
	}
	if ( (hostname == NULL && servname == NULL)
		|| (hostname == NULL && (flags & AI_NUMERICHOST) != 0) /*There should be no name resolution here!*/
		|| (servname == NULL && (flags & AI_NUMERICSERV) != 0) /*There should be no service resolution here!*/)
	{
		return EAI_NONAME;
	}
	/*
	 * Look up the service name (port) if it was requested.
	 */
	 if(service_lookup(servname, proto, &port, &service_ptr, &err) != 0)
	 {
	 	return err;
	 }
	 /*If the socket type wasn't specified, try to figure it out from the service
	 */
	 if (socktype == 0)
	 {
		if (strcmp(service_ptr->s_proto, "tcp") == 0)
			socktype = SOCK_STREAM;
		else if (strcmp(service_ptr->s_proto, "udp") == 0)
			socktype = SOCK_DGRAM;
		else /*Give up, we could not figure out which socket type so far*/
			return EAI_SOCKTYPE;
	 }	
	 /*
	 *AI_V4MAPPED with family==AF_INET6
	 */
	 if( (flags & AI_V4MAPPED) != 0 && family == AF_INET6)
	 {
		 /*
		 *AI_ALL with AI_V4MAPPED and family=AF_INET6 must retrieve both IPv4 and IPv6, so set family to AF_UNSPEC?
		 */
	 	 if(flags & AI_ALL)
		 {
		 	family = AF_UNSPEC;
		 }
	 }
	/*
	 * Handle AI_NUMERICHOST or no family specified
	 *(1) If hostname is not a non-null numeric host address string, return error to prevent name resolution.
	 *(2) XXX:IPv6 SCOPE ID????
	 */
	if (family == 0 || (flags & AI_NUMERICHOST) != 0)
	{
		char addrbuf[sizeof(struct in6_addr)];
		int parsedv4, parsedv6,
		addrsize, addroff;
		if(hostname == NULL 
			|| ( (0 == (parsedv4 = inet_pton(AF_INET, hostname, addrbuf)))
			&& (0 == (parsedv6 = inet_pton(AF_INET, hostname, addrbuf)))))
		{
			/*hostname is not a numeric host address string*/
			return EAI_NONAME;
		}
		if(family == AF_INET6)
		{
			if(parsedv4)
			{
				v42v6_map(addrbuf);
			}
			addrsize = sizeof(struct in6_addr);
			addroff = (char *)(&SOCKADDR_IN6(0)->sin6_addr) - (char *)0;
		}else{
			addrsize = sizeof(struct in_addr);
			addroff = (char *)(&SOCKADDR_IN(0)->sin_addr) - (char *)0;
			family = AF_INET;
		}
		temp_ai = malloc(((family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)));
		if(temp_ai == NULL)
		{
			return EAI_MEMORY;
		}
		memset(temp_ai, 0, sizeof(struct sockaddr_in6));
		temp_ai->ai_socktype = socktype;
		memmove((char *)temp_ai->ai_addr + addroff, addrbuf, addrsize);
		if((flags & AI_CANONNAME) != 0)
		{
			char namebuf[NI_MAXHOST];
			if(getnameinfo(temp_ai->ai_addr, (socklen_t)temp_ai->ai_addrlen, namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST) == 0) {
					temp_ai->ai_canonname = strndup(namebuf, NI_MAXHOST);
					if(temp_ai->ai_canonname == NULL) {
						getdns_mirror_freeaddrinfo(temp_ai);
						return EAI_MEMORY;
					}
				}else{
					temp_ai->ai_canonname = NULL;
				}
		}
		goto end;
	}
	/*
	* hostname not specified:
	*(1) If AI_PASSIVE: caller wants a socket to bind to.
	* If hostname is null, socket address shall be *_ANY.
	*(2) otherwise, socket address shall be the loopback address.
	*/
	if(hostname == NULL)
	{
		socklen_t addrlen = (family == AF_INET6) ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
		if(flags & AI_PASSIVE)
		{
			if(family == AF_INET)
				((struct sockaddr_in*)(temp_ai->ai_addr))->sin_addr.s_addr = htonl(INADDR_ANY);
			else
				((struct sockaddr_in6*)(temp_ai->ai_addr))->sin6_addr = in6addr_any;
		}else{
			((struct sockaddr_in*)(temp_ai->ai_addr))->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		}
		if( (temp_ai = malloc(sizeof(struct addrinfo))) == NULL)
		{
			return EAI_MEMORY;
		}
		UNUSED_PARAM(addrlen);
		UNUSED_PARAM(protocol);
		COPY_ADDRINFO_PARAMS(temp_ai, flags, family, socktype, protocol, temp_ai->ai_addr, addrlen, NULL);
	}
	if(temp_ai == NULL)
	{
		/*
		*If AI_ADDRCONFIG is set, restrict which addresses can be returned.
		*/
		if((flags & AI_ADDRCONFIG) != 0)
		{
		/*XXX : How do we figure out that IPv4 or/and IPv6 is configured on the local system? The _res global?*/
		}
		/*
		NOW RESOLVE NAME!!!!!!!!!!
		*/
	}
	if (temp_ai == NULL) {
		if (err == 0)
			err = EAI_NONAME;
		return err;
	}
	end:
		*res = temp_ai;	
	return 0;
}

void getdns_mirror_freeaddrinfo(struct addrinfo *ai)
{

}
