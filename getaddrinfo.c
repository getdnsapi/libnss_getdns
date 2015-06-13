#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <nss.h>
#include <stdlib.h>
#include <getdns/getdns.h>
#include "logger.h"
#include "addr_utils.h"

#define  UNUSED_PARAM(x) ((void)(x))	

/*
*TODO: Confirm that all the error codes returned are compatible with POSIX gai_strerror().
*/
extern void __freeaddrinfo(struct addrinfo*);
extern void v42v6_map(char*);
extern enum nss_status _nss_getdns_getaddrinfo(const char*, int, struct addrinfo**, struct addrinfo*);
extern enum nss_status eai2nss_code(int, int*);
extern void *addr_data_ptr(struct sockaddr_storage*);
extern void getdns_process_statcode(getdns_return_t, uint32_t, enum nss_status*, int*, int*);
extern getdns_return_t getdns_getaddrinfo(const char*, int, struct addrinfo**, struct addrinfo*, uint32_t*);

int parse_addrtype_hints(const struct addrinfo *hints, const char *protocol, int *hint_err)
{
	if(hints == NULL)return -1;
	if ((hints->ai_flags & ~(AI_MASK)) != 0)
	{
		*hint_err = EAI_BADFLAGS;
		errno = EINVAL;
		return -1;
	}
	if (hints->ai_addrlen || hints->ai_canonname || hints->ai_addr || hints->ai_next)
	{
			*hint_err = EAI_SYSTEM;
			errno = EINVAL;
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
			errno = EAFNOSUPPORT;
			return -1;
	}
	switch (hints->ai_socktype)
	{
		case 0: /*socket type not specified:addresses of any type can be returned.*/
				break;
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
			errno = EPROTONOSUPPORT;
			return -1;
	}	
	UNUSED_PARAM(protocol);
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
		if (*srvptr == NULL)
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
		*srvptr = getservbyport(*port, protocol);
	}
	*err = (*srvptr == NULL) ? EAI_SERVICE : 0;
	return *err == 0 ? 0 : -1;
}

int __getdns_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints,
	struct addrinfo **res, enum nss_status *status)
{
	struct servent *service_ptr;
	const char *proto;
	int family, socktype, flags, protocol;
	struct addrinfo *temp_ai;
	getdns_return_t return_code;
	int err = 0;
	int port = 0;
	temp_ai = NULL;
	proto = NULL; 
	service_ptr = NULL;
	*res = NULL;
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
		err_log("getdns_mirror_getaddrinfo: BAD HINTS. Error: %d / %d / %d\n", err, hints->ai_socktype, SOCK_RAW);
		return eai2nss_code(err, status);
	}
	if ( (hostname == NULL && servname == NULL)
		|| (hostname == NULL && (flags & AI_NUMERICHOST) != 0) /*There should be no name resolution here!*/
		|| (servname == NULL && (flags & AI_NUMERICSERV) != 0) /*There should be no service resolution here!*/)
	{
		return eai2nss_code(EAI_NONAME, status);
	}
	if(servname != NULL)
	{
		/*
		 * Look up the service name (port) if it was requested.
		 */
		 if(service_lookup(servname, proto, &port, &service_ptr, &err) != 0)
		 {
		 	return eai2nss_code(err, status);
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
				return eai2nss_code(EAI_SOCKTYPE, status);
		 }
	}	
	 /*
	 *AI_V4MAPPED without AF_INET6 must be ignored;
	 *AI_ALL without AI_V4MAPPED must be ignored
	 */
	 if( (flags & AI_V4MAPPED) == 0 || family != AF_INET6)
	 {
	 	flags &= ~(AI_V4MAPPED | AI_ALL);
	 }
	/*
	 * Handle AI_NUMERICHOST or no family specified
	 *(1) If hostname is not a non-null numeric host address string, return error to prevent name resolution.
	 */
	if (family == 0 || (flags & AI_NUMERICHOST) != 0)
	{
		char addrbuf[sizeof(struct in6_addr)];
		int parsedv4=0, parsedv6=0, addrsize;
		if(( family != 0 && hostname != NULL) 
			&& ( (0 == (parsedv4 = inet_pton(AF_INET, hostname, addrbuf)))
			&& (0 == (parsedv6 = inet_pton(AF_INET, hostname, addrbuf)))))
		{
			/*hostname is not a numeric host address string*/
			return eai2nss_code(EAI_NONAME, status);
		}
		if(parsedv4 && family == AF_INET6)
		{
			v42v6_map(addrbuf);
		}
		temp_ai = _allocaddrinfo(family);
		if(temp_ai == NULL)
		{
			return eai2nss_code(EAI_MEMORY, status);
		}
		SET_AF_PORT(temp_ai->ai_addr, port);
		temp_ai->ai_socktype = socktype;
		addrsize = (family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
		memcpy(addr_data_ptr((struct sockaddr_storage*)(temp_ai->ai_addr)), addrbuf, addrsize);
		if((flags & AI_CANONNAME) != 0)
		{
			char namebuf[NI_MAXHOST];
			if(getnameinfo(temp_ai->ai_addr, (socklen_t)temp_ai->ai_addrlen, namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST) == 0) {
					temp_ai->ai_canonname = strndup(namebuf, NI_MAXHOST);
					if(temp_ai->ai_canonname == NULL) {
						__freeaddrinfo(temp_ai);
						return eai2nss_code(EAI_MEMORY, status);
					}
				}else{
					temp_ai->ai_canonname = NULL;
				}
		}
		if((flags & AI_NUMERICHOST) != 0)
		{
			goto end;
		}
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
			if(family == AF_INET)
				((struct sockaddr_in*)(temp_ai->ai_addr))->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			else
				((struct sockaddr_in6*)(temp_ai->ai_addr))->sin6_addr = in6addr_loopback;
		}
		if( (temp_ai = _allocaddrinfo(family)) == NULL)
		{
			return EAI_MEMORY;
		}
		UNUSED_PARAM(addrlen);
		UNUSED_PARAM(protocol);
		COPY_ADDRINFO_PARAMS(temp_ai, flags, family, socktype, protocol, temp_ai->ai_addr, addrlen, NULL);
		goto end;
	}
	/*
	*If AI_ADDRCONFIG is set, restrict which addresses can be returned.
	*/
	if((flags & AI_ADDRCONFIG) != 0)
	{
	/*TODO : How do we figure out that IPv4 or/and IPv6 is configured on the local system? The _res global?*/
	}
	/*
	NOW RESOLVE NAME!!!!!!!!!!
	*/
	int h_errnop = 0;
	struct addrinfo query_hints = {.ai_family = family, .ai_socktype = socktype, .ai_protocol = protocol, .ai_flags = flags};
	__freeaddrinfo(temp_ai);
	temp_ai = NULL;
	uint32_t respstatus;
	return_code = getdns_getaddrinfo(hostname, family, &temp_ai, &query_hints, &respstatus);
	if( (respstatus == GETDNS_RESPSTATUS_NO_NAME) &&  ((hints->ai_flags & AI_V4MAPPED) != 0 && family == AF_INET6) )
	{
		query_hints.ai_flags |= AI_V4MAPPED;
		return_code = getdns_getaddrinfo(hostname, AF_INET, &temp_ai, &query_hints, &respstatus);
	}
	getdns_process_statcode(return_code, respstatus, status, &errno, &h_errnop);
	end:
		if (temp_ai == NULL || respstatus != GETDNS_RESPSTATUS_GOOD)
		{
			if (err == 0)
			{
				err = EAI_NONAME; 
			}
			temp_ai = NULL;
			return err;
		}
		*res = temp_ai;	
		err_log("GETADDRINFO: STATUS: %d, ERR_CODE: %d\n", respstatus, eai2nss_code(0, status));
		return eai2nss_code(0, status);
}


int getdns_mirror_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints,	struct addrinfo **res)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;
	return __getdns_getaddrinfo(hostname, servname, hints, res, &status);
}

void getdns_mirror_freeaddrinfo(struct addrinfo *ai)
{
	__freeaddrinfo(ai);
}
