#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "addr_utils.h"
#include "logger.h"

extern uint32_t getdns_getnameinfo (const void*, const int, char*, size_t);
extern int getdns_eai_error_code(uint32_t);

#define ERR_RETURN(err_code){errno = err_code; h_errno = err_code; return err_code;}
static int check_flags(int flags)
{
	if ((flags & ~(NI_MASK)) !=0 /*Presence of unexpected flag*/
		|| ((flags & NI_NAMEREQD) !=0 && (flags & NI_NUMERICHOST) !=0)	/*NI_NUMERICHOST and NI_NAMEREQD conflict with each other*/
		)
	{
		return EAI_BADFLAGS;
	}
	return 0;
}

static int parse_ipv6_scope_id(const int if_index, const int flags, char *ifname_buf, size_t buflen)
{
	/*
	*The numeric form of the scope-id shall returned if NI_NUMERICSCOPE is set.
	*As of Glibc2 NI_NUMERICSCOPE is missing.
	*RFC3493 does not mention NI_NUMERICSCOPE  among the flags either.
	*But it is mentioned in POSIX.1-2008.
	*Referring to RFC 4007.
	*/	
	memset(ifname_buf, 0, buflen);
	#ifdef NI_NUMERICSCOPE
	if((flags & NI_NUMERICSCOPE) != 0)
	#else
	if(if_indextoname(if_index, ifname_buf) == NULL)
	#endif
		snprintf(ifname_buf, buflen, "%d", if_index);
	return strlen(ifname_buf) > 0 ? 0 : -1;
}

void extract_sa_addr(const struct sockaddr *sa, socklen_t salen, void **addr, int *port, size_t *sa_addrlen, int *err)
{
	//socklen_t socklen;
	switch (sa->sa_family) {
		case AF_INET:
			*port = ((const struct sockaddr_in *)sa)->sin_port;
			*addr = &((struct sockaddr_in *)sa)->sin_addr.s_addr;
			//socklen = sizeof(struct sockaddr_in);
			*sa_addrlen = sizeof(struct in_addr);
			break;
		case AF_INET6:
			*port = ((const struct sockaddr_in6 *)sa)->sin6_port;
			*addr = ((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
			//socklen = sizeof(struct sockaddr_in6);
			*sa_addrlen = sizeof(struct in6_addr);
			break;
		default:
			*err = EAI_FAMILY;
			return;
	}
	//if(socklen != salen)
	//	*err = EAI_FAIL;
}

int getdns_mirror_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen,
	char *serv, size_t servlen, int flags)
{
	int err = 0;
	int family, port;
	struct servent *srvc;
	void *addr;
	char *protocol;
	size_t addrlen = 0;
	/*
	*Either host or serv must be non-null, with its corresponding XXXlen being greater than zero.
	*Another interresting case is when host is null while NI_NAMEREQD is set: who would do that?!
	*/
	if(!sa || ((!host || hostlen == 0) && ( (!serv || servlen == 0) || (flags & NI_NAMEREQD) != 0)))
	{
		ERR_RETURN(EAI_FAIL);
	}
	if(hostlen > NI_MAXHOST || servlen > NI_MAXSERV)
	{
		ERR_RETURN(EAI_MEMORY);
	}
	if((err = check_flags(flags)) != 0)
	{
		ERR_RETURN(err);
	}
	family = sa->sa_family;
	addr = NULL;
	extract_sa_addr(sa, salen, &addr, &port, &addrlen, &err);
	if(err !=0 || addr == NULL)
	{
		ERR_RETURN(err);
	}
	protocol = (flags & NI_DGRAM) ? "udp" : "tcp";
	/*
	*No service shall be returned if servlen is 0 or the service argument is null
	*/
	if(serv != NULL && servlen > 0)
	{
		/*Use numeric form of service addr instead of its name if
		*(1) NI_NUMERICSERV is set, or
		*(2) service name cannot be looked up by port and protocol
		*/
		if ((flags & NI_NUMERICSERV) != 0 || (srvc = getservbyport(port, protocol)) == NULL)
		{
			char numaddr[NI_MAXSERV];
			int numaddrlen = -1;
			if( ((numaddrlen = snprintf(numaddr, NI_MAXSERV, "%d", ntohs(port))) + 1 < servlen) && numaddrlen > 0)
			{
				strncpy(serv, numaddr, numaddrlen+1);
			}else{
				err = numaddrlen > 0 ? EAI_OVERFLOW : EAI_MEMORY;
				ERR_RETURN(err);
			}		
		}else{
			if(strlen(srvc->s_name) + 1 < servlen)
			{
				strcpy(serv, srvc->s_name);
			}else{
				ERR_RETURN(EAI_OVERFLOW);
			}
		}
	}
	/*
	*No hostame shall be returned if hostlen is 0 or the host argument is null
	*/
	if(host != NULL && hostlen > 0)
	{
		char addrstring[NI_MAXHOST];
		char if_name[IF_NAMESIZE];
		int if_index;
		if((flags & NI_NUMERICHOST) != 0)
		{
			/*Numeric form of host address was requested instead of its name*/
			if (inet_ntop(family, addr, addrstring, sizeof(addrstring)) == NULL)
			{
				ERR_RETURN(EAI_SYSTEM);
			}
			/*
			*Add the IPv6 scope-id if present.
			*/
			if_index = ((const struct sockaddr_in6 *)sa)->sin6_scope_id;
			if(family == AF_INET6 && if_index)
			{
				if( (err = parse_ipv6_scope_id(if_index, flags, if_name, IF_NAMESIZE)) != 0)
				{
					ERR_RETURN(err);
				}
				char *addrstring_endptr = addrstring + strlen(addrstring);
				if(snprintf(addrstring_endptr, sizeof(addrstring) - (addrstring_endptr - addrstring), "%%%s", if_name) != strlen(if_name));
				{
					ERR_RETURN(EAI_MEMORY);
				}
			}
			if(strlen(addrstring) < hostlen)
			{
				strcpy(host, addrstring);
			}else{
				ERR_RETURN(EAI_OVERFLOW);
			}			
		}else{
			/*Now we shall resolve the nodename*/
			void *addr_data;
			if(family == AF_INET6)
			{
				addr_data = (struct in6_addr*)addr;
				if(addr_data && IN6_IS_ADDR_V4MAPPED(addr_data))
				{
					/*IPv4-mapped IPv6 addresses must be resolved just like normal IPv4 addresses*/
					addr_data += 12;
					family = AF_INET;
				}
			}else{
				addr_data = (struct in_addr*)addr;
			}
			if((err = getdns_getnameinfo(addr_data, family, host, hostlen)) != 0)
			{
				ERR_RETURN(getdns_eai_error_code(err));
			}
		}
		if((flags & NI_NOFQDN) != 0)
		{
			/*
			*This applies to local hosts only.
			*TODO:how to efficiently determine if an address references a local host?
			*NOT VERY HELPFUL: glibc kind of does it badly using gethostbyname("localhost") and gethostbyaddr(INADDR_LOOPBACK)
			*KIND OF HELPFUL: getdns builds local hosts (from /etc/hosts and /etc/resolv.conf) with the context.
			*WORRYING: getdns does not seem to resolve the local machine's address configured with DHCP: It just maps localhost to INADDR_LOOPBACK!
			*/
			if(family == AF_INET)
			{
				char *p = strchr(host, '.');
				if(p)
					*p = '\0';
			}else if(IN6_IS_ADDR_LINKLOCAL(sa) || IN6_IS_ADDR_SITELOCAL(sa))
			{
			
			}
		}		
		
	}
	if((flags & NI_NAMEREQD) != 0 && strlen(host) == 0)
	{
		ERR_RETURN(EAI_NONAME);
	}
	ERR_RETURN(0);
}
