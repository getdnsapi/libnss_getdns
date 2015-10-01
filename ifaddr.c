// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "context_interface.h"
#include "logger.h"

int resolve_local(const char *query, response_bundle **ret)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, is_hostname = 0;
	char hostname[NI_MAXHOST];
	/*
	*Get all locally-configured interface addresses.
	*/
	if(getifaddrs(&ifaddr) == -1)
	{
	   log_critical("resolve_local< getifaddrs failed>");
	   return -1;
	}
	if(gethostname(hostname, NI_MAXHOST) != 0)
	{
		log_critical("gethostname() failed.");
		return -1;
	}
	if(strcasecmp(hostname, query) == 0)
	{
		is_hostname = 1;
	}
	*ret = malloc(sizeof(response_bundle));
	if(!(*ret))
	{
		log_critical("malloc failed");
		return -1;
	}
	memset(*ret, 0, sizeof(response_bundle));
	(*ret)->respstatus = RESP_BUNDLE_LOCAL_CONFIG.respstatus;
	(*ret)->dnssec_status = RESP_BUNDLE_LOCAL_CONFIG.dnssec_status;
	(*ret)->ipv4_count = 0;
	(*ret)->ipv6_count = 0;
	(*ret)->ttl = 0;
	memcpy((*ret)->ipv4, "ipv4:", 5);
	memcpy((*ret)->ipv6, "ipv6:", 5);
	char *ipv4_ptr = &((*ret)->ipv4[5]);
	char *ipv6_ptr = &((*ret)->ipv6[5]);
	size_t len;
	strncpy((*ret)->cname, hostname, strlen(hostname)); 
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
		   continue;
		family = ifa->ifa_addr->sa_family;
		if(family == AF_INET)
		{
			char address_str[NI_MAXHOST];
			if(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), address_str, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
			{
				continue;
			}
			len = strlen(address_str)+1;
			if(!is_hostname && (strncasecmp(address_str, query, len-1) != 0))
			{
				/*
				*Neither the hostname, nor a local IP address, so continue;
				*/
				continue;
			}
			(*ret)->ipv4_count++;
			snprintf(ipv4_ptr, len+1, "%s,", address_str);
			ipv4_ptr += len;
		}else if(family == AF_INET6){
			char address_str[NI_MAXHOST];
			if(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), address_str, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
			{
				continue;
			}
			len = strlen(address_str)+1;
			/*
			*Local IPv6 addresses can be scoped (with iface index, as ADDRESS%if_idx)
			*/
			if(!is_hostname && (strncasecmp(address_str, query, strchrnul(address_str, '%') - address_str) != 0))
			{
				/*
				*Neither the hostname, nor a local IP address, so continue;
				*/
				continue;
			}
			(*ret)->ipv6_count++;
			snprintf(ipv6_ptr, len+1, "%s,", address_str);
			ipv6_ptr += len;
		}
	}
	freeifaddrs(ifaddr);
	if(1 > ((*ret)->ipv4_count + (*ret)->ipv6_count))
	{
		free(*ret);
		*ret = NULL;
		return -1;
	}
	memset(ipv4_ptr-1, 0, 1);
	memset(ipv6_ptr-1, 0, 1);
	return 0;
}

int has_ipv6_addresses()
{
	struct ifaddrs *ifaddr, *ifa;
	/*
	*Get all locally-configured interface addresses.
	*/
	if(getifaddrs(&ifaddr) == -1)
	{
	   log_critical("resolve_local< getifaddrs failed>");
	   return 0;
	}
	
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr && (ifa->ifa_addr->sa_family == AF_INET))
		{
			return 0;
		}
	}
	return 1;
}
