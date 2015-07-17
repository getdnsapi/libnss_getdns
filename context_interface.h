#include "nss_getdns.h"

#ifndef GETDNS_CONTEXT_MANAGER_INTERFACE_H
#define GETDNS_CONTEXT_MANAGER_INTERFACE_H

#define GETDNS_ERR_IPV4 "ipv4:127.127.127.127"
#define GETDNS_ERR_IPV6 "ipv6:::ffff:127.127.127.127"
#define GETDNS_ERR_LOCALNAME "getdns-errors.localhost"
#define GETDNS_CONFIG_IPV4 "ipv4:127.127.127.128"
#define GETDNS_CONFIG_IPV6 "ipv6:::ffff:127.127.127.128"
#define GETDNS_CONFIG_LOCALNAME "getdns-config.localhost"

#define MAX_NUM_ANSWERS 10

/*
This structure holds a bundle of addresses for a domain name resolution answer.
*/
typedef struct response_addr_bundle
{
	uint32_t respstatus;
	uint32_t dnssec_status;
	long ttl;
	char *cname;
	uint32_t ipv4_count; /*Number of IPv4 addresses*/
	uint32_t ipv6_count; /*Number of IPv6 addresses*/
	char *ipv4; /*comma-separated list of IPv4 addresses*/
	char *ipv6; /*comma-separated list of IPv6 addresses*/
} response_bundle;

/*
This structure holds a FLAT bundle of addresses for a domain name resolution answer.
*/
typedef struct flat_response_addr_bundle
{
	uint32_t respstatus;
	uint32_t dnssec_status;
	long ttl;
	char cname[NI_MAXHOST];
	uint32_t ipv4_count; /*Number of IPv4 addresses*/
	uint32_t ipv6_count; /*Number of IPv6 addresses*/
	char ipv4[NI_MAXHOST*MAX_NUM_ANSWERS]; /*comma-separated list of IPv4 addresses*/
	char ipv6[NI_MAXHOST*MAX_NUM_ANSWERS]; /*comma-separated list of IPv6 addresses*/
} flat_response_bundle;

/*
Request holder.
*/
typedef struct request_params_bundle
{
	char query[NI_MAXHOST];
	int reverse;
	int af;
} req_params;
	
/*
*Response bundle for negative answers
*/
extern response_bundle RESP_BUNDLE_EMPTY;
/*
*Response bundle for local configuration pages
*/
extern response_bundle RESP_BUNDLE_LOCAL_CONFIG;
/*
*Response bundle for errors (DNSSEC/TLS)
*/
extern response_bundle RESP_BUNDLE_LOCAL_ERR;
/*
*Test response bundle for bogus
*/
extern response_bundle RESP_BUNDLE_LOCAL_BOGUS;

/*
*Function to be implemented to manage the GETDNS context and extensions.
*Returns 0 on success, and -1 on failure.
*Context initialization is heavy, and access accross multiple threads and processes must be done with care.
*It's up to the implementation how to create, use, and destroy contexts.
*A typical use case is having one context around and reusing it for a particular process, thus reducing the context initialization overhead.
*Another case is having a single context per user session and using it for all processes.
*The simplest case is to create a context on demand and destroying it immediately.
*/
typedef int (*getdns_context_proxy)(char* name_or_address_as_ascii_string, int bool_do_reverse_lookup, int address_family, response_bundle **result);

int resolve_with_managed_ctx(char* query, int is_reverse, int af, response_bundle **result);

const char *get_dnssec_code_description(int code);
#endif
