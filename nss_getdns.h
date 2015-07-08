#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <getdns/getdns_ext_libevent.h>
#include "getdns_libevent.h"
#include "config.h"

#ifndef _GETDNS_NSS_H_
#define _GETDNS_NSS_H_

#define CONFIG_FILE "/etc/getdns.conf"

/*
*The following definitions are for compatibility with platforms that do not have types defined in nss.h
*/
#ifdef HAVE_NSS_H
#include <nss.h>
#else
/* Possible results of lookup using a nss_* function.  */
enum nss_status
{
  NSS_STATUS_TRYAGAIN = -2,
  NSS_STATUS_UNAVAIL,
  NSS_STATUS_NOTFOUND,
  NSS_STATUS_SUCCESS,
  NSS_STATUS_RETURN
};


/* Data structure used for the 'gethostbyname4_r' function.  */
struct gaih_addrtuple
  {
    struct gaih_addrtuple *next;
    char *name;
    int family;
    uint32_t addr[4];
    uint32_t scopeid;
  };
  
#endif

typedef enum {ADDR_HOSTENT, ADDR_GAIH, ADDR_ADDRINFO, ADDR_SERVENT, REV_HOSTENT} addr_param_t;

#if defined(__FreeBSD__)
struct gaih_addrtuple
  {
    struct gaih_addrtuple *next;
    char *name;
    int family;
    uint32_t addr[4];
    uint32_t scopeid;
  };
#endif

struct addr_param
	{
		addr_param_t addr_type;
		union
		{
		struct hostent *p_hostent;
		struct gaih_addrtuple **p_gaih;
		struct addrinfo **p_addrinfo;
		struct servent *p_servent;
		} addr_entry;
		struct addrinfo *hints;
	};

/*
Retrieve system global getdns context and default extensions
*/
getdns_return_t load_context(getdns_context **ctx, getdns_dict **ext);

getdns_return_t getdns_gethostinfo(const char *name, int af, struct addr_param *result_ptr, 
        char *intern_buffer, size_t buflen, int32_t *ttlp, char **canonp, uint32_t *respstatus, uint32_t *dnssec_status);
      
/*
*Wrapper for getaddrinfo(), with the same signature as in the specification, except for the GETDNS_RESPSTATUS_ parameter.
*/  
getdns_return_t getdns_getaddrinfo(const char *name, int af, struct addrinfo **result, struct addrinfo *hints, uint32_t *respstatus);

/*
*Wrapper for getnameinfo(), with the same signature as in the specification, except for the GETDNS_RESPSTATUS_ parameter.
*/
getdns_return_t getdns_getnameinfo(const void *addr, const int af, char *nodename, size_t namelen, uint32_t *respstatus);

void getdns_process_statcode(getdns_return_t, uint32_t, enum nss_status *nss_code, int *errnop, int *h_errnop);

enum nss_status eai2nss_code(int, int*);

int getdns_eai_error_code(getdns_return_t, uint32_t);

int errno2herrno(int err);

#endif
