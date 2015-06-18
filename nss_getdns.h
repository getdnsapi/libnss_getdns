#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <getdns/getdns.h>
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
