#include <arpa/inet.h>
#include <netdb.h>
#include <nss.h>
#include <errno.h>
#include <assert.h>
#include <getdns/getdns.h>

#ifndef _GETDNS_NSS_H_
#define _GETDNS_NSS_H_

typedef enum {ADDR_HOSTENT, ADDR_GAIH, ADDR_SERVENT, REV_HOSTENT} addr_param_t;
struct addr_param
	{
		addr_param_t addr_type;
		union
		{
		struct hostent *p_hostent;
		struct gaih_addrtuple **p_gaih;
		struct servent *p_servent;
		} addr_entry;
	};
#endif
