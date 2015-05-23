#include <nss.h>
#include <errno.h>
#include <getdns/getdns_ext_libevent.h>

#ifndef IN6ADDRSZ
#define IN6ADDRSZ sizeof(struct in6_addr)
#endif
#ifndef INADDRSZ
#define INADDRSZ sizeof(struct in_addr)
#endif

/*
Convert getdns return values to NSS status codes
*/
static enum nss_status nss_getdns_retval_interpret(getdns_return_t return_t)
{
  switch(return_t)
  {
    case GETDNS_RETURN_GENERIC_ERROR:
      return NSS_STATUS_UNAVAIL;
  }
  return NSS_STATUS_UNAVAIL;
}

/*
Convert getdns status codes to NSS status codes
*/
static enum nss_status nss_getdns_statcode_interpret(uint32_t status)
{
  switch(status)
  {
    case GETDNS_RESPSTATUS_GOOD: return NSS_STATUS_SUCCESS;
    case GETDNS_RESPSTATUS_NO_NAME: return NSS_STATUS_NOTFOUND;
    case GETDNS_RESPSTATUS_ALL_TIMEOUT: return NSS_STATUS_TRYAGAIN;
    case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
    case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
      return NSS_STATUS_SUCCESS;
  }
  return NSS_STATUS_UNAVAIL;
}
