#include <stdarg.h>
#include <errno.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <nss.h>
#include <netdb.h>
#include <stdlib.h>
#include "nss_getdns.h"
#include "logger.h"

#if defined(__FreeBSD__)
#define  UNUSED_PARAM(x) ((void)(x))

#define BUFFER_SIZE 1024

struct getnamaddr {
         struct hostent *hp;
         char *buf;
         size_t buflen;
         int *he;
};
     
NSS_METHOD_PROTOTYPE(__bsdnss_gethostbyname);
NSS_METHOD_PROTOTYPE(__bsdnss_gethostbyname2);
NSS_METHOD_PROTOTYPE(__bsdnss_gethostbyaddr);
NSS_METHOD_PROTOTYPE(__bsdnss_gethostbyaddr2);
NSS_METHOD_PROTOTYPE(__bsdnss_getaddrinfo);
NSS_METHOD_PROTOTYPE(__bsdnss_getnameinfo);
NSS_METHOD_PROTOTYPE(__bsdnss_freeaddrinfo);


extern enum nss_status _nss_getdns_gethostbyname_r (const char *name, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop);
extern enum nss_status _nss_getdns_gethostbyname2_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop);
extern enum nss_status _nss_getdns_gethostbyaddr_r (const void*, socklen_t, int,
        struct hostent*, char*, size_t, int*, int*);
extern enum nss_status _nss_getdns_gethostbyaddr2_r (const void*, socklen_t, int,
        struct hostent*, char*, size_t, int*, int*, int32_t*);
extern enum nss_status _nss_getdns_gethostbyname3_r (const char*, int, struct hostent*, 
        char*, size_t, int*, int*, int32_t*, char**);
extern void getdns_mirror_freeaddrinfo(struct addrinfo*);
	
extern int __nss_mod_init(); extern void __nss_mod_destroy();

extern int getdns_mirror_getaddrinfo(const char*, const char*, const struct addrinfo*, struct addrinfo**);
extern int getdns_mirror_getnameinfo(const struct sockaddr*, socklen_t, char*, size_t, char*, size_t, int);
extern enum nss_status eai2nss_code(int, enum nss_status*);

static ns_mtab methods[]={
  { NSDB_HOSTS, "gethostbyname_r", &__bsdnss_gethostbyname, &_nss_getdns_gethostbyname_r },
  { NSDB_HOSTS, "gethostbyname2_r", &__bsdnss_gethostbyname2, &_nss_getdns_gethostbyname2_r },
  { NSDB_HOSTS, "gethostbyaddr_r", &__bsdnss_gethostbyaddr, &_nss_getdns_gethostbyaddr_r },
  { NSDB_HOSTS, "gethostbyaddr2_r", &__bsdnss_gethostbyaddr2, &_nss_getdns_gethostbyaddr2_r },
  { NSDB_HOSTS, "getaddrinfo", &__bsdnss_getaddrinfo, &getdns_mirror_getaddrinfo },
  { NSDB_HOSTS, "getnameinfo", &__bsdnss_getnameinfo, &getdns_mirror_getnameinfo },
  { NSDB_HOSTS, "freeaddrinfo", &__bsdnss_freeaddrinfo, &getdns_mirror_freeaddrinfo}
};

static struct getnamaddr *allocgetnamaddr(struct hostent *val, cha *buf, size_t buflen, int *he)
{
	struct getnamaddr *ret = malloc(sizeof(struct getnamaddr));
	if(!ret)
	{
		err_log("[allocgetnamaddr]: memory error.");
		return NULL;
	}	
	ret->hp = val;
	ret->buf = buf;
	ret->buflen = buflen;
	ret->he = he;
	return ret;
}
/*
The functions below are implemented following a documentation for the nsdispatch() function in NetBSD 6.1.5 man-pages.
The functions are noted to not follow the standard calling convention for the standard nsdispatch API until changed in "the future",
and so that is what we assume here.
That means the return value will be passed back via the rval argument (first argument to the nss_method functions below.
*/
int __bsdnss_gethostbyname(void *rval,void *cb_data,va_list ap)
{
  const char *name;  
  char *buffer;
  size_t buflen;
  struct hostent *ret;
  int *errnop;
  enum nss_status status;
  enum nss_status (*api_funct)(const char *, int, struct hostent *, char *, size_t, int *, int *);
  name = va_arg(ap, const char*);
  ret = va_arg(ap, struct hostent *);
  buffer = va_arg(ap, char*);
  buflen = va_arg(ap, size_t);
  errnop = va_arg(ap, int*);
  api_funct = cb_data;
  status = api_funct(name, AF_INET, ret, buffer, buflen, errnop, &h_errno);
  status = __nss_compat_result(status, *errnop);
  if(status == NS_SUCCESS)
  {
    *((struct hostent **)rval) = ret;
  }else{
  	*((struct hostent **)rval) = NULL;
  }
  err_log("BSDNSS_GETHOSTBYNAME_r(%s): %d.\n", name, status);
  return status;
}

int __bsdnss_gethostbyname2(void *rval, void *cb_data, va_list ap)
{
  const char *name;  
  char *buffer;
  size_t buflen;
  struct hostent *ret;
  int af, *errnop, namelen;
  enum nss_status status;
  enum nss_status (*api_funct)(const char *, int, struct hostent *, char *, size_t, int *, int *);
  name = va_arg(ap, const char*);
  namelen = va_arg(ap, int);
  af = va_arg(ap, int);
  //ret = va_arg(ap, struct hostent **);
  //buffer = va_arg(ap, char*);
  //buflen = va_arg(ap, size_t);
  //errnop = va_arg(ap, int*);
  api_funct = cb_data;
  buflen = 1024;
  buffer = malloc(buflen);
  ret = malloc(sizeof(struct hostent));
  if(!ret || !buffer)
  {
  	return __nss_compat_result(NSS_TRYAGAIN, &errno);
  }
  status = api_funct(name, af, ret, buffer, buflen, &errno, &h_errno);
  status = __nss_compat_result(status, *errnop);
  if(status == NS_SUCCESS)
  {
    *((struct getnamaddr**)rval) = allcgetnamaddr(ret, buffer, buflen, h_errno);
  }else{
  	*((struct getnamaddr**)rval) = NULL;
  }
  err_log("BSDNSS_GETHOSTBYNAME2_r(%s): %d.\n", name, status);
  return status;
}

int __bsdnss_gethostbyaddr(void *rval, void *cb_data, va_list ap)
{
  const char *addr;
  socklen_t len;
  int af;
  struct hostent *ret, **result;
  char *buffer;
  size_t buflen;
  int *errnop;  
  enum nss_status status;
  enum nss_status (*api_funct)(struct in_addr *, int, int, struct hostent *, char *, size_t, int *, int *); 
  addr = va_arg(ap, const char*);
  len = va_arg(ap, socklen_t);
  af = va_arg(ap, int);
  ret = va_arg(ap, struct hostent*);
  buffer = va_arg(ap, char*);
  buflen = va_arg(ap, size_t);
  result = va_arg(ap, struct hostent**);
  errnop = va_arg(ap, int*);
  api_funct = cb_data;
  status = api_funct((struct in_addr*)addr, len, af, ret, buffer, buflen, errnop, &h_errno);
  status = __nss_compat_result(status, *errnop);
  if(status == NS_SUCCESS)
  {
    *((struct hostent **)rval) = ret;
    *result = ret;
  }
  err_log("BSDNSS_GETHOSTBYADDR_r: %d.\n", status);
  return status;
}

int __bsdnss_gethostbyaddr2(void *rval, void *cb_data, va_list ap)
{  
  const char *addr;
  socklen_t len;
  int af;
  struct hostent *ret, **result;
  char *buffer;
  size_t buflen;
  int *errnop;  
  enum nss_status status;
  enum nss_status (*api_funct)(struct in_addr *, int, int, struct hostent *, char *, size_t, int *, int *);
  addr = va_arg(ap, const char*);
  len = va_arg(ap, socklen_t);
  af = va_arg(ap, int);
  ret = va_arg(ap, struct hostent*);
  buffer = va_arg(ap, char*);
  buflen = va_arg(ap, size_t);
  result = va_arg(ap, struct hostent**);
  errnop = va_arg(ap, int*);
  api_funct = cb_data;
  status = api_funct((struct in_addr*)addr, len, af, ret, buffer, buflen, errnop, &h_errno);
  status = __nss_compat_result(status, *errnop);
  if(status == NS_SUCCESS)
  {
    *((struct hostent **)rval) = ret;
    *result = ret;
  }
  err_log("BSDNSS_GETHOSTBYADDR2_r: %d.\n", status);
  return status;
}

int __bsdnss_getaddrinfo(void *rval, void *cb_data, va_list ap)
{
  enum nss_status status;
  int (*api_funct)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
  const char *hostname, *servname;
  const struct addrinfo *hints;
  struct addrinfo *result = NULL;
  int ret;
  hostname = va_arg(ap, char*);
  hints = va_arg(ap, const struct addrinfo*);
  servname = va_arg(ap, char*);
  api_funct = cb_data;
  ret = api_funct(hostname, servname, hints, &result);
  ret = eai2nss_code(ret, &status);
  if(status == NS_SUCCESS && ret == 0)
  {
    *((struct addrinfo**)rval) = result;
  }else{
    rval = NULL;
  }
  err_log("BSDNSS: getaddrinfo(%s): %d\n", hostname, status);
  return status;
}

int __bsdnss_getnameinfo(void *rval, void *cb_data, va_list ap)
{
  const struct sockaddr *sa;
  socklen_t salen;
  char *host, *serv;
  size_t hostlen, servlen;
  int flags, ret;
  enum nss_status status;
  enum nss_status (*api_funct)(const struct sockaddr*, socklen_t, char*, size_t, char*, size_t, int);
  sa = va_arg(ap, const struct sockaddr*);
  salen = va_arg(ap, socklen_t);
  host = va_arg(ap, char*);
  hostlen = va_arg(ap, size_t);
  serv = va_arg(ap, char*);
  servlen = va_arg(ap, size_t);
  flags = va_arg(ap, int);
  api_funct = cb_data;
  ret = api_funct(sa, salen, host, hostlen, serv, servlen, flags);
  ret = eai2nss_code(ret, &status);
  if(status != NS_SUCCESS)
  {
    host = NULL;
    serv = NULL;
  }
  err_log("BSDNSS: getnameinfo(HOST:%s, SERV:%s): %d\n", host, serv, status);
  return status;
}

int __bsdnss_freeaddrinfo(void *rval, void *cb_data, va_list ap)
{
  struct sockaddr *sa;
  void (*api_funct)(struct sockaddr*);
  sa = va_arg(ap, struct sockaddr*);
  api_funct = cb_data;
  api_funct(sa);
  return 0;
}

void nss_module_unregister(ns_mtab *mtab, u_int nelems)
{
	__nss_mod_destroy();
}

ns_mtab *nss_module_register(const char *source, unsigned int *mtabsize, nss_module_unregister_fn *unreg)
{
  if( __nss_mod_init() == 0)
  {
  	*mtabsize=sizeof(methods)/sizeof(methods[0]);
  	*unreg = &nss_module_unregister;
  }else{
  	*mtabsize=sizeof(methods)/sizeof(methods[0]);
  	*unreg=NULL;
  }
  return methods;
}
#endif
