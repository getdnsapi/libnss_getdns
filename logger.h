#define DEBUG 1
#ifndef _GETDNS_NSS_SYSLG_
#define _GETDNS_NSS_SYSLG_
#include "config.h"
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define err_log(args...) syslog(LOG_ERR, args) 
#else
#define err_log(args...)
#endif  

#if defined(DEBUG) && DEBUG >= 1
#define debug_log(args...) err_log(args)
#else
#define debug_log(args...)
#endif

#endif /*GETDNS_NSS_SYSLOG*/
