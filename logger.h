#define DEBUG 1

#ifndef _GETDNS_NSS_SYSLG_
#define _GETDNS_NSS_SYSLG_

#if defined(__linux__)
#include <syslog.h>
#define err_log(args...) syslog (LOG_ERR, args)
#else
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_MAC == 1
#include <syslog.h>
#define err_log(args...) syslog (LOG_ERR, args)
#endif /*OS_MAC*/
#else
#define err_log(args...)
#endif  /*IF_OS_MAC_OR_NOT*/
#endif   /*IF_LINUX_OR_NOT*/

#if DEBUG >= 1
#define debug_log(args...) err_log(args)
#else
#define debug_log(args...)
#endif /*debug_log*/

#endif /*GETDNS_NSS_SYSLOG*/
