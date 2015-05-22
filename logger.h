#ifndef _GETDNS_NSS_SYSLG_
#define _GETDNS_NSS_SYSLG_

/*
#if defined(__unix__)
#include <syslog.h>
#define err_log(args...) syslog (LOG_ERR, args)
#else
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_MAC == 1
#include <syslog.h>
#define err_log(args...) syslog (LOG_ERR, args)
#endif
#else
#define err_log(args...) no_op()
#endif
#endif

void no_op(){}
*/

#include <syslog.h>
#define err_log(args...) syslog (LOG_ERR, args)
#endif
