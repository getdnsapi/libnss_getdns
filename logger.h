#ifndef _GETDNS_NSS_SYSLG_
#define _GETDNS_NSS_SYSLG_

/*Log levels*/
#define LOG_LEVELS_CRITICAL 0
#define LOG_LEVELS_WARNING 1
#define LOG_LEVELS_INFO 2
#define LOG_LEVELS_VERBOSE 3

extern int log_level;

#include "config.h"

/*
*TODO: What if syslog is unavailable?
*/
#ifdef HAVE_SYSLOG_H	
	#include <syslog.h>
	#define log_filter(level, args...)	\
		do{	\
			if(level <= log_level){\
				switch(level){\
					case LOG_LEVELS_VERBOSE: syslog( LOG_DEBUG|LOG_CONS, args);break;\
					case LOG_LEVELS_INFO: syslog( LOG_INFO, args);break;\
					case LOG_LEVELS_WARNING: syslog(LOG_ERR, args);break;\
					default: syslog( LOG_CRIT, args);\
				}\
			} \
		}while(0)
#else
	#define log_filter(level, args...)
#endif /*HAVE_SYSLOG_H*/

#ifdef LOG_LEVEL /*Compile-time log-level configuration*/
	#ifdef HAVE_SYSLOG_H	
	#include <syslog.h>
	/*Critical conditions always logged*/
	#define log_critical(args...) syslog(LOG_CRIT, args)
		#if LOG_LEVEL >= LOG_LEVELS_WARNING
			#define log_warning(args...) syslog(LOG_ERR, args) 
		#else
			#define log_warning(args...)
		#endif
		#if LOG_LEVEL >= LOG_LEVELS_INFO
			#define log_info(args...) syslog(LOG_INFO, args) 
		#else
			#define log_info(args...)
		#endif
		#if LOG_LEVEL >= LOG_LEVELS_VERBOSE
			#define log_debug(args...) syslog(LOG_DEBUG|LOG_CONS, args) 
		#else
			#define log_debug(args...)
		#endif  
	#else
		#define log_critical(args...)
		#define log_warning(args...)
		#define log_info(args...)
		#define log_debug(args...)
	#endif /*HAVE_SYSLOG_H*/
#else
	#define log_critical(args...) log_filter(LOG_LEVELS_CRITICAL, args)
	#define log_warning(args...)	log_filter(LOG_LEVELS_WARNING, args)
	#define log_info(args...)	log_filter(LOG_LEVELS_INFO, args)
	#define log_debug(args...)	log_filter(LOG_LEVELS_VERBOSE, args)
#endif /*LOG_LEVEL*/

#endif /*GETDNS_NSS_SYSLOG*/
