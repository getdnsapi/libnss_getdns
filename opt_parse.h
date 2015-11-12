#ifndef GETDNS_OPT_PARSE_H
#define GETDNS_OPT_PARSE_H

enum resolv_options 
{
	DNSSEC_VALIDATE = 1, /* (1 << 0) */
	DNSSEC_SECURE_ONLY = 2, /* (1 << 1) */
	DNSSEC_ROADBLOCK_AVOIDANCE = 4, /* (1 << 2) */
	/*Options 0 to 4 are reserved for DNSSEC*/
	TLS_DISABLE = 1 << 5,
	TLS_PREFER = 1 << 6,
	TLS_REQUIRE = 1 << 7,
	/*Options 5 to 10 are reserved for transport modes*/
	DEBUG_CRITICAL = 1 << 11,
	DEBUG_WARNING = 1 << 12,
	DEBUG_INFO = 1 << 13,
	DEBUG_VERBOSE = 1 << 14,
	/*Every interface has an IPv6 address*/
	IFACE_INET6 = 1 << 15
};

#define MINIMAL_DEFAULTS_OPTION_STR "MIN_DEFAULTS"
#define MINIMAL_DEFAULTS_ATTR "MIN_DEFAULTS:%d%*s"
#define DNSSEC_OPTION_STR "dnssec"
#define DNSSEC_ATTR_VALIDATE "validate"
#define DNSSEC_ATTR_SECURE_ONLY "secure_only"
#define DNSSEC_ATTR_ROADBLOCK_AVOIDANCE "roadblock_avoidance"
#define TLS_OPTION_STR "tls"
#define TLS_ATTR_DISABLE "disable_tls"
#define TLS_ATTR_PREFER "prefer_tls"
#define TLS_ATTR_REQUIRE "require_tls"
#define DEBUG_OPTION_STR "logging"
#define DEBUG_ATTR_CRITICAL "critical"
#define DEBUG_ATTR_WARNING "warning"
#define DEBUG_ATTR_INFO "info"
#define DEBUG_ATTR_VERBOSE "verbose"

extern const char* dnssec_atstrings[];
extern const int dnssec_atflags[];
extern const int dnssec_attr_num;
extern const char* tls_atstrings[];
extern const int tls_atflags[];
extern const int tls_attr_num;
extern const char* debug_atstrings[];
extern const int debug_atflags[];
extern const int debug_attr_num;

void parse_single_option(char*, const int*, const char**, const int, int*);
void parse_options(char *conf_file, int *ret);
void save_options(int options, char *options_file, int cur_user);
int parse_keyval_options(char *data);
char *print_options(int option_code);
int get_local_defaults(char *label);
void set_log_level(int options, int *ret);
#endif
