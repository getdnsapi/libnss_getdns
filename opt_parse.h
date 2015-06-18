#ifndef GETDNS_OPT_PARSE_H
#define GETDNS_OPT_PARSE_H

typedef enum resolv_options 
{
	DNSSEC_VALIDATE = 1,
	DNSSEC_SECURE_ONLY = 2,
	TLS_DISABLE = 4,
	TLS_PREFER = 8,
	TLS_REQUIRE = 16
} res_opt ;

#define DNSSEC_OPTION_STR "dnssec"
#define DNSSEC_ATTR_VALIDATE "validate"
#define DNSSEC_ATTR_SECURE_ONLY "secure_only"
#define TLS_OPTION_STR "tls"
#define TLS_ATTR_DISABLE "disable_tls"
#define TLS_ATTR_PREFER "prefer_tls"
#define TLS_ATTR_REQUIRE "require_tls"

extern const char* dnssec_atstrings[];
extern const int dnssec_atflags[];
extern const int dnssec_attr_num;
extern const char* tls_atstrings[];
extern const int tls_atflags[];
extern const int tls_attr_num;

void parse_options(char *conf_file, int *ret);

#endif
