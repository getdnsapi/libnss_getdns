// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h> 
#include "logger.h"
#include "opt_parse.h"

#define _GNU_SOURCE

int log_level = LOG_LEVELS_CRITICAL;

/*DNSSEC preferences*/
const char* dnssec_atstrings[] = {DNSSEC_ATTR_VALIDATE, DNSSEC_ATTR_SECURE_ONLY, DNSSEC_ATTR_ROADBLOCK_AVOIDANCE};
const int dnssec_atflags[] = {DNSSEC_VALIDATE, DNSSEC_SECURE_ONLY, DNSSEC_ROADBLOCK_AVOIDANCE};
const int dnssec_attr_num = sizeof dnssec_atstrings/ sizeof(char*);
/*Transport mode preferences*/
const char* tls_atstrings[] = {TLS_ATTR_DISABLE, TLS_ATTR_PREFER, TLS_ATTR_REQUIRE};
const int tls_atflags[] = {TLS_DISABLE, TLS_PREFER, TLS_REQUIRE};
const int tls_attr_num = sizeof tls_atstrings/ sizeof(char*);
/*Debug levels*/
const char* debug_atstrings[] = {DEBUG_ATTR_CRITICAL, DEBUG_ATTR_WARNING, DEBUG_ATTR_INFO, DEBUG_ATTR_VERBOSE};
const int debug_atflags[] = {DEBUG_CRITICAL, DEBUG_WARNING, DEBUG_INFO, DEBUG_VERBOSE};
const int debug_attr_num = sizeof debug_atstrings/ sizeof(char*);

/*
*Parse option line for a specific option, return its ID-val with ret (|ORed) .
*/
void parse_single_option(char *attrs, const int *atflags, const char **atstrings, const int arr_size, int *ret)
{
	char *next = NULL, *attribute = NULL;
	if(!strtok_r(attrs, ":", &next))
	{
		return;
	}
	while( (attribute = strtok_r(NULL, " ", &next)) != NULL)
	{
		int idx;
		for(idx=0; idx<arr_size; idx++)
		{
			if(0 == strncmp(attribute, atstrings[idx], strlen(atstrings[idx])))
			{
				*ret |= atflags[idx];
			}
		}
		
	}
}

/*
*Parse option line for an option code.
*/
void parse_option_code(char *option_line, char *options_format, int *ret, int override)
{
	int minimal_options;
	if(sscanf(option_line, options_format, &minimal_options) == 1)
	{
		if(override)
		{
			*ret = minimal_options;
		}else{
			*ret |= minimal_options;
		}
	}
}

/*
*Parse known option strings from option code.
*/
char *reverse_parse_known_options(int option_code, const int *atflags, const char **atstrings, const int arr_size)
{
	if(option_code == 0)
	{
		return NULL;
	}
	size_t idx, bufsiz = 2048;
	char options[bufsiz];
	memset(options, 0, bufsiz);
	for(idx=0; idx<arr_size; idx++)
	{
		if( 0 != (atflags[idx] & option_code))
		{
			char *cur = &(options[strlen(options)]);
			snprintf(cur, bufsiz - strlen(cur), "%s ", atstrings[idx]);
		}
	}
	if(strlen(options) > 0)
	{
		return strdup(options);
	}
	return NULL;
}

/*
*Parse options in an http-form-like format
*/


int parse_keyval_options(char *data)
{
	if(!data)
	{
		return 0;
	}
	size_t len = strlen(data), i;
	for(i = 0; i < len; i++)
	{
		if(data[i] == '=')
			data[i] = ':';
	}
	int ret = 0;
	char *pos = NULL, *arg = data;
	while( (pos = strtok(arg, "&")) != NULL )
	{
		arg = NULL;
		char *option_line;
		if(strchr(pos, '\n'))
		{
			pos = strrchr(pos, '\n')+1;
		}
		if((option_line = strstr(pos, DNSSEC_OPTION_STR)) == pos)
		{
			parse_single_option(option_line, dnssec_atflags, dnssec_atstrings, dnssec_attr_num, &ret);
		}else if((option_line = strstr(pos, TLS_OPTION_STR)) == pos)
		{
			parse_single_option(option_line, tls_atflags, tls_atstrings, tls_attr_num, &ret);
		}else if((option_line = strstr(pos, DEBUG_OPTION_STR)) == pos)
		{
			parse_single_option(option_line, debug_atflags, debug_atstrings, debug_attr_num, &ret);
		}
	}
	return ret;
}

void parse_options(char *conf_file, int *ret)
{
	FILE *in;
	*ret = 0;
	char buf[1024];
	memset(buf, 0, 1024);
	char *pos = buf, *option_line;
	if((in = fopen(conf_file, "r")) != NULL)
	{
		while (fgets(pos, sizeof(buf), in))
		{
			/* Skip whitespaces*/
			while (*pos == ' '  || *pos == '\f' || *pos == '\t' || *pos == '\v')pos++;
			/* Skip comments or end of line */
			if (*pos == '#' || *pos == '\r' || *pos == '\n')continue;
			/*
			*Option must be the first substring on the option line.
			*The single option extractor must take care of making sure the substring is indeed a word.
			*/
			if((option_line = strstr(pos, MINIMAL_DEFAULTS_OPTION_STR)) == pos)
			{
				//parse_option_code(option_line, MINIMAL_DEFAULTS_ATTR, ret, 1);				
			}else if((option_line = strstr(pos, DNSSEC_OPTION_STR)) == pos)
			{
				parse_single_option(option_line, dnssec_atflags, dnssec_atstrings, dnssec_attr_num, ret);
			}else if((option_line = strstr(pos, TLS_OPTION_STR)) == pos)
			{
				parse_single_option(option_line, tls_atflags, tls_atstrings, tls_attr_num, ret);
			}else if((option_line = strstr(pos, DEBUG_OPTION_STR)) == pos)
			{
				parse_single_option(option_line, debug_atflags, debug_atstrings, debug_attr_num, ret);
			}
		}
		fclose(in);	
	}else{
		log_critical("Could not open config file %s (ERROR: %s)\n", conf_file, strerror(errno));
	}
}

void save_options(int option_code, char *options_file, int cur_user)
{
	char *options = NULL;
	FILE *out;
	char name[1024];
	memset(name, 0, 1024);
	if(cur_user)
	{
		char *user_home_dir = getenv("HOME");
		snprintf(name, 1024, "%s/%s", user_home_dir, ".getdns");
		mkdir(name,  S_IRWXU);
		snprintf(name, 1024, "%s/%s/%s.conf", user_home_dir, ".getdns", options_file);
	}else{
		snprintf(name, 1024, "%s", options_file);
	}
	if((out = fopen(name, "w")) != NULL)
	{
		fprintf(out, "#option code\
		(interpreted in textual format below).\n#Note this is redundant since this code alone would suffice.\n%s: %d\n", MINIMAL_DEFAULTS_OPTION_STR, option_code);
		if( (options = reverse_parse_known_options(option_code, dnssec_atflags, dnssec_atstrings, dnssec_attr_num)) != NULL)
		{
			fprintf(out, "\t#DNSSEC settings\n%s: %s\n", DNSSEC_OPTION_STR, options);
			free(options);
		}
		if( (options = reverse_parse_known_options(option_code, tls_atflags, tls_atstrings, tls_attr_num)) != NULL)
		{
			fprintf(out, "\t#Transport mode preferences\n%s: %s\n", TLS_OPTION_STR, options);
			free(options);
		}
		if( (options = reverse_parse_known_options(option_code, debug_atflags, debug_atstrings, debug_attr_num)) != NULL)
		{
			fprintf(out, "\t#Debug settings\n%s: %s\n", DEBUG_OPTION_STR, options);
			free(options);
		}
		fclose(out);
	}else{
		log_critical("Could not write to config file %s (ERROR: %s)\n", name, strerror(errno));
	}
	
}

char *print_options(int option_code)
{
	size_t bufsiz = 2048, cursor = 0;
	char buf[bufsiz];
	char *options = NULL;
	if( (options = reverse_parse_known_options(option_code, dnssec_atflags, dnssec_atstrings, dnssec_attr_num)) != NULL)
	{
		cursor += snprintf(buf + cursor, bufsiz - cursor, "%s_%s;", DNSSEC_OPTION_STR, options);
	}
	if( (options = reverse_parse_known_options(option_code, tls_atflags, tls_atstrings, tls_attr_num)) != NULL)
	{
		cursor += snprintf(buf + cursor, bufsiz - cursor, "%s_%s;", TLS_OPTION_STR, options);
	}
	if( (options = reverse_parse_known_options(option_code, debug_atflags, debug_atstrings, debug_attr_num)) != NULL)
	{
		cursor += snprintf(buf + cursor, bufsiz - cursor, "%s_%s;", DEBUG_OPTION_STR, options);
	}
	return strdup(buf);
}
int get_local_defaults(char *label)
{
	int ret = 0;
	char name[1024];
	memset(name, 0, 1024);
	char *user_home_dir = getenv("HOME");
	snprintf(name, 1024, "%s/%s/%s.conf", user_home_dir, ".getdns", label);
	parse_options(name, &ret);
	return ret;
}

void set_log_level(int options, int *level)
{
	if(options & DEBUG_VERBOSE)
	{
		*level = LOG_LEVELS_VERBOSE;
	}else if(options & DEBUG_INFO)
	{
		*level = LOG_LEVELS_INFO;
	}else if(options & DEBUG_WARNING)
	{
		*level = LOG_LEVELS_WARNING;
	}else{
		*level = LOG_LEVELS_CRITICAL;
	}
}
