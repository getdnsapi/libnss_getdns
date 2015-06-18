#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "logger.h"
#include "opt_parse.h"

const char* dnssec_atstrings[] = {DNSSEC_ATTR_VALIDATE, DNSSEC_ATTR_SECURE_ONLY};
const int dnssec_atflags[] = {DNSSEC_VALIDATE, DNSSEC_SECURE_ONLY};
const int dnssec_attr_num = sizeof dnssec_atstrings/ sizeof(char*);
const char* tls_atstrings[] = {TLS_ATTR_DISABLE, TLS_ATTR_PREFER, TLS_ATTR_REQUIRE};
const int tls_atflags[] = {TLS_DISABLE, TLS_PREFER, TLS_REQUIRE};
const int tls_attr_num = sizeof tls_atstrings/ sizeof(char*);

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

void parse_options(char *conf_file, int *ret)
{
	FILE *in;
	*ret = 0;
	char buf[1024];
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
			if((option_line = strstr(pos, DNSSEC_OPTION_STR)) == pos)
			{
				parse_single_option(option_line, dnssec_atflags, dnssec_atstrings, dnssec_attr_num, ret);
				
			}else if((option_line = strstr(pos, TLS_OPTION_STR)) == pos)
			{
				parse_single_option(option_line, tls_atflags, tls_atstrings, tls_attr_num, ret);
			}
		}
		fclose(in);	
	}else{
		err_log("Could not open config file %s (ERROR: %s)\n", conf_file, strerror(errno));
	}
}
