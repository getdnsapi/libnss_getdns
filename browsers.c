#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <math.h>
#include "logger.h"
#include "browsers.h"

#define _GNU_SOURCE
#define MAXSTRLEN 1024

int find_matched(char *line, const char **keys, const int arr_size)
{
	char *next = NULL, *entry = NULL;
	int found = 0;
	if(!strtok_r(line, "=", &next))
	{
		return 0;
	}
	while( (entry = strtok_r(NULL, ";", &next)) != NULL)
	{
		int idx;
		for(idx=0; idx<arr_size; idx++)
		{
			if(0 == strncmp(entry, keys[idx], strlen(keys[idx])))
			{
				found += 1;
				break;
			}
		}
		
	}
	return found;
}

int mime_lookup(char *entries_file, const char **types, int arr_len)
{
	FILE *in;
	int found = 0;
	char buf[1024];
	char *pos = buf, *entry_line;
	if((in = fopen(entries_file, "r")) != NULL)
	{
		while (fgets(pos, sizeof(buf), in))
		{
			/* Skip whitespaces to avoid worrying about misformatted files*/
			while (*pos == ' '  || *pos == '\f' || *pos == '\t' || *pos == '\v')pos++;
			/* Skip end of line */
			if (*pos == '\r' || *pos == '\n')continue;
			/*
			*Option MimeType declaration must be at the beginning of a line...
			*/
			if((entry_line = strstr(pos, "MimeType=")) == pos)
			{			
				found = find_matched(entry_line, types, arr_len);
				break;				
			}
		}
		fclose(in);	
	}else{
		log_warning("Could not open entries file %s (ERROR: %s)\n", entries_file, strerror(errno));
	}
	return found;
}

int is_known_browser(struct query_hints *params)
{
	if(!params)return 0;
	log_info("Process %d/%d is %s", params->ppid, params->pid, params->name);
	params->score = 0;
	float weights[3] = {0.5, 0.5, 0.5};
	if(params->af == AF_UNSPEC)
		weights[0] += 0.1;
	if(params->name)
	{
		if(strstr(KNOWN_BROWSERS, params->name) != NULL || strstr(params->name, "WebKit") != NULL)
		{
			weights[1] += 0.1;
		}
		char entries_file[MAXSTRLEN];
		int found_entries;
		int len = snprintf(entries_file, sizeof(entries_file), "%s/%s.desktop", DESKTOP_APP_ENTRIES_DIR, params->name);
		if(len && access(entries_file, R_OK) != -1)
		{
			const char *browser_mimes[3] = {"text/html", "application/xhtml", "x-scheme-handler/http"};
			if( (found_entries = mime_lookup(entries_file, browser_mimes, 3)) > 0)
			{
				weights[2] += 0.5*found_entries/(1.0 + found_entries) ;
			}
		}
	}
	float num = (weights[0]*weights[1]*weights[2]);
	float denom = (weights[0]*weights[1]*weights[2]) + ((1-weights[0]) * (1-weights[1]) * (1-weights[2]) );
	params->score = ceilf(100*num/denom)/100;
	return params->score >= (float)THRESHOLD;	
}

int browser_check(int af)
{
	extern char *program_invocation_name;
	extern char *__progname;
	char *prog_name = __progname == program_invocation_name ? __progname : strtok(program_invocation_name, " ");
	if(strchr(prog_name, '/'))
	{
		prog_name = strrchr(prog_name, '/') + 1;
	}
	struct query_hints hints = {.pid=getpid(), .ppid=getppid(),.af=af, .name=prog_name};
	log_debug("BROWSER? __progname: %s, p_i_n: %s, name: %s", __progname, program_invocation_name, prog_name);
	return is_known_browser(&hints);
}
