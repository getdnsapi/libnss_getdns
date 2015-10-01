// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "../browsers.h"

#define MAXSTRLEN 1024

extern int is_known_browser(struct query_hints *params);
extern int find_matched(char *line, const char **keys, const int arr_size);
extern int mime_lookup(char *entries_file, const char **types, int arr_len);
extern int is_known_browser(struct query_hints *params);

void test_matched_entries()
{
	char line[MAXSTRLEN] = "MimeType=text/html;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;x-scheme-handler/geo;image/svg+xml;";
	const char *keys[3] = {"text/html", "application/xhtml", "x-scheme-handler/http"};
	printf("TEST LINE: %s\n", line);
	assert(find_matched(line, keys, 3) == 4);
	printf("ALL TESTS PASSED!\n");
}

void test_options_file()
{
	printf("Testing configurations file\n");
	/*
	*Write sample entries in a test file.
	*/
	char entries_file[] = "desktop_entry.sample";
	const char *keys[5] =  {"text/html", "application/json+xml", "application/xhtml", "x-scheme-handler/http", "text/javascript"};
	FILE *fp;
	if(!(fp = fopen(entries_file, "w")))
	{
		perror("test_desktop_entries_file");
		exit(1);
	}
	fprintf(fp, "[Title, or section label?]\n");
	fprintf(fp, "something=in_their_language\n");
	fprintf(fp, "settings[attr]=value or something\n");
	fprintf(fp, "MimeType=text/html;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;x-scheme-handler/geo;image/svg+xml;");
	fprintf(fp, "settings[attr]=value or something\n");
	fclose(fp);
	/*
	*Now test if the file was successfully parsed.
	*/
	assert(mime_lookup(entries_file, keys, 5) == 4);
	printf("ALL TESTS PASSED!\n");
}

void test_browsers(int af)
{
	char *names[11] = {"firefox", "opera", "wget", "ping", "ie", "curl", "mozilla", "chrome", "chromium", "chromium-browser", "google-chrome"}; 
	size_t len = sizeof(names) / sizeof(names[0]);
	int idx;
	printf("Testing browser detection for address family %d:\n", af);
	for(idx=0; idx<len; idx++)
	{
		struct query_hints hints = {.pid=0, .ppid=0,.af=af, .name=names[idx]};
		int detected = is_known_browser(&hints);
		printf("\t%s : %s (score: %.2f%%) \n", hints.name,  detected ? "YES" : "NO", 100*hints.score);
	}
	printf("======================\n");
}

int main()
{
	printf("======================\n");
	test_matched_entries();
	test_options_file();
	test_browsers(AF_UNSPEC);
	test_browsers(AF_INET);
	printf("==========END=========\n");
	return 0;
}
