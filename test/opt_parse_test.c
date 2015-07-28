#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../opt_parse.h"

#define MAXSTRLEN 1024

void test_dnssec_settings()
{
	int options = 0;
	assert( !(options & (DNSSEC_VALIDATE | DNSSEC_SECURE_ONLY | TLS_DISABLE | TLS_PREFER | TLS_REQUIRE)) );
	char *attributes = malloc(MAXSTRLEN);
	if(!attributes) exit(1);
	/*Test parsing dnssec settings from parsed line*/
	snprintf(attributes, MAXSTRLEN, "dnssec: %s %s", DNSSEC_ATTR_VALIDATE, DNSSEC_ATTR_SECURE_ONLY);
	printf("TEST LINE: %s\n", attributes);
	parse_single_option(attributes, dnssec_atflags, dnssec_atstrings, dnssec_attr_num, &options);
	assert(options  == (DNSSEC_VALIDATE | DNSSEC_SECURE_ONLY));
	printf("ALL TESTS PASSED!\n");
}

void test_tls_settings()
{
	int options = 0;
	assert( !(options & (DNSSEC_VALIDATE | DNSSEC_SECURE_ONLY | TLS_DISABLE | TLS_PREFER | TLS_REQUIRE)) );
	char *attributes = malloc(MAXSTRLEN);
	if(!attributes) exit(1);
	/*Test parsing tls settings from parsed line*/
	snprintf(attributes, MAXSTRLEN, "tls: %s %s", TLS_ATTR_REQUIRE, TLS_ATTR_DISABLE);
	printf("TEST LINE: %s\n", attributes);
	parse_single_option(attributes, tls_atflags, tls_atstrings, tls_attr_num, &options);
	assert(options & TLS_DISABLE);
	assert(options & TLS_REQUIRE);
	assert(!(options & TLS_PREFER));
	printf("ALL TESTS PASSED!\n");
	free(attributes);
}

void test_options_file()
{
	printf("Testing configurations file\n");
	/*
	*Write sample settings in a test file.
	*/
	char conf_file[] = "getdns.conf";
	FILE *fp;
	if(!(fp = fopen(conf_file, "w")))
	{
		perror("test_options_file");
		exit(1);
	}
	fprintf(fp, "#This is a comment.\n");
	fprintf(fp, "dnssec: %s\n", DNSSEC_ATTR_VALIDATE);
	fprintf(fp, "#Attributes can be specified separately. And lines may start with a whitespace\n");
	fprintf(fp, " 	dnssec: %s\n", DNSSEC_ATTR_SECURE_ONLY);
	fprintf(fp, "tls: %s %s\n", TLS_ATTR_REQUIRE, TLS_ATTR_DISABLE);
	fprintf(fp, "#It should be ok to have duplicates.\n");
	fprintf(fp, "tls: %s %s\n", TLS_ATTR_REQUIRE, TLS_ATTR_DISABLE);
	fprintf(fp, "#This should not be parsed, it is not at the beginning of a line: tls: %s.\n", TLS_ATTR_PREFER);
	fclose(fp);
	/*
	*Now test if the file was successfully parsed in textual mode.
	*/
	int options = 0;
	parse_options(conf_file, &options);
	assert(options  & (DNSSEC_VALIDATE | DNSSEC_SECURE_ONLY));
	assert(options & TLS_DISABLE);
	assert(options & TLS_REQUIRE);
	assert(!(options & TLS_PREFER));
	/*
	*Save options and test if the file is successfully parsed in combined mode.
	*/
	char local_conf_file[] = "getdns_app_preferences";
	save_options(options, local_conf_file, 0);
	int local_options = 0;
	parse_options(local_conf_file, &local_options);
	assert(local_options  & (DNSSEC_VALIDATE | DNSSEC_SECURE_ONLY));
	assert(local_options & TLS_DISABLE);
	assert(local_options & TLS_REQUIRE);
	assert(!(local_options & TLS_PREFER));
	printf("ALL TESTS PASSED!\n");
}

void test_form_parser()
{
	printf("Testing the form parser\n");
	int options = parse_keyval_options(strdup("This is a stream containing an http form  with\n\r\r tls=require_tls&logging=critical&dnssec=validate \n\r\r"));
	assert(options & (DNSSEC_VALIDATE | TLS_REQUIRE | DEBUG_CRITICAL));
	printf("\nParsed options: %s\n====\n====\n", print_options(options));
	printf("ALL TESTS PASSED!\n");
	
}
int main()
{
	printf("======================\n");
	test_tls_settings();
	test_dnssec_settings();
	test_options_file();
	test_form_parser();
	printf("==========END=========\n");
	return 0;
}
