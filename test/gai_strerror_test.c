#include <stdio.h>
#include <getdns/getdns_extra.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#define MAXSTRLEN 1024

extern const char *module_gai_strerror(int);

int getdns_codes[] = 
	{
	/*All getdns response statuses*/
	GETDNS_RESPSTATUS_GOOD,
	GETDNS_RESPSTATUS_NO_NAME,
	GETDNS_RESPSTATUS_ALL_TIMEOUT,
	GETDNS_RESPSTATUS_NO_SECURE_ANSWERS,
	GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS,
	/*All getdns DNSSEC values*/
	GETDNS_DNSSEC_SECURE,
	GETDNS_DNSSEC_BOGUS,
	GETDNS_DNSSEC_INDETERMINATE,
	GETDNS_DNSSEC_INSECURE,
	GETDNS_DNSSEC_NOT_PERFORMED,
	 /*All getdns return values*/
	GETDNS_RETURN_GOOD,
	GETDNS_RETURN_GENERIC_ERROR,
	GETDNS_RETURN_BAD_DOMAIN_NAME,
	GETDNS_RETURN_BAD_CONTEXT,
	GETDNS_RETURN_CONTEXT_UPDATE_FAIL,
	GETDNS_RETURN_UNKNOWN_TRANSACTION,
	GETDNS_RETURN_NO_SUCH_LIST_ITEM,
	GETDNS_RETURN_NO_SUCH_DICT_NAME,
	GETDNS_RETURN_WRONG_TYPE_REQUESTED,
	GETDNS_RETURN_NO_SUCH_EXTENSION,
	GETDNS_RETURN_EXTENSION_MISFORMAT,
	GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED,
	GETDNS_RETURN_MEMORY_ERROR,
	GETDNS_RETURN_INVALID_PARAMETER
	};
int gai_errcodes[] = 
	{
	EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, 
	EAI_FAMILY, EAI_MEMORY, 
	EAI_NONAME, EAI_OVERFLOW, EAI_SYSTEM
	};
	
void test_gai_error_codes();
void test_getdns_codes();
void test_perror();
void test_generic_error(const char* (*)(int), const char* (*)(int), char*, int*, int);
int compare(const char *s1, const char *s2, int verbose)
{
	if(verbose)
	{
		printf("TEST(%s) => %s\n", s1, s2);
	}
	return strncmp(s1, s2, MAXSTRLEN);
}
int main()
{
	test_getdns_codes();
	test_gai_error_codes();
	test_perror();
	return 0;
}

void test_getdns_codes()
{
	const char * (*func)(int) = (const char * (*)(int))(&getdns_get_errorstr_by_id);
	test_generic_error(func, &module_gai_strerror, "module_gai_strerror()", getdns_codes, sizeof(getdns_codes)/ sizeof(getdns_codes[0]));
}

void test_gai_error_codes()
{
	test_generic_error(&gai_strerror, &module_gai_strerror, "gai_strerror()", gai_errcodes, sizeof(gai_errcodes)/sizeof(gai_errcodes[0]));
}

void test_perror()
{
	const char * (*func)(int) = (const char * (*)(int))(&strerror);
	errno = 2;
	test_generic_error(func, &module_gai_strerror, "perror()", gai_errcodes, sizeof(gai_errcodes)/sizeof(gai_errcodes[0]));
}

void test_generic_error(const char* (*strerror1)(int), const char* (*strerror2)(int), char *test_tag, int *errcodes_arr, int siz)
{
	size_t idx, num = siz;
	printf("\n=============\nTESTING <%s>\n===========\n", test_tag);
	for(idx=0; idx<num;idx++)
	{
		if(0 != compare(strerror1(errcodes_arr[idx]), strerror2(errcodes_arr[idx]), 1))
		{
			fprintf(stderr, "TEST %d FAILED!\n", (int)idx);
			exit(1);
		}
	}
	printf("\n=============\nPASSED: %d\n===========\n", (int)idx);
}
