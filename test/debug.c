// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../nss_getdns.h"


extern void *addr_data_ptr(struct sockaddr_storage *arg);
extern enum nss_status _nss_getdns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp);

void tt()
{
	struct addrinfo hints, *res=NULL;
    int status;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = 0;
    hints.ai_flags = 32;
    hints.ai_socktype=1;
    if(getaddrinfo("us1.siteimprove.com", NULL, &hints, &res) != 0)
    {
    	perror("getaddrinfo");
    }else{
    	char ip[NI_MAXHOST], tmp[NI_MAXHOST];
    	struct sockaddr_storage *ss;
	    ss = (struct sockaddr_storage*)res->ai_addr;
		inet_ntop(ss->ss_family, addr_data_ptr(ss), tmp, sizeof(*ss));
	    snprintf(ip, res->ai_addrlen , "%s", tmp);
    	printf("getXXinfo:  %s\n" , ip);
    	freeaddrinfo(res);
    }
}
void t()
{
	struct gaih_addrtuple *pat;
	pat = malloc(sizeof(struct gaih_addrtuple));
	if(pat)
	{
		const char *name = strdup("us1.siteimprove.com");
		pat->next = 0;
		char p_name[6] = {'\210', '\350', '\256', '\305', '\326', '\177'};
		pat->name = p_name;
		pat->family = 0;
		uint32_t addr[4] = {32726, 3218074472, 32726, 3218074176};
		memcpy(pat->addr, addr, 4);
		pat->scopeid = 0;
		char buffer[1024];
		int my_errno = 0, my_herrno=0;
		int c;
		//for(c=0;c<10000;c++)
		{
			_nss_getdns_gethostbyname4_r(name, &pat, buffer, 1024, &my_errno, &my_herrno, NULL);
			printf("errno: %d, h_errno: %d\n", my_errno, my_herrno);
		}
	}
}

        
int main()
{
	int idx;
	while(idx++ < 1000)
	{
		int pid = fork();
		if(!pid){
		tt();
		t();
		}else
			wait(NULL);
	}
    return 0;
}
