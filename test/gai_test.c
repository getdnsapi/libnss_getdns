// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<errno.h>
#include<netdb.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include "../logger.h"

int test_gai_funf(char*, char*, int*, int, int, int(*)(const char*, const char*, int*, const struct addrinfo*, struct addrinfo**), void(struct addrinfo*));
extern int getdns_mirror_getaddrinfo(const char*, const char*, const struct addrinfo*, struct addrinfo**);
extern int getdns_mirror_getnameinfo(const struct sockaddr*, socklen_t, char*, size_t, char*, size_t, int);
extern void getdns_mirror_freeaddrinfo(struct addrinfo*);
extern void *addr_data_ptr(struct sockaddr_storage*);
int hostname_to_ip(char * hostname , char* ret, int *ret_af, int af, int turns, int(*gai_func)(const char*, const char*, const struct addrinfo*, struct addrinfo**),
        void(ai_free_func)(struct addrinfo*));

int main(int argc , char *argv[])
{
    if(argc <4 )
    {
        fprintf(stderr, "Usage: %s <hostname_to_resolve> <address_family[4|6]> <num_iterations>\n", argv[0]);
        exit(1);
    }
    char *hostname = argv[1];
    int af = atoi(argv[2]);
    int num_runs = atoi(argv[3]);
    if(af == 4){
    	af = AF_INET;
    }else if(af == 6)
    	af = AF_INET6;
    else if(af == 7){
    	af = AF_UNSPEC;
    }else{
    	fprintf(stderr, "Valid address families: 4 or 6.\n");
        exit(1);
    }
    clock_t t;
    char ip_1[NI_MAXHOST] = "UNKNOWN", ip_2[NI_MAXHOST] = "UNKNOWN", 
    	rev_ip_1[NI_MAXHOST], rev_ip_2[NI_MAXHOST];
    int ret = 0, ret1 = 0, ret2 = 0, ret1_af=0, ret2_af=0;
    struct sockaddr_storage sas1, sas2;
    struct hostent *he = NULL;
    printf("\n================\n");
    t = clock();
    if( 0 == (hostname_to_ip(hostname , ip_1, &ret1_af, af, num_runs, &getaddrinfo, &freeaddrinfo) 
    	| hostname_to_ip(hostname , ip_2, &ret2_af, af, num_runs, &getaddrinfo, &freeaddrinfo) ))
    {
		printf("getXXinfo: %s resolved to %s\n" , hostname , ip_1);
		printf("getXXinfo: %s resolved to %s\n" , hostname , ip_2);
		printf("\n");
		sas1.ss_family = ret1_af;
		inet_pton(ret1_af, ip_1, addr_data_ptr(&sas1));
		sas2.ss_family = ret2_af;
		inet_pton(ret2_af, ip_2, addr_data_ptr(&sas2));
		char errbuf[2048];
		int flags = NI_NAMEREQD;
		struct sockaddr *sa1 = (struct sockaddr*)&sas1;
		struct sockaddr *sa2 = (struct sockaddr*)&sas2;
		ret1 = getnameinfo(sa1, sizeof(*sa1), rev_ip_1, sizeof(rev_ip_1), NULL, 0, flags);
		if(ret1==0)
			printf("Reverse lookup for %s (%s) => %s\n", ip_1, hostname, rev_ip_1);
		else{
			snprintf(errbuf, sizeof(errbuf), "%s: %s", "getnameinfo [1]", gai_strerror(ret1));
			herror(errbuf);
		}
		ret2 = getnameinfo(sa2, sizeof(*sa2), rev_ip_2, sizeof(rev_ip_2), NULL, 0, flags);
		if(ret2==0)
			printf("Reverse lookup for %s (%s) => %s\n", ip_2, hostname, rev_ip_2);
		else{
			snprintf(errbuf, sizeof(errbuf), "%s: %s", "getnameinfo [2]", gai_strerror(ret2));
			herror(errbuf);
		}
	}   
	t = clock() - t;
	double elapsed = ((double)t)/CLOCKS_PER_SEC;
	printf("================\n");
	printf("ELAPSED: %.3f seconds", elapsed);
	printf("\n================\n");
	return ret;  
}

int hostname_to_ip(char * hostname , char* ret, int *ret_af, int af, int turns, int(*gai_func)(const char*, const char*, const struct addrinfo*, struct addrinfo**), 
	void(ai_free_func)(struct addrinfo*))
{
    struct addrinfo hints, *res=NULL, *res0 = NULL;
    int status;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    //hints.ai_flags = AI_V4MAPPED | AI_ALL;
    int times = 0;
    while(times++ < turns)
    {
		if( 0 != (status = gai_func(hostname, NULL, &hints, &res0)) )
		;/*{
			fprintf(stderr, "ERROR INFO: %s\n", gai_strerror(status));
		    herror("getaddrinfo");
		    if(res0)
		    	ai_free_func(res0);
		    return 1;
		}*/
		int count = 0;
		char tmp[NI_MAXHOST];
		for(res = res0; res; res = res->ai_next)
		{
		    struct sockaddr_storage *ss;
		    if(*ret_af == 0)*ret_af = res->ai_family;
		    ss = (struct sockaddr_storage*)res->ai_addr;
		    inet_ntop(ss->ss_family, addr_data_ptr(ss), tmp, sizeof(*ss));
		    snprintf(ret, res->ai_addrlen , "%s", tmp);
		   /*printf("Addr #%d: %s\n (SA_port: %d, SA_family: %d);\n\
		    PROTO:%d; FAMILY: %d; FLAGS: %d; ADDRLEN: %d; CANONNAME: %s\n", ++count, count == 1? ret : tmp,
		    s_in->sin_port, s_in->sin_family, res->ai_protocol, res->ai_family, res->ai_flags, res->ai_addrlen, res->ai_canonname);*/
		    //printf("Addr #%d: %s \n", ++count, count == 1? ret : tmp);
		}
		if(res0)
		{	
			ai_free_func(res0);
		}
    }
    return 0;
}
