#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<errno.h>
#include<netdb.h>
#include<arpa/inet.h>
#include "../logger.h"
 
int hostname_to_ip(char *  , char *, char *);
 
int main(int argc , char *argv[])
{
    err_log("Welcome!!!\n");
    if(argc <2)
    {
        //fprintf(stderr, "Usage: %s <hostname_to_resolve> <servname> <protoname>\n", argv[0]);
        fprintf(stderr, "Usage: %s <hostname_to_resolve>\n", argv[0]);
        exit(1);
    }
     
    char *hostname = argv[1];
    char ip_1[NI_MAXHOST], ip_2[NI_MAXHOST], rev_ip_1[NI_MAXHOST], rev_ip_2[NI_MAXHOST];
    int ret = 0;
    struct sockaddr_in sa1, sa2;
     
    if( 0 == (ret = hostname_to_ip(hostname , ip_1, ip_2)) )
    {
		printf("\n");
		printf("getXXbyYY: %s resolved to %s\n" , hostname , ip_1);
		printf("getXXinfo: %s resolved to %s\n" , hostname , ip_2);
		printf("\n");
		sa1.sin_family = AF_INET;
		inet_pton(AF_INET, ip_1, &sa1.sin_addr);
		sa2.sin_family = AF_INET;
		inet_pton(AF_INET, ip_2, &sa2.sin_addr);
		if( 0 == (ret = getnameinfo((struct sockaddr*)&sa1, sizeof(sa1), rev_ip_1, sizeof(rev_ip_1), NULL, 0, NI_NAMEREQD)
				& getnameinfo((struct sockaddr*)&sa2, sizeof(sa2), rev_ip_2, sizeof(rev_ip_2), NULL, 0, NI_NAMEREQD)) )
		{
			printf("Reverse lookup for %s (%s) => %s\n", ip_1, hostname, rev_ip_1);
			printf("Reverse lookup for %s (%s) => %s\n", ip_2, hostname, rev_ip_2);
		}else{
			char errbuf[2048];
			snprintf(errbuf, sizeof(errbuf), "%s: %s", "getnameinfo", gai_strerror(ret));
			herror(errbuf);
		}
	}   
	return ret;  
}

int hostname_to_ip(char * hostname , char* ip_getXXbyYY, char* ip_getXXinfo)
{
    struct hostent *he;
    struct in_addr **addr_list;
    struct addrinfo hints, *res, *res0;
    int i;
    /*
    Use gethostyname..........
    */  
    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        herror("gethostbyname");
        return 1;
    }
    
 
    addr_list = (struct in_addr **) he->h_addr_list;
    printf("h_name: %s\n", he->h_name);
    for(i = 0; addr_list[i] != NULL; i++)
    {
        strcpy(ip_getXXbyYY , inet_ntoa(*addr_list[i]) );
        break;//Return the first answer;
    }
    
    /*
    Use getaddrinfo...........
    */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = 0;
    //hints.ai_flags = AI_PASSIVE;
    if( getaddrinfo(hostname, NULL, &hints, &res0) )
    {
        herror("getaddrinfo");
        	return 1;
    }
    
    for(res = res0; res; res = res->ai_next)
    {
        strcpy(ip_getXXinfo , inet_ntoa( ((struct sockaddr_in*)res->ai_addr)->sin_addr ) );
        break;//Return the first answer;
    }
    return 0;
}

int hostname_to_serv(char * hostname , char* ip_getXXbyYY, char* ip_getXXinfo, char *servname, char *protoname)
{
    struct servent *se;
    struct addrinfo hints, *res, *res0;
    int i;
    /*
    Use getservbyname..........
    */  
    if ( (se = getservbyname( servname, protoname ) ) == NULL)
    {
        herror("getservbyname");
        if ( (se = getservbyport( atoi(servname), protoname ) ) == NULL)
		{
		    herror("getservbyport");
		    return 1;
		}
    }
	int count = 0;
	sprintf(ip_getXXbyYY , "SERVNAME: %s, PORT: %d, PROTO: %s \n", se->s_name, se->s_port, se->s_proto);
	while(*(se->s_aliases))
	{
	    printf("Alias %d: %s \n", count++, *(se->s_aliases) );
	    se->s_aliases++;
	}
    
    /*
    Use getaddrinfo...........
    */
    memset(&hints, 0, sizeof(hints));
   // hints.ai_family = PF_UNSPEC;
   // hints.ai_socktype = 0;
    //hints.ai_flags = AI_NUMERICHOST;
    if( getaddrinfo(hostname, servname, &hints, &res0) )
    {
        herror("getaddrinfo");
        	return 1;
    }else{
		for(res = res0; res; res = res->ai_next)
		{
		    strcpy(ip_getXXinfo , inet_ntoa( ((struct sockaddr_in*)res->ai_addr)->sin_addr ) );
		    break;//Return the first answer;
		}
    }
    return 0;
}
