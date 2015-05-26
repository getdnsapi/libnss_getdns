#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<errno.h>
#include<netdb.h>
#include<arpa/inet.h>
#include "logger.h"
 
int hostname_to_ip(char *  , char *, char *);
 
int main(int argc , char *argv[])
{
    err_log("Welcome!!!\n");
    if(argc <2)
    {
        fprintf(stderr, "Usage: %s <hostname_to_resolve>\n", argv[0]);
        exit(1);
    }
     
    char *hostname = argv[1];
    char ip[100], ip_2[100];
     
    hostname_to_ip(hostname , ip, ip_2);
    printf("\n");
    printf("getXXbyYY: %s resolved to %s\n" , hostname , ip);
    printf("getXXinfo: %s resolved to %s\n" , hostname , ip_2);
    printf("\n");
     
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
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if( getaddrinfo(hostname, "https", &hints, &res0) )
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
