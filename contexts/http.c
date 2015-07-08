#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <err.h>
#include "../logger.h"
#include "http.h"
 
#define HTTP_HTML_HEADER "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: %ld\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
#define HTTP_ICON_HEADER "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: %ld\r\nConnection: close\r\nContent-Type: image/x-icon\r\n\r\n"

struct error_t dnnsec_errmsg = {.err_title="DNSSEC failure", .err_msg="Bogus answers received.",
	.err_details="This may be caused by a misconfiguration, or an attacker trying to redirect you."};
	
void load_page(enum service_type srv_rq, char **header, char **content)
{
	FILE *fp;
	char *header_str = NULL, *fname = NULL;
	size_t page_size = 0, len = 0;
	struct error_t *err_msg = NULL;
	switch(srv_rq)
	{
		case ERROR_PAGE:
			header_str = HTTP_HTML_HEADER;
			fname = "/usr/local/share/getdns_module/error.html";
			break;
		case FAVICON:
			header_str = HTTP_ICON_HEADER;
			fname = "/usr/local/share/getdns_module/dnssec.ico";
			break;
		default:
			header_str = HTTP_HTML_HEADER;
			fname = "/usr/local/share/getdns_module/settings.html";
	}
	fp = fopen(fname, "rb");
	if(!fp)
	{
		err_log("Unable to read template file <%s>", fname);
		return;
	}
	/*Get file length*/
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	*content = malloc(len+1);
	if(!(*content))
	{
		return;
	}
	fread(*content, len, 1, fp);
	fclose(fp);
	/*Complete page*/
	*header = malloc(strlen(header_str) + 10);
	if(err_msg != NULL)
	{
		len = strlen(*content) + strlen(err_msg->err_title) + strlen(err_msg->err_msg) + strlen(err_msg->err_details)+10;
		char *output = malloc(len);
		if(!output)
		{
			return;
		}
    	page_size = snprintf(output, len, *content, err_msg->err_title, err_msg->err_title, err_msg->err_msg, err_msg->err_details);
    	char *temp = *content;
    	*content = output;
    	free(temp);
    	temp = NULL;
	}else{
		page_size = strlen(*content);
	}
	snprintf(*header, strlen(header_str) + 10, header_str, (long)page_size);
}

enum service_type process_input(int fd)
{
	size_t len, bufsiz = 2048;
	char buf[bufsiz];
	while( (len = read(fd, buf, bufsiz)) > 0)
	{
		printf("%s", buf);
		if(strstr(buf, "favicon"))
		{
			return FAVICON;
		}else if(strstr(buf, "POST / HTTP/"))
		{
			return FORM_DATA;
		}
		if(len < bufsiz)
			break;
	}
	return HOME_PAGE;
}

void http_listen(int port)
{
  int one = 1, client_fd;
  struct sockaddr_in svr_addr, cli_addr;
  socklen_t sin_len = sizeof(cli_addr);
  err_log("http_listen<STARTING.................>");
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    err_log("Couln't open socket");
 
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
  svr_addr.sin_family = AF_INET;
  svr_addr.sin_addr.s_addr = INADDR_ANY;
  svr_addr.sin_port = htons(port);
 
  if (bind(sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) == -1) {
		close(sock);
		err_log("Couldn't bind");
		perror("");
		return;
  }
 
  listen(sock, 5);
  while (1) {
    client_fd = accept(sock, (struct sockaddr *) &cli_addr, &sin_len); 
    if (client_fd == -1)
    {
		err_log("Couldn't accept connection");
		close(client_fd);
		continue;
    }
    char *content = NULL, *header = NULL;
    load_page(process_input(client_fd), &header, &content);
    if(content == NULL || header == NULL)
    {
    	err_log("Error reading file...");
    	close(client_fd);
    	continue;
    }   
    write(client_fd, header, strlen(header));
    write(client_fd, content, strlen(content));
    write(client_fd, "\r\n", strlen("\r\n"));
    close(client_fd);
    free(content);
    free(header);
  }
}
