#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <err.h>
#include <sys/file.h>
#include "../logger.h"
#include "http.h"
#include "../opt_parse.h"
#include "../context_interface.h"
#include "../nss_getdns.h"

#define HTTP_HTML_HEADER "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: %ld\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
#define HTTP_ICON_HEADER "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: %ld\r\nConnection: close\r\nContent-Type: image/x-icon\r\n\r\n"


struct error_t dnssec_errmsg = {.err_title="DNSSEC failure", .err_msg="",
	.err_details=""};
	
void load_page(enum service_type srv_rq, char **header, char **content, char *status_msg)
{
	FILE *fp;
	char *header_str = NULL, *fname = NULL;
	size_t page_size = 0, len = 0;
	struct error_t *err_msg = NULL;
	int form_pg = 0;
	switch(srv_rq)
	{
		case ERROR_PAGE:
			header_str = HTTP_HTML_HEADER;
			fname = "/usr/local/share/getdns_module/error.html";
			err_msg = &dnssec_errmsg;
			if(status_msg!= NULL)
			{
				err_msg->err_msg = status_msg;
			}
			break;
		case FAVICON:
			header_str = HTTP_ICON_HEADER;
			fname = "/usr/local/share/getdns_module/dnssec.ico";
			break;
		default:
			header_str = HTTP_HTML_HEADER;
			form_pg = 1;
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
	memset(*content, 0, len+1);
	fread(*content, len, 1, fp);
	fclose(fp);
	/*Complete page*/
	*header = malloc(strlen(header_str) + 10);
	if(err_msg != NULL)
	{
		len = strlen(*content) + strlen(err_msg->err_title) + strlen(err_msg->err_msg) + 10;
		char *output = malloc(len);
		memset(output, 0, len);
		if(!output)
		{
			return;
		}
    	page_size = snprintf(output, len, *content, err_msg->err_title, err_msg->err_title, err_msg->err_msg);
    	char *temp = *content;
    	*content = output;
    	free(temp);
    	temp = NULL;
	}else if(form_pg){
		char *form_data = print_options(get_local_defaults(CONFIG_FILE_LOCAL));
		size_t len = strlen(*content) + strlen(form_data);
		char *output = malloc(len);
		memset(output, 0, len);
		page_size = snprintf(output, len, *content, form_data);
		char *temp = *content;
    	*content = output;
    	free(temp);
    	free(form_data);
    	temp = NULL;
	}else{
		page_size = strlen(*content);
	}
	snprintf(*header, strlen(header_str) + 10, header_str, (long)page_size);
}

enum service_type process_input(int fd, char **msg)
{
	size_t len, bufsiz = 2048;
	char buf[bufsiz];
	memset(buf, 0, bufsiz);
	int ret = 0;
	enum service_type req_type = HOME_PAGE;
	*msg = NULL;
	while( (len = read(fd, buf, bufsiz)) > 0)
	{
		ret |= parse_keyval_options(buf);
		if(strstr(buf, "favicon"))
		{
			return FAVICON;
		}else if(strstr(buf, "POST / HTTP/"))
		{
			req_type = FORM_DATA;
		}else{
			char *pos = NULL;
			if((pos = strstr(buf, "Host: ")) != NULL)
			{
				char host[NI_MAXHOST], patt[64];
				memset(host, 0, NI_MAXHOST);
				memset(patt, 0, sizeof(patt));
				snprintf(patt, sizeof(patt), "Host: %%%d[^\n\r\\:]", NI_MAXHOST);
				sscanf(pos, patt, host);
				if(get_dnssec_info(strdup(host), msg) < 0)
				{
					req_type = ERROR_PAGE;
				}
				break;
			}
		}
		if(len < bufsiz)
			break;
	}
	if(ret > 0)
	{
		save_options(ret, CONFIG_FILE_LOCAL, 1);
	}
	return req_type;
}

void http_listen(int port)
{

	pid_t pid = fork();
	if(pid > 0)
	{
	exit(EXIT_SUCCESS);
	}
	umask(0);
	setsid();
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	int reuse_addr = 1, client_fd;
	struct sockaddr_in svr_addr, cli_addr;
	socklen_t sin_len = sizeof(cli_addr);
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		err_log("Couln't open socket");
		exit(EXIT_FAILURE);
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(int));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;
	svr_addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) == -1) {
		close(sock);
		err_log("Couldn't bind");
		perror("");
		return;
	}
	listen(sock, 10);
	while (1) {
		client_fd = accept(sock, (struct sockaddr *) &cli_addr, &sin_len); 
		if (client_fd == -1)
		{
			err_log("Couldn't accept connection");
			close(client_fd);
			continue;
		}
		if(fork() == 0)
		{
			close(sock);
			char *content = NULL, *header = NULL, *status_msg = NULL;
			enum service_type srvc = process_input(client_fd, &status_msg);
			load_page(srvc, &header, &content, status_msg != NULL ? status_msg : "");
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
			exit(EXIT_SUCCESS);
		}else{
			close(client_fd);
			continue;
		}
	}
}

int get_dnssec_info(char *query, char **status_msg)
{
	response_bundle *result = NULL;
	int ret = resolve_with_managed_ctx(query, 0, AF_UNSPEC, &result);
	int status = -1;
	if(ret > -1 && result != NULL)
	{	
		char err_template[] = "<h2>Could not securely resolve %s</h2><hr/><p>REASON: %s <fieldset><legend>DNSSEC status</legend>%s</fieldset></p>",
			msg_template[] = "<hr/><hr/><p>%s resolved to <h3>%s</h3></p>";
		const char *error_str = get_dnssec_code_description(result->dnssec_status);
		const char *respstatus_str = get_dnssec_code_description(result->respstatus);
		if((result->respstatus == GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS) || (result->dnssec_status == GETDNS_DNSSEC_BOGUS)
				|| (result->respstatus == GETDNS_RESPSTATUS_NO_SECURE_ANSWERS))
		{
			status = -1;
			char tmp[strlen(err_template) + strlen(query) + strlen(error_str) + strlen(respstatus_str)];
			memset(tmp, 0, sizeof(tmp));
			snprintf(tmp, sizeof(tmp), err_template, query, respstatus_str, error_str); 
			*status_msg = strdup(tmp);
		}else{
			status = 0;
			char tmp[strlen(msg_template) + strlen(query) + strlen(result->ipv4) + strlen(result->ipv6)];
			memset(tmp, 0, sizeof(tmp));
			if(result->ipv6_count > 0)
			{
				snprintf(tmp, sizeof(tmp), msg_template, query, result->ipv6+5); 
			}else if(result->ipv4_count > 0)
			{
				snprintf(tmp, sizeof(tmp), msg_template, query, result->ipv4+5); 
			}
			*status_msg = strdup(tmp);
		} 
	}else{
		*status_msg = strdup("ERROR.");
	}
	return status;
}

void check_service()
{
	pid_t c_pid = fork();
	if( c_pid == 0)
	{
		umask(0);
		setsid();
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		char cmd[1024];
		snprintf(cmd, sizeof(cmd), "fuser %d/tcp", HTTP_UNRPRIV_PORT);
		FILE *f = popen(cmd, "r");
		if(!f)
		{
			debug_log("http_d_listen< %s >", strerror(errno));
		}else{
			char buf[256];
			if(fscanf(f, "%255[^\n]", buf) > 0)
			{
				debug_log("http_d_listen< Port %d may still be in use: { %s }. >", HTTP_UNRPRIV_PORT, buf);
			}else{
				http_listen(HTTP_UNRPRIV_PORT);
			}
			pclose(f);
		}
	}else{
		debug_log("http_d_listen< Restarted http service. >");
		return;
	}
}
