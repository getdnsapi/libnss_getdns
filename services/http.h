// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#ifndef _HTTP_LOCALHOST_H
#define _HTTP_LOCALHOST_H

#define HTTP_UNRPRIV_PORT 8080
#define HTTP_PRIV_PORT 80
#define HTTP_SERV_STATUS_FILE "getdns_http_file.lock"

enum service_type {ERROR_PAGE, FORM_DATA, HOME_PAGE, FAVICON, UNKNOWN};
struct error_t
{
	char *err_title;
	char *err_msg;
	char *err_details;
};

void load_page(enum service_type srv_rq, char **header, char **content, char *status_msg);
enum service_type process_input(int fd, char **status_msg);
void http_listen(int port);
void check_service();
int get_dnssec_info(char *query, char **status_msg);
#endif
