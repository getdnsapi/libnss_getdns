#ifndef _HTTP_LOCALHOST_H
#define _HTTP_LOCALHOST_H

#define HTTP_UNRPRIV_PORT 8080
#define HTTP_PRIV_PORT 80

enum service_type {ERROR_PAGE, FORM_DATA, HOME_PAGE, FAVICON};
struct error_t
{
	char *err_title;
	char *err_msg;
	char *err_details;
};

void load_page(enum service_type srv_rq, char **header, char **content);
enum service_type process_input(int fd);
void http_listen(int port);

#endif
