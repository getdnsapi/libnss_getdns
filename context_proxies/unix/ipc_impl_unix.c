#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../nss_getdns.h"
#include "../../logger.h"
#include "../../context_interface.h"
#include "../../query.h"
#include "../../logger.h"
#include "ipc_impl_unix.h"

#define MAXBUFSIZ sizeof(response_bundle)
#define ADDRESS "/var/tmp/getdns_module_unix.sock"
#define BACKLOG_SIZE 64

void ipc_unix_listen()
{
	static getdns_context *context = NULL;
	static getdns_dict *extensions = NULL;
	static time_t last_changed = 0;
    int sockfd, clientfd;
    socklen_t fromlen, socklen;
    struct sockaddr_un server_addr;
    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        log_critical("ipc_unix_listen< socket: %s >", strerror(errno));
        exit(EXIT_FAILURE);
    }
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, ADDRESS);
    unlink(ADDRESS);
    socklen = sizeof(server_addr.sun_family) + strlen(server_addr.sun_path);
    
    if(bind(sockfd, (struct sockaddr *)(&server_addr), socklen) < 0)
    {
        log_critical("ipc_unix_listen< bind: %s >", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if(listen(sockfd, BACKLOG_SIZE) < 0)
    {
        log_critical("ipc_unix_listen< listen: %s >", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while(1)
    {
    
		if((clientfd = accept(sockfd, (struct sockaddr *)(&server_addr), &fromlen)) < 0)
		{
		    log_debug("ipc_unix_listen< accept: %s >", strerror(errno));
		    continue;
		}
		load_context(&context, &extensions, &last_changed);
		if(context != NULL && extensions != NULL)
		{
			char buf[MAXBUFSIZ];
			size_t len;
			response_bundle *reply = NULL;
			if( (len = read(clientfd, buf, MAXBUFSIZ)) > 0)
			{
				req_params req;
				memset(&req, 0, sizeof(req));
				memcpy(&req, buf, len);
				getdns_return_t ret = do_query(context, extensions, &req, &reply);
				if( (ret != GETDNS_RETURN_GOOD) || (reply == NULL) )
				{
					log_warning("ipc_unix_listen< RESPONSE_BUNDLE is null >");
					reply = &RESP_BUNDLE_EMPTY;
				}
				len = sizeof(response_bundle);
				if(write(clientfd, reply, len) <= len)
				{
					log_warning("ipc_unix_listen< write: %s >", strerror(errno));
				}
				if(reply && reply != &RESP_BUNDLE_EMPTY)
				{
					free(reply);
				}
			}			
		}else{
			log_critical("ipc_unix_listen< NULL CONTEXT >");
			exit(EXIT_FAILURE);
		}
		close(clientfd);
    }
}

int ipc_unix_proxy_resolve(char* query, int type, int af, response_bundle **result)
{
	int sockfd, socklen;
    struct sockaddr_un server_addr;
    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        log_critical("ipc_unix_proxy_resolve < socket(%s): %s >", ADDRESS, strerror(errno));
        return -1;
    }
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, ADDRESS);
    socklen = sizeof(server_addr.sun_family) + strlen(server_addr.sun_path);
    if(connect(sockfd, (struct sockaddr *)(&server_addr), socklen) < 0)
    {
    	int errnum = errno;
        log_info("ipc_unix_proxy_resolve< connect(%s): %s >", ADDRESS, strerror(errnum));
        if(errnum == ECONNREFUSED)
        {
        	ipc_unix_start_daemon();
        	log_info("ipc_unix_proxy_resolve< Retrying to connect to %s >", ADDRESS);
        	if(connect(sockfd, (struct sockaddr *)(&server_addr), socklen) < 0)
        	{
        		log_critical("ipc_unix_proxy_resolve< Retry failed: %s >", strerror(errno));
        		return -1;
        	}
        }else{
        	log_critical("ipc_unix_proxy_resolve< Exiting with error. >");
        	return -1;
        }
    }
    req_params request = {.reverse=type, .af=af};
    memset(request.query, 0, sizeof(request.query));
    memcpy(request.query, query, strlen(query));
    if(send(sockfd, &request, sizeof(req_params), 0) <= 0)
    {
    	log_warning("ipc_unix_proxy_resolve< send: %s >", strerror(errno));
        return -1;
    }
    char buf[MAXBUFSIZ];
    size_t len;
    if( (len = recv(sockfd, buf, MAXBUFSIZ, 0) ) <= 0)
    {
    	log_warning("ipc_unix_proxy_resolve< recv: %s >", strerror(errno));
        return -1;
    }
    *result = malloc(sizeof(response_bundle));
	if(*result == NULL)
	{
		log_critical("ipc_unix_proxy_resolve< MALLOC failed >");
		return -1;
	}
	memset(*result, 0, sizeof(response_bundle));
    memcpy(*result, buf, len);
    close(sockfd);
    return 0;
}

#ifdef HAVE_CONTEXT_PROXY
getdns_context_proxy ctx_proxy = &ipc_unix_proxy_resolve;
#endif

void ipc_unix_start_daemon()
{
	/*
	*This function can be called from any process, 
	*so make sure here that the daemon is created in a detached process
	*/
	pid_t pid = fork();
	if(pid < 0)
	{
		log_critical("start_ipc_daemon < fork: %s >", strerror(errno));
		return;
	}
	if(pid > 0)
	{
		return;
	}
	/*
	*New process will create a daemon process and exit.
	*/
	pid_t sessid /*Session ID (We will fork from then exit parent.)*/;
	pid_t ipc_pid = fork();
	/*Make sure fork succeeded*/
	if(ipc_pid < 0)
	{
		log_critical("ipc_dbus_listen< Error forking. >");
		exit(EXIT_FAILURE);
	}
	/*Exit parent process*/
	if(ipc_pid > 0)
	{
		log_info("ipc_dbus_listen< Entering daemon mode. >");
		exit(EXIT_SUCCESS);
	}
	/*
	*Now we are in the child process, daemon mode
	*Create new session ID and reset file mode mask, 
	*change to a safe working dir, and close out standard file descriptors.
	*/
	umask(0);
	sessid = setsid();
	if(sessid < 0)
	{
		log_critical("ipc_dbus_listen< setsid() failed >");
		exit(EXIT_FAILURE);
	}
	if( (chdir("/")) < 0)
	{
		log_critical("ipc_dbus_listen< chdir() failed >");
		exit(EXIT_FAILURE);
	}
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/*IPC daemon starts....*/
	log_info("ipc_unix_start_daemon< starting IPC context proxy daemon >");
	ipc_unix_listen();
}
