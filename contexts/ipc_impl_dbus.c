#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "../nss_getdns.h"
#include "../logger.h"
#include "../context_interface.h"
#include "../query.h"
#include "http.h"
#include "ipc_interface.h"
#include "../context_interface.h"
#include "../config.h"

static getdns_context *context = NULL;
static getdns_dict *extensions = NULL;
size_t size_of_local_addr = sizeof(GETDNS_CONFIG_LOCALNAME);

/*
Sends method call over bus.
Returns true if method succeeded.
Method result data is placed into result
*/
int ipc_dbus_proxy_resolve(char* query, int type, int af, response_bundle **result)
{
	if(strncmp(query, GETDNS_CONFIG_LOCALNAME, size_of_local_addr)==0)
	{
		*result = malloc(sizeof(RESP_BUNDLE_LOCAL_CONFIG));
		if(*result)
		{
			(*result)->respstatus = RESP_BUNDLE_LOCAL_CONFIG.respstatus;
			(*result)->dnssec_status = RESP_BUNDLE_LOCAL_CONFIG.dnssec_status;
			(*result)->ipv4_count = 1;
			(*result)->ipv6_count = 1;
			(*result)->ipv4 = strdup(RESP_BUNDLE_LOCAL_CONFIG.ipv4);
			(*result)->ipv6 = strdup(RESP_BUNDLE_LOCAL_CONFIG.ipv6);
			(*result)->ttl = 0;
			(*result)->cname = strdup(RESP_BUNDLE_LOCAL_CONFIG.cname);
			return 0;
		}
		return -1;
	}
	DBusMessage* msg;
	DBusConnection* conn;
	DBusError err;
	DBusPendingCall* pending;
	int ret;
	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
	if(dbus_error_is_set(&err)) { 
		err_log("proxy_resolve< Connection Error: (%s) >", err.message); 
		dbus_error_free(&err);
		return -1;
	}
	if (NULL == conn)
	{ 
	 	return -1; 
	}
	if (!dbus_bus_name_has_owner(conn, IPC_SERVICE_NAME, &err))
	{
		err_log("proxy_resolve< [%s] No such name on the bus! >", IPC_SERVICE_NAME);
		return -1;
	}
	msg = dbus_message_new_method_call(IPC_SERVICE_NAME, IPC_OBJECT_PATH, IPC_IFACE, METHOD_GETDNS_RESOLVE);
	if(NULL == msg)
	{ 
	  	err_log("proxy_resolve< Query: %s: Method call failed (MESSAGE=NULL) >", query);
	  	return -1;
	}
	dbus_message_set_auto_start(msg, true);
	if (!dbus_message_append_args(msg, DBUS_TYPE_STRING, &query, DBUS_TYPE_INT32, &type, DBUS_TYPE_INT32, &af, DBUS_TYPE_INVALID)) 
	{
	  	return -1;
	}
	if (!dbus_connection_send_with_reply (conn, msg, &pending, -1)) //Default timeout is -1
	{
	  	return -1;
	}
	if (NULL == pending) 
	{ 
	  	err_log("proxy_resolve< Pending Call = Null. Exiting. >"); 
	  	return -1; 
	}
	dbus_connection_flush(conn);
	/*free the message*/
	dbus_message_unref(msg);
	/*wait for reply*/
	dbus_pending_call_block(pending);
	/*Check the reply message*/
	msg = dbus_pending_call_steal_reply(pending);
	if (NULL == msg)
	{
		err_log("proxy_resolve< Null reply >"); 
		dbus_pending_call_unref(pending);
		return -1; 
	}
	/*free the pending message handle*/
	dbus_pending_call_unref(pending);
	/*read the message*/
	*result = malloc(sizeof(response_bundle));
	if(*result == NULL)
	{
		err_log("proxy_resolve< MALLOC failed >");
		dbus_message_unref(msg);  
		return ret;
	}
	if(!dbus_message_get_args(msg, &err, DBUS_TYPE_UINT32, &ret, DBUS_TYPE_UINT32, &((*result)->respstatus),
		DBUS_TYPE_UINT32, &((*result)->dnssec_status), DBUS_TYPE_UINT64, &((*result)->ttl),
		DBUS_TYPE_UINT32, &((*result)->ipv4_count), DBUS_TYPE_UINT32, &((*result)->ipv6_count),
		DBUS_TYPE_STRING, &((*result)->ipv4), DBUS_TYPE_STRING, &((*result)->ipv6),
		DBUS_TYPE_STRING, &((*result)->cname), DBUS_TYPE_INVALID))
	{
		err_log("proxy_resolve< Error reading message: %s >", err.message);
		if(*result != NULL)
		{
			(*result)->respstatus = GETDNS_RETURN_GENERIC_ERROR;
			(*result)->ipv4_count = 0;
			(*result)->ipv6_count = 0;
		}
	}
	dbus_message_unref(msg);  
	return ret;
}

#if defined(HAVE_CONTEXT_PROXY) && HAVE_CONTEXT_PROXY == 1
	getdns_context_proxy ctx_proxy = &ipc_dbus_proxy_resolve;
#endif

void handle_method_call(DBusMessage* msg, DBusConnection* conn)
{
	DBusMessage* reply;
	DBusError err;
	char *query;
	int reverse, af;
	dbus_uint32_t success = 0;
	dbus_uint32_t serial = 0;
	getdns_dict *response = NULL;
	response_bundle *addr_data = NULL;
	dbus_error_init(&err);
	err_log("handle_method_call< Handling message... >\n");
	if(context == NULL || extensions == NULL)
	{
		load_context(&context, &extensions);
	}
	if(context != NULL && extensions != NULL)
	{
		if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &query, DBUS_TYPE_INT32, &reverse, DBUS_TYPE_INT32, &af, DBUS_TYPE_INVALID))
		{
			do_query(query, af, reverse, context, extensions, &response);
			if(response)
			{
				parse_addr_bundle(response, &addr_data, reverse, af);
			}
			getdns_dict_destroy(response);
		}else{
			err_log("%s", err.message); 
		}
	}else{
		err_log("Invalid context");
	}
	if(addr_data == NULL)
	{
		success = 0;
		addr_data = &RESP_BUNDLE_EMPTY;
	}else{
		success = 1;
	}
	reply = dbus_message_new_method_return(msg);
	if (!dbus_message_append_args(reply, DBUS_TYPE_UINT32, &success, DBUS_TYPE_UINT32, &(addr_data->respstatus),
		DBUS_TYPE_UINT32, &(addr_data->dnssec_status), DBUS_TYPE_UINT64, &(addr_data->ttl),
		DBUS_TYPE_UINT32, &(addr_data->ipv4_count), DBUS_TYPE_UINT32, &(addr_data->ipv6_count),
		DBUS_TYPE_STRING, &(addr_data->ipv4), DBUS_TYPE_STRING, &(addr_data->ipv6),
		DBUS_TYPE_STRING, &(addr_data->cname), DBUS_TYPE_INVALID))
	{
		err_log("handle_method_call< Error appending arguments. >");
	}else if(addr_data && addr_data != &RESP_BUNDLE_EMPTY)
	{
		free(addr_data->ipv4);
		free(addr_data->ipv6);
		free(addr_data);
	}
	/*send reply && flush connection*/
	if (!dbus_connection_send(conn, reply, &serial))
	{
	  err_log("handle_method_call< Error sending reply. >"); 
	  exit(EXIT_FAILURE);
	}
	dbus_connection_flush(conn);
	/*free the reply*/
	dbus_message_unref(reply);
}

/**
 * Expose a method call and listen
 */
void ipc_dbus_listen() 
{
	DBusMessage* msg;
	DBusConnection* conn;
	DBusError err;
	int ret;
	pid_t ipc_pid /*ID of the main IPC handler*/, http_pid /*The http child*/, sessid /*Session ID (We will fork from then exit parent.)*/;
	ipc_pid = fork();
	/*Make sure fork succeeded*/
	if(ipc_pid < 0)
	{
		err_log("ipc_dbus_listen< Error forking. >");
		exit(EXIT_FAILURE);
	}
	/*Exit parent process*/
	if(ipc_pid > 0)
	{
		debug_log("ipc_dbus_listen< Entering daemon mode. >");
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
		err_log("ipc_dbus_listen< setsid() failed >");
		exit(EXIT_FAILURE);
	}
	if( (chdir("/")) < 0)
	{
		err_log("ipc_dbus_listen< chdir() failed >");
		exit(EXIT_FAILURE);
	}
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/*IPC daemon starts....*/
	/*reinitialise the error*/
	dbus_error_init(&err);
	/*connect to the bus*/
	conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
	if (dbus_error_is_set(&err))
	{ 
	  err_log("ipc_dbus_listen< Connection Error (%s) >", err.message); 
	  dbus_error_free(&err); 
	}
	if (NULL == conn)
	{
	  err_log("ipc_dbus_listen< Connection failed. >"); 
	  exit(EXIT_FAILURE); 
	}
	/*Register name on the bus*/
	ret = dbus_bus_request_name(conn, IPC_SERVICE_NAME, DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
	if (dbus_error_is_set(&err))
	{ 
	  err_log("ipc_dbus_listen< Name Error (%s) >", err.message); 
	  dbus_error_free(&err);
	}
	if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
	{ 
	  err_log("ipc_dbus_listen< Could not own name (%s). Error: %d >", IPC_SERVICE_NAME, ret);
	  exit(EXIT_FAILURE); 
	}
	/*http config listener*/
	if((http_pid = fork()) == 0)
	{
		http_listen(HTTP_UNRPRIV_PORT);
	}else{
		/*Listen for messages*/
		while(true)
		{
		  /*non blocking read for next message*/
		  dbus_connection_read_write(conn, 0);
		  msg = dbus_connection_pop_message(conn);
		  if(msg != NULL)
		  {
		  		if(dbus_message_is_method_call(msg, IPC_IFACE, METHOD_GETDNS_RESOLVE))
		  		{
		  			handle_method_call(msg, conn);
		  		}
		  	dbus_message_unref(msg);
		  }
		}
		/*close connection*/
		dbus_connection_close(conn);
		kill(http_pid, 9);
		if(context != NULL)
		{
			getdns_context_destroy(context);
		}
		if(extensions != NULL)
		{
			getdns_dict_destroy(extensions);
		}
	}
}
