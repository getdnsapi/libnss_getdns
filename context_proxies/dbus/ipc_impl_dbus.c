#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include "../../nss_getdns.h"
#include "../../logger.h"
#include "../../context_interface.h"
#include "../../query.h"
#include "ipc_interface.h"
#include "../../config.h"

static getdns_context *context = NULL;
static getdns_dict *extensions = NULL;
static time_t last_changed = 0;

/*
Sends method call over bus.
Returns true if method succeeded.
Method result data is placed into result
*/
int ipc_dbus_proxy_resolve(char* query, int type, int af, response_bundle **result)
{
	DBusMessage *request, *reply;
	DBusConnection *conn;
	DBusError err;
	DBusPendingCall *pending;
	int ret;
	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
	if(dbus_error_is_set(&err)) { 
		log_critical("proxy_resolve< Connection Error: (%s) >", err.message); 
		dbus_error_free(&err);
		return -1;
	}
	if (NULL == conn)
	{ 
	 	return -1; 
	}
	if (!dbus_bus_name_has_owner(conn, IPC_SERVICE_NAME, &err))
	{
		log_warning("proxy_resolve< [%s] No such name on the bus! >", IPC_SERVICE_NAME);
		log_info("proxy_resolve< start_service_by_name([%s]) >", IPC_SERVICE_NAME);
		dbus_uint32_t flags = 0, dbus_result;
		if(!dbus_bus_start_service_by_name(conn, IPC_SERVICE_NAME, flags, &dbus_result, &err))
		{
			log_critical("proxy_resolve< start_service_by_name FAILED: %s>", err.message);
			return -1;
		}
	}
	request = dbus_message_new_method_call(IPC_SERVICE_NAME, IPC_OBJECT_PATH, IPC_IFACE, METHOD_GETDNS_RESOLVE);
	if(NULL == request)
	{ 
	  	log_critical("proxy_resolve< Query: %s: Method call failed (MESSAGE=NULL) >", query);
	  	return -1;
	}
	if (!dbus_message_append_args(request, DBUS_TYPE_STRING, &query, DBUS_TYPE_INT32, &type, DBUS_TYPE_INT32, &af, DBUS_TYPE_INVALID)) 
	{
	  	return -1;
	}
	if (!dbus_connection_send_with_reply (conn, request, &pending, -1)) //Default timeout is -1
	{
	  	return -1;
	}
	if (NULL == pending) 
	{ 
	  	log_warning("proxy_resolve< Pending Call = Null. Exiting. >"); 
	  	return -1; 
	}
	dbus_connection_flush(conn);
	/*free the message*/
	dbus_message_unref(request);
	/*wait for reply*/
	dbus_pending_call_block(pending);
	/*Check the reply message*/
	reply = dbus_pending_call_steal_reply(pending);
	if (NULL == reply)
	{
		log_warning("proxy_resolve< Null reply >"); 
		dbus_pending_call_unref(pending);
		return -1; 
	}
	/*free the pending message handle*/
	dbus_pending_call_unref(pending);
	/*read the message*/
	*result = malloc(sizeof(response_bundle));
	if(*result == NULL)
	{
		log_critical("proxy_resolve< MALLOC failed >");
		dbus_message_unref(reply);  
		return ret;
	}
	if(!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT32, &ret, DBUS_TYPE_UINT32, &((*result)->respstatus),
		DBUS_TYPE_UINT32, &((*result)->dnssec_status), DBUS_TYPE_UINT64, &((*result)->ttl),
		DBUS_TYPE_UINT32, &((*result)->ipv4_count), DBUS_TYPE_UINT32, &((*result)->ipv6_count),
		DBUS_TYPE_STRING, &((*result)->ipv4), DBUS_TYPE_STRING, &((*result)->ipv6),
		DBUS_TYPE_STRING, &((*result)->cname), DBUS_TYPE_INVALID))
	{
		log_warning("proxy_resolve< Error reading message: %s >", err.message);
		if(*result != NULL)
		{
			(*result)->respstatus = GETDNS_RETURN_GENERIC_ERROR;
			(*result)->ipv4_count = 0;
			(*result)->ipv6_count = 0;
		}
	}
	dbus_message_unref(reply);  
	return ret;
}

#ifdef HAVE_CONTEXT_PROXY
getdns_context_proxy ctx_proxy = &ipc_dbus_proxy_resolve;
#endif

void handle_method_call(DBusMessage* msg, DBusConnection* conn)
{
	DBusMessage* reply;
	DBusError err;
	dbus_uint32_t success = 0;
	dbus_uint32_t serial = 0;
	response_bundle *addr_data = NULL;
	dbus_error_init(&err);
	if(context == NULL || extensions == NULL)
	{
		load_context(&context, &extensions, &last_changed);
	}
	if(context != NULL && extensions != NULL)
	{
		req_params req;
		if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &(req.query), DBUS_TYPE_INT32, &(req.reverse), DBUS_TYPE_INT32, &(req.af), DBUS_TYPE_INVALID))
		{
			do_query(context, extensions, &req, &addr_data);
		}else{
			log_warning("%s", err.message); 
		}
	}else{
		log_critical("Invalid context");
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
		log_critical("handle_method_call< Error appending arguments. >");
	}else if(addr_data && addr_data != &RESP_BUNDLE_EMPTY)
	{
		free(addr_data);
	}
	/*send reply && flush connection*/
	if (!dbus_connection_send(conn, reply, &serial))
	{
	  log_warning("handle_method_call< Error sending reply. >"); 
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
	/*reinitialise the error*/
	dbus_error_init(&err);
	/*connect to the bus*/
	conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
	if (dbus_error_is_set(&err))
	{ 
	  log_warning("ipc_dbus_listen< Connection Error (%s) >", err.message); 
	  dbus_error_free(&err); 
	}
	if (NULL == conn)
	{
	  log_critical("ipc_dbus_listen< Connection failed. >"); 
	  exit(EXIT_FAILURE); 
	}
	/*Register name on the bus*/
	ret = dbus_bus_request_name(conn, IPC_SERVICE_NAME, DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
	if (dbus_error_is_set(&err))
	{ 
	  log_critical("ipc_dbus_listen< Name Error (%s) >", err.message); 
	  dbus_error_free(&err);
	}
	if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
	{ 
	  log_critical("ipc_dbus_listen< Could not own name (%s). Error: %d >", IPC_SERVICE_NAME, ret);
	  exit(EXIT_FAILURE); 
	}
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
	if(context != NULL)
	{
		getdns_context_destroy(context);
	}
	if(extensions != NULL)
	{
		getdns_dict_destroy(extensions);
	}
}
