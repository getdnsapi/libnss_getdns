// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#ifndef _IPC_DBUS_INTERFACE_H_
#define _IPC_DBUS_INTERFACE_H_
#define IPC_SERVICE_NAME  "net.getdnsapi.StubResolver"
#define IPC_OBJECT_PATH "/net/getdnsapi/StubResolver"
#define IPC_IFACE "net.getdnsapi.StubResolver"

/*
*Methods implemented in the interface.
*/
#define METHOD_GETDNS_RESOLVE  "secure_resolve"
#define METHOD_LOCALHOST_ERROR_PAGE_IP  "error_page_ip"

/*
*Signals implemented in the interface
*/
#define SIGNAL_LOCAL_HTTP_CONN_STATUS "local_http_bind_status_change"
#define SIGNAL_ADD_DNSSEC_EXCEPTION	"add_exception_for_name"

#endif
