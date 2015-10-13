#include "context_interface.h"

#ifndef _GETDNS_MODULE_QUERY_H
#define _GETDNS_MODULE_QUERY_H
getdns_return_t do_query(getdns_context *context, getdns_dict *extensions, req_params *request, response_bundle **ret);
getdns_return_t parse_addr_bundle(getdns_dict *response, response_bundle **ret, req_params *request);
#endif
