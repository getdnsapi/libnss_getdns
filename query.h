#ifndef _GETDNS_MODULE_QUERY_H
#define _GETDNS_MODULE_QUERY_H

int do_query(const char *query, int af, int reverse, getdns_context *context, getdns_dict *extensions, getdns_dict **response);
getdns_return_t parse_addr_bundle(getdns_dict *response, response_bundle **ret, int reverse, int af);
#endif
