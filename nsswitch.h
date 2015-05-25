#include <nss.h>
#include <errno.h>
#include <getdns/getdns.h>

#ifndef _GETDNS_NSSWITCH_H
#define _GETDNS_NSSWITCH_H 1
/*
Convert getdns status codes & return values to NSS status codes, and set errno values
*/
void getdns_process_statcode(uint32_t status, enum nss_status *nss_code, int *errnop, int *h_errnop);
#endif
