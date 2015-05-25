#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include "nsswitch.h"
#include "logger.h"

static enum nss_status getdns_getaddrinfo(const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    memset(result, 0, sizeof(struct hostent));
    if(!name || !buffer || !buflen || !result){
        getdns_process_statcode(GETDNS_RETURN_MEMORY_ERROR, &status, errnop, h_errnop);
        err_log("GETDNS: Memory error...");
        return status;
    }
     if( (af != AF_INET) && (af != AF_INET6) && (af != AF_UNSPEC) ){
        getdns_process_statcode(GETDNS_RETURN_WRONG_TYPE_REQUESTED, &status, errnop, h_errnop);
        err_log("GETDNS: Wrong type requested...");
        return status;
    }
    getdns_context *context = NULL;
    getdns_dict *extensions = NULL;
    getdns_dict *response = NULL;
    getdns_return_t return_code; 
    uint16_t request_type;
    /*
    Create and check getdns context
    */
    return_code = getdns_context_create(&context, 1);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("Creating dns context failed.");
        goto clean_and_return;
    }
    extensions = getdns_dict_create();
    return_code = getdns_dict_set_int(extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("getdns: setting extension (IPv4/IPv6) failed.");
        goto clean_and_return;
    }
    
    /*getdns extensions for doing both IPv4 and IPv6
    */
    
    /*
    Perform lookup synchronously
    */
    request_type = (af == AF_INET6 ? GETDNS_RRTYPE_A6 : (af == AF_INET ? GETDNS_RRTYPE_A : GETDNS_RRTYPE_A|GETDNS_RRTYPE_A6));
    return_code = getdns_general_sync(context, name, request_type, extensions, &response);
    if(return_code != GETDNS_RETURN_GOOD || response == NULL){
        err_log("getdns_address_sync failed with status: %d", return_code);
        if(response == NULL){
            goto clean_and_return;
        }else{
            goto clean_and_return;
        }
    }
    /*
    Process result
    */
    uint32_t resp_status;
    return_code = getdns_dict_get_int(response, "status", &resp_status);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("getdns_dict_get_int failed with error code: %d\n", return_code);
        goto clean_and_return;
    }
    if(resp_status != GETDNS_RESPSTATUS_GOOD){
        /*The search returned a negative answer*/
        return_code = resp_status;
        err_log("The search returned no results: error code: %d\n", resp_status);
        goto clean_and_return;
    }
    /*Extract just the A and AAAA records in the answers*/
    getdns_list *addr_list;
    getdns_bindata *c_name;
    return_code = getdns_dict_get_list(response, "just_address_answers", &addr_list);//( af == AF_INET6 ? "answer_ipv6_address" : "answer_ipv4_address" ), &addr_list);
    return_code &= getdns_dict_get_bindata(response, "canonical_name", &c_name);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("getdns_dict_get_list failed with error code: %d\n", return_code);
        goto clean_and_return;
    }
    size_t num_addresses, rec_count;
    return_code = getdns_list_get_length(addr_list, &num_addresses);
    err_log("GETDNS: GOT: %zd addresses...\n", num_addresses);
    if(num_addresses < 1){
        return_code = GETDNS_RESPSTATUS_NO_NAME;
        goto clean_and_return;
    }  
    if( buflen < (num_addresses * sizeof(result->h_length)) ){
        return_code = GETDNS_RETURN_MEMORY_ERROR;
        err_log("GETDNS: Memory error: buflen: %zd (have %zd)\n", buflen, num_addresses * sizeof(result->h_length));
        goto clean_and_return;
    }  
    result->h_addrtype = af;
    char canon_name[INET6_ADDRSTRLEN];
    result->h_name = buffer;
    strncpy(buffer, (char*)c_name->data, sizeof(canon_name));
    buffer += sizeof(canon_name);
    result->h_length = (af == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN);
    result->h_addr_list = malloc(sizeof(char*) * (1 + num_addresses));
    result->h_addr_list[num_addresses] = NULL;
    for(rec_count = 0; rec_count < num_addresses; ++rec_count)
    {
        getdns_dict *next_record;
        return_code = getdns_list_get_dict(addr_list, rec_count, &next_record);
        getdns_bindata *rec_data;
        return_code = getdns_dict_get_bindata(next_record, "address_data", &rec_data);
        char *addr_str = getdns_display_ip_address(rec_data);
        err_log("GETDNS: got %s for CNAME <%s>\n", addr_str, result->h_name);
        result->h_addr_list[rec_count] = addr_str;
    }
    clean_and_return:
        getdns_dict_destroy(response);
        getdns_context_destroy(context);
        getdns_process_statcode(return_code, &status, errnop, h_errnop);
        err_log("GETDNS: Returning code: %d , NSS: %d, errnop: %d, h_errnop: %d\n", return_code, status, *errnop, *h_errnop);
        return status;
}
  
/*gethostbyname4_r sends out parallel A and AAAA queries*/
enum nss_status _nss_getdns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, 
        char *buffer, size_t buflen, int *errnop, int *herrnop, int32_t *ttlp)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    if(*pat == NULL)
    {
        uintptr_t pad = (-(uintptr_t) buffer % __alignof__ (struct gaih_addrtuple));
        buffer += pad;
	    buflen = buflen > pad ? buflen - pad : 0;
	    if(buflen < sizeof (struct gaih_addrtuple))
	    {  
	        getdns_process_statcode(GETDNS_RETURN_MEMORY_ERROR, &status, errnop, h_errnop);
            err_log("GETDNS: Buffer too small...");
            return status;
	    }
        *pat = (struct gaih_addrtuple *) buffer;
        buffer += sizeof (struct gaih_addrtuple);
	    buflen -= sizeof (struct gaih_addrtuple);
    }
    (*pat)->name = NULL;
    (*pat)->next = NULL;
    (*pat)->family = af;
    err_log("GETDNS: gethostbyname4 <%s>: STATUS: %d\n", name, status);
    return status;
}

enum nss_status _nss_getdns_gethostbyname3_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    enum nss_status status;
    status = getdns_getaddrinfo(name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp);
    err_log("GETDNS: gethostbyname3: STATUS: %d\n", status);
    return status;
}

enum nss_status _nss_getdns_gethostbyname2_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    err_log("GETDNS: gethostbyname2!\n");
    return _nss_getdns_gethostbyname3_r (name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_getdns_gethostbyname_r (const char *name, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    err_log("GETDNS: gethostbyname!\n");
    enum nss_status status = NSS_STATUS_NOTFOUND;
    /*if (_res.options & RES_USE_INET6)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET6, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);*/
    if (status == NSS_STATUS_NOTFOUND)
        status = _nss_getdns_gethostbyname3_r (name, AF_INET, result, buffer,
					buflen, errnop, h_errnop, NULL, NULL);
    return status;
}
