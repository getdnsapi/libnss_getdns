#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <nss.h>
#include <errno.h>
#include <getdns/getdns.h>
#include "logger.h"

/*
The following macro extracts answers into a hostent struct.
It is called from getdns_getaddrinfo().
Adapted from what gethostbyname3_r() does, it was extracted to make the getdns_getaddrinfo() function generic for
both structs used in gethostbyname3_r() [hostent] and gethostbyname4_r() [gaih_addrtuple].
*/

#define EXTRACT_HOSTENT() \
do {\
    memset(result, 0, sizeof(struct hostent));  \
    if( buflen < (num_addresses + 1) * sizeof(result->h_length) ){ \
        return_code = GETDNS_RETURN_MEMORY_ERROR;   \
        err_log("GETDNS: Memory error: buflen: %zd\n", buflen); \
        goto clean_and_return;  \
    }  \
    result->h_addrtype = af;    \
    result->h_name = canon_name;    \
    result->h_length = (af == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN);   \
    result->h_addr_list = (char**)buffer;   \
    buffer += ((num_addresses + 1) * sizeof(char*));  \
    result->h_addr_list[num_addresses] = NULL;  \
    for(rec_count = 0; rec_count < num_addresses; ++rec_count)  \
    {   \
        getdns_dict *next_record;   \
        return_code = getdns_list_get_dict(addr_list, rec_count, &next_record); \
        getdns_bindata *rec_data;   \
        return_code = getdns_dict_get_bindata(next_record, "address_data", &rec_data);  \
        char *tmp_name = (char*)(rec_data->data);   \
        memcpy(buffer, tmp_name, strlen(tmp_name)); \
        result->h_addr_list[rec_count] = (char*)buffer;   \
        buffer += strlen(tmp_name); \
    }   \
} while (0)


/*
The following macro extracts answers into a gaih_addruple struct.
It is called from getdns_getaddrinfo().
Adapted from what gethostbyname4_r() does, it was extracted to make the getdns_getaddrinfo() function generic for
both structs used in gethostbyname3_r() [hostent] and gethostbyname4_r() [gaih_addrtuple].
*/

#define EXTRACT_ADDRTUPLE() \
do {\
    if( buflen < (num_addresses * sizeof(struct gaih_addrtuple *)) + INET6_ADDRSTRLEN ){ \
        return_code = GETDNS_RETURN_MEMORY_ERROR;   \
        err_log("GETDNS: Memory error: buflen: %zd\n", buflen); \
        goto clean_and_return;  \
    }  \
    struct gaih_addrtuple *gaih_ptr = *result_addrtuple; \
    for(rec_count = 0; rec_count < num_addresses; ++rec_count)  \
    {   \
        getdns_dict *next_record;   \
        return_code = getdns_list_get_dict(addr_list, rec_count, &next_record); \
        getdns_bindata *rec_data, *addr_type;   \
        return_code = getdns_dict_get_bindata(next_record, "address_data", &rec_data);  \
        return_code = getdns_dict_get_bindata(next_record, "address_type", &addr_type);  \
        struct gaih_addrtuple *addr_tuple = (struct gaih_addrtuple *)buffer;    \
        buffer += sizeof(struct gaih_addrtuple *); \
        buflen -= sizeof(struct gaih_addrtuple *); \
        addr_tuple->name = canon_name;  \
        addr_tuple->family = rec_data->size == 4 ? AF_INET : AF_INET6;  \
        memcpy (addr_tuple->addr, rec_data->data, rec_data->size);  \
	    addr_tuple->scopeid = 0;  \
	    addr_tuple->next = NULL;  \
	    if(rec_count > 0){ \
	        gaih_ptr->next = addr_tuple; \
	    }   \
	    else{   \
	        *result_addrtuple = addr_tuple;  \
	    }   \
	    gaih_ptr = addr_tuple;  \
    }   \
} while (0)

#define DO_CHECK_PARAMS()	\
do{	\
    if(!name || !buflen || (!result && !result_addrtuple)){	\
        getdns_process_statcode(GETDNS_RETURN_MEMORY_ERROR, &status, errnop, h_errnop);	\
        err_log("GETDNS: Memory error...");	\
        return status;	\
    }	\
    if( (af != AF_INET) && (af != AF_INET6) && (af != AF_UNSPEC) ){	\
        getdns_process_statcode(GETDNS_RETURN_WRONG_TYPE_REQUESTED, &status, errnop, h_errnop);	\
        err_log("GETDNS: Wrong type requested...");	\
        return status;	\
    }	\
} while (0)

/*
Convert getdns status codes & return values to NSS status codes, and set errno values
*/
extern void getdns_process_statcode(uint32_t status, enum nss_status *nss_code, int *errnop, int *h_errnop);

enum nss_status getdns_getaddrinfo(const char *name, int af, struct hostent *result, struct gaih_addrtuple **result_addrtuple, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    getdns_context *context = NULL;
    getdns_dict *extensions = NULL;
    getdns_dict *response = NULL;
    getdns_return_t return_code; 
    uint16_t request_type;
    memset(buffer, 0, buflen);
    uintptr_t pad = 0;//-(uintptr_t) buffer & __alignof__ (struct hostent_data);
    buffer += pad;
    buflen = buflen > pad ? buflen - pad : 0;
    DO_CHECK_PARAMS();
    /*
    Create and check getdns context
    */
    return_code = getdns_context_create(&context, 1);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("Failed creating dns context <ERR_CODE: %d>.\n", return_code);
        goto clean_and_return;
    }
    extensions = getdns_dict_create();
    return_code = getdns_dict_set_int(extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("Failed setting (IPv4/IPv6) extension  <ERR_CODE: %d>.\n", return_code);
        goto clean_and_return;
    }
    
    /*getdns extensions for doing both IPv4 and IPv6
    */
    
    /*
    Perform lookup synchronously
    */
    if( af == AF_INET || af == AF_INET6 ){
        request_type = (af == AF_INET6 ? GETDNS_RRTYPE_A6 : (af == AF_INET ? GETDNS_RRTYPE_A : GETDNS_RRTYPE_A6));
        return_code = getdns_general_sync(context, name, request_type, extensions, &response);
    }else{
        return_code = getdns_address_sync(context, name, extensions, &response);
    } 
    if(return_code != GETDNS_RETURN_GOOD || response == NULL){
        err_log("getdns_address failed with status code: < %d >", return_code);
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
        err_log("getdns_dict_get_int failed with error code < %d >\n", return_code);
        goto clean_and_return;
    }
    if(resp_status != GETDNS_RESPSTATUS_GOOD){
        /*The search returned a negative answer*/
        return_code = resp_status;
        err_log("The search returned no results: error code < %d >\n", resp_status);
        goto clean_and_return;
    }
    /*Extract just the A and AAAA records in the answers*/
    getdns_list *addr_list = NULL;
    getdns_bindata *c_name = NULL;
    return_code = getdns_dict_get_list(response, "just_address_answers", &addr_list);
    return_code &= getdns_dict_get_bindata(response, "canonical_name", &c_name);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("getdns_dict_get_list failed with error code < %d >\n", return_code);
        goto clean_and_return;
    }
    size_t num_addresses = 0, rec_count;
    return_code = getdns_list_get_length(addr_list, &num_addresses);
    if(num_addresses < 1){
        return_code = GETDNS_RESPSTATUS_NO_NAME;
        goto clean_and_return;
    }  
    char *cname_str = NULL;
    return_code = getdns_convert_dns_name_to_fqdn(c_name, &cname_str);
    if(return_code != GETDNS_RETURN_GOOD || !cname_str)
    {   
        err_log("GETDNS: Failed converting CNAME...\n");
        goto clean_and_return;
    }
    int cname_len = strlen(cname_str);
    memcpy(buffer, cname_str, cname_len-1);
    char *canon_name = buffer;
    buffer += cname_len;
    buflen -= cname_len;
    if(result != NULL && result_addrtuple == NULL)
    {
        EXTRACT_HOSTENT();
    }else{
        EXTRACT_ADDRTUPLE();
    }
    clean_and_return:
        getdns_dict_destroy(response);
        getdns_context_destroy(context);
        getdns_process_statcode(return_code, &status, errnop, h_errnop);
        err_log("GETDNS: Returning code: %d , NSS: %d, errnop: %d, h_errnop: %d\n", return_code, status, *errnop, *h_errnop);
        if(canonp && status == NSS_STATUS_SUCCESS)
        {
            *canonp = result->h_name;
        }
        return status;
}
