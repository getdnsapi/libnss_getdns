#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include "nsswitch.h"
#include "logger.h"


/*
Default hints when the hints parameter is null
*/
static const struct addrinfo no_hints =
{
    .ai_flags = 0,
    .ai_family = AF_UNSPEC,
    .ai_socktype = 0,
    .ai_protocol = 0,
    .ai_addrlen = 0,
    .ai_addr = NULL,
    .ai_canonname = NULL,
    .ai_next = NULL
};

/*
Initialize addrinfo struct
*/
static void init_addr_info(struct addrinfo **ret, const struct addrinfo *hints)
{
    *ret = malloc(sizeof(struct addrinfo));
    if(*ret != NULL){
        (*ret)->ai_flags = hints->ai_flags;
        (*ret)->ai_family = hints->ai_family;
        (*ret)->ai_socktype = hints->ai_socktype;
        (*ret)->ai_protocol = hints->ai_protocol;
        (*ret)->ai_canonname = hints->ai_canonname;
        (*ret)->ai_addr->sa_family = hints->ai_family; 
    }
}

static enum nss_status getdns_getaddrinfo(const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    if(!name || !buffer || !result){
        *h_errnop = NO_DATA;
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    enum nss_status status = NSS_STATUS_NOTFOUND;
    getdns_context *context = NULL;
    getdns_dict *response = NULL;
    getdns_return_t return_code; 
    /*
    Create and check getdns context
    */
    return_code = getdns_context_create(&context, 1);
    if(return_code != GETDNS_RETURN_GOOD){
        goto clean_and_return;
    }
    /*
    Perform lookup synchronously
    */
    return_code = getdns_address_sync(context, name, NULL, &response);
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
        err_log("The search returned no results: error code: %d\n", resp_status);
        goto clean_and_return;
    }
    /*Extract just the A and AAAA records in the answers*/
    getdns_list *addr_list;
    if( (af != AF_INET) && (af != AF_INET6) ){
        *h_errnop = NO_DATA;
        *errnop = EAFNOSUPPORT;
        return_code = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
        goto clean_and_return;
    }
    result->h_addrtype = af;
    result->h_name = ??HOW TO SET H_NAME???? name ?;
    result->h_length = ( af == AF_INET6 ? IN6ADDRSZ : INADDRSZ );
    return_code = getdns_dict_get_list(response, ( af == AF_INET6 ? "answer_ipv6_address" : "answer_ipv4_address" ), &addr_list);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("getdns_dict_get_list failed with error code: %d\n", return_code);
        goto clean_and_return;
    }
    size_t num_addresses, rec_count;
    return_code = getdns_list_get_length(addr_list, &num_addresses);
    if(num_addresses < 1){
        *h_errnop = NO_DATA;
        *errnop = ENOENT;
        return_code = GETDNS_RESPSTATUS_NO_NAME;
        goto clean_and_return;
    }  
    if( buflen < (num_addresses * sizeof(result->h_length)) ){
        *h_errnop = NO_DATA;
        *errnop = ERANGE;
        return_code = GETDNS_RETURN_MEMORY_ERROR;
        goto clean_and_return;
    }  
    result->h_addr_list = malloc(sizeof(char*) * (1 + num_addresses));
    result->h_addr_list[num_addresses] = NULL;
    for(rec_count = 0; rec_count < num_addresses; ++rec_count)
    {
        getdns_dict *next_record;
        return_code = getdns_list_get_dict(addr_list, rec_count, &next_record);
        getdns_bindata *rec_data;
        return_code = getdns_dict_get_bindata(next_record, "address_data", &rec_data);
        char *addr_str = getdns_display_ip_address(rec_data);
        result->h_addr_list[rec_count] = addr_str;
    }
    clean_and_return:
    getdns_dict_destroy(response);
    getdns_context_destroy(context);
    return nss_getdns_retval_interpret(return_code);
}
  
/*gethostbyname4_r sends out parallel A and AAAA queries*/
enum nss_status _nss_getdns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, 
        char *buffer, size_t buflen, int *errnop, int *herrnop, int32_t *ttlp)
{
    err_log("GETDNS: gethostbyname4!\n");
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_getdns_gethostbyname3_r (const char *name, int af, struct hostent *result, 
        char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    const struct addrinfo hints = { .ai_family = af
	                               , .ai_flags  = AI_NUMERICHOST };
	status = getaddress(name, NULL, &hints, result);
    err_log("GETDNS: gethostbyname3: STATUS: %d\n", status);
    return NSS_STATUS_NOTFOUND;
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
