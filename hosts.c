#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <getdns/getdns.h>
#include "logger.h"
#include "nss_getdns.h"
#include "addr_utils.h"
#include <stdio.h>


static const getdns_bindata TYPE_IPv4 = {4, (void *)"IPv4"};
static const getdns_bindata TYPE_IPv6 = {16, (void *)"IPv6"};
extern void __freeaddrinfo(struct addrinfo*);
extern void v42v6_map(char*);
extern void *addr_data_ptr(struct sockaddr_storage*);

#define  UNUSED_PARAM(x) ((void)(x))

/*static getdns_return_t extract_cname(getdns_dict *response_tree, char *intern_buffer, size_t *buflen, char **ret)
{
	getdns_bindata *c_name = NULL;
	getdns_dict_get_bindata(response_tree, "canonical_name", &c_name);
	return getdns_convert_dns_name_to_fqdn(c_name, ret);
}*/

/*
Too many lines, but hopefully cleaner since we have to write everything in the buffer provided by the application.
*/
static getdns_return_t extract_cname(char *cname_label, getdns_dict *response_tree, char *intern_buffer, size_t *buflen, char **ret)
{
	getdns_bindata *c_name = NULL;
	char *cname_str = NULL;
	getdns_return_t return_code;
	if( (return_code = getdns_dict_get_bindata(response_tree, cname_label, &c_name)) != GETDNS_RETURN_GOOD || c_name == NULL)
    {   
        err_log("GETDNS: Failed parsing the canonical name (%s)...\n", cname_label);
        return return_code;
    }
    if( (return_code = getdns_convert_dns_name_to_fqdn(c_name, &cname_str)) != GETDNS_RETURN_GOOD || cname_str == NULL)
    {   
        err_log("GETDNS: Failed converting CNAME (%s)...\n", cname_label);
        return return_code;
    }
    size_t cname_len = strlen(cname_str);
    if(*buflen > cname_len)
    {
    	memcpy(intern_buffer, cname_str, cname_len-1);
    	intern_buffer[cname_len-1] = '\0';
		*ret = intern_buffer;
		intern_buffer += cname_len;
		*buflen -= cname_len;
		free(cname_str);
		return GETDNS_RETURN_GOOD;
    }
    return GETDNS_RETURN_MEMORY_ERROR;
}

static getdns_return_t extract_hostent(struct hostent *result, getdns_list *replies_tree, int af, 
		uint32_t rr_type_filter, char *intern_buffer, size_t *buflen, uint32_t *respstatus)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	*respstatus = GETDNS_RESPSTATUS_NO_NAME;
	size_t reply_idx, num_replies, addr_idx = 0;
	return_code = getdns_list_get_length(replies_tree, &num_replies);
	if(num_replies < 1){
        return GETDNS_RETURN_GENERIC_ERROR;
    }
	memset(result, 0, sizeof(struct hostent)); 
	result->h_addrtype = af;
	result->h_length = (af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr));  
	result->h_addr_list = (char**)intern_buffer; 
	getdns_dict *ref_reply;
	ref_reply = NULL;
	size_t tot_answers = 0;
	for(reply_idx = 0; reply_idx < num_replies; ++reply_idx)
	{
		getdns_dict *tmp_reply;
		return_code = getdns_list_get_dict(replies_tree, reply_idx, &tmp_reply);
		getdns_list* answers;
		return_code = getdns_dict_get_list(tmp_reply, "answer", &answers);
		size_t num_answers;
        getdns_list_get_length(answers, &num_answers);
        tot_answers += num_answers;
	}
	intern_buffer += sizeof(char*) * (tot_answers + 1);
	*buflen -= sizeof(char*) * (tot_answers + 1);
	for(reply_idx = 0; reply_idx < num_replies; ++reply_idx)
	{
		getdns_dict *cur_reply;
		return_code = getdns_list_get_dict(replies_tree, reply_idx, &cur_reply);
		getdns_list* answers;
		return_code = getdns_dict_get_list(cur_reply, "answer", &answers);
		size_t num_answers;
        return_code = getdns_list_get_length(answers, &num_answers);
        size_t answer_idx;
        for (answer_idx = 0; answer_idx < num_answers; ++answer_idx)
        {
        	getdns_dict * rr;
        	uint32_t rr_type;
            return_code = getdns_list_get_dict(answers, answer_idx, &rr);
        	return_code = getdns_dict_get_int(rr, "type", &rr_type); 
        	if (rr_type == rr_type_filter)
        	{
        		getdns_dict *rdata;
        		getdns_bindata *rdata_raw;
        		return_code = getdns_dict_get_dict(rr, "rdata", &rdata); 
        		return_code = getdns_dict_get_bindata(rdata, "rdata_raw", &rdata_raw);
        		char *tmp_name = (char*)(rdata_raw->data);  
        		size_t len = rdata_raw->size;
        		if(*buflen < len)
        		{
        			err_log("GETDNS: buffer too small.\n");
        			return GETDNS_RETURN_MEMORY_ERROR;
        		}
        		memcpy(intern_buffer, tmp_name, len);        
        		result->h_addr_list[addr_idx++] = intern_buffer;  
        		intern_buffer += len;
        		*buflen -= len;
        		ref_reply = rr_type_filter == GETDNS_RRTYPE_PTR ? rdata : cur_reply;
        	}
        }
	}
	if(addr_idx > 0)
	{
		return_code = extract_cname(rr_type_filter == GETDNS_RRTYPE_PTR ? "ptrdname" : "canonical_name", ref_reply, intern_buffer, buflen, &(result->h_name));
		*respstatus = GETDNS_RESPSTATUS_GOOD;
	}
	result->h_addr_list[addr_idx] = NULL;
	return return_code;
}

static getdns_return_t extract_addrinfo(struct addrinfo **result, struct addrinfo *hints, 
		getdns_list *replies_tree, uint32_t rr_type_filter, uint32_t *respstatus)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	size_t reply_idx, num_replies;
	struct addrinfo *ai, *result_ptr;
	int addrsize, family;
	int hints_map_all = 0;
	return_code = getdns_list_get_length(replies_tree, &num_replies);
	if(num_replies < 1){
        return GETDNS_RETURN_GENERIC_ERROR;
    }
	addrsize = (hints->ai_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));  
	size_t num_matching_responses = 0;
	ai = NULL, result_ptr = NULL;
	getdns_dict *parent = NULL;
	family = hints->ai_family;
	if((hints->ai_family == AF_INET6) && (hints->ai_flags & AI_V4MAPPED))
	{
		//if(hints->ai_flags & AI_ALL)
		{
			/*AI_ALL and AI_V4MAPPED are treated equally here since AI_V4MAPPED is meaningful only when no IPv6 were found.*/
			hints_map_all = 1;
		}
	}else{
		hints->ai_flags &= ~AI_V4MAPPED;
	}
	for(reply_idx = 0; reply_idx < num_replies; ++reply_idx)
	{
		getdns_dict *cur_reply;
		return_code = getdns_list_get_dict(replies_tree, reply_idx, &cur_reply);
		getdns_list* answers;
		return_code = getdns_dict_get_list(cur_reply, "answer", &answers);
		size_t num_answers;
        return_code = getdns_list_get_length(answers, &num_answers);
        size_t answer_idx;
        parent = parent == NULL ? cur_reply : parent;
        for (answer_idx = 0; answer_idx < num_answers; ++answer_idx)
        {
        	getdns_dict * rr;
        	uint32_t rr_type;
            return_code = getdns_list_get_dict(answers, answer_idx, &rr);
        	return_code = getdns_dict_get_int(rr, "type", &rr_type); 
        	/*
        	*Disregard address that do not match the requested type unless 
        	*(1)we should map IPv4 to IPv6 addresses
        	*or
        	*(2)we have AI_V4MAPPED and AI_ALL set with AF_INET6
        	*AI_V4MAPPED and AF_INET6 should both be set if the first attempt to retrieve IPv6 addresses returned empty.
        	*/
        	UNUSED_PARAM(rr_type_filter);
        	if ( (rr_type == rr_type_filter) || (hints_map_all && (rr_type == GETDNS_RRTYPE_A || rr_type == GETDNS_RRTYPE_AAAA)) )
        	{
        		getdns_dict *rdata;
        		getdns_bindata *rdata_raw;
        		return_code = getdns_dict_get_dict(rr, "rdata", &rdata); 
        		return_code = getdns_dict_get_bindata(rdata, "rdata_raw", &rdata_raw);
        		char *addr_data;
        		if(rr_type == GETDNS_RRTYPE_A && (hints->ai_flags & AI_V4MAPPED))
        		{
        			addr_data = alloca(sizeof(struct sockaddr_in6));
        			memcpy(addr_data, rdata_raw->data, rdata_raw->size);
        			v42v6_map(addr_data);
        			family = AF_INET6;
        			addrsize = sizeof(struct sockaddr_in6);
        		}else{
        			addrsize = (rr_type == GETDNS_RRTYPE_AAAA) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        			addr_data = alloca(addrsize);
        			memcpy(addr_data, rdata_raw->data, rdata_raw->size);
        		}
        		ai = _allocaddrinfo(family); 
        		if(ai == NULL)
        		{
        			err_log("Memory error (MALLOC).\n");
        			return GETDNS_RETURN_MEMORY_ERROR;
        		}
        		ai->ai_addr->sa_family = family;
        		memcpy(addr_data_ptr((struct sockaddr_storage*)(ai->ai_addr)), addr_data, addrsize);
        		COPY_ADDRINFO_PARAMS(ai, hints->ai_flags, family, hints->ai_socktype, hints->ai_protocol, ai->ai_addr, addrsize, NULL);
        		char cname_buf[NI_MAXHOST], *tmp_name; 
        		size_t buflen = NI_MAXHOST;
        		if(extract_cname("canonical_name", parent, cname_buf, &buflen, &tmp_name) == GETDNS_RETURN_GOOD)
        		{
        			ai->ai_canonname = strndup(cname_buf, NI_MAXHOST);
        			if(ai->ai_canonname == NULL)
        			{
        				err_log("Memory error (strndup).\n");
        				__freeaddrinfo(ai);
        				__freeaddrinfo(*result);
        				return GETDNS_RETURN_MEMORY_ERROR;
        			}        		
        		}else{
        			ai->ai_canonname = NULL;
        		}
        		if(result_ptr != NULL){
					result_ptr->ai_next = ai;
				}   
				else{
					*result = ai;
				}
				result_ptr = ai;
				num_matching_responses++;
        	}
        }
	}
	*respstatus = num_matching_responses > 0 ? GETDNS_RESPSTATUS_GOOD : GETDNS_RESPSTATUS_NO_NAME;
	return num_matching_responses > 0 ? return_code : GETDNS_RETURN_GENERIC_ERROR;
}

/*
The following macro extracts answers into a gaih_addruple struct.
It is called from getdns_gethostinfo().
Adapted from what gethostbyname4_r() does, it was extracted to make the getdns_gethostinfo() function generic for
both structs used in gethostbyname3_r() [hostent] and gethostbyname4_r() [gaih_addrtuple].
TODO: is it ugly enough?
*/
#define EXTRACT_ADDRTUPLE() \
do {\
	memset(result_addrtuple, 0, sizeof(struct gaih_addrtuple*));  \
	size_t rec_count, num_replies;	\
    getdns_list_get_length(addr_list, &num_replies);	\
    if( buflen < (num_replies * sizeof(struct gaih_addrtuple *)) + INET6_ADDRSTRLEN ){ \
        return_code = GETDNS_RETURN_MEMORY_ERROR;   \
        err_log("GETDNS: Memory error: buflen: %zd\n", buflen); \
        goto end;  \
    }  \
    struct gaih_addrtuple *gaih_ptr = *result_addrtuple; \
    char *canon_name;	\
    extract_cname(rr_type_filter == GETDNS_RRTYPE_PTR ? "ptrdname" : "canonical_name", replies_tree, intern_buffer, &buflen, &canon_name);	\
    for(rec_count = 0; rec_count < num_replies; ++rec_count)  \
    {   \
        getdns_dict *next_record;   \
        return_code = getdns_list_get_dict(addr_list, rec_count, &next_record); \
        getdns_bindata *rec_data, *addr_type;   \
        return_code = getdns_dict_get_bindata(next_record, "address_data", &rec_data);  \
        return_code = getdns_dict_get_bindata(next_record, "address_type", &addr_type);  \
        struct gaih_addrtuple *addr_tuple = (struct gaih_addrtuple *)intern_buffer;    \
        intern_buffer += sizeof(struct gaih_addrtuple *); \
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

/*
Check for intern_buffer size and address family
*/
#define DO_CHECK_PARAMS()	\
do{	\
    if(!name || !buflen || (!result_ptr)){	\
        err_log("GETDNS: Memory error...");	\
        return GETDNS_RETURN_MEMORY_ERROR;	\
    }	\
    if( (af != AF_INET) && (af != AF_INET6) && (af != AF_UNSPEC) ){	\
        err_log("GETDNS: Wrong type requested...");	\
        return GETDNS_RETURN_WRONG_TYPE_REQUESTED;	\
    }	\
} while (0)


/*
Retrieve system global getdns context and default extensions
*/
extern getdns_return_t load_context(getdns_context **ctx, getdns_dict **ext);

/*
Extract one of the top-level nodes in the replies_tree
TODO: 
	*MAJOR: should the lookups be asynchronous????
	*MINOR: this function has so many parameters!
*/
static int parse_response(const char *query, getdns_context *context, getdns_dict *extensions, 
		getdns_dict **response, getdns_list **replies_list, const int af, 
		const addr_param_t param_type, const char *node_selector, uint32_t *resp_status)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	uint16_t request_type;
	/*
    Perform lookup synchronously
    */
    if(param_type == REV_HOSTENT){
    	getdns_dict *address = getdns_dict_create();
    	getdns_bindata address_data = {(af == AF_INET6 ? 16 : 4), (void *)query };
    	return_code &= getdns_dict_set_bindata(address, "address_type", af == AF_INET6 ? &TYPE_IPv6 : &TYPE_IPv4);
    	return_code &= getdns_dict_set_bindata(address, "address_data", &address_data);
        return_code &= getdns_hostname_sync(context, address, extensions, response);
        getdns_dict_destroy(address);
    }else if( af == AF_INET || af == AF_INET6 ){
        request_type = af == AF_INET ? GETDNS_RRTYPE_A : GETDNS_RRTYPE_AAAA;
        return_code = getdns_general_sync(context, query, request_type, extensions, response);
    }else{
        return_code = getdns_address_sync(context, query, extensions, response);
    }
    if(return_code != GETDNS_RETURN_GOOD || *response == NULL){
        if(*response == NULL){
        	err_log("GETDNS: no answers found.");
        }
        err_log("GETDNS: failed with status code: < %d, %d >", return_code, *resp_status);
       	return return_code;
    }
    /*
    Process result and extract one of the top-level nodes for further parsing
    */
    return_code = getdns_dict_get_int(*response, "status", resp_status);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("getdns_dict_get_int failed with error code < %d >\n", return_code);
        return return_code;
    }
    if(*resp_status != GETDNS_RESPSTATUS_GOOD){
        /*The search returned a negative answer*/
        return_code = GETDNS_RETURN_GENERIC_ERROR;
        err_log("GETDNS: The search returned no results: error code < %d >\n", *resp_status);
        return return_code;
    }
    return_code = getdns_dict_get_list(*response, node_selector, replies_list);
    //printf("RESPONSE: %s\n", getdns_pretty_print_dict(*response));
    return return_code;
}

/*
This is the magic function:
It combines both getaddrinfo() and getnameinfo(), so in short, everything the module does!
This was decided for simplicity purposes since this is just a wrapper around getdns which does all the work.
*/
getdns_return_t getdns_gethostinfo(const char *name, int af, struct addr_param *result_ptr, 
        char *intern_buffer, size_t buflen, int32_t *ttlp, char **canonp, uint32_t *respstatus)
{
    getdns_context *context = NULL;
    getdns_dict *extensions = NULL;
    getdns_dict *replies_tree = NULL;
    getdns_list *addr_list = NULL;
    getdns_return_t return_code; 
    memset(intern_buffer, 0, buflen);
    DO_CHECK_PARAMS();
    UNUSED_PARAM(ttlp);
    *respstatus = GETDNS_RESPSTATUS_NO_NAME;
    /*
    Load system global getdns context and default extensions
    */
    return_code = load_context(&context, &extensions);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("Failed creating dns context <ERR_CODE: %d>.\n", return_code);
        goto end;
    }    
    /*
    gethostbyname4_r uses a weird struct for the result, so we'll deal with it with particularity (ADDR_GAIH).
    All the others end up calling gethostbyaddr3_r or gethostbyname2_r, which have a comparable signature.
    */
    char *node_selector = result_ptr->addr_type == ADDR_GAIH ? "just_address_answers" : "replies_tree" ; 
    return_code = parse_response(name, context, extensions, &replies_tree, &addr_list, af, result_ptr->addr_type, node_selector, respstatus);
    if(return_code != GETDNS_RETURN_GOOD){
        err_log("GETDNS <%s>: Failed parsing response: ERROR < %d >\n", name, return_code);
        goto end;
    }
    uint32_t rr_type_filter = result_ptr->addr_type == REV_HOSTENT ? GETDNS_RRTYPE_PTR : (af == AF_INET ? GETDNS_RRTYPE_A : GETDNS_RRTYPE_AAAA) ; 
    if(result_ptr->addr_type == ADDR_GAIH)
    {
    	struct gaih_addrtuple **result_addrtuple = result_ptr->addr_entry.p_gaih;
    	/**
    	TODO: The EXTRACT_ADDRTUPLE macro is ugly...
    	*/
       EXTRACT_ADDRTUPLE();
    }else if(result_ptr->addr_type == ADDR_ADDRINFO){
    	return_code =  extract_addrinfo(result_ptr->addr_entry.p_addrinfo, result_ptr->hints, addr_list, rr_type_filter, respstatus);
    }    
    else{
        return_code = extract_hostent(result_ptr->addr_entry.p_hostent, addr_list, af, rr_type_filter, intern_buffer, &buflen, respstatus);
    }   
    end:
    	/*
    	This section is not complete:
    	TODO:
    	1. All the getdns data structures need to be cleaned up, or does destroying the top-level node suffice? 
    	*/
        if(canonp && *respstatus == GETDNS_RESPSTATUS_GOOD)
        {
            *canonp = result_ptr->addr_entry.p_hostent->h_name;
        }
        if(replies_tree)
        {
        	getdns_dict_destroy(replies_tree);
        }
        return return_code;
}


getdns_return_t getdns_getnameinfo (const void *addr, const int af, char *nodename, size_t namelen)
{
    getdns_return_t return_code;
    uint32_t respstatus;
    struct hostent result;
    size_t buflen = 1024;
    do{
    	char buffer[buflen];
		struct addr_param result_ptr = {.addr_type=REV_HOSTENT, .addr_entry={.p_hostent=&result}};
		return_code = getdns_gethostinfo(addr, af, &result_ptr, buffer, buflen, NULL, NULL, &respstatus);
    	buflen *= 2;
    }while(return_code == GETDNS_RETURN_MEMORY_ERROR);
    if(return_code == GETDNS_RETURN_GOOD)
    {
    	if(strlen(result.h_name) > namelen || nodename == NULL)
    	{
    		return GETDNS_RETURN_MEMORY_ERROR;
    	}else{
    		strcpy(nodename, result.h_name);
    	}
    }
    return return_code;
}


getdns_return_t getdns_getaddrinfo(const char *name, int af, struct addrinfo **result, struct addrinfo *hints, uint32_t *respstatus)
{
    struct addr_param result_ptr = {.addr_type=ADDR_ADDRINFO, .addr_entry={.p_addrinfo=result}, .hints=hints};
    char bufplholder[4];
    return getdns_gethostinfo(name, af, &result_ptr, bufplholder, 4, NULL, NULL, respstatus);
}