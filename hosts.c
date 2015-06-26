#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <getdns/getdns_ext_libevent.h>
#include "getdns_libevent.h"
#include "logger.h"
#include "nss_getdns.h"
#include "addr_utils.h"


static const getdns_bindata TYPE_IPv4 = {4, (void *)"IPv4"};
static const getdns_bindata TYPE_IPv6 = {16, (void *)"IPv6"};
extern void __freeaddrinfo(struct addrinfo*);
extern void v42v6_map(char*);
extern void *addr_data_ptr(struct sockaddr_storage*);

#define  UNUSED_PARAM(x) ((void)(x))

struct callback_fn_arg
{
	struct addr_param *result_ptr;
	int af;
    char *buffer;
    size_t buflen;
    uint32_t *respstatus;
    uint32_t *dnssec_status;
};
	
static char *extract_cname(getdns_dict *response_tree, char *cname_label)
{
	getdns_bindata *c_name = NULL;
	char *cname_str = NULL;
	if( getdns_dict_get_bindata(response_tree, cname_label, &c_name) != GETDNS_RETURN_GOOD || c_name == NULL)
	{   
	    debug_log("GETDNS: Failed parsing the canonical name (%s)...\n", cname_label);
	    return NULL;
	}
	if( getdns_convert_dns_name_to_fqdn(c_name, &cname_str) != GETDNS_RETURN_GOOD || cname_str == NULL)
	{   
	    debug_log("GETDNS: Failed converting CNAME (%s)...\n", cname_label);
	}
	return cname_str;
}

/*
*Extract the dnssec_status from a replies_tree.
*/
static uint32_t getdnssec_status(getdns_dict *response)
{
	getdns_list *addr_list = NULL;
	uint32_t ret = GETDNS_DNSSEC_INDETERMINATE;
	if(getdns_dict_get_list(response, "replies_tree", &addr_list) == GETDNS_RETURN_GOOD)
	{
		size_t reply_idx, num_replies;
		getdns_list_get_length(addr_list, &num_replies);
		/*
		*The for-loop below assumes it is possible to get both bogus and non-bogus RRsets in the same reply.
		*For example, bogus A records with non-bogus AAAA records received.
		*TODO: In that case, should the non-bogus RRset be returned in the answer, or should all the answer be flagged as bogus?
		*NOW: all the answer is being considered bogus.
		*/
		for(reply_idx = 0; reply_idx < num_replies; ++reply_idx)
		{
			getdns_dict *cur_reply;
			if(getdns_list_get_dict(addr_list, reply_idx, &cur_reply) == GETDNS_RETURN_GOOD)
			{
				getdns_dict_get_int(cur_reply, "dnssec_status", &ret);
				if(ret == GETDNS_DNSSEC_BOGUS)
					break;
			}
		}
	}
	return ret;
}

/*
*TODO: Check for and handle [_res.options & RES_USE_INET6]
*/
static getdns_return_t extract_hostent(struct hostent *result, getdns_dict *response, int af, 
		uint32_t rr_type_filter, char *intern_buffer, size_t buflen, uint32_t *respstatus)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	*respstatus = GETDNS_RESPSTATUS_NO_NAME;
	size_t reply_idx, num_replies, addr_idx = 0;
	getdns_list *replies_tree = NULL;
	if((return_code= getdns_dict_get_list(response, "replies_tree", &replies_tree)) != GETDNS_RETURN_GOOD)
	{
		debug_log("extract_addrtuple():error parsing response.");
		return return_code;
	}
	return_code = getdns_list_get_length(replies_tree, &num_replies);
	if(num_replies < 1){
		*respstatus = GETDNS_RESPSTATUS_NO_NAME;
        return GETDNS_RETURN_GENERIC_ERROR;
    }
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
	/*Reserve the first section for result->h_addr_list[tot_answers] and result->h_name*/
	intern_buffer += sizeof(char*) * (tot_answers + 1);
	buflen -= sizeof(char*) * (tot_answers + 1);
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
        		if(buflen < len)
        		{
        			debug_log("GETDNS: buffer too small.\n");
        			return GETDNS_RETURN_MEMORY_ERROR;
        		}
        		memcpy(intern_buffer, tmp_name, len);        
        		result->h_addr_list[addr_idx++] = intern_buffer;  
        		intern_buffer += len;
        		buflen -= len;
        		ref_reply = rr_type_filter == GETDNS_RRTYPE_PTR ? rdata : cur_reply;
        	}
        }
	}
	/*
	*Extract canonical name (alias)
	*This is weird: for address records, the top-level tree contains the canonical_name attribute,
	*but for PTR records, each record has its own canonical_name. Which one to return as the alias?
	*/
	if(addr_idx > 0)
	{
		char *canon_name = extract_cname(ref_reply, rr_type_filter == GETDNS_RRTYPE_PTR ? "ptrdname" : "canonical_name");
		if(canon_name != NULL){
			size_t len = strlen(canon_name)+1;
			if(buflen < len)
    		{
    			debug_log("GETDNS: buffer too small.\n");
    			return GETDNS_RETURN_MEMORY_ERROR;
    		}
			memcpy(intern_buffer, canon_name, len);
			result->h_name = intern_buffer;
		}else{
			result->h_name = NULL;
		}		
		*respstatus = GETDNS_RESPSTATUS_GOOD;
	}
	result->h_addr_list[addr_idx] = NULL;
	return return_code;
}

static getdns_return_t extract_addrinfo(struct addrinfo **result, struct addrinfo *hints, 
		getdns_dict *response, uint32_t rr_type_filter, uint32_t *respstatus)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	size_t reply_idx, num_replies;
	struct addrinfo *ai, *result_ptr;
	int addrsize, family;
	int hints_map_all = 0;
	getdns_list *replies_tree = NULL;
	if((return_code = getdns_dict_get_list(response, "replies_tree", &replies_tree)) != GETDNS_RETURN_GOOD)
	{
		debug_log("extract_addrinfo():error parsing response.");
		return return_code;
	}
	return_code = getdns_list_get_length(replies_tree, &num_replies);
	if(num_replies < 1){
		*respstatus = GETDNS_RESPSTATUS_NO_NAME;
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
        			debug_log("Memory error (MALLOC).\n");
        			return GETDNS_RETURN_MEMORY_ERROR;
        		}
        		ai->ai_addr->sa_family = family;
        		memcpy(addr_data_ptr((struct sockaddr_storage*)(ai->ai_addr)), addr_data, addrsize);
        		COPY_ADDRINFO_PARAMS(ai, hints->ai_flags, family, hints->ai_socktype, hints->ai_protocol, ai->ai_addr, addrsize, NULL);
        		char *canon_name; 
        		canon_name = extract_cname(parent, "canonical_name");
        		if(canon_name != NULL)
        		{
        			ai->ai_canonname = strndup(canon_name, NI_MAXHOST);
        			free(canon_name);    
        			if(ai->ai_canonname == NULL)
        			{
        				debug_log("Memory error (strndup).\n");
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
	/*Make sure we got answers from the requested type, otherwise nothing.*/
	*respstatus = num_matching_responses > 0 ? GETDNS_RESPSTATUS_GOOD : GETDNS_RESPSTATUS_NO_NAME;
	return num_matching_responses > 0 ? return_code : GETDNS_RETURN_GENERIC_ERROR;
}

/*
*TODO: Check for and handle [_res.options & RES_USE_INET6]
*/
static getdns_return_t extract_addrtuple(struct gaih_addrtuple **result_addrtuple, getdns_dict *response, 
		uint32_t rr_type_filter, char *intern_buffer, size_t buflen, uint32_t *respstatus)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	getdns_list *addr_list = NULL;
	if((return_code= getdns_dict_get_list(response, "just_address_answers", &addr_list)) != GETDNS_RETURN_GOOD)
	{
		debug_log("extract_addrtuple():error parsing response.");
		return return_code;
	}
	size_t rec_count, num_replies;
	size_t idx, min_space, cname_len;
    getdns_list_get_length(addr_list, &num_replies);
    char *canon_name, *hname;
    canon_name = extract_cname(response, rr_type_filter == GETDNS_RRTYPE_PTR ? "ptrdname" : "canonical_name");
    cname_len = strlen(canon_name);
    min_space = __alignof__(canon_name) + (__alignof__(struct gaih_addrtuple) * num_replies);
    if( buflen < min_space )
    {
        return_code = GETDNS_RETURN_MEMORY_ERROR;
        debug_log("GETDNS: Buffer too small: %zd\n", buflen);
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    struct gaih_addrtuple *gaih_ptr = *result_addrtuple;
    /*Fill in hostname*/
    hname = intern_buffer;
    memcpy(hname, canon_name, cname_len+1);
    idx = __alignof__(canon_name);
    /*Fill in addresses*/
    for(rec_count = 0; rec_count < num_replies; ++rec_count)
    {
        getdns_dict *next_record;
        return_code &= getdns_list_get_dict(addr_list, rec_count, &next_record);
        getdns_bindata *rec_data, *addr_type;
        return_code &= getdns_dict_get_bindata(next_record, "address_data", &rec_data);
        return_code &= getdns_dict_get_bindata(next_record, "address_type", &addr_type);
        struct gaih_addrtuple *addr_tuple = (struct gaih_addrtuple*) (intern_buffer + idx);
        idx += __alignof__(struct gaih_addrtuple);
        addr_tuple->name = hname;
        addr_tuple->family = rec_data->size == 4 ? AF_INET : AF_INET6;
        memcpy (addr_tuple->addr, rec_data->data, rec_data->size);
	    addr_tuple->scopeid = 0;
	    addr_tuple->next = NULL;
	    if(rec_count > 0){
	        gaih_ptr->next = addr_tuple;
	    }
	    else{
	        *result_addrtuple = addr_tuple;
	    }
	    gaih_ptr = addr_tuple;
    }
    assert(idx == min_space);
    if(canon_name != NULL)
    	free(canon_name);
    *respstatus = num_replies > 0 ? GETDNS_RESPSTATUS_GOOD : GETDNS_RESPSTATUS_NO_NAME;
	return return_code;
}

void answer_callbackfn(getdns_context *context, getdns_callback_type_t callback_type,
                     getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
	if (callback_type == GETDNS_CALLBACK_COMPLETE)
	{
		struct callback_fn_arg *arg = (struct callback_fn_arg*)userarg;
		assert(arg != NULL);
		struct addr_param *result_ptr = arg->result_ptr;
		int af = arg->af;
		char *buffer = arg->buffer;
		size_t buflen = arg->buflen;
		uint32_t *respstatus = arg->respstatus;
		uint32_t *dnssec_status = arg->dnssec_status;
		uint32_t rr_type_filter = result_ptr->addr_type == REV_HOSTENT ? GETDNS_RRTYPE_PTR : (af == AF_INET ? GETDNS_RRTYPE_A : GETDNS_RRTYPE_AAAA) ; 
		getdns_return_t return_code;
		*dnssec_status = getdnssec_status(response);
		if((return_code = getdns_dict_get_int(response, "status", respstatus)) != GETDNS_RETURN_GOOD)
		{
	    	debug_log("getdns_dict_get_int: failure(%d)\n", return_code);
		}else{
    		if(result_ptr->addr_type == ADDR_GAIH)
			{
				return_code =  extract_addrtuple(result_ptr->addr_entry.p_gaih, response, rr_type_filter, buffer, buflen, respstatus);
			}else if(result_ptr->addr_type == ADDR_ADDRINFO){
				return_code =  extract_addrinfo(result_ptr->addr_entry.p_addrinfo, result_ptr->hints, response, rr_type_filter, respstatus);
			}    
			else{
				return_code = extract_hostent(result_ptr->addr_entry.p_hostent, response, af, rr_type_filter, buffer, buflen, respstatus);
			} 
    	}
    	getdns_dict_destroy(response);
	}else if(callback_type == GETDNS_CALLBACK_CANCEL){
		err_log("The callback was cancelled.");
	}else{
		err_log("Callback_type: %d.", callback_type);
	}
}

static int parse_response(const char *query, getdns_context *context, getdns_dict *extensions, struct callback_fn_arg *userarg)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	assert(userarg);
	/*
    Perform lookup asynchronously
    */
    getdns_transaction_t transaction_id = 0;
    struct event_base *event_base = event_base_new();
	if (event_base == NULL)
	{
		err_log("Failed to create the event base.");
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	(void)getdns_extension_set_libevent_base(context, event_base);
    if(userarg->result_ptr->addr_type == REV_HOSTENT){
    	getdns_dict *address = getdns_dict_create();
    	getdns_bindata address_data = {(userarg->af == AF_INET6 ? 16 : 4), (void *)query };
    	return_code &= getdns_dict_set_bindata(address, "address_type", userarg->af == AF_INET6 ? &TYPE_IPv6 : &TYPE_IPv4);
    	return_code &= getdns_dict_set_bindata(address, "address_data", &address_data);
        return_code &= getdns_hostname(context, address, extensions, (void*)userarg, &transaction_id, answer_callbackfn);
        getdns_dict_destroy(address);
	}else{
        return_code = getdns_address(context, query, extensions, (void*)userarg, &transaction_id, answer_callbackfn);
    }
    if(return_code == GETDNS_RETURN_BAD_DOMAIN_NAME)
	{
		debug_log("Bad IP address: %s", query);
		event_base_free(event_base);
		return GETDNS_RETURN_GENERIC_ERROR;
	}else{
		 if(event_base_dispatch(event_base) != 0)
		 	err_log("Event base dispatch failed.");
	}
    event_base_free(event_base);
    if(return_code != GETDNS_RETURN_GOOD){
        debug_log("getdns_address_sync: failure(%d)", return_code);
       	return return_code;
    }
	switch(*(userarg->respstatus))
	{
		case GETDNS_RESPSTATUS_GOOD:
			break;
		/*NO_SECURE_ANSWERS or ALL_TIMEOUT: no results to parse, so just return error.*/
		case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
			debug_log("GETDNS: No secure answers.");
		case GETDNS_RESPSTATUS_NO_NAME:
		case GETDNS_RESPSTATUS_ALL_TIMEOUT:
		case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
			debug_log("GETDNS: The search returned no results: response code: < %d >\n", *(userarg->respstatus));
			return GETDNS_RETURN_GENERIC_ERROR;
		default:
			debug_log("Unkown status code returned: %d\n", *(userarg->respstatus));
			/*No results to parse, so just return error.*/
			return GETDNS_RETURN_GENERIC_ERROR;
	}
    return return_code;
}

/*
* This function combines both getaddrinfo() and getnameinfo(), so in short, everything the module does!
* This was decided for simplicity purposes since this is just a wrapper around getdns which does all the work.
*/
getdns_return_t getdns_gethostinfo(const char *name, int af, struct addr_param *result_ptr, 
        char *intern_buffer, size_t buflen, int32_t *ttlp, char **canonp, uint32_t *respstatus, uint32_t *dnssec_status)
{
    getdns_context *context = NULL;
    getdns_dict *extensions = NULL;
    getdns_return_t return_code; 
    if(!intern_buffer || buflen < sizeof(char) || (!result_ptr))
    {
        debug_log("getdns_gethostinfo: Memory error...");
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    *respstatus = GETDNS_RESPSTATUS_NO_NAME;
    if( (af != AF_INET) && (af != AF_INET6) && (af != AF_UNSPEC) )
    {
        debug_log("getdns_gethostinfo: Address family not supported: %d .", af);
        return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
    }
    memset(intern_buffer, 0, buflen);
    UNUSED_PARAM(ttlp);
    /*
    Load system global getdns context and default extensions
    */
    if((return_code = load_context(&context, &extensions)) == GETDNS_RETURN_GOOD){
		struct callback_fn_arg arg = {.result_ptr=result_ptr, .af=af, .buffer=intern_buffer, .buflen=buflen,
     			.respstatus=respstatus, .dnssec_status=dnssec_status
     	};
		if((return_code = parse_response(name, context, extensions, &arg)) != GETDNS_RETURN_GOOD)
		{
			debug_log("getdns_gethostinfo(<%s>): Failed parsing response: ERROR < %d >\n", name, return_code);
		}
    }else{
    	debug_log("Failed creating dns context <ERR_CODE: %d>.\n", return_code);
    }
	/*
	This section is not complete:
	TODO:
	1. Do all the getdns data structures need to be cleaned up, or does destroying the top-level node suffice? 
	*Let's valgrind it and see, maybe?!
	*/
    if(canonp && *respstatus == GETDNS_RESPSTATUS_GOOD)
    {
        *canonp = result_ptr->addr_entry.p_hostent->h_name;
    }
    debug_log("Query(%s) => < %d > - DNSSEC STATUS: {%s}\n", name, *respstatus, getdns_get_errorstr_by_id(*dnssec_status));
    /*
    *Now the context is not being shared accross multiple calls, so free it now.
    *TODO: It would be a lot better, really, if the context could be reused at least within a process.
    *However, that is hard to do when REENTRANCE is required. Hmmm!
    *Should we use a copy of an initial context? Or is it worthwhile finding a way to reuse it???
    */
    getdns_context_destroy(context);
    return return_code;
}

/*
*wrapper for getnameinfo().
*/
getdns_return_t getdns_getnameinfo (const void *addr, const int af, char *nodename, size_t namelen, uint32_t *respstatus)
{
    getdns_return_t return_code;
    uint32_t dnssec_status = GETDNS_DNSSEC_NOT_PERFORMED;
    struct hostent result;
    size_t buflen = 1024;
    do{
    	char buffer[buflen];
		struct addr_param result_ptr = {.addr_type=REV_HOSTENT, .addr_entry={.p_hostent=&result}};
		return_code = getdns_gethostinfo(addr, af, &result_ptr, buffer, buflen, NULL, NULL, respstatus, &dnssec_status);
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

/*
*wrapper for getaddrinfo()
*/
getdns_return_t getdns_getaddrinfo(const char *name, int af, struct addrinfo **result, struct addrinfo *hints, uint32_t *respstatus)
{
    struct addr_param result_ptr = {.addr_type=ADDR_ADDRINFO, .addr_entry={.p_addrinfo=result}, .hints=hints};
    char bufplholder[4];
    uint32_t dnssec_status = GETDNS_DNSSEC_INDETERMINATE;
    return getdns_gethostinfo(name, af, &result_ptr, bufplholder, 4, NULL, NULL, respstatus, &dnssec_status);
}
