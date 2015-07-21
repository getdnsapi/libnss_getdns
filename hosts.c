#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include "logger.h"
#include "nss_getdns.h"
#include "addr_utils.h"
#include "context_interface.h"

#define  UNUSED_PARAM(x) ((void)(x))

extern void __freeaddrinfo(struct addrinfo*);
extern void v42v6_map(char*);
extern void *addr_data_ptr(struct sockaddr_storage*);

const int IN6_ADDRLEN = sizeof(struct sockaddr_in6);
const int IN_ADDRLEN = sizeof(struct sockaddr_in);


struct callback_fn_arg
{
	struct addr_param *result_ptr;
	int af;
    char *buffer;
    size_t buflen;
    uint32_t *respstatus;
    uint32_t *dnssec_status;
};

static int parse_addr_list(char *arg, char **buf_ptr, int num)
{
	int ret = 0;
	char *next = NULL;
	if(num <=0 || !buf_ptr || !strtok_r(arg, ":", &next)) /*Starts with ipv4: or ipv6:*/
	{
		return 0;
	}
	while((buf_ptr[ret] = strtok_r(NULL, ",", &next)) != NULL && (num > ret++));
	return ret == num ? ret : 0;
}

/*
*TODO: Check for and handle [_res.options & RES_USE_INET6]
*/
static getdns_return_t extract_hostent(struct hostent *result, response_bundle *response, int af, int reverse, 
		char *intern_buffer, size_t buflen, uint32_t *respstatus)
{
	*respstatus = GETDNS_RESPSTATUS_NO_NAME;
	size_t answer_idx, num_answers = 0, addr_idx = 0;
	char *addr_string;
	if(!response)
	{
		log_info("extract_addrtuple():error parsing response.");
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	if((af == AF_INET6) || ((af == AF_UNSPEC) && (response->ipv6_count > 0)))
	{
		num_answers = response->ipv6_count;
		addr_string = response->ipv6;
		result->h_length = sizeof(struct in6_addr);
	}else if(af == AF_INET || af == AF_UNSPEC){
		num_answers = response->ipv4_count;
		addr_string = response->ipv4;
		result->h_length = sizeof(struct in_addr);
	}else{
		log_warning("getdns_gethostinfo: Address family not supported: %d .", af);
		*respstatus = GETDNS_RESPSTATUS_NO_NAME;
        return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
	}
	if(num_answers < 1){
		*respstatus = GETDNS_RESPSTATUS_NO_NAME;
        return GETDNS_RETURN_GENERIC_ERROR;
    }
	result->h_addrtype = af;
	result->h_addr_list = (char**)intern_buffer; 
	/*Reserve the first section for result->h_addr_list[num_answers] and result->h_name*/
	intern_buffer += sizeof(char*) * (num_answers + 1);
	buflen -= sizeof(char*) * (num_answers + 1);
	char *addr_list[num_answers];
	if(parse_addr_list(addr_string, addr_list, num_answers) != num_answers)
	{
		*respstatus = GETDNS_RESPSTATUS_NO_NAME;
        return GETDNS_RETURN_GENERIC_ERROR;
	}
	for (answer_idx = 0; answer_idx < num_answers; ++answer_idx)
    {
		char tmp_name[af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr)];
		memset(tmp_name, 0, sizeof(tmp_name));
		inet_pton(af, addr_list[answer_idx], tmp_name);
		size_t len = sizeof(tmp_name);
		if(buflen < len)
		{
			log_warning("GETDNS: buffer too small.\n");
			return GETDNS_RETURN_MEMORY_ERROR;
		}
		memcpy(intern_buffer, tmp_name, len);        
		result->h_addr_list[addr_idx++] = intern_buffer;  
		intern_buffer += len;
		buflen -= len;
    }
    memcpy(intern_buffer, response->cname, strlen(response->cname));
	result->h_name = intern_buffer;
    *respstatus = response->respstatus;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t add_addrinfo(struct addrinfo **result_ptr, struct addrinfo *hints, const char *addr_string, const int addr_size, const char *canon_name)
{
	int addrsize, family;
	family = (addr_size == IN_ADDRLEN) ? AF_INET : AF_INET6;
	char addr_data[sizeof(struct in6_addr)];
	inet_pton(family, addr_string, addr_data);
	struct addrinfo *ai;
	if(addr_size == IN_ADDRLEN && hints->ai_family == AF_INET6)
	{
		v42v6_map(addr_data);
		family = AF_INET6;
		addrsize = sizeof(struct sockaddr_in6);
	}else{
		addrsize = (hints->ai_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	}
	ai = _allocaddrinfo(family); 
	if(ai == NULL)
	{
		log_critical("Memory error (MALLOC).\n");
		return GETDNS_RETURN_MEMORY_ERROR;
	}
	ai->ai_addr->sa_family = family;
	memcpy(addr_data_ptr((struct sockaddr_storage*)(ai->ai_addr)), addr_data, sizeof(addr_data));
	COPY_ADDRINFO_PARAMS(ai, hints->ai_flags, family, hints->ai_socktype, hints->ai_protocol, ai->ai_addr, addrsize, NULL);
	if(canon_name != NULL)
	{
		ai->ai_canonname = strndup(canon_name, NI_MAXHOST);
		if(ai->ai_canonname == NULL)
		{
			log_critical("Memory error (strndup).\n");
			__freeaddrinfo(ai);
			return GETDNS_RETURN_MEMORY_ERROR;
		}    		
	}else{
		ai->ai_canonname = NULL;
	}
	if(*result_ptr != NULL){
		(*result_ptr)->ai_next = ai;
	}   
	*result_ptr = ai;
	return GETDNS_RETURN_GOOD;
}

static getdns_return_t parse_addrinfo(char *addr_list_string, const char *cname, const int num_addresses, size_t addrlen, 
	struct addrinfo **result, struct addrinfo *hints)
{
	char *addr_list[num_addresses];
	size_t answer_idx;
	struct addrinfo *result_ptr = NULL;
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	if(parse_addr_list(addr_list_string, addr_list, num_addresses) != num_addresses)
	{
	    return GETDNS_RETURN_GENERIC_ERROR;
	}
	for(answer_idx = 0; answer_idx < num_addresses; ++answer_idx)
	{
				
		if( GETDNS_RETURN_GOOD != (return_code = add_addrinfo(&result_ptr, hints, addr_list[answer_idx], addrlen, cname)))
		{
			__freeaddrinfo(*result);
			return return_code;
		}
		if(*result == NULL)
		{
			*result = result_ptr;
		}
	}
	return return_code;
}

static getdns_return_t extract_addrinfo(struct addrinfo **result, struct addrinfo *hints, 
		response_bundle *response, uint32_t *respstatus)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	int hints_map_all = 0, hints_v4mapped = 0;

	if(!response)
	{
		log_info("extract_addrinfo():error parsing response.");
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	if((response->ipv4_count + response->ipv6_count) < 1){
		*respstatus = GETDNS_RESPSTATUS_NO_NAME;
        return GETDNS_RETURN_GENERIC_ERROR;
    } 
	if((hints->ai_family == AF_INET6) && (hints->ai_flags & AI_V4MAPPED))
	{
		hints_v4mapped = 1;
		if(hints->ai_flags & AI_ALL)
		{
			hints_map_all = 1;
		}
	}else{
		hints->ai_flags &= ~AI_V4MAPPED;
	}
	if((hints->ai_family == AF_INET6)  || (hints->ai_family == AF_UNSPEC))
	{
		return_code = parse_addrinfo(response->ipv6, response->cname, response->ipv6_count, IN6_ADDRLEN, result, hints);
	}
	if((hints->ai_family == AF_INET) || ((hints->ai_family == AF_UNSPEC) && (*result == NULL)))
	{
		return_code = parse_addrinfo(response->ipv4, response->cname, response->ipv4_count, IN_ADDRLEN, result, hints);
	} 
	if(hints_map_all || ((*result == NULL) && hints_v4mapped))
	{
		return_code = parse_addrinfo(response->ipv4, response->cname, response->ipv4_count, IN_ADDRLEN, result, hints);
	}
	*respstatus = *result != NULL ? GETDNS_RESPSTATUS_GOOD : GETDNS_RESPSTATUS_NO_NAME;
	return *result != NULL ? return_code : GETDNS_RETURN_GENERIC_ERROR;
}

/*
*TODO: Check for and handle [_res.options & RES_USE_INET6]
*/
static getdns_return_t extract_addrtuple(struct gaih_addrtuple **result_addrtuple, response_bundle *response, 
		char *intern_buffer, size_t buflen, uint32_t *respstatus)
{
	if(!response)
	{
		log_warning("extract_addrtuple():error parsing response.");
		return GETDNS_RETURN_GENERIC_ERROR;
	}else if(response->ipv4_count + response->ipv6_count <= 0)
	{
		log_info("extract_addrtuple(): No answers: %s.", getdns_get_errorstr_by_id(response->respstatus));
		*respstatus = GETDNS_RESPSTATUS_NO_NAME;
		return GETDNS_RETURN_GOOD;
	}
	size_t rec_count = 0, num_answers = 0;
	size_t idx, min_space, cname_len;
	num_answers = response->ipv4_count + response->ipv6_count;
    char *canon_name = response->cname;
    cname_len = strlen(canon_name) + 2;
    min_space = cname_len + (sizeof(struct gaih_addrtuple) * num_answers);
    if( buflen < min_space )
    {
        log_critical("GETDNS: Buffer too small: %zd\n", buflen);
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    struct gaih_addrtuple *gaih_ptr = *result_addrtuple;
    /*Fill in hostname*/
    char *hname;
    hname = intern_buffer;
    memcpy(hname, canon_name, cname_len-2);
    memset(hname + cname_len-1, 0, sizeof(char));
    idx = cname_len;
    /*Fill in addresses*/
    void add_addrtuple(char *data, int family)
    {
    	struct gaih_addrtuple *addr_tuple = (struct gaih_addrtuple*) (intern_buffer + idx);
        idx += sizeof(struct gaih_addrtuple);
        addr_tuple->name = hname;
        addr_tuple->family = family;
		char ip_data[family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN];
		inet_pton(family, data, ip_data); 
		size_t len = sizeof(ip_data);
        memcpy(addr_tuple->addr, ip_data, len);
	    addr_tuple->scopeid = 0;
	    addr_tuple->next = NULL;
	    if(rec_count > 0){
	        gaih_ptr->next = addr_tuple;
	    }else{
	        *result_addrtuple = addr_tuple;
	    }
	    gaih_ptr = addr_tuple;
    }
    if(response->ipv6_count > 0)
    {
    	char *addr_list[response->ipv6_count];
    	int num = parse_addr_list(response->ipv6, addr_list, response->ipv6_count);
		for(rec_count = 0; rec_count < num; ++rec_count)
		{
		    add_addrtuple(addr_list[rec_count], AF_INET6);
		}
    }
    if(response->ipv4_count > 0)
    {
    	char *addr_list[response->ipv4_count];
    	int num = parse_addr_list(response->ipv4, addr_list, response->ipv4_count);
		int addr_idx;
		for(addr_idx = 0; addr_idx < num; ++addr_idx)
		{
		    add_addrtuple(addr_list[addr_idx], AF_INET);
		    rec_count++;
		}
    }
    assert(idx <= min_space); /*Check if we didn't write past the intended space...*/
    *respstatus = rec_count > 0 ? GETDNS_RESPSTATUS_GOOD : GETDNS_RESPSTATUS_NO_NAME;
	return GETDNS_RETURN_GOOD;
}

int resolve(const char *query, struct callback_fn_arg *userarg)
{
		struct callback_fn_arg *arg = (struct callback_fn_arg*)userarg;
		assert(arg != NULL);
		struct addr_param *result_ptr = arg->result_ptr;
		int af = arg->af;
		char *buffer = arg->buffer;
		size_t buflen = arg->buflen;
		uint32_t *respstatus = arg->respstatus;
		uint32_t *dnssec_status = arg->dnssec_status;
		getdns_return_t return_code;
		response_bundle *response = NULL;
		if(result_ptr->addr_type == REV_HOSTENT)
		{
			size_t len = af == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
			char ip_data[len];
			inet_ntop(af, query, ip_data, len);
			resolve_with_managed_ctx(ip_data, 1, af, &response);
		}else if(result_ptr->addr_type == ADDR_GAIH){
			resolve_with_managed_ctx((char*)query, 0, af, &response);
		}else{
			resolve_with_managed_ctx((char*)query, 0, af, &response);
		}
		if(response == NULL)
		{
			log_warning("resolve< NULL RESPONSE >");
			return GETDNS_RETURN_GENERIC_ERROR;
		}else{
			*dnssec_status = response->dnssec_status;
			*respstatus = response->respstatus;	
    		if(result_ptr->addr_type == ADDR_GAIH)
			{
				return_code =  extract_addrtuple(result_ptr->addr_entry.p_gaih, response, buffer, buflen, respstatus);
			}else if(result_ptr->addr_type == ADDR_ADDRINFO){
				return_code =  extract_addrinfo(result_ptr->addr_entry.p_addrinfo, result_ptr->hints, response, respstatus);
			}    
			else{
				return_code = extract_hostent(result_ptr->addr_entry.p_hostent, response, af, result_ptr->addr_type == REV_HOSTENT, buffer, buflen, respstatus);
			}
    	}
	free(response);
	return return_code;
}

/*
* This function combines both getaddrinfo() and getnameinfo(), so in short, everything the module does!
* This was decided for simplicity purposes since this is just a wrapper around getdns which does all the work.
*/
getdns_return_t getdns_gethostinfo(const char *name, int af, struct addr_param *result_ptr, 
        char *intern_buffer, size_t buflen, int32_t *ttlp, char **canonp, uint32_t *respstatus, uint32_t *dnssec_status)
{
    getdns_return_t return_code; 
    if(!intern_buffer || buflen < sizeof(char) || (!result_ptr))
    {
        log_critical("getdns_gethostinfo: Memory error...");
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    *respstatus = GETDNS_RESPSTATUS_NO_NAME;
    if( (af != AF_INET) && (af != AF_INET6) && (af != AF_UNSPEC) )
    {
        log_warning("getdns_gethostinfo: Address family not supported: %d .", af);
        return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
    }
    memset(intern_buffer, 0, buflen);
    UNUSED_PARAM(ttlp);
	struct callback_fn_arg arg = {.result_ptr=result_ptr, .af=af, .buffer=intern_buffer, .buflen=buflen,
 			.respstatus=respstatus, .dnssec_status=dnssec_status
 	};
	if((return_code = resolve(name, &arg)) != GETDNS_RETURN_GOOD)
	{
		log_info("getdns_gethostinfo(<%s>): Failed parsing response: ERROR < %d >\n", name, return_code);
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
	log_debug("Query(%s) => < %d > - DNSSEC STATUS: {%s}\n", name, *respstatus, getdns_get_errorstr_by_id(*dnssec_status));
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
getdns_return_t getdns_getaddrinfo(const char *name, int af, struct addrinfo **result, struct addrinfo *ai_hints, uint32_t *respstatus)
{
    struct addr_param result_ptr = {.addr_type=ADDR_ADDRINFO, .addr_entry={.p_addrinfo=result}, .hints=ai_hints};
    char bufplholder[4];
    uint32_t dnssec_status = GETDNS_DNSSEC_INDETERMINATE;
    getdns_return_t ret = getdns_gethostinfo(name, af, &result_ptr, bufplholder, 4, NULL, NULL, respstatus, &dnssec_status);
    return ret;
}
