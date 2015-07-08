#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include "logger.h"
#include "nss_getdns.h"
#include "context_interface.h"
#include "browsers.h"

#define ASSERT_OR_RETURN(expr) \
do{	\
	if((return_code = expr) != GETDNS_RETURN_GOOD) 	\
	{	\
		goto clean_and_return; 	\
	}	\
}while(0)

#define DNSSEC_CHECK_BOGUS() \
do{	\
	if((((*ret)->respstatus == GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS) || ((*ret)->dnssec_status == GETDNS_DNSSEC_BOGUS)))	\
	{	\
		if(browser_check(af_filter))	\
		{	\
			(*ret)->respstatus = RESP_BUNDLE_LOCAL_ERR.respstatus;	\
			(*ret)->dnssec_status = RESP_BUNDLE_LOCAL_ERR.dnssec_status;	\
			(*ret)->ipv4_count = 1;	\
			(*ret)->ipv6_count = 1;	\
			(*ret)->ipv4 = strdup(RESP_BUNDLE_LOCAL_ERR.ipv4);	\
			(*ret)->ipv6 = strdup(RESP_BUNDLE_LOCAL_ERR.ipv6);	\
			(*ret)->ttl = 0;	\
			(*ret)->cname = strdup(RESP_BUNDLE_LOCAL_ERR.cname);	\
		}else{	\
			(*ret)->ipv4_count = 0;	\
			(*ret)->ipv6_count = 0;	\
			(*ret)->respstatus = GETDNS_RESPSTATUS_NO_NAME;	\
		}	\
		return GETDNS_RETURN_GOOD;	\
	}	\
}while(0)

static const getdns_bindata TYPE_IPv4 = {4, (void *)"IPv4"};
static const getdns_bindata TYPE_IPv6 = {16, (void *)"IPv6"};

response_bundle RESP_BUNDLE_EMPTY = {.ttl=0, .respstatus=GETDNS_RESPSTATUS_NO_NAME, .dnssec_status=GETDNS_DNSSEC_INDETERMINATE,
	.ipv4_count=0, .ipv6_count=0, .ipv4="", .ipv6="", .cname=""};
	
response_bundle RESP_BUNDLE_LOCAL_CONFIG = {.ttl=0, .respstatus=GETDNS_RESPSTATUS_GOOD, .dnssec_status=GETDNS_DNSSEC_INDETERMINATE,
	.ipv4_count=1, .ipv6_count=1, .ipv4=GETDNS_CONFIG_IPV4, .ipv6=GETDNS_CONFIG_IPV6, .cname=GETDNS_CONFIG_LOCALNAME};
	
response_bundle RESP_BUNDLE_LOCAL_ERR = {.ttl=0, .respstatus=GETDNS_RESPSTATUS_GOOD, .dnssec_status=GETDNS_DNSSEC_INDETERMINATE,
	.ipv4_count=1, .ipv6_count=1, .ipv4=GETDNS_ERR_IPV4, .ipv6=GETDNS_ERR_IPV6, .cname=GETDNS_CONFIG_LOCALNAME};
	
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

int do_query(const char *query, int af, int reverse, getdns_context *context, getdns_dict *extensions, getdns_dict **response)
{
	getdns_return_t return_code = GETDNS_RETURN_GENERIC_ERROR;
	/*
    Perform lookup synchronously
    */
    if(reverse)
    {
    	char dd[(af == AF_INET6 ? 16 : 4)];
    	inet_pton(af, query, dd);
    	getdns_dict *address = getdns_dict_create();
    	getdns_bindata address_data = {(af == AF_INET6 ? 16 : 4), (void *)dd};
    	return_code &= getdns_dict_set_bindata(address, "address_type", af == AF_INET6 ? &TYPE_IPv6 : &TYPE_IPv4);
    	return_code &= getdns_dict_set_bindata(address, "address_data", &address_data);
        return_code &= getdns_hostname_sync(context, address, extensions, response);
        getdns_dict_destroy(address);
	}else{
        return_code = getdns_address_sync(context, query, extensions, response);
    }
    if(return_code != GETDNS_RETURN_GOOD)
    {
        debug_log("getdns_address: failure(%d)", return_code);
       	return return_code;
    }
    return return_code;
}

getdns_return_t parse_ipaddr_bundle(getdns_dict *response, int af_filter, response_bundle **ret)
{
	uint32_t respstatus;
	getdns_return_t return_code = GETDNS_RETURN_MEMORY_ERROR;
	getdns_list * just_the_addresses_ptr;
	return_code = getdns_dict_get_list(response, "just_address_answers", &just_the_addresses_ptr);
	size_t num_addresses, rec_count;
	return_code = getdns_list_get_length(just_the_addresses_ptr, &num_addresses);
	*ret = malloc(sizeof(response_bundle));
	size_t ipv4_len = 5 + (num_addresses *  (1+INET_ADDRSTRLEN)),
		ipv6_len = 5 + (num_addresses *  (1+INET6_ADDRSTRLEN));
	char *ipv4 = malloc(ipv4_len);
	char *ipv6 = malloc(ipv6_len);
	if(!(*ret) || !ipv4 || !ipv6)
	{
		err_log("parse_addr_bundle< Malloc failed. >");
		return GETDNS_RETURN_MEMORY_ERROR;
	}
	return_code = getdns_dict_get_int(response, "status", &respstatus);
	if (return_code != GETDNS_RETURN_GOOD) 
	{
		free(*ret);
		*ret = NULL;
		err_log("Error: %d", return_code);
		return return_code;
	}
	memset(ipv4, 0, ipv4_len);
	memset(ipv6, 0, ipv6_len);
	(*ret)->respstatus = respstatus;
	(*ret)->dnssec_status = getdnssec_status(response);
	(*ret)->ipv4_count = 0;
	(*ret)->ipv6_count = 0;
	(*ret)->ipv4 = ipv4;
	(*ret)->ipv6 = ipv6;
	(*ret)->ttl = 0;
	(*ret)->cname = extract_cname(response, "canonical_name");
	memcpy((*ret)->ipv4, "ipv4:", 5);
	memcpy((*ret)->ipv6, "ipv6:", 5);
	DNSSEC_CHECK_BOGUS();
	char *ipv4_ptr = (*ret)->ipv4 + 5;
	char *ipv6_ptr = (*ret)->ipv6 + 5;
	for ( rec_count = 0; rec_count < num_addresses; ++rec_count )
	{
		getdns_dict * address;
		if(getdns_list_get_dict(just_the_addresses_ptr, rec_count, &address) == GETDNS_RETURN_GOOD)
		{
			getdns_bindata *address_data;
			getdns_dict_get_bindata(address, "address_data", &address_data);
			char *address_str = getdns_display_ip_address(address_data);
			size_t len = strlen(address_str)+1;
			if(address_data->size == 4)
			{
				(*ret)->ipv4_count++;
				snprintf(ipv4_ptr, len+1, "%s,", address_str);
				ipv4_ptr += len;
			}else if(address_data->size ==  16){
				(*ret)->ipv6_count++;
				snprintf(ipv6_ptr, len+1, "%s,", address_str);
				ipv6_ptr += len;
			}	
			free(address_str);			
		}					
	}
	memset(ipv4_ptr-1, 0, 1);
	memset(ipv6_ptr-1, 0, 1);
	return return_code;
}

getdns_return_t parse_nameaddr_bundle(getdns_dict *response, int af_filter,  response_bundle **ret)
{
	uint32_t respstatus;
	getdns_return_t return_code = GETDNS_RETURN_MEMORY_ERROR;
	getdns_list *replies_tree;
	return_code = getdns_dict_get_list(response, "replies_tree", &replies_tree);
	size_t num_replies, num_answers, reply_idx;
	return_code = getdns_list_get_length(replies_tree, &num_replies);
	*ret = malloc(sizeof(response_bundle));
	size_t ipv4_len = 5 + (num_replies *  (1+NI_MAXHOST)), ipv6_len = 6;
	char *ipv4 = malloc(ipv4_len);
	char *ipv6 = malloc(ipv6_len);
	if(!(*ret) || !ipv4 || !ipv6)
	{
		err_log("parse_nameaddr_bundle< Malloc failed. >");
		return GETDNS_RETURN_MEMORY_ERROR;
	}
	return_code = getdns_dict_get_int(response, "status", &respstatus);
	if (return_code != GETDNS_RETURN_GOOD) 
	{
		free(*ret);
		*ret = NULL;
		err_log("Error: %d", return_code);
		return return_code;
	}
	memset(ipv4, 0, ipv4_len);
	memset(ipv6, 0, ipv6_len);
	(*ret)->respstatus = respstatus;
	(*ret)->dnssec_status = getdnssec_status(response);
	(*ret)->ipv4_count = 0;
	(*ret)->ipv6_count = 0;
	(*ret)->ipv4 = ipv4;
	(*ret)->ipv6 = ipv6;
	(*ret)->ttl = 0;
	(*ret)->cname = extract_cname(response, "canonical_name");
	DNSSEC_CHECK_BOGUS();
	memcpy((*ret)->ipv4, "ipv4:", 5);
	memcpy((*ret)->ipv6, "ipv6:", 5);
	char *dname_ptr = (*ret)->ipv4 + 5;

	for ( reply_idx = 0; reply_idx < num_replies; ++reply_idx )
	{
		getdns_dict *reply;
		ASSERT_OR_RETURN(getdns_list_get_dict(replies_tree, reply_idx, &reply));
		getdns_list *answers;
		ASSERT_OR_RETURN(getdns_dict_get_list(reply, "answer", &answers));
		ASSERT_OR_RETURN(getdns_list_get_length(answers, &num_answers));
		if(num_answers > 0)
		{
			getdns_dict *rr;
			ASSERT_OR_RETURN(getdns_list_get_dict(answers, 0, &rr));
			uint32_t rr_type;
			ASSERT_OR_RETURN(getdns_dict_get_int(rr, "type", &rr_type));
			if(rr_type == GETDNS_RRTYPE_PTR)
			{
				getdns_dict *data;
				ASSERT_OR_RETURN(getdns_dict_get_dict(rr, "rdata", &data));
				(*ret)->cname = extract_cname(data, "ptrdname");
				getdns_bindata *dname;
				ASSERT_OR_RETURN(getdns_dict_get_bindata(data, "rdata_raw", &dname));
				char *dname_str;
				ASSERT_OR_RETURN(getdns_convert_dns_name_to_fqdn(dname, &dname_str));
				size_t len = strlen(dname_str)+1;
				(*ret)->ipv4_count++;
				snprintf(dname_ptr, len+1, "%s,", dname_str);
				dname_ptr += len;
				free(dname_str);
			}
		}
	}
	memset(dname_ptr-1, 0, 1);
	return return_code;
	clean_and_return:
		free(ipv4);
		free(ipv6);
		free(*ret);
		return return_code;
}

getdns_return_t parse_addr_bundle(getdns_dict *response, response_bundle **ret, int reverse, int af)
{
	if(reverse)
	{
		return parse_nameaddr_bundle(response, af, ret);
	}else{
		return parse_ipaddr_bundle(response, af, ret);
	}
}