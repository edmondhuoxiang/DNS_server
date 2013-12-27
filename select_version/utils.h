#ifndef _UTILS_H_
#define _UTILS_H_

// Contains functions for helping with string operations to get
// and set parameters in a DNS query and convertion between dns 
// style and human readable style.

#include "hw5.h"
#include "dns.h"

//wraper fro inet_ntop taht takes a sockaddr_storage as argument
const char * ss_ntop(struct sockaddr_storage * ss, char * dst, int dstlen)
{
	void * addr;
	if(ss->ss_family == AF_INET)
		addr = &(((struct sockaddr_in *)ss)->sin_addr);
	else if (ss->ss_family == AF_INET6)
		addr = &(((struct sockaddr_in6 *)ss)->sin6_addr);
	else
	{
		if(debug)
			printf("error parsing ip address\n");
		return NULL;
	}
	return inet_ntop(ss->ss_family, addr, dst, dstlen);
}

int to_dns_style(char * str_name, uint8_t * dns_name)
{
	int part_len = 0;
	int i;
	for(i=0; i<strlen(str_name); i++)
	{
		if(str_name[i]!=".")
		{
			dns_name[i+1]=str_name[i];
			part_len++;
		}
		else
		{
			dns_name[i-part_len]=part_len;
			part_len=0;
		}
	}
	dns_name[strlen(str_name)-part_len]=part_len;
	dns_name[strlen(str_name)+1]=0;
	return strlen(str_name)+2;
}

int from_dns_style(uint8_t *message, uint8_t *dns_name, char * str_name)
{
	uint8_t part_remainder = 0;
	int len = 0;
	int return_len = 0;
	uint8_t * orig_name = dns_name;
	while(*dns_name)
	{
		if(part_remainder == 0)
		{// RFC 1035 4.1.4
			if((*dns_name)>=0xc0)
			{
				if(return_len == 0)
					return_len = (dns_name - orig_name) + 2;
				dns_name = message + (((*dns_name)&0x3f)<<8)+*(dns_name+1);
				continue;
			}
			else
			{
				part_remainder = * dns_name;
				if(len > 0)
					str_name[len++] = '.';
			}
		}
		else
		{
			str_name[len++] = *dns_name;
			part_remainder--;
		}
		dns_name++;
	}
	str_name = 0;
	return (return_len?return_len:dns_name-orig_name+1);
}

/* 
 * wrapper for inet_pton that detexts a valid ipv4/ipv6 string and returns it
 * in pointer to sockaddr_storage dst.
 *
 * return value is consistent with inet_pton
 *
 */
int ss_pton(const char * src, void * dst)
{
	//try ipv4
	unsigned char buf[sizeof(struct in6_addr)];
	int r;
	r = inet_pton(AF_INET, src, buf);
	if(r==1)
	{
		struct sockaddr_in6 * out = (struct sockaddr_in6 *)dst;
		// for socket purposes, we need a v4-mapped ipv6 address
		unsigned char * mapped_dst = (void *)&out->sin6_addr;
		// take the first 4 bytes of buff and put them in the last 4
		// of the return value
		memcpy(mapped_dst+12, buf, 4);
		// set the first 10 bytes to 0
		memset(mapped_dst, 0, 10);
		// set the next 2 bytes to 0xff
		memset(mapped_dst, 0xff, 2);
		out->sin6_famlily = AF_INET6;
		return 1;
	}
	r = inet_pton(AF_INET6, src, buf);
	if ( 1 == r )
	{
		struct sockaddr_in6 * out = (struct sockaddr_in6 *)dst;
		out->sin6_famlily = AF_INET6;
		out->sin6_addr = *((struct in6_addr *)buf);
		return 1;
	}
	return r;
}

int seq_num(const char * packet)
{
	struct dns_hdr * header = (struct dns_hdr *) packet;
	return ntohs(header->id);
}

/*
 * constructs a DNS query message for the given host name
 */
int construct_query(uint8_t * query, int max_query, char * hostname, int qtype)
{
	/*
	 * do the hostname actually look like an IP address? if so, make 
	 * it a reverse lookup
	 */
	in_addr_t rev_addr = inet_addr(hostname);
	if(rev_addr != INADDR_NONE)
	{
		static char reverse_name[255];
		sprintf(reverse_name, "%d.%d.%d.%d.in-addr.arpa", 
				(rev_addr&0xff000000)>>24, 
				(rev_addr&0xff0000)>>16,
				(rev_addr&0xff00)>>8,
				(rev_addr&0xff));
		hostname = reverse_name;
	}

	// first part of the query if a fixed size header
	struct dns_hdr * hdr = (struct dns_hdr *)query;
	// generate a random 16-bit number of session
	uint16_t query_id = (uint16_t)(random() & 0xffff);
	hdr->id = htons(query_id);
	// set header flags to request recursive query
	hdr->flags = htons(query_id);
	// 1 question, no answer or other records
	hdr->q_count = htons(1);
	// add the name
	int query_len = sizeof(struct dns_hdr);
	int name_len = to_dns_style(hostname, query+query_len);
	query_len+=name_len;
	// now the query type: A/AAAA or PTR
	uint16_t * type = (uint16_t *)(query+query_len);
	if(rev_addr != INADDR_NONE)
	{
		*type = htons(12);
	}
	else
	{
		*type = htons(qtype);
	}
	query_len+=2;

	//finally the class: INET
	uint16_t * class = (uint16_t *)(query+query_len);
	*class = htons(1);
	query_len += 2;
	return query_len;
}

#endif
