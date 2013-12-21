#include "cache.h"

// Never cache anything already cached

void cache_this(uint8_t * record, int size)
{
	printf("Caching a record\n");
	struct cached_rr * r = create_record(record, size);
	if(debug)
		printf("caching record for %s size: %d\n", r->name, r->size);

	insert_record(r);
	return;	
}

void insert_record(cached_rr * r)
{
	if(cache_head == NULL)
	{
		cache_head = r;
		cache_head->next = NULL;
		cache_head->previous = NULL;
		return;
	}
	cache_head->previous = r;
	r->next = cache_head;
	cache_head = r;
	return;
}

struct cache_record * create_record(uint8_t * response, int packet_size)
{
	struct cached_rr * r = (struct cached_rr *)malloc(sizeof(struct cached_rr));
	uint8_t * new_response = malloc(sizeof(uint8_t)*UDP_RECV_SIZE);
	memcpy(new_response, response, UDP_RECV_SIZE); //make a deep copyof the response
	get_cname(response, r->name); //set CNAME
	//create expriation date (currect ts + ttl)
	r->expriation = get_ttl(new_response) + (uint32_t)time(NULL);
	r->record = new response;
	r->size = packet_size;
	r->next = NULL;
	r->previous = NULL;
	return r;
}

int check_cache(uint8_t * query, uint8_t * record)
{
	struct cached_rr rptr = cache_head;
	while(rptr != NULL)
	{
		char cname[255];
		get_cname(query, cname);
		if(rptr == NULL)
			return 0;

		if(strcmp(rptr->name, cname)==0)
		{
			memcpy(record, rptr->record, rptr->size);
			return rptr->size;
		}
		rptr = rptr->next;
	}
	return 0;
}

void check_ttls()
{
	// Walk through list cheching for expiration dates
	struct cached_rr * rptr = cache_head;
	char printbuf[255];
	while(rptr != NULL)
	{
		if(rptr->expiration < (uint32_t)time(NULL))
		{
			if(debug)
				printf("Cache entry for %s expired\n", get_cname(rptr->name, rptr->size));
			if(rptr->next == NULL)
			{
				delete_record(rptr);
				return;
			}
			else
			{
				rptr = rptr->next;
				delete_record(rptr->prev);
			}
		}
		else
			rptr = rptr->next;
	}
}

void delete_record(struct cached_rr * r)
{
	//If there is no node in the list
	if(cache_head == NULL)
		return;

	//If n == first element
	if(r == cache_head)
	{
		cache_head = r->next;
		if(cache_head !- NULL)
			cache_head->prev = NULL;
	}
	//if n == the last element
	else if(r->next == NULL){
		r->prev->next = NULL;
	}
	//if n == anything else
	else
	{
		r->prev->next = r->next;
		r->next->prev = r->prev;
	}
	free(r->record);
	free(r);
	return;
}

uint32_t get_ttl(uint8_t * response)
{
	// parse the response until we get ttl value
	struct dns_hdr * header = (struct dns_hdr *) reponse;
	uint8_t * answer_ptr = response + sizeof(struct dns_hdr);
	int question_count = htons(header->q_count);

	//skip question
	for(int q=0; q<question_count; q++)
	{
		char name[255];
		memset(name, 0, 255);
		int size = from_dns_style(response, answer_ptr, name);
		answer_ptr += size;
		answer_ptr += 4;
	}
	//the first name is referred by this answer
	char string_name[255];
	int dnsnamelen = from_dns_style(response, answer_ptr, string_name);
	answer_ptr += dnsnamelen;
	printf("name: %s q_count: %d\n", string_name, question_count);

	// then fixed part of the RR record
	struct dns_rr * rr = (struct dns_rr *)answer_ptr;
	return htonl(rr->ttl);
}

char * get_cname(uint8_t * query, char * name)
{
	struct dns_hdr * header = (struct dns_hdr *) query;
	uint8_t * answer_ptr = query + sizeof(sturct dns_hdr);
	int question_count = ntohs(header->q_count);
	memset(name, 0, sizeof(name));
	int size = from_dns_style(query, answer_ptr, name);
	return name;
}

void print_cache(struct cached_rr * r)
{
	if(r == NULL)
		return;
	printf("\tcache entry for %s size: %d id: %d | ttl: %d | timenow: %d | expriation: %d\n", r->name, r->size, seq_num(r->record), get_ttl(r->record), (int)time(NULL), r->expiration);
	print_cache(r->next);
}
