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


