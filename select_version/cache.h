#ifdef _CACHE_H_
#define _CACHE_H_
 /*
 	Cache for the DNS server
 */

#define MAXCACHESIZE 1024

struct cached_rr{
	uint8_t * record;			//User malloc to initialize space and store the resource record
	char name[255];				//Name of target domain
	int size;					//size of record
	int expiration;
	struct cached_rr * next;	//next record in cache
	struct cashed_rr * previous;//previous record in cache
};

// The head of list for cached records
struct cached_rr * cache_head = NULL;

// Insert the query from record into cache, and map the first returned answer to the queried domain
void cache_this(uint8_t * record, int size);

// Insert the record node into the list
void insert_record(struct cached_rr * r);

// Delete the record from the list
void delete_record(struct cached_rr * r);

// Malloc space for new node
struct cached_rr * create_record(uint8_t * response, int packet_size);

// Check if the query has been cached, if so it sets 'response' to the correct response to 'query'
// and returns the size of response, Otherwise it would return 0
int check_cache(uint8_t * query, uint8_t * response);

// Invalidates all entries that have expired according to their ttl values
void check_ttls();

// Grab the canonnical name that was queried for from the dns query
char * get_cname(uint8_t * query, char * name);

// Grab the int ttl value from the record
uint32_t get_ttl(uint8_t * record);

// Print out everything in cache
void print_cache(struct cached_rr * head);

#endif
