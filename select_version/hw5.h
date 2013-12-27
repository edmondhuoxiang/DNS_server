#ifndef _HW5_H_
#define _HW%_H_

#include <stdlib.h>
#include <stdint.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define RECTYPE_A 1
#define RECTYPE_NS 2
#define RECTYPE_CNAME 5
#define RECTYPE_SOA 6
#define RECTYPE_PTR 12
#define RECTYPE_AAAA 28

#define IPV4_ADDR_LEN		0x0004
#define DNS_REPLY_FLAGS		0x8180
#define DNS_REPLY_REFUSED	0x8183
#define DNS_REPLY_NAME		0xC00C
#define DNS_REPLY_TTL		0x0005
#define DNS_CLASS_IN		0x0001
#define DNS_TYPE_A			0x0001
#define DNS_TYPE_NS			0x0002
#define DNS_NUM_ANSWERS		0x0002
#define UDP_RECV_SIZE		1500
#define PERIOD_SIEZ			1
#define PERIOD "."
#define CLIENT	1
#define RECURSIVE
#define HELPER

int sockfd; //GLobel defined socket desciptor, needed in  multiple files. 

typedef struct addrinfo saddrinfo;
typedef struct sockaddr_storage sss;
int root_server_count;
sss root_servers[255];
static int debug=0;
static int debug=0;
socklen_t addrlen = sizeof(struct sockaddr_in6);

void usage() {
	printf("Usage: hw5 [-d] [-p port]\n\t-d: debug\n\t-p: port\n");
	exit(1);
}

struct NODE{
	int type;	// helper/recursive/client
	struct NODE * next;
	struct NODE * prev;
	uint8_t * query;
	int query_size;
	struct NODE * dependent;	//This is the request taht depends on this request to get an answer
	int timestamp;
	int retries;
	struct sockaddr_storage * nameservers; //array of nameserver;
	int ns_count;
	int ns_to_resolve;
	struct sockaddr_int6 client_address; //Client to send data back to 
}

//Dns header structure
struct dns_hdr {
	uint16_t id;
	uint16_t flags;
	uint16_t q_count;		//number of questions
	uint16_t a_count;		//number of answer sections
	uint16_t auth_count;	//number of authoritative sections
	uint16_t other_count;	//number of other resource sections
} __attribute__((packed));

struct dns_query_section {
	uint16_t type;
	uint16_t class;
} __attribute__((packed));

struct dns_rr {
	//first a variable sized name, then
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t datalen;
} __attribute__((packed));

struct dns_answer_section
{
	uint16_t name;
	uint16_t type;
	uint16_t class;
	uint16_t ttl_top;
	uint16_t ttl;
	uint16_t data_len;
};

#endif
