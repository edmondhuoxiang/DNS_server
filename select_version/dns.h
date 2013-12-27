#ifndef _DNS_H_
#define _DNS_H_

#include "hw5.h"

// Main work function. Takes a DNS request and resolves it recursively starting with the root name servers.
int resolve_name(int sock,					//UDP sock to communicate DNS
				uint8_t * request,			//Request DNS query (from dig for example)
				int packet_size,			//Size of request
				uint8_t * response,			//store the response with answer section
				struct sockaddr_storage * nameservers, //The current level of name servers to query
				int nameserver_count);		//The numberof nameservers

// returns: true if answer is found, otherwise not
// side effect: While answer is found, populate result with ip address.
int extract_answer(uint8_t * response, sss * result);

// Reads from server file and fill root_servers[]
void read_server_file();

// This function should be called while receiving a response from a NS and  then being used to 
// advance the state of the sending query_node' dependent node. 
// The response should be parsed for answers and passed up along  the dependancy path until the client 
// request node is found where upon it should be sent to that client
void advance_state(struct NODE * state, uint8_t * response, int packet_size);

//This function sends the next request to a random NS from 'state's nameserver list. It creates a new 
//state if 'state' is a CLIENT type (creates a RECURSIVE state to satisfy the CLIENT). Or it sends the
//next request in the recursion name resolving if the state is of type RECURSIVE of HELPER
void send_next_request(struct NODE * dependent);

//This function appends aa nameserver ip to the nameserver list of state. The use case is for when a HELPER
//state receives a response (ns ip), it's dependent (a RECURSIVE state) must have the nameserver ip address
//for it's nameserver list
int append_ns_ip(struct NODE * state, uint8_t * response);

#endif
