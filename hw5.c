#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns.h"

typedef struct addrinfo saddrinfo;
typedef struct sockaddr_storage sss;
sss name_server;
static int debug=0;

void usage() {
	printf("Usage: hw5 [-d] [-p port]\n\t-d: debug\n\t-p: port\n");
	exit(1);
}

// wrapper for inet_ntop that takes a sockaddr_storage as argument
const char * ss_ntop(struct sockaddr_storage * ss, char * dst, int dstlen)
{		  
	void * addr;
	if (ss->ss_family == AF_INET)
		addr = &(((struct sockaddr_in*)ss)->sin_addr);
	else if (ss->ss_family == AF_INET6)
		addr = &(((struct sockaddr_in6*)ss)->sin6_addr);
	else
	{
		if (debug)
			printf("error parsing ip address\n");
		return NULL;
	}
	return inet_ntop(ss->ss_family, addr, dst, dstlen);
}

/*
 * wrapper for inet_pton that detects a valid ipv4/ipv6 string and returns it in pointer to
 * sockaddr_storage dst
 *
 * return value is consistent with inet_pton
 */
int ss_pton(const char * src, void * dst){
	// try ipv4
	unsigned char buf[sizeof(struct in6_addr)];
	int r;
	r = inet_pton(AF_INET,src,buf);
	if (r == 1){
		char printbuf[INET6_ADDRSTRLEN];
		struct sockaddr_in6 * out = (struct sockaddr_in6*)dst;
		// for socket purposes, we need a v4-mapped ipv6 address
		unsigned char * mapped_dst = (void*)&out->sin6_addr;
		// take the first 4 bytes of buf and put them in the last 4
		// of the return value
		memcpy(mapped_dst+12,buf,4);
		// set the first 10 bytes to 0
		memset(mapped_dst,0,10);
		// set the next 2 bytes to 0xff
		memset(mapped_dst+10,0xff,2);
		out->sin6_family = AF_INET6;
		return 1;
	}
	r = inet_pton(AF_INET6,src,buf);
	if (r == 1){
		struct sockaddr_in6 * out = (struct sockaddr_in6*)dst;
		out->sin6_family = AF_INET6;
		out->sin6_addr = *((struct in6_addr*)buf);
		return 1;
	}
	return r;
}


void read_server_file() {
	char addr[25];

	FILE *f = fopen("name-server.txt","r");
	fscanf(f," %s ",addr);
	ss_pton(addr,&name_server);
}

char * get_hostname_from_query(char * dns_packet, int packet_size){
	char * domain_name_pointer = NULL;
	char * domain_name = NULL;
	char * tmp_ptr = NULL;
	int dns_header_len = sizeof(struct dns_hdr);
	int name_part_len = 0;
	int dn_len = 0;

	if(packet_size > dns_header_len){
		domain_name_pointer = (dns_packet + dns_header_len);

		do{
			/* Get the length of the next part of the domain name */
			name_part_len = (int) domain_name_pointer[0];

			/* If the length is zero or invalid, then stop processing the domain name */
			if((name_part_len <= 0) || (name_part_len > (packet_size-dns_header_len))){
				break;
			}
			domain_name_pointer++;

			tmp_ptr = domain_name;
			domain_name = realloc(domain_name, (dn_len+name_part_len+PERIOD_SIZE+1));
			if(domain_name == NULL){
				if(tmp_ptr) free(tmp_ptr);
				perror("Realloc Failure");
				return NULL;
			}
			memset(domain_name+dn_len,0,name_part_len+PERIOD_SIZE+1);
			strncat(domain_name,domain_name_pointer,name_part_len);
			strncat(domain_name, PERIOD, PERIOD_SIZE);
			
			dn_len += name_part_len+PERIOD_SIZE+1;
			domain_name_pointer += name_part_len;
		}while(name_part_len > 0);
	}
	return domain_name;
}

char * receive(int lsock, int sock_type, int * rx_bytes, struct sockaddr_in6 * clientaddr){
	int recv_size=0;
	int clen=0, header_offset=0;
	int addrlen=sizeof(struct sockaddr_in6);
	char *buffer=NULL, *tmp_ptr=NULL, *data_ptr=NULL;
	char *clen_ptr=NULL, *line_end_ptr=NULL;

	if(sock_type == SOCK_DGRAM){
		if((buffer = malloc(UDP_RECV_SIZE+1))==NULL){
			perror("Malloc failed");
			return NULL;
		}

		if((*rx_bytes = recvfrom(lsock, buffer, UDP_RECV_SIZE, 0, (struct sockaddr *)clientaddr, (socklen_t *)&addrlen))<0){
			perror("RECVFROM Failed");
			return NULL;
		}
	}

	return buffer;
}


int main(int argc, char ** argv){
	int sockfd;
	struct sockaddr_in6 server_address;
	struct sockaddr_in6 client_address;
	int port_num=53;
	int packet_size=0;
	char * dns_packet=NULL;
	char * question_domain=NULL;
	struct dns_hdr * header=NULL;
	char client_ip[INET6_ADDRSTRLEN];

	char *optString = "dp";
	int opt = getopt(argc, argv, optString);
	while( opt != -1){
		switch(opt) {
			case 'd':
				debug = 1;
				printf("Debug mode\n");
				break;
			case 'p':
				port_num=atoi(argv[optind]);
				break;
			case '?':
				usage();
				break;
		}
		opt = getopt(argc, argv, optString);
	}

	read_server_file();

	//Create socket as DNS Server
	printf("Creating socket on port: %d\n", port_num);
	sockfd=socket(AF_INET6, SOCK_DGRAM, 0);
	if(sockfd<0){
		perror("Unable to screate socket");
		return -1;
	}

	memset(&server_address, 0, sizeof(server_address));
	server_address.sin6_family=AF_INET6;
	server_address.sin6_addr = in6addr_any;
	server_address.sin6_port=htons(port_num);
	if(bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address))<0){
		perror("Uable to bind");
		return -1;
	}
	printf("Bind successful\n");
	
	while(1){
		if(dns_packet) 
			free(dns_packet);
		dns_packet=NULL;
		printf("Waiting for query...\n");
		if((dns_packet=receive(sockfd, SOCK_DGRAM, &packet_size, &client_address))==NULL){
			perror("Receive Failed");
			return EXIT_FAILURE;
		}
		
		if(packet_size<(int)(sizeof(struct dns_hdr)+sizeof(struct dns_query_section))){
			perror("Receive invalid DNS request");
			continue;
		}

		header = (struct dns_hdr *)dns_packet;

		//Get Domain from query
		question_domain=get_hostname_from_query(dns_packet, packet_size);
		if(question_domain[strlen(question_domain)-1] == '.')
			question_domain[strlen(question_domain)-1] = '\0';


		printf("Receive query for %s\n", question_domain);

		//create sock to authoritative server
		int sock_client = socket(AF_INET6, SOCK_DGRAM, 0);
		if(sock_client<0){
			perror("Creating socket failed: ");
			exit(1);
		}

		if(name_server.ss_family == AF_INET)
			((struct sockaddr_in*)&name_server)->sin_port = htons(53);
		else if(name_server.ss_family == AF_INET6)
			((struct sockaddr_in6*)&name_server)->sin6_port = htons(53);
		else{
			printf("ss_family not set\n");
			exit(1);
		}

		//Send query to authoritative server
		int send_count = sendto(sock_client, dns_packet, packet_size, 0, (struct sockaddr*)&name_server, sizeof(struct sockaddr_in6));
		if(send_count<0){
			perror("Send failed");
			exit(1);
		}

		//await the response
		if(dns_packet) 
			free(dns_packet);
		if((dns_packet=receive(sock_client, SOCK_DGRAM, &packet_size, &server_address))==NULL){
			perror("Receive Failed");
			return EXIT_FAILURE;
		}

		close(sock_client);

		//send the response to client
		send_count = sendto(sockfd, dns_packet, packet_size, 0, (struct sockaddr*)&client_address, sizeof(struct sockaddr_in6));
	}

	return 0;
}


