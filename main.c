
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <unistd.h>

#include "timeutils.h"
#include "pcaptypes.h"
#include "networkutils.h"
#include "parsing.h"

int next_packet(pcaprec_hdr_t *packet_header, FILE *file, int sockfd,
		struct sockaddr_ll *socket_address){

	unsigned char *body = (unsigned char*)malloc(packet_header->incl_len);
	fread(body, 1, packet_header->incl_len, file);

	if(!is_supported_packet((struct ethhdr*)body))
		return 0;

	if(sendto(sockfd, body, packet_header->incl_len, 0, (struct sockaddr*)socket_address,
			sizeof(*socket_address)) == -1){
		perror("failed to send packet");
	}

	free(body);

	return 1;
}


int main(int argc, char *argv[]){

	if(argc != 2){
		fprintf(stderr, "Unexpected number of parameters (%d)\n", argc);
		exit(EXIT_FAILURE);
	}

	char *file_path = argv[1];
	FILE *file;

	if((file = fopen(file_path, "rb")) == NULL)	{
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}

	pcap_hdr_t global_header;
	if(!parse_global_header(file, &global_header)){
		fprintf(stderr, "failed to parse global header");
		exit(EXIT_FAILURE);
	}

	printf("global header was read (version major: %u, minor: %u)\n",
			global_header.version_major, global_header.version_minor);

	int sockfd = create_socket();
	struct sockaddr_ll socket_address = init_socket_addr(sockfd);

	int packet_count = 0;
	struct timeval last_time;
	last_time.tv_sec = -1;

	pcaprec_hdr_t packet_header;
	while(parse_packet_header(file, &packet_header))
	{
		last_time = wait_until_next(&last_time, &packet_header);

		if(next_packet(&packet_header, file, sockfd, &socket_address))
			++packet_count;
	}

	close(sockfd);

	printf("sent %d packets\n", packet_count);

	fclose(file);

	return 0;
}
