
#include "replay.h"
#include "pcaptypes.h"
#include "networkutils.h"
#include "parsing.h"
#include "timeutils.h"

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <arpa/inet.h>

int next_packet(pcaprec_hdr_t *packet_header, FILE *file, int sockfd,
		struct sockaddr_ll *socket_address, struct override_fields overrides){

	unsigned char *body = (unsigned char*)malloc(packet_header->incl_len);
	fread(body, 1, packet_header->incl_len, file);

	if(is_supported_packet((struct ethhdr*)body)){

		if(modify_packet(body, overrides)){

			if(sendto(sockfd, body, packet_header->incl_len, 0,
					(struct sockaddr*)socket_address,
					sizeof(*socket_address)) == -1)
				perror("failed to send packet");

		}
	}

	free(body);

	return 1;
}

void replay(const struct pcap_replay_args *args) {

	FILE *file = NULL;
	struct override_fields overrides = {0};
	int sockfd = 0;

	if((file = fopen(args->file_path, "rb")) == NULL)	{
		perror("Failed to open file");
		return;
	}

	pcap_hdr_t global_header;
	if(!parse_global_header(file, &global_header)){
		fprintf(stderr, "failed to parse global header");
		goto cleanup;
	}

	struct sockaddr_ll socket_address;
	if (!init_socket(args->interface_name, &sockfd, &socket_address))
		goto cleanup;

	int packet_count = 0;
	int packet_ignored = 0;

	struct timeval last_time;
	last_time.tv_sec = -1;

	if(args->override_dest_ip){
		overrides.dest_ip = malloc(sizeof(overrides.dest_ip));
		overrides.mac = malloc(sizeof(unsigned char) * ETH_ALEN);

		*overrides.dest_ip = inet_addr(args->override_dest_ip);
		if(!resolve_mac(args->override_dest_ip, overrides.mac))
			goto cleanup;
	}

	pcaprec_hdr_t packet_header;
	while (parse_packet_header(file, &packet_header)) {
		last_time = wait_until_next(&last_time, &packet_header);
		if (next_packet(&packet_header, file, sockfd, &socket_address, overrides))
			++packet_count;
		else
			++packet_ignored;
	}

	printf("sent %d out of %d packets\n", packet_count,
			packet_count + packet_ignored);

	cleanup:
	free(overrides.dest_ip);
	free(overrides.mac);
	close(sockfd);
	fclose(file);
}
