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

	int sent = 0;
	if(is_supported_packet((struct ethhdr*)body)){

		modify_packet(body, overrides);

		if(sendto(sockfd, body, packet_header->incl_len, 0,
				(struct sockaddr*)socket_address, sizeof(*socket_address)) == -1)
			perror("failed to send packet");
		else
			sent = 1;
	}

	free(body);

	return sent;
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
		fprintf(stderr, "failed to parse global header\n");
		goto cleanup;
	}

	struct sockaddr_ll socket_address;
	if (!init_socket(args->interface_name, &sockfd, &socket_address))
		goto cleanup;

	int packet_count = 0;
	int packet_ignored = 0;

	struct timeval last_time;
	last_time.tv_sec = -1;

	if(args->override_dst_ip){
		overrides.dest_ip = malloc(sizeof(overrides.dest_ip));
		overrides.dest_mac = malloc(sizeof(unsigned char) * ETH_ALEN);

		*overrides.dest_ip = inet_addr(args->override_dst_ip);
		if(!resolve_remote_mac(args->override_dst_ip, overrides.dest_mac)){
			fprintf(stderr, "failed to resolve dst-override mac");
			goto cleanup;
		}
	}

	if(args->override_src_ip){
		overrides.src_ip = malloc(sizeof(overrides.src_ip));
		overrides.src_mac = malloc(sizeof(unsigned char) * ETH_ALEN);

		*overrides.src_ip = inet_addr(args->override_src_ip);
		if(!resolve_local_mac(args->override_src_ip, overrides.src_mac)){
			fprintf(stderr, "failed to resolve src-override mac");
			goto cleanup;
		}
	}

	printf("starting to play file...\n");
	pcaprec_hdr_t packet_header;
	while (parse_packet_header(file, &packet_header)) {
		last_time = wait_until_next(&last_time, &packet_header);
		if (next_packet(&packet_header, file, sockfd, &socket_address, overrides))
			++packet_count;
		else
			++packet_ignored;

		int sum = packet_count + packet_ignored;
		if(sum % 1000 == 0)
			printf("packets statistics (sent: %d, ignored: %d)\n", packet_count, packet_ignored);
	}

	printf("finished playing file (sent: %d, ignored: %d)\n",
			packet_count, packet_ignored);

	cleanup:
	free(overrides.dest_ip);
	free(overrides.dest_mac);
	close(sockfd);
	fclose(file);
}
