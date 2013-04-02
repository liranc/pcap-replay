
#include "networkutils.h"

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>

int init_socket(const char * interface_name, int *sockfd, struct sockaddr_ll *addr) {

	*sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(*sockfd == -1) {
		perror("failed to create raw socket");
		return 0;
	}

	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(if_idx));
	strcpy(if_idx.ifr_name, interface_name);
	if (ioctl(*sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return 0;
	}

	struct ifreq if_mac;
	memset(&if_mac, 0, sizeof(struct ifreq));
	strcpy(if_mac.ifr_name, interface_name);
	if (ioctl(*sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		return 0;
	}

	addr->sll_ifindex = if_idx.ifr_ifindex;
	addr->sll_halen = ETH_ALEN;

	return 1;
}

int is_supported_packet(struct ethhdr *packet){

	if(ntohs(packet->h_proto) != ETH_P_IP)
		return 0;

	struct iphdr *ip_hdr = (struct iphdr*)((unsigned char*)packet + sizeof(struct ethhdr));

	if(ip_hdr->protocol != IPPROTO_UDP)
		return 0;

	return 1;
}

int parse_mac_column(char *line, const char *lookup_ip, char *mac_result){

	int column_num = 0;
	char *column;

	column = strtok(line, " ");
	while(column){
		++column_num;

		switch(column_num){
		case 1:
			if(strcmp(lookup_ip, column) != 0)
				return 0;
			break;
		case 3:
			if(strcmp("0x0", column) == 0)
				return 0;
			break;
		case 4:
			strcpy(mac_result, column);
			return 1;
		}

		column = strtok(NULL, " ");
	}

	return 0;
}

int resolve_mac_from_arp_table(const char *lookup_ip, char *mac){
	FILE *arp_file = fopen("/proc/net/arp", "r");
	if(arp_file == NULL){
		perror("failed to open arp table file");
		return 0;
	}

	int found = 0;
	int line_num = 0;
	char line_buff[2000] = {0};
	while(fgets(line_buff, sizeof(line_buff), arp_file) != NULL){
		++line_num;

		if(line_num == 1)
			continue;

		if(parse_mac_column(line_buff, lookup_ip, mac)){
			found = 1;
			break;
		}
	}

	fclose(arp_file);

	return found;
}

int resolve_mac(const char *ip, unsigned char mac[ETH_ALEN]){

	int dummy_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(dummy_sockfd == -1){
		perror("failed to create mac resolving socket");
		return 0;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = 8872;
	inet_aton(ip, &addr.sin_addr);
	if(connect(dummy_sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1){
		perror("failed to connect dummy socket");
		return 0;
	}

	int retcode = 0;
	clock_t start_time = clock();
	do{
		char mac_str[18] = {0};
		if(resolve_mac_from_arp_table(ip, mac_str)){
			printf("resolved MAC: %s for IP: %s\n", mac_str, ip);
			retcode = 1;
			break;
		}
		else{
			printf("MAC address for %s wasn't found in ARP table. Resolving...\n", ip);
			write(dummy_sockfd, NULL, 0);
			sleep(1);
		}
	} while(((clock() - start_time) * 1000 / CLOCKS_PER_SEC) < 10000);

	if(!retcode)
		fprintf(stderr, "failed to resolve MAC address for IP: %s", ip);

	close(dummy_sockfd);
	return retcode;
}
