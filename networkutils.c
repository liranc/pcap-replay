
#include "networkutils.h"

#include <stdio.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <string.h>

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

int create_socket() {

	int sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(sockfd == -1) {
		perror("failed to create raw socket");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

struct sockaddr_ll init_socket_addr(int sockfd) {
	const char *interface_name = "lo";

	struct ifreq if_idx;
	struct ifreq if_mac;

	memset(&if_idx, 0, sizeof(if_idx));
	strcpy(if_idx.ifr_name, interface_name);

	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(EXIT_FAILURE);
	}

	memset(&if_mac, 0, sizeof(struct ifreq));
	strcpy(if_mac.ifr_name, interface_name);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_ll socket_address;
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;
	return socket_address;
}

int is_supported_packet(struct ethhdr *packet){

	if(ntohs(packet->h_proto) != ETH_P_IP)
		return 0;

	struct iphdr *ip_hdr = (struct iphdr*)((unsigned char*)packet + sizeof(struct ethhdr));

	if(ip_hdr->protocol != IPPROTO_UDP)
		return 0;

	return 1;
}
