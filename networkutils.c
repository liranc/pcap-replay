
#include "networkutils.h"

#include <stdio.h>

#include <net/if.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <string.h>


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
