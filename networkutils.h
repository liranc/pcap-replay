#ifndef __NETWORKUTILS__
#define __NETWORKUTILS__

#include <stdint.h>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

struct override_fields{
	unsigned char *mac;
	uint32_t *dest_ip;
};

int init_socket(const char * interface_name, int *sockfd, struct sockaddr_ll *addr);
int is_supported_packet(struct ethhdr *packet);
int resolve_mac(const char *ip, unsigned char mac[ETH_ALEN]);
int modify_packet(unsigned char *body, struct override_fields overrides);

#endif
