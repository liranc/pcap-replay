#ifndef __NETWORKUTILS__
#define __NETWORKUTILS__

#include <stdint.h>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

struct override_fields{
	unsigned char *dest_mac;
	uint32_t *dest_ip;

	unsigned char *src_mac;
	uint32_t *src_ip;
};

int init_socket(const char * interface_name, int *sockfd, struct sockaddr_ll *addr);
int is_supported_packet(struct ethhdr *packet);
int resolve_remote_mac(const char *ip, unsigned char mac[ETH_ALEN]);
int resolve_local_mac(const char* ip, unsigned char mac[ETH_ALEN]);
void modify_packet(unsigned char *body, struct override_fields overrides);

#endif
