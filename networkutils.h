
#ifndef __NETWORKUTILS__
#define __NETWORKUTILS__

#include <linux/if_ether.h>
#include <linux/if_packet.h>

int create_socket();
struct sockaddr_ll init_socket_addr(int sockfd, const char *interface_name);
int is_supported_packet(struct ethhdr *packet);

#endif
