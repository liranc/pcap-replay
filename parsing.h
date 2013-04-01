
#ifndef __PARSING__
#define __PARSING__

#include <stdio.h>
#include "pcaptypes.h"

int parse_global_header(FILE *file, pcap_hdr_t *dst);
int parse_packet_header(FILE *file, pcaprec_hdr_t *dst);

#endif
