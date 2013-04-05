#include "parsing.h"

#include <stdlib.h>

int parse_global_header(FILE *file, pcap_hdr_t *dst){
	int success = fread(dst, 1, sizeof(*dst), file) == sizeof(*dst);
	return success;
}

int parse_packet_header(FILE *file, pcaprec_hdr_t *dst){
	int success = fread(dst, 1, sizeof(*dst), file) == sizeof(*dst);
	return success;
}
