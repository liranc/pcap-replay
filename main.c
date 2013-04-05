
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "replay.h"

int parse_cmd_args(int argc, char **argv, struct pcap_replay_args *args){

	memset(args, 0, sizeof(*args));

	int c;
	while ((c = getopt (argc, argv, "i:f:d:")) != -1){
		switch(c){
		case 'i':
			args->interface_name = optarg;
			break;
		case 'f':
			args->file_path = optarg;
			break;
		case 'd':
			args->override_dest_ip = optarg;
			break;
		}
	}

	if(!args->file_path) {
		fprintf(stderr, "missing file path\n");
		return 0;
	}

	if(!args->interface_name){
		fprintf(stderr, "missing interface name\n");
		return 0;
	}

	return 1;
}

int main(int argc, char *argv[]){

	struct pcap_replay_args args;
	if(!parse_cmd_args(argc, argv, &args))
		exit(EXIT_FAILURE);

	replay(&args);

	return 0;
}
