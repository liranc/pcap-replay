#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "replay.h"

void print_help(){
	printf("Usage: pcap-replay [OPTION]... [INTERFACE] [FILE]\n");
	printf("Replay recorder pcap FILE\n");
	printf("\n");
	printf("  -i\tinterface name\n");
	printf("  -d\toverride destination IP\n");
	printf("  -i\toverride source IP\n");
	printf("  -h\tdisplay this help and exit\n");
}

int parse_cmd_args(int argc, char **argv, struct pcap_replay_args *args){

	int c;
	memset(args, 0, sizeof(*args));

	while ((c = getopt (argc, argv, "i:d:s:h")) != -1){
		switch(c){
		case 'i':
			args->interface_name = optarg;
			break;
		case 'd':
			args->override_dst_ip = optarg;
			break;
		case 's':
			args->override_src_ip = optarg;
			break;
		case 'h':
			print_help();
			return 0;
		}
	}

	int files_count = argc - optind;
	if(files_count != 1){
		if(files_count < 1)
			fprintf(stderr, "input file wasn't specified\n");

		if(files_count > 1)
			fprintf(stderr, "too many input files were specified\n");

		return 0;
	}
	else
		args->file_path = argv[optind];

	if(!args->interface_name){
		fprintf(stderr, "missing interface name\n");
		return 0;
	}

	return 1;
}

void print_args(const struct pcap_replay_args *args){
	printf("input args:\n");
	printf("\tfile path: %s\n", args->file_path);
	printf("\tinterface name: %s\n", args->interface_name);
	if(args->override_src_ip)
		printf("\toverride src ip: %s\n", args->override_src_ip);
	if(args->override_dst_ip)
		printf("\toverride dst ip: %s\n", args->override_dst_ip);
}

int main(int argc, char *argv[]){

	struct pcap_replay_args args;
	if(!parse_cmd_args(argc, argv, &args))
		exit(EXIT_FAILURE);

	print_args(&args);
	printf("\n");

	replay(&args);

	return 0;
}
