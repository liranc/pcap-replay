#ifndef __REPLAY__
#define __REPLAY__

struct pcap_replay_args{
	char *override_dest_ip;
	char *interface_name;
	char *file_path;
};

void replay(const struct pcap_replay_args *args);

#endif
