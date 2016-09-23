/* Test sniff of packet.
*/

#include "snifstat.h"

void usage(const char *);
void reset_counter(int);

/* Global value for alarm signal to reset counter. */
unsigned int counter = 0;

unsigned int dflag = 0;

int main(int argc, char **argv) {
	char ifname[IFNAMSIZ];
	int argch;
	char *filter = NULL;
	char ether_addrs[ETHER_ADDR_LEN];
	uint8_t *mac_addrs = NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *capture = NULL;
	bpf_u_int32 netp, netmask;
	struct bpf_program comp_filter;

	struct itimerval itv, oitv;
	struct itimerval *itvp = &itv;

	unsigned int *counterp = &counter;

	while((argch = getopt(argc, argv, "di:")) != -1) {
		switch(argch) {
			case 'i':
				strncpy(ifname, optarg, IFNAMSIZ);
				break;

			case 'd':
				dflag = 1;
				break;
		}
	}

	/* Exit if no positional filter argument. */
	if(argc - optind < 1) {
		usage(argv[0]);
		exit(1);
	}

	/* Last argument should now be the filter string. */
	filter = argv[optind];

	/* Determine IPv4 network and netmask of device ifname. */
	if(pcap_lookupnet(ifname, &netp, &netmask, errbuf) == -1) {
		fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
		exit(1);
	}

	/* Wrapper for pcap_create and pcap_activate in pcap v1.0. */
	if((capture = pcap_open_live(ifname, 65535, 1, 10, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		exit(1);
	}

	if(pcap_compile(capture, &comp_filter, filter, 0, netmask) != 0) {
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(capture));
		exit(1);
	}

	if(pcap_setfilter(capture, &comp_filter) == -1) {
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(capture));
		exit(1);
	}

	if(signal(SIGALRM, reset_counter) == SIG_ERR) {
		perror("signal: ");
		exit(1);
	}

	if((mac_addrs = get_hw_address(ifname, dflag)) < 0) {
		fprintf(stderr, "get_hw_address: failed to get hw address from %s\n", *ifname);
		exit(1);
	}

	/* TODO: Check if ether_addrs is set. */

	timerclear(&itvp->it_interval);
	itvp->it_value.tv_sec = 1;
	itvp->it_value.tv_usec = 0;
}

void reset_counter(int signal) {
	int *counterp = &counter;
	*counterp = 1;
	return;
}

void usage(const char *appname) {
	printf("Usage: %s -i <interface> <filter>\n", appname);
	printf("\t-i <interface>\t Specify interface to capture from\n");

	return;
}
