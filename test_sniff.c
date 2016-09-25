/* Test sniff of packet.
*/

#include "snifstat.h"

void usage(const char *);
void reset_counter(int);

/* Global value for alarm signal to reset counter. 
 * TODO: Rework code to use pcap_loop and pcap_breakloop instead of this. */
unsigned int counter = 0;

int main(int argc, char **argv) {
	char ifname[IFNAMSIZ];
	unsigned int sniff_timeout = 1;
	unsigned int dflag = 0;
	int argch;
	char *filter = NULL;
	uint8_t *mac = NULL;
	unsigned int *resetp = &counter;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *capture = NULL;
	bpf_u_int32 netp, netmask;
	struct bpf_program comp_filter;
	struct pcap_pkthdr header;

  const u_char *packet = NULL;
  struct ether_header *ethernet = NULL;

	struct itimerval itv, oitv;
	struct itimerval *itvp = &itv;

	while((argch = getopt(argc, argv, "di:t:")) != -1) {
		switch(argch) {
			case 't':
				sniff_timeout = atoi(optarg);
				break;

			case 'i':
				strncpy(ifname, optarg, IFNAMSIZ);
				break;

			case 'd':
				dflag = 1;
				break;
		}
	}

	/* Exit if missing positional filter argument. */
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

	/* Wrapper for pcap_create and pcap_activate since pcap v1.0. */
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

	/* Signal the end of packet capturing. */
	if(signal(SIGALRM, reset_counter) == SIG_ERR) {
		perror("signal: ");
		exit(1);
	}

	if((mac = get_hw_address(ifname, dflag)) == NULL) {
		fprintf(stderr, "get_hw_address: failed to get hw address from %s\n", ifname);
		exit(1);
	}

	if(dflag) {
		fprintf(stderr, "%s:MAC[%02X:%02X:%02X:%02X:%02X:%02X]\n",
				ifname,
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	/* Setup a cleared timer struct for signal, with 1 second in tv_sec. */
	timerclear(&itvp->it_interval);
	itvp->it_value.tv_sec = sniff_timeout;
	itvp->it_value.tv_usec = 0;

	if(setitimer(ITIMER_REAL, itvp, &oitv) < 0) {
		fprintf(stderr, "setitimer: failed setting timer\n");
		exit(1);
	}

	if(dflag) {
		fprintf(stderr, "Sniffing for %d second(s) and exiting.\n", sniff_timeout);
	}

	*resetp = 0;

	while(*resetp == 0) {
		if((packet = pcap_next(capture, &header)) != NULL) {
			ethernet = (struct ether_header *)packet;

			if(dflag) {
				fprintf(stderr, "Captured packet header length: %u\n", header.len);
			}
		}
	}

	pcap_close(capture);
	exit(0);
}

void reset_counter(int signal) {
	unsigned int *counterp = &counter;
	*counterp = 1;
	return;
}

void usage(const char *appname) {
	printf("Usage: %s -i <interface> <filter>\n", appname);
	printf("\t-i <interface>\t Specify interface to capture from\n");

	return;
}
