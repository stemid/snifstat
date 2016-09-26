
/* Snifstat is meant to capture packets on an interface, using a filter
 * defined in cli args, and calculate sizes of the packets captured to
 * produce output similar to the old tool called ifstat. Output will be
 * total packet size for each second.
 *
 * by Stefan Midjich <swehack at gmail dot com>
*/

#include "snifstat.h"

pcap_t *capture = NULL;
double cur_in, cur_out;
uint8_t *mac_address = NULL;

int main(int argc, char **argv) {
	char ifname[IFNAMSIZ];
	unsigned int sniff_timeout = 1;
	unsigned int dflag = 0;
	int argch;
	char *filter = NULL;
	uint8_t *local_mac = NULL;
	int loop_status;

	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp, netmask;
	struct bpf_program comp_filter;

	/*
	struct pcap_pkthdr header;
  const u_char *packet = NULL;*/

	struct itimerval itv, oitv;
	struct itimerval *itvp = &itv;

	unsigned short ws_current, ws_iter_count = 0;

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
	if(signal(SIGALRM, break_capture) == SIG_ERR) {
		perror("signal: failed to capture SIGALRM");
		exit(1);
	}

	/* Capture interrupt signal for neat cleanup. */
	if(signal(SIGINT, cleanup_capture) == SIG_ERR) {
		perror("signal: failed to capture SIGINT");
		exit(1);
	}

	if((local_mac = get_hw_address(ifname, dflag)) == NULL) {
		fprintf(stderr, "get_hw_address: failed to get hw address from %s\n", ifname);
		exit(1);
	}

	mac_address = local_mac;

	if(dflag) {
		fprintf(stderr, "Found NIC %s:MAC[%02X:%02X:%02X:%02X:%02X:%02X]\n",
				ifname,
				local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
	}

	/* Clear the timer struct and setup a timeout of sniff_timeout seconds. */
	timerclear(&itvp->it_interval);
	itvp->it_value.tv_sec = sniff_timeout;
	itvp->it_value.tv_usec = 0;

	if(setitimer(ITIMER_REAL, itvp, &oitv) < 0) {
		fprintf(stderr, "setitimer: failed setting timer\n");
		exit(1);
	}

	while((loop_status = pcap_loop(capture, -1, capture_callback, NULL)) < 0) {
		/* Reset timer. */
    if(setitimer(ITIMER_REAL, itvp, &oitv) < 0) {
      fprintf(stderr, "setitimer: \n");
      exit(1);
    }

		ws_current = get_windowsize();

		/* Display header whenever the old one scrolls off edge by three lines. */
		if(ws_iter_count >= ws_current-3 || ws_iter_count == 0) {
			ws_iter_count = 0;
			output_header(ifname);
		}

		ws_iter_count++;

		/* Output formatted traffic data. */
		output_data(cur_in, cur_out);

		/* Reset global traffic values. */
		cur_in = 0.0;
		cur_out = 0.0;
	}

	pcap_close(capture);
	exit(0);
}

/* TODO: Maybe check so that header.len isn't larger than a double. */
void capture_callback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet) {
	struct ether_header *ethernet = (struct ether_header *)packet;

	/*fprintf(stderr, "cmp(%d): mac_address[%02X:%02X:%02X:%02X:%02X:%02X](%lu) => ether_dhost[%02X:%02X:%02X:%02X:%02X:%02X](%lu)\n", 
			MAX_ADDR_LEN, mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5], sizeof(mac_address),
			ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5], sizeof(ethernet->ether_dhost));
			*/

	/* Check direction of traffic by comparing with current hosts hw address. */
	if(memcmp(mac_address, ethernet->ether_dhost, 6) == 0) {
		cur_in += header->len;
	}

	if(memcmp(mac_address, ethernet->ether_shost, 6) == 0) {
		cur_out += header->len;
	}
	return;
}

/* Compare two uint8_t arrays. */
int hwaddrscmp(uint8_t *a1, uint8_t *a2) {
	do {
		if(*a1++ != *a2++) {
			fprintf(stderr, "cmp a1[%02X] => a2[%02X]\n", *a1, *a2);
			return(*(uint8_t*)a1-*(uint8_t*)(a2-1));
		}
	} while(a1 != NULL || a2 != NULL);

	fprintf(stderr, "End of comparison\n");

	return(0);
}

void output_header(char *ifname) {
	int show_in_bits = 1;
	char bits_suffix[] = "Kbps";
	char bytes_suffix[] = "kB/s";

	fprintf(stdout, "%11s [%02X:%02X:%02X:%02X:%02X:%02X]\n%5s in %5s out\n", 
			ifname,
			mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5],
			(show_in_bits == 1) ? bits_suffix : bytes_suffix, 
			(show_in_bits == 1) ? bits_suffix : bytes_suffix);
	fflush(stdout);
	return;
}

void output_data(double in, double out) {
	fprintf(stdout, "%8.2lf %9.2lf\n", in, out);
	fflush(stdout);
	return;
}

/* Returns number of rows in window. */
unsigned short get_windowsize(void) {
  struct winsize ws;

  if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0) {
    return(-1);
  }

  return(ws.ws_row);
}

void break_capture(int signal) {
	pcap_breakloop(capture);
	return;
}

void cleanup_capture(int signal) {
	pcap_breakloop(capture);
	pcap_close(capture);
	return;
}

void usage(const char *appname) {
	printf("Usage: %s -i <interface> <filter>\n", appname);
	printf("\t-i <interface>\t Specify interface to capture from\n");

	return;
}
