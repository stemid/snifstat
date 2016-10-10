/*
 * This file is part of Snifstat.
 *
 * Snifstat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Snifstat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Snifstat.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Snifstat is meant to capture packets on an interface, using a filter
 * defined in cli args, and calculate sizes of the packets captured to
 * produce output similar to the old tool called ifstat. Output will be
 * total packet size for each second.
 *
 * by Stefan Midjich <swehack at gmail dot com>
*/

#include "snifstat.h"

pcap_t *capture = NULL;
uint8_t *mac_address = NULL;
char ifname[IFNAMSIZ];

static uint8_t phys_size;
static double cur_in, cur_out;
static char show_suffix[32] = "Bytes";
static unsigned int sniff_timeout = 1;
static uint8_t traffic_unit = 0;
static uint8_t dflag = 0;
static uint8_t batch_mode = 0;
static unsigned short ws_iter_count = 0;

int main(int argc, char **argv) {
    int argch;
    char *filter = NULL;
    int loop_status;

    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp, netmask;
    struct bpf_program comp_filter;
    int nic_dlt;

    struct itimerval itv, oitv;
    struct itimerval *itvp = &itv;

    while((argch = getopt(argc, argv, "Bkmgdi:t:")) != -1) {
        switch(argch) {
            case 'B':
                batch_mode = 1;
                break;

            case 'k':
                strncpy(show_suffix, "kByte/s", 32);
                traffic_unit = 1;
                break;

            case 'm':
                strncpy(show_suffix, "MByte/s", 32);
                traffic_unit = 2;
                break;

            case 'g':
                strncpy(show_suffix, "GByte/s", 32);
                traffic_unit = 3;
                break;

            case 't':
                sniff_timeout = atoi(optarg);
                break;

            case 'i':
                strncpy(ifname, optarg, IFNAMSIZ);
                break;

            case 'd':
                dflag = 1;
                break;

            default:
                fprintf(stderr, "Incorrect argument provided\n");
                usage();
                exit(1);

        }
    }

    /* Exit if missing positional filter argument. */
    if(argc - optind < 1) {
        usage();
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

    /* Cleanup callback. */
    if(atexit(exit_callback) != 0) {
        perror("atexit: ");
        exit(1);
    }

    /* Signal the end of packet capturing. */
    if(signal(SIGALRM, output_data) == SIG_ERR) {
        perror("signal: failed to capture SIGALRM");
        exit(1);
    }

    /* Capture interrupt signal for neat cleanup. */
    if(signal(SIGINT, cleanup_capture) == SIG_ERR) {
        perror("signal: failed to capture SIGINT");
        exit(1);
    }

    /* Get the NICs HW address to determine flow of packets later. */
    if((mac_address = get_hw_address(ifname, dflag)) == NULL) {
        fprintf(stderr, "get_hw_address: failed to get hw address from %s\n", ifname);
        exit(1);
    }

    nic_dlt = pcap_datalink(capture);

    /* Select a pysical layer segment size. */
    switch(nic_dlt) {
        case DLT_EN10MB: /* Ethernet */
            phys_size = 14;
            break;

        case DLT_IEEE802: /* WiFi */
            phys_size = 22;
            break;

        case DLT_FDDI: /* Fiber interface */
            phys_size = 21;
            break;

        case DLT_LOOP: /* OpenBSD loop device or RAW device */
            phys_size = 12;
            break;

        case DLT_NULL:
            phys_size = 4;

        default:
            phys_size = 0;
            break;
    }

    if(dflag)
        fprintf(stderr, "phys_size: %d, nic_dlt: %d\n", phys_size, nic_dlt);

    /* Clear the timer struct and setup a timeout of sniff_timeout seconds. */
    timerclear(&itvp->it_interval);
    itvp->it_value.tv_sec = sniff_timeout;
    itvp->it_value.tv_usec = 0;

    /* This will cause a SIGALARM to be sent to output current traffic stats. */
    if(setitimer(ITIMER_REAL, itvp, &oitv) < 0) {
        fprintf(stderr, "setitimer: failed setting timer\n");
        exit(1);
    }

    if(batch_mode == 0)
        output_header(ifname);

    /* Main pcap loop that will capture packets in a buffer. */
    loop_status = pcap_loop(capture, -1, capture_callback, NULL);

    exit(0);
}

/* capture_callback is called once for every packet. Counts the amount of 
 * traffic and stores it in two global values, one for each direction the 
 * traffic is going. */
void capture_callback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header *ethernet = (struct ether_header *)packet;
    const struct sniff_ip *ip = NULL;
    uint16_t ip_size;
    uint32_t total_size = 0;

    /* Get IP header by counting past start of packet by size of physical layer
     * segment.*/
    ip = (struct sniff_ip*)(packet+phys_size);
    ip_size = IP_HL(ip)*4;

    /* These are some recommendations from tcpdump examples to check for
     * malformed IP headers. */
    if(IP_HL(ip) >= 5 && ip_size < IP_HL(ip)*4) {
        fprintf(stderr, "capture_callback: Malformed IP datagram\n");
        return;
    }

    /* This is actually all we need for packet length. */
    total_size = phys_size+ntohs(ip->ip_len);

    /* Check direction of traffic by comparing with current hosts hw address. */
    if(memcmp(mac_address, ethernet->ether_dhost, MAX_ETHER_LEN) == 0) {
        cur_in += total_size;
    }

    if(memcmp(mac_address, ethernet->ether_shost, MAX_ETHER_LEN) == 0) {
        cur_out += total_size;
    }
    return;
}

/* output_data updates stdout with the current traffic amount, as counted
 * by capture_callback. */
void output_data(int signal) {
    struct itimerval itv, oitv;
    struct itimerval *itvp = &itv;
    unsigned short ws_current = get_windowsize();

    /* Clear the timer struct and setup a timeout of sniff_timeout seconds. */
    timerclear(&itvp->it_interval);
    itvp->it_value.tv_sec = sniff_timeout;
    itvp->it_value.tv_usec = 0;

    if(setitimer(ITIMER_REAL, itvp, &oitv) < 0) {
        fprintf(stderr, "setitimer: failed setting timer\n");
        exit(1);
    }

    /* Display header whenever the old one scrolls off edge by three lines. */
    if(ws_iter_count >= ws_current-3) {
        ws_iter_count = 0;
        if(batch_mode == 0)
            output_header(ifname);
    }

    ws_iter_count++;

    /* Output formatted traffic data. */
    fprint_data(cur_in, cur_out);

    /* Reset global traffic values. */
    cur_in = 0.0;
    cur_out = 0.0;

    return;
}

void output_header(char *ifname) {
    fprintf(stdout, "%11s [%02X:%02X:%02X:%02X:%02X:%02X]\n%5s in %5s out\n", 
            ifname,
            mac_address[0], mac_address[1], mac_address[2], 
            mac_address[3], mac_address[4], mac_address[5],
            show_suffix, show_suffix);

    fflush(stdout);
    return;
}

void fprint_data(double in, double out) {
    switch(traffic_unit) {
        case 1:
            in /= 1000;
            out /= 1000;
            break;
        case 2:
            in /= 1000000;
            out /= 1000000;
            break;
        case 3:
            in /= 1000000000;
            out /= 1000000000;
            break;
        default:
            in /= 1;
            out /= 1;
            break;
    }

    if(batch_mode == 0) {
        fprintf(stdout, "%8.2lf %9.2lf\n", in, out);
    } else {
        fprintf(stdout, "%s;%lf,%lf\n", ifname, in, out);
    }

    fflush(stdout);
    return;
}

void exit_callback(void) {
    cleanup_capture(0);
    return;
}

void cleanup_capture(int signal) {
    if(capture != NULL) {
        pcap_breakloop(capture);
        pcap_close(capture);
        capture = NULL;
    }
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

void usage(void) {
    printf("%s\n\n"
            "Usage: %s [-kmgd] [-t <timeout>] -i <interface> <filter>\n"
            "\t<filter> is a BPF, see pcap-filter(7) for more info.\n"
            "\t-i <interface>\t Specify interface to capture from\n"
            "\t-t <timeout>\t How often to display traffic stats\n"
            "\t-k \t\t Show values in KiloBytes\n"
            "\t-m \t\t Show values in MegaBytes\n"
            "\t-g \t\t Show values in GigaBytes\n"
            "\t-h \t\t Show help\n\n"
            "%s\n"
            "%s\n",
            APP_DESC, APP_NAME, APP_COPYRIGHT, APP_DISCLAIMER);

    return;
}

