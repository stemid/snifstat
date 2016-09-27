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
char show_suffix[255] = "Bytes";
unsigned int traffic_unit = 0;
unsigned short ws_iter_count = 0;
char ifname[IFNAMSIZ];
unsigned int sniff_timeout = 1;

int main(int argc, char **argv) {
  unsigned int dflag = 0;
  int argch;
  char *filter = NULL;
  int loop_status;

  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp, netmask;
  struct bpf_program comp_filter;

  struct itimerval itv, oitv;
  struct itimerval *itvp = &itv;

  while((argch = getopt(argc, argv, "kmgdi:t:")) != -1) {
    switch(argch) {
      case 'k':
        strncpy(show_suffix, "kByte/s", 255);
        traffic_unit = 1;
        break;

      case 'm':
        strncpy(show_suffix, "MByte/s", 255);
        traffic_unit = 2;
        break;

      case 'g':
        strncpy(show_suffix, "GByte/s", 255);
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

  if((mac_address = get_hw_address(ifname, dflag)) == NULL) {
    fprintf(stderr, "get_hw_address: failed to get hw address from %s\n", ifname);
    exit(1);
  }

  if(dflag) {
    fprintf(stderr, "Found NIC %s:MAC[%02X:%02X:%02X:%02X:%02X:%02X]\n",
        ifname,
        mac_address[0], mac_address[1], mac_address[2], 
        mac_address[3], mac_address[4], mac_address[5]);
  }

  /* Clear the timer struct and setup a timeout of sniff_timeout seconds. */
  timerclear(&itvp->it_interval);
  itvp->it_value.tv_sec = sniff_timeout;
  itvp->it_value.tv_usec = 0;

  if(setitimer(ITIMER_REAL, itvp, &oitv) < 0) {
    fprintf(stderr, "setitimer: failed setting timer\n");
    exit(1);
  }

  output_header(ifname);

  loop_status = pcap_loop(capture, -1, capture_callback, NULL);

  exit(0);
}

/* capture_callback counts the amount of traffic and stores it in two global
 * values, one for each direction the traffic is going.
 * TODO: Maybe check so that header.len isn't larger than a double. */
void capture_callback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet) {
  struct ether_header *ethernet = (struct ether_header *)packet;
  const struct sniff_ip *ip = NULL;
  const struct sniff_tcp *tcp = NULL;
  const struct sniff_udp *udp = NULL;
  const struct ip *ip_header = NULL;
  const char *payload = NULL;
  int ip_size;
  int tcp_size;
  int udp_size = 0;
  int payload_size;
  double total_size;
  unsigned int ip_header_len;

  /* Debug
     fprintf(stderr, "cmp(%d): mac_address[%02X:%02X:%02X:%02X:%02X:%02X](%lu)"
     "=> ether_dhost[%02X:%02X:%02X:%02X:%02X:%02X](%lu)\n", 
     MAX_ADDR_LEN, 
     mac_address[0], mac_address[1], mac_address[2], 
     mac_address[3], mac_address[4], mac_address[5], sizeof(mac_address),
     ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], 
     ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5], 
     sizeof(ethernet->ether_dhost));
     */


  /* Get the length of packet */
  ip = (struct sniff_ip*)(packet+SIZE_ETHERNET);
  ip_size = IP_HL(ip)*4;

  if(IP_HL(ip) >= 5 && ip_size < IP_HL(ip)*4) {
    fprintf(stderr, "capture_callback: Malformed IP datagram\n");
    return;
  }

  tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+ip_size);
  tcp_size = TH_OFF(tcp)*4;

  if(tcp_size < TH_OFF(tcp)*4) {
    fprintf(stderr, "capture_callback: Malformed TCP segment\n");
    return;
  }

  ip_header = (struct ip*)(packet+SIZE_ETHERNET);
  ip_header_len = IP_HL(ip)*4;

  /* Check for UDP packet. 
   * TODO: Finish UDP support. */
  if(ip_header->ip_p == IPPROTO_UDP) {
    udp = (struct sniff_udp*)((u_char*)ip+ip_header_len);
    udp_size = ntohs(udp->uh_ulen);
    /*fprintf(stderr, "sport: %d, dport: %d, udp_size: %f\n", 
      ntohs(udp->uh_sport), ntohs(udp->uh_dport), udp_size);*/

    payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + udp_size);
    payload_size = ntohs(ip->ip_len) - (ip_size + udp_size);
  } else {
    payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + tcp_size);
    payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);
  }

  total_size = payload_size+tcp_size+ip_size+udp_size;

  /*fprintf(stderr, "total_size: %f\n", total_size);*/

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
  /*(show_in_bits == 1) ? bits_suffix : bytes_suffix, 
    (show_in_bits == 1) ? bits_suffix : bytes_suffix);*/

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
  }

  fprintf(stdout, "%8.2lf %9.2lf\n", in, out);
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

