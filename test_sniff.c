/* Test sniff of packet.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* getifaddrs(3) */
#include <sys/types.h>
#include <ifaddrs.h>

/* timerclear(3) */
#include <sys/time.h>

#include <signal.h>

/* duh -lpcap */
#include <pcap.h>

void usage(const char *);
void reset_counter(int);

/* Global value for alarm signal to reset counter. */
unsigned int counter = 0;

int main(int argc, char **argv) {
  char *ifname = NULL;
  int argch;
  char *filter = NULL;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *capture = NULL;
  bpf_u_int32 netp, netmask;
  struct bpf_program comp_filter;

  unsigned char *ether_addrs = NULL;
  struct ifaddrs *ifa = NULL;
  struct sockaddr_dl *sdl = NULL;

  struct itimerval itv, oitv;
  struct itimerval *itvp = &itv;

  unsigned int *counterp = &counter;

  while((argch = getopt(argc, argv, "i:")) != -1) {
    switch(argch) {
      case 'i':
      if(strlen(optarg) < 16) {
        ifname = optarg;
      } else {
        usage(argv[0]);
        exit(1);
      }
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

  if(getifaddrs(&ifa) == -1) {
    perror("getifaddrs: ");
    exit(1);
  }

  /* TODO: Get ethernet address of ifname, port code to Linux. */
  for(;ifa;ifa = ifa->ifa_next) {
    if(strncmp(ifname, ifa->ifa_name, sizeof(ifa->ifa_name)) == 0) {
      sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      if((ether_addrs = malloc(sdl->sdl_alen)) == NULL) {
        perror("malloc: ");
        exit(1);
      }
      memcpy(ether_addrs, LLADDR(sdl), sdl->sdl_alen);
      break;
    }
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
