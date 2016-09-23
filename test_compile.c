/* Testcase for snifstat.c

by Stefan Midjich
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* getopt(3) */
#include <unistd.h>

/* duh -lpcap */
#include <pcap.h>

void usage(const char *);

int main(int argc, char **argv) {
  int argch;
  char *ifname = NULL;
  bpf_u_int32 netp, netmask;
  char *filter = NULL;
  pcap_t *pcap_handle = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filterd;

  while((argch = getopt(argc, argv, "i:f:")) != -1) {
    switch(argch) {
      case 'i':
      if(strlen(optarg) < 16) {
        ifname = optarg;
        optreset = 1;
      } else {
        usage(argv[0]);
        exit(1);
      }
      break;

      case 'f':
      filter = optarg;
      optreset = 1;
      break;
    }
  }

  /* Exit if no filter provided. */
  /*if(argc - optind < 1) {
    usage(argv[0]);
    exit(1);
  }*/

  /*filter = argv[optind];*/

  if(pcap_lookupnet(ifname, &netp, &netmask, errbuf) != 0) {
    fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
    exit(1);
  }

  /* Wrapper for pcap_create and pcap_activate in pcap v1.0. */
  if((pcap_handle = pcap_open_live(ifname, 65535, 1, 100, errbuf)) == NULL) {
    fprintf(stderr, "pcap_open_live: %s\n", errbuf);
    exit(1);
  }

  if(pcap_compile(pcap_handle, &filterd, filter, 0, netmask) != 0) {
    fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pcap_handle));
    exit(1);
  }

  exit(0);
}

void usage(const char *appname) {
  printf("Usage: %s -i <interface> <filter>\n", appname);
  printf("\t-i <interface>\t Specify interface to capture from\n");

  return;
}
