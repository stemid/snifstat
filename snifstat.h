#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <signal.h>

/* getifaddrs(3) */
#include <ifaddrs.h>

/* socket(2) */
#include <sys/socket.h>

/* ioctl(2) */
#include <sys/ioctl.h>

/* timerclear(3) */
#include <sys/time.h>

/* TODO: Support more BSDs. */
#ifdef __OpenBSD__

/* Pretty much all of this is for the get_hw_address function. */
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_types.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>

uint8_t * get_hw_address(char *, int);

#endif

#ifdef __gnu_linux__
/* uint8_t */
#include <stdint.h>

/* Linux MAX_ADDR_LEN */
#include <linux/netdevice.h>

/* ether_header */
#include <net/ethernet.h>

/* IFNAMSIZ */
#include <linux/if.h>

uint8_t * get_hw_address(char *, int);
#endif

/* duh -lpcap */
#include <pcap.h>

void usage(const char *);
void break_capture(int);
void cleanup_capture(int);
unsigned short get_windowsize(void);
int hwaddrscmp(uint8_t *, uint8_t *);
void output_header(char *);
void output_data(double, double);
void capture_callback(u_char *, const struct pcap_pkthdr *, const u_char *);

