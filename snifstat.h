#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>

/* getifaddrs(3) */
#include <ifaddrs.h>

/* socket(2) */
#include <sys/socket.h>

/* ioctl(2) */
#include <sys/ioctl.h>

/* timerclear(3) */
#include <sys/time.h>

#include <signal.h>

#ifdef __FreeBSD__
/* BSD IFNAMSIZ */
#include <net/if.h>

void lookup_addrs(char *);
u_int32_t ipaddrtonetmask(u_int32_t);

#endif

#ifdef __gnu_linux__
/* uint8_t */
#include <stdint.h>

/* Linux MAX_ADDR_LEN */
#include <linux/netdevice.h>

/* IFNAMSIZ */
#include <linux/if.h>

#define ETHER_ADDR_LEN MAX_ADDR_LEN

uint8_t * get_hw_address(char *, int);
#endif

/* duh -lpcap */
#include <pcap.h>
