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
*/

#define APP_NAME "snifstat"
#define APP_DESC "Sniff network and calculate traffic amount"
#define APP_COPYRIGHT	"Copyright (c) Stefan Midjich"
#define APP_DISCLAIMER	"This program comes with ABSOLUTELY NO WARRANTY"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <signal.h>
#include <errno.h>

/* getifaddrs(3) */
#include <ifaddrs.h>

/* socket(2) */
#include <sys/socket.h>

/* ioctl(2) */
#include <sys/ioctl.h>

/* timerclear(3) */
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>

#if defined(__OpenBSD__) || (defined(__APPLE__) && defined( __MACH__)) || defined(__FreeBSD__)

/* Pretty much all of this is for the get_hw_address function. */
#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
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

#define MAX_ETHER_LEN 6

/* duh -lpcap */
#include <pcap.h>

/* Pcap related */
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
    u_short	uh_sport;		/* source port */
    u_short	uh_dport;		/* destination port */
    u_short	uh_ulen;		/* datagram length */
    u_short	uh_sum;			/* datagram checksum */
};

#define SIZE_UDP 8

void usage(void);
void output_data(int);
void exit_callback(void);
void cleanup_capture(int);
unsigned short get_windowsize(void);
int hwaddrscmp(uint8_t *, uint8_t *);
void output_header(char *);
void fprint_data(double, double);
void capture_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
