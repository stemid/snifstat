/* Functions to look up ethernet address on BSD systems.
 * These were mostly borrowed from OpenBSD source tree, 
 * usr.sbin/rarpd/rarpd.c and reworked slightly to fit into this program.
 */

#include "snifstat.h"

uint8_t * get_hw_address(char *ifname, int dflag) {
  struct ifaddrs *ifap = NULL, *ifa = NULL;
  struct sockaddr_dl *sdl = NULL;
  uint8_t *mac = NULL;

  if (getifaddrs(&ifap) == -1) {
		fprintf(stderr, "getifaddrs: %s\n", strerror(errno));
		return(NULL);
  }

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (strcmp(ifa->ifa_name, ifname))
      continue;

    sdl = (struct sockaddr_dl *) ifa->ifa_addr;
    if (sdl->sdl_family == AF_LINK && sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == MAX_ETHER_LEN) {
      if((mac = malloc(sizeof(uint8_t)*MAX_ETHER_LEN)) == NULL) {
        perror("malloc: ");
        return(NULL);
      }
      memcpy(mac, (uint8_t*)LLADDR(sdl), MAX_ETHER_LEN);
			break;
    }
  }

  freeifaddrs(ifap);
  return mac;
}

