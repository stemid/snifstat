/* Functions to look up ethernet address on Linux systems. */

#include "snifstat.h"

uint8_t * get_hw_address(char *ifname, int dflag) {
  struct ifaddrs *ifa = NULL, *ifap = NULL;
  struct ifreq req;
  int32_t sd = socket(PF_INET, SOCK_DGRAM, 0);
  uint8_t *mac = NULL;

  if(getifaddrs(&ifa) == -1) {
		fprintf(stderr, "getifaddrs: %s\n", strerror(errno));
    return(NULL);
  }

	ifap = ifa;

  if(sd < 0) {
    freeifaddrs(ifap);
    return(NULL);
  }

  for(;ifa;ifa = ifa->ifa_next) {
    if(ifa->ifa_data != 0) {
      continue;
    }

    /* Find if matching the ifname. */
    if(strncmp(ifname, ifa->ifa_name, sizeof(*ifname)) == 0) {
      strncpy(req.ifr_name, ifa->ifa_name, IFNAMSIZ);
      if(ioctl(sd, SIOCGIFHWADDR, &req ) != -1 ) {
        if((mac = malloc(sizeof(uint8_t)*MAX_ETHER_LEN)) == NULL) {
          perror("malloc: ");
          return(NULL);
        }
        memcpy(mac, (uint8_t*)req.ifr_ifru.ifru_hwaddr.sa_data, MAX_ETHER_LEN);
        break;
      }
    }
  }

  freeifaddrs(ifap);
  return mac;
}

