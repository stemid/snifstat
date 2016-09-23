/* Functions to look up ethernet address on Linux systems.
 */

#include "snifstat.h"

/* TODO: Put ethernet address into an argument pointer instead. Have the 
 * pointer defined and allocated outside of this function according to 
 * limits of MAX_ADDR_LEN.
 */
uint8_t * get_hw_address(char *ifname, int dflag) {
	struct ifaddrs *ifa = NULL;
	struct sockaddr_dl *sdl = NULL;
	struct ifreq req;
	int32_t sd = socket(PF_INET, SOCK_DGRAM, 0);
	uint8_t *mac = NULL;

	if(getifaddrs(&ifa) == -1) {
		perror("getifaddrs: ");
		return(-1);
	}

	if(sd < 0) {
		freeifaddrs(ifa);
		return(-1);
	}

	for(;ifa;ifa = ifa->ifa_next) {
		/* Find if matching the ifname. */
		if(ifa->ifa_data != 0) {
			continue;
		}
		if(strncmp(ifname, ifa->ifa_name, sizeof(*ifname)) == 0) {
			strncpy(req.ifr_name, ifa->ifa_name, sizeof(ifa->ifa_name));
			if(ioctl(sd, SIOCGIFHWADDR, &req ) != -1 ) {
				mac = (uint8_t*)req.ifr_ifru.ifru_hwaddr.sa_data;

				if(dflag) {
					fprintf(stderr, "%s:MAC[%02X:%02X:%02X:%02X:%02X:%02X]\n",
							ifa->ifa_name,
							mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				}
			}

			printf("Found if %s\n", ifa->ifa_name);
			break;
		}
	}

	return mac;
}

