/* Functions to look up ethernet address on Linux systems.
*/

#include "snifstat.h"

/* TODO: Put ethernet address into an argument pointer instead. Have the 
 * pointer defined and allocated outside of this function according to 
 * limits of MAX_ADDR_LEN.
 */
uint8_t * get_hw_address(char *ifname, int dflag) {
	struct ifaddrs *ifa = NULL, *ifap = NULL;
	struct ifreq req;
	int32_t sd = socket(PF_INET, SOCK_DGRAM, 0);
	uint8_t *mac = NULL;

	if(getifaddrs(&ifa) == -1) {
		perror("getifaddrs: ");
		return(NULL);
	}

	ifap = ifa;

	if(sd < 0) {
		freeifaddrs(ifa);
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
				/* TODO: Find some other size because MAX_ADDR_LEN at 32 is too large. */
				if((mac = malloc(sizeof(uint8_t)*6)) == NULL) {
					perror("malloc: ");
					return(NULL);
				}
				memcpy(mac, (uint8_t*)req.ifr_ifru.ifru_hwaddr.sa_data, 6);
				break;
			}
		}
	}

	freeifaddrs(ifap);
	return mac;
}

