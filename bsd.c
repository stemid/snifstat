/* Functions to look up ethernet address on BSD systems.
 * These were mostly borrowed from OpenBSD source tree, 
 * usr.sbin/rarpd/rarpd.c and reworked slightly to fit into this program.
 */

#include "snifstat.h"

uint8_t * get_hw_address(char *ifname, int dflag) {
	struct ifaddrs *ifap = NULL, *ifa = NULL;
	struct sockaddr_dl *sdl = NULL;
	uint8_t * eaddr = NULL;
	struct if_addr *ia = NULL;
	int found = 0;

	if (getifaddrs(&ifap) != 0) {
		fprintf(stderr, "getifaddrs: %s\n", strerror(errno));
		/* NOTREACHED */
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname))
			continue;

		sdl = (struct sockaddr_dl *) ifa->ifa_addr;
		if (sdl->sdl_family == AF_LINK && sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == 6) {
			/*memcpy((caddr_t)eaddr, (caddr_t)LLADDR(sdl), 6);*/
			eaddr = (uint8_t*)LLADDR(sdl);

			/* TODO: Remove debug code from API functions when finished. */
			if (dflag) {
				fprintf(stderr, "%s:MAC[%02X:%02X:%02X:%02X:%02X:%02X]\n",
						ifa->ifa_name,
						eaddr[0], eaddr[1], eaddr[2],
						eaddr[3], eaddr[4], eaddr[5]);
			}

			found = 1;
		}
	}

	freeifaddrs(ifap);
	if (!found && dflag) {
		fprintf(stderr, "lookup_addrs: Never saw interface `%s'!", ifname);
	}

	return eaddr;
}
