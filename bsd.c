/* Functions to look up ethernet address on BSD systems.
 * These were mostly borrowed from OpenBSD source tree, 
 * usr.sbin/rarpd/rarpd.c and reworked slightly to fit into this program.
 */

/*
 * Lookup the ethernet address of the interface attached to the BPF
 * file descriptor 'fd'; return it in 'eaddr'.
 */
u_char * lookup_addrs(char *ifname) {
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_dl *sdl;
	u_char eaddr[ETHER_ADDR_LEN];
	struct if_addr *ia;
	struct in_addr in;
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
			memcpy((caddr_t)eaddr, (caddr_t)LLADDR(sdl), 6);

			if (dflag) {
				fprintf(stderr, "%s: %x:%x:%x:%x:%x:%x\n",
						ifa->ifa_name,
						eaddr[0], eaddr[1], eaddr[2],
						eaddr[3], eaddr[4], eaddr[5]);
			}

			found = 1;
		} else if (sdl->sdl_family == AF_INET) {
			ia = malloc(sizeof (struct if_addr));

			if (ia == NULL) {
				fprintf(stderr, "lookup_addrs: malloc: %s\n", strerror(errno));
				return(-1);
			}

			ia->ia_next = NULL;
			ia->ia_ipaddr = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
			ia->ia_netmask = ((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr;

			/* If SIOCGIFNETMASK didn't work,
				 figure out a mask from the IP
				 address class. */
			if (ia->ia_netmask == 0)
				ia->ia_netmask = ipaddrtonetmask(ia->ia_ipaddr);

			if (dflag) {
				in.s_addr = ia->ia_ipaddr;
				fprintf(stderr, "\t%s\n", inet_ntoa(in));
			}
		}
	}

	freeifaddrs(ifap);
	if (!found && dflag) {
		fprintf(stderr, "lookup_addrs: Never saw interface `%s'!", ifname);
		return(-1);
	}
}

/*
 * Get the netmask of an IP address.  This routine is used if
 * SIOCGIFNETMASK doesn't work.
 */
u_int32_t ipaddrtonetmask(u_int32_t addr) {
	if (IN_CLASSA(addr))
		return IN_CLASSA_NET;
	if (IN_CLASSB(addr))
		return IN_CLASSB_NET;
	if (IN_CLASSC(addr))
		return IN_CLASSC_NET;
}
