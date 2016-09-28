# Snifstat

This started as a single file program on FreeBSD 4.x ca. 10 years ago. I needed a program that would sniff traffic according to a BPF rule, just like tcpdump, and then count all the packets it had captured and display traffic stats sort of like ifstat. 

So snifstat was born. 

Now I've made an effort to re-write the program for libpcap 1.0, Linux and in the process I solved some amateur mistakes I made back then. 

More or less the original snifstat.c is still on [gist](https://gist.github.com/stemid/8946ac0beeadbfc894421be449ea31e9).


# Download

For now clone the git repo. 

	$ git clone https://github.com/stemid/snifstat.git

# Compile

On Linux and Mac OS this should work.

	$ cd snifstat
	$ make

## On OpenBSD

On BSD first install GNU Make and then compile. 

	$ sudo pkg_add -r gmake
	$ gmake

# Run

	$ ./snifstat -h
	...
	$ sudo ./snifstat -t 2 -i en3 'tcp'

# TODO

 * Support more [physical layers](http://www.tcpdump.org/linktypes.html) than just Ethernet and 802.11 (WiFi).
 * Solve remaining: ``grep -rC2 'TODO: ' .``
 * Cleanup & comment code.
 * Test on FreeBSD.
 * Do 1.0 release.
 * Package for RPM, Deb and maybe others.
 * Add other output formats so output can be read by scripts.
 * Ask for help from reddit/IRC to ensure my coding is sound.
 * Unit test could inject packets while running program in aforementioned "script mode" to verify function.
