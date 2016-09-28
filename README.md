# Snifstat

Ever wanted to see how much traffic would go through a tcpdump filter? I did, and I wanted it output every second or so to the screen so I could monitor it while troubleshooting.

Snifstat does that. You specify an interface, a filter and it captures packets according to that filter, calculates the sizes and each second outputs a summary of the packet sizes on screen.

# Install

  - Go to releases and download the latest release.
  - Follow the instructions in [INSTALL.md](INSTALL.md).

Or clone the git repo for some specific branch.

	$ git clone -b snifstat-1.0 https://github.com/stemid/snifstat.git

# Run

	$ ./snifstat -h
	...
	$ sudo ./snifstat -t 2 -i team0 -m 'tcp'
      team0
	MByte/s in MByte/s out
		0.42      1.72
		0.29      1.84
	...

