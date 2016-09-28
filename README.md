# Snifstat

Ever wanted to see how much traffic would go through a tcpdump filter? I did, and I wanted it output every second or so to the screen so I could monitor it while troubleshooting. 

Snifstat does that. You specify an interface, a filter and it captures packets according to that filter, calculates the sizes and each second outputs a summary of the packet sizes on screen.

# Download

  - Go to [releases](/stemid/snifstat/releases/new) and download the latest release
  - Follow the instructions in INSTALL.md

Or clone the git repo for some specific branch.

	$ git clone -b snifstat-1.0 https://github.com/stemid/snifstat.git

# Install

See [INSTALL.md](INSTALL.md) for more instructions.
