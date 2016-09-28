# Compile

	$ cd snifstat-1.0
	$ make

On OpenBSD you must use gmake for GNU Make.

	$ gmake

## CentOS 7 dependencies

	$ sudo yum install gcc libpcap-devel

## Ubuntu 14.04 dependencies

	$ sudo apt-get install gcc libpcap0.8-dev libpcap0.8 -y

## OpenBSD 5.x dependencies

	$ sudo pkg\_add -r gmake gcc

# Install

	$ sudo make install

The Makefile is very simple for now so if you need to install somewhere else use ``INSTALL_PREFIX`` in the make args.

	$ make INSTALL\_PREFIX=$HOME/bin install
