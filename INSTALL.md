# Release

First of all check the releases page on github to see if there's a finished release for your platform.

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

	$ sudo pkg_add -r gmake gcc

## FreeBSD 10.x dependencies

FreeBSD 10 by default does not come with sudo. 

	$ su -
	Password: ***
	$ pkg install gcc gmake

# Install

	$ sudo make install

The Makefile is very simple for now so if you need to install somewhere else use ``INSTALL_PREFIX`` in the make args.

	$ make INSTALL_PREFIX=$HOME install
