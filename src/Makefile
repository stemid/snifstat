UNAME := $(shell uname)
TARGET = snifstat
CC=cc
platform_files = linux.c

ifeq ($(UNAME), Linux)
	platform_files=linux.c
endif
ifeq ($(UNAME), OpenBSD)
	platform_files=bsd.c
endif
ifeq ($(UNAME), Darwin)
	platform_files=bsd.c
endif
ifeq ($(UNAME), FreeBSD)
	platform_files=bsd.c
endif

$(TARGET): snifstat.c
	$(CC) -o $@ $(platform_files) $< -lpcap
