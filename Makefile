UNAME := $(shell uname)
TARGET = snifstat
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

$(TARGET): snifstat.o
	gcc -lpcap -o $@ $^

snifstat.o: snifstat.c
	gcc -o $@ $(platform_files) $<

clean:
	rm -f *.o snifstat
