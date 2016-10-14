.PHONY: clean
.PHONY: install

ifeq ($(UNAME), FreeBSD)
	INSTALL_PREFIX=/usr/local
endif

INSTALL_PREFIX ?= /usr

build:
	$(MAKE) -C src

install: build
	mkdir -p $(INSTALL_PREFIX)/bin
	install -m0755 src/snifstat $(INSTALL_PREFIX)/bin/
	mkdir -p $(INSTALL_PREFIX)/share/man/man1
	install -m0644 src/snifstat.1 $(INSTALL_PREFIX)/share/man/man1/

clean:
	rm -f src/*.o src/snifstat
