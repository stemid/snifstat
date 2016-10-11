.PHONY: clean
.PHONY: install

INSTALL_PREFIX ?= /usr/local

build:
	$(MAKE) -C src

install: build
	install -m0755 src/snifstat $(INSTALL_PREFIX)/bin/
	mkdir -p $(INSTALL_PREFIX)/share/man/man1
	install -m0644 src/snifstat.1 $(INSTALL_PREFIX)/share/man/man1/

clean:
	rm -f src/*.o src/snifstat
