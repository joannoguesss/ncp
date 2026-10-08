# ncp - network copy

PREFIX  = /usr/local
MANDIR  = $(PREFIX)/share/man

CC      = cc
CFLAGS  = -std=c99 -O2 -Wall -Wextra -pedantic
LDLIBS  = -lssl -lcrypto

ncp: ncp.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ ncp.c $(LDLIBS)

install: ncp
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(MANDIR)/man1
	install -m 755 ncp $(DESTDIR)$(PREFIX)/bin/ncp
	install -m 644 ncp.1 $(DESTDIR)$(MANDIR)/man1/ncp.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/ncp $(DESTDIR)$(MANDIR)/man1/ncp.1

clean:
	rm -f ncp

.PHONY: install uninstall clean
