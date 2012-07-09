M4 = m4

prefix = /usr/local/lua52
libdir = $(prefix)/lib
datadir = $(prefix)/share
includedir = $(prefix)/include
lua52path = $(datadir)/lua/5.2
lua52cpath = $(libdir)/lua/5.2

all: cqueues.so

CPPFLAGS = -D_GNU_SOURCE -I$(DESTDIR)$(includedir)/lua/5.2 # -DSOCKET_DEBUG
DFLAGS = -Wall -Wextra -g
CFLAGS = -O2 -std=gnu99 -fPIC $(DFLAGS)

UNAME = $(shell uname -s)

ifeq ($(UNAME), Darwin)
DFLAGS += -Wno-deprecated-declarations
endif

ifeq ($(UNAME), $(filter $(UNAME), OpenBSD NetBSD FreeBSD Darwin))
CPPFLAGS += -DDNS_RANDOM=arc4random
else
CPPFLAGS += -DDNS_RANDOM=RAND_bytes
endif

ifeq ($(UNAME), Linux)
LDFLAGS = -L$(DESTDIR)$(libdir) -llua52 -lssl -lcrypto -lrt -lm
else
LDFLAGS = -L$(DESTDIR)$(libdir) -llua52 -lssl -lcrypto
endif

ifeq ($(UNAME), Darwin)
SOFLAGS = -bundle -undefined dynamic_lookup
else
SOFLAGS = -shared
endif


cqueues.so: cqueues.o socket.o errno.o lib/socket.o lib/dns.o
	$(CC) -o $@ $^ $(SOFLAGS) $(LDFLAGS)

cqueues.o: cqueues.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

socket.o: socket.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

errno.o: errno.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

errno.c: errno.c.m4
	$(M4) $^ > $@

lib/socket.o: lib/socket.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib/dns.o: lib/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: clean clean~

clean:
	rm -rf *.so *.o lib/*.o *.dSYM

clean~: clean
	rm -f *~ lib/*~
