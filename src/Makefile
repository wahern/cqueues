M4 = m4

prefix = /usr/local/lua52
libdir = $(prefix)/lib
datadir = $(prefix)/share
includedir = $(prefix)/include
lua52include = $(includedir)/lua/5.2
lua52path = $(datadir)/lua/5.2
lua52cpath = $(libdir)/lua/5.2

VENDOR.OS = $(shell ../mk/vendor.os)
VENDOR.CC = $(shell env CC="${CC}" ../mk/vendor.cc)

all: cqueues.so

CPPFLAGS = -D_GNU_SOURCE -I$(DESTDIR)$(lua52include) # -DSOCKET_DEBUG

ifeq ($(VENDOR.CC), gcc)
DFLAGS = -Wall -Wextra -Wno-override-init -Wno-unused -g
CFLAGS = -O2 -std=gnu99 -fPIC $(DFLAGS)
endif

ifeq ($(VENDOR.CC), clang)
DFLAGS = -Wall -Wextra -Wno-initializer-overrides -Wno-unused -g
CFLAGS = -O2 -std=gnu99 -fPIC $(DFLAGS)
endif

ifeq ($(VENDOR.CC), sunpro)
CFLAGS = -xcode=pic13
endif

ifeq ($(VENDOR.OS), SunOS)
CPPFLAGS += -Usun
endif

ifeq ($(VENDOR.OS), Darwin)
DFLAGS += -Wno-deprecated-declarations
endif

ifeq ($(VENDOR.OS), $(filter $(VENDOR.OS), OpenBSD NetBSD FreeBSD Darwin))
CPPFLAGS += -DDNS_RANDOM=arc4random
else
CPPFLAGS += -DDNS_RANDOM=RAND_bytes
endif

ifeq ($(VENDOR.OS), Linux)
LDFLAGS = -L$(DESTDIR)$(libdir) -lssl -lcrypto -lrt -lm
else
ifeq ($(VENDOR.OS), SunOS)
LDFLAGS = -L$(DESTDIR)$(libdir) -lssl -lcrypto
else
LDFLAGS = -L$(DESTDIR)$(libdir) -lssl -lcrypto
endif
endif

ifeq ($(VENDOR.OS), Darwin)
SOFLAGS = -bundle -undefined dynamic_lookup
else
SOFLAGS = -shared
endif


ifeq ($(VENDOR.OS), SunOS)
cqueues.so: cqueues.o socket.o errno.o lib/socket.o lib/dns.o
	$(CC) -o $@ $^ $(SOFLAGS) $(LDFLAGS)
else
cqueues.so: cqueues.o socket.o errno.o lib/socket.o lib/dns.o
	$(CC) -o $@ $^ $(SOFLAGS) $(LDFLAGS)
endif

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


install: $(lua52cpath)/_cqueues.so $(lua52path)/cqueues.lua $(lua52path)/cqueues/socket.lua $(lua52path)/cqueues/errno.lua

$(lua52cpath)/_cqueues.so: cqueues.so
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/cqueues.lua: cqueues.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/cqueues/socket.lua: socket.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/cqueues/errno.lua: errno.lua
	mkdir -p $(@D)
	cp -p $< $@
 
.PHONY: clean clean~

clean:
	rm -rf errno.c *.so *.o lib/*.o *.dSYM

clean~: clean
	rm -f *~ lib/*~
