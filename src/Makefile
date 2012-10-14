M4 = m4

prefix = /usr/local/lua52
libdir = $(prefix)/lib
datadir = $(prefix)/share
includedir = $(prefix)/include
lua52include = $(includedir)/lua/5.2
lua52path = $(datadir)/lua/5.2
lua52cpath = $(libdir)/lua/5.2

LUAC = $(prefix)/bin/luac

VENDOR.OS = $(shell ../mk/vendor.os)
VENDOR.CC = $(shell env CC="${CC}" ../mk/vendor.cc)

cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
            > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;)

all: cqueues.so

CPPFLAGS = -D_REENTRANT -D_THREAD_SAFE
CPPFLAGS += -D_GNU_SOURCE -I$(DESTDIR)$(lua52include) -DSOCKET_DEBUG
CPPFLAGS += -DCQUEUES_COMMIT='"$(shell git show --pretty='%H' HEAD 2>/dev/null | sed -n '1p')"'

ifeq ($(VENDOR.CC), gcc)
DFLAGS = -Wall -Wextra $(call cc-option, -Wno-missing-field-initializers) $(call cc-option, -Wno-override-init) -Wno-unused -g
CFLAGS = -O2 -std=gnu99 -fPIC $(DFLAGS)
endif

ifeq ($(VENDOR.CC), clang)
DFLAGS = -Wall -Wextra -Wno-missing-field-initializers -Wno-initializer-overrides -Wno-unused -g
CFLAGS = -O2 -std=gnu99 -fPIC $(DFLAGS)
endif

ifeq ($(VENDOR.CC), sunpro)
DFLAGS = -g
CFLAGS = -xcode=pic13 $(DFLAGS)
endif

ifeq ($(VENDOR.OS), SunOS)
CPPFLAGS += -Usun -D_XPG4_2 -D__EXTENSIONS__
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
LDFLAGS = -L$(DESTDIR)$(libdir) -lssl -lcrypto -lrt -lm -pthread
else
ifeq ($(VENDOR.OS), SunOS)
LDFLAGS = -L$(DESTDIR)$(libdir) -lssl -lcrypto -lpthread
else
LDFLAGS = -L$(DESTDIR)$(libdir) -lssl -lcrypto -lpthread
endif
endif

ifeq ($(VENDOR.OS), Darwin)
SOFLAGS = -bundle -undefined dynamic_lookup
else
SOFLAGS = -shared
endif


cqueues.so: cqueues.o socket.o errno.o signal.o thread.o notify.o dns.o lib/socket.o lib/dns.o lib/notify.o
	$(CC) -o $@ $^ $(SOFLAGS) $(LDFLAGS)

cqueues.o: cqueues.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

socket.o: socket.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

errno.o: errno.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

errno.c: errno.c.m4
	$(M4) $^ > $@

signal.o: signal.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

thread.o: thread.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

notify.o: notify.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

dns.o: dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib/socket.o: lib/socket.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib/dns.o: lib/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib/notify.o: lib/notify.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<


install: $(lua52cpath)/_cqueues.so $(lua52path)/cqueues.lua \
         $(lua52path)/cqueues/socket.lua $(lua52path)/cqueues/errno.lua \
         $(lua52path)/cqueues/signal.lua $(lua52path)/cqueues/thread.lua \
         $(lua52path)/cqueues/notify.lua $(lua52path)/cqueues/dns/resolver.lua \
         $(lua52path)/cqueues/dns/config.lua $(lua52path)/cqueues/dns/hosts.lua

$(lua52cpath)/_cqueues.so: cqueues.so
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/cqueues.lua: cqueues.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/socket.lua: socket.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/errno.lua: errno.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/signal.lua: signal.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/thread.lua: thread.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/notify.lua: notify.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/dns/resolver.lua: dns.resolver.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/dns/config.lua: dns.config.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(lua52path)/cqueues/dns/hosts.lua: dns.hosts.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

.PHONY: clean clean~

clean:
	rm -rf errno.c *.so *.o lib/*.o *.dSYM

clean~: clean
	rm -f *~ lib/*~
