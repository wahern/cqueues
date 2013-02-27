M4 = m4

prefix = /usr/local/lua52
libdir = $(prefix)/lib
datadir = $(prefix)/share
includedir = $(prefix)/include
luainclude = $(includedir)/lua/5.2
luapath = $(datadir)/lua/5.2
luacpath = $(libdir)/lua/5.2

LUAC = $(prefix)/bin/luac

# backwards compatibile install paths
ifneq ($(origin lua52include), undefined)
luainclude = $(lua52include)
endif

ifneq ($(origin lua52path), undefined)
luapath = $(lua52path)
endif

ifneq ($(origin lua52cpath), undefined)
luacpath = $(lua52cpath)
endif


VENDOR.OS = $(shell ../mk/vendor.os)
VENDOR.CC = $(shell env CC="${CC}" ../mk/vendor.cc)

cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
            > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;)

all: cqueues.so

CPPFLAGS = -D_REENTRANT -D_THREAD_SAFE
CPPFLAGS += -D_GNU_SOURCE -I$(luainclude) -DSOCKET_DEBUG
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
LDFLAGS = -L$(DESTDIR)$(libdir) -L$(libdir) -lssl -lcrypto -lrt -lm -pthread
else
ifeq ($(VENDOR.OS), SunOS)
LDFLAGS = -L$(DESTDIR)$(libdir) -L$(libdir) -lssl -lcrypto -lpthread
else
LDFLAGS = -L$(DESTDIR)$(libdir) -L$(libdir) -lssl -lcrypto -lpthread
endif
endif

ifeq ($(VENDOR.OS), Darwin)
SOFLAGS = -bundle -undefined dynamic_lookup
else
SOFLAGS = -shared
endif


cqueues.so: cqueues.o socket.o errno.o signal.o thread.o notify.o dns.o lib/socket.o lib/dns.o lib/notify.o
	$(CC) -o $@ $^ $(SOFLAGS) $(LDFLAGS)

cqueues.o: cqueues.c cqueues.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

socket.o: socket.c cqueues.h lib/socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

errno.o: errno.c cqueues.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

errno.c: errno.c.m4
	$(M4) $^ > $@

signal.o: signal.c cqueues.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

thread.o: thread.c cqueues.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

notify.o: notify.c cqueues.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

dns.o: dns.c cqueues.h lib/dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib/socket.o: lib/socket.c lib/socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib/dns.o: lib/dns.c lib/dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

lib/notify.o: lib/notify.c lib/notify.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<


install: $(DESTDIR)$(luacpath)/_cqueues.so \
         $(DESTDIR)$(luapath)/cqueues.lua \
         $(DESTDIR)$(luapath)/cqueues/socket.lua \
         $(DESTDIR)$(luapath)/cqueues/errno.lua \
         $(DESTDIR)$(luapath)/cqueues/signal.lua \
         $(DESTDIR)$(luapath)/cqueues/thread.lua \
         $(DESTDIR)$(luapath)/cqueues/notify.lua \
         $(DESTDIR)$(luapath)/cqueues/dns/resolver.lua \
         $(DESTDIR)$(luapath)/cqueues/dns/config.lua \
         $(DESTDIR)$(luapath)/cqueues/dns/hosts.lua \
         $(DESTDIR)$(luapath)/cqueues/dns/hints.lua \
         $(DESTDIR)$(luapath)/cqueues/dns/record.lua \
         $(DESTDIR)$(luapath)/cqueues/dns/packet.lua

$(DESTDIR)$(luacpath)/_cqueues.so: cqueues.so
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues.lua: cqueues.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/socket.lua: socket.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/errno.lua: errno.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/signal.lua: signal.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/thread.lua: thread.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/notify.lua: notify.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/dns/resolver.lua: dns.resolver.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/dns/config.lua: dns.config.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/dns/hosts.lua: dns.hosts.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/dns/hints.lua: dns.hints.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/dns/record.lua: dns.record.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

$(DESTDIR)$(luapath)/cqueues/dns/packet.lua: dns.packet.lua
	mkdir -p $(@D)
	$(LUAC) -p $<
	cp -p $< $@

.PHONY: clean clean~

clean:
	rm -rf errno.c *.so *.o lib/*.o *.dSYM

clean~: clean
	rm -f *~ lib/*~

help:
	@echo "Available targets:"
	@echo ""
	@echo "       all - build all binary targets"
	@echo "cqueues.so - build cqueues.so module"
	@echo "   install - install cqueues modules"
	@echo "     clean - rm binary targets, object files, debugging symbols, etc"
	@echo "    clean~ - clean + rm *~"
	@echo "      help - echo this help message"
	@echo ""
	@echo "Some important Make variables:"
	@echo ""
	@echo "    prefix - path to install root"
	@echo 'luainclude - path to Lua headers ($$(prefix)/include/lua/5.2)'
	@echo '   luapath - install path for Lua modules ($$(prefix)/share/lua/5.2)'
	@echo '  luacpath - install path for Lua C modules ($$(prefix)/lib/lua/5.2)'
	@echo '      LUAC - path to luac utility ($$(prefix)/bin/luac)'
	@echo ""
	@echo "Report bugs to <william@25thandClement.com>"
