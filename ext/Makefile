prefix = /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib
datadir = $(prefix)/share
includedir = $(prefix)/include
luainclude =
luapath =
luacpath =
LUAC =

# backwards compatible install paths
ifneq ($(origin lua52include), undefined)
luainclude = $(lua52include)
endif

ifneq ($(origin lua52path), undefined)
luapath = $(lua52path)
endif

ifneq ($(origin lua52cpath), undefined)
luacpath = $(lua52cpath)
endif


# call helper to derive our Lua paths
ENV = CC CPPFLAGS prefix bindir libdir datadir includedir \
      luainclude luapath luacpath LUAC
$(shell env $(foreach V, $(ENV), $(V)="$(call $(V))") ../mk/lua.path make > .config)
include .config


VENDOR.OS = $(shell ../mk/vendor.os)
VENDOR.CC = $(shell env CC="${CC}" ../mk/vendor.cc)

ifneq ($(luainclude),)
CPPFLAGS = -I$(luainclude)
endif

ifeq ($(VENDOR.CC), sunpro)
DFLAGS = -g
CFLAGS = -xcode=pic13 $(DFLAGS)
CPPFLAGS += -DOPENSSL_NO_EC
else
DFLAGS = -g -Wall -Wextra -Wno-deprecated-declarations -Wno-unused
CFLAGS = -fPIC $(DFLAGS)
endif

LDFLAGS = -lssl -lcrypto

ifeq ($(VENDOR.OS), Darwin)
SOFLAGS = -bundle -undefined dynamic_lookup
else
SOFLAGS = -shared
endif


all: openssl.so

openssl.so: openssl.o
	$(CC) -o $@ $^ $(SOFLAGS) $(LDFLAGS)

openssl.o: openssl.c compat52.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<


install: $(DESTDIR)$(luacpath)/_openssl.so \
         $(DESTDIR)$(luapath)/openssl/bignum.lua \
         $(DESTDIR)$(luapath)/openssl/pubkey.lua \
         $(DESTDIR)$(luapath)/openssl/x509.lua \
         $(DESTDIR)$(luapath)/openssl/x509/name.lua \
         $(DESTDIR)$(luapath)/openssl/x509/altname.lua \
         $(DESTDIR)$(luapath)/openssl/x509/chain.lua \
         $(DESTDIR)$(luapath)/openssl/x509/store.lua \
         $(DESTDIR)$(luapath)/openssl/ssl/context.lua \
         $(DESTDIR)$(luapath)/openssl/ssl.lua \
         $(DESTDIR)$(luapath)/openssl/digest.lua \
         $(DESTDIR)$(luapath)/openssl/hmac.lua \
         $(DESTDIR)$(luapath)/openssl/cipher.lua

$(DESTDIR)$(luacpath)/_openssl.so: openssl.so
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/bignum.lua: openssl.bignum.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/pubkey.lua: openssl.pubkey.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/x509.lua: openssl.x509.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/x509/name.lua: openssl.x509.name.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/x509/altname.lua: openssl.x509.altname.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/x509/chain.lua: openssl.x509.chain.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/x509/store.lua: openssl.x509.store.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/ssl/context.lua: openssl.ssl.context.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/ssl.lua: openssl.ssl.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/digest.lua: openssl.digest.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/hmac.lua: openssl.hmac.lua
	mkdir -p $(@D)
	cp -p $< $@

$(DESTDIR)$(luapath)/openssl/cipher.lua: openssl.cipher.lua
	mkdir -p $(@D)
	cp -p $< $@


.PHONY: clean clean~ help

clean:
	rm -f *.so *.o
	rm -f .config

clean~: clean
	rm -f *~

help:
	@echo "Available targets:"
	@echo ""
	@echo "       all - build all binary targets"
	@echo "openssl.so - build openssl.so module"
	@echo "   install - install openssl modules"
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
	@echo '      LUAC - path to luac utility ($$(bindir)/luac)'
	@echo ""
	@echo "(NOTE: all the common GNU-style paths are supported, including"
	@echo "prefix, bindir, libdir, datadir, includedir, and DESTDIR.)"
	@echo ""
	@echo "Report bugs to <william@25thandClement.com>"
