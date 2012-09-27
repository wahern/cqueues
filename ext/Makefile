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


CPPFLAGS = -I$(DESTDIR)$(lua52include)

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

openssl.o: openssl.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<


install: $(lua52cpath)/_openssl.so $(lua52path)/openssl/bignum.lua \
         $(lua52path)/openssl/pubkey.lua $(lua52path)/openssl/x509.lua \
         $(lua52path)/openssl/x509/name.lua $(lua52path)/openssl/x509/altname.lua \
         $(lua52path)/openssl/x509/chain.lua $(lua52path)/openssl/x509/store.lua \
         $(lua52path)/openssl/ssl/context.lua

$(lua52cpath)/_openssl.so: openssl.so
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/bignum.lua: openssl.bignum.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/pubkey.lua: openssl.pubkey.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/x509.lua: openssl.x509.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/x509/name.lua: openssl.x509.name.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/x509/altname.lua: openssl.x509.altname.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/x509/chain.lua: openssl.x509.chain.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/x509/store.lua: openssl.x509.store.lua
	mkdir -p $(@D)
	cp -p $< $@

$(lua52path)/openssl/ssl/context.lua: openssl.ssl.context.lua
	mkdir -p $(@D)
	cp -p $< $@


.PHONY: clean clean~

clean:
	rm -f *.so *.o

clean~: clean
	rm -f *~
