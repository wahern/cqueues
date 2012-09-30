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
DFLAGS = -Wall -Wextra -Wno-deprecated-declarations -Wno-unused
CFLAGS = -fPIC $(DFLAGS)
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


.PHONY: clean clean~

clean:
	rm -f *.so *.o

clean~: clean
	rm -f *~
