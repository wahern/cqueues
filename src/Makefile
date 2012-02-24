
prefix     = /usr/local/lua52
libdir     = $(prefix)/lib
datadir    = $(prefix)/share
includedir = $(prefix)/include
lua52path  = $(datadir)/lua/5.2
lua52cpath = $(libdir)/lua/5.2

d := $(CURDIR)

all: $(d)/cqueues.so


CPPFLAGS_$(d) := -D_GNU_SOURCE -D_DARWIN_C_SOURCE -D_BSD_SOURCE $(DESTDIR)$(includedir)/lua/5.2
DFLAGS_$(d)   := -Wall -g
CFLAGS_$(d)   := -O2 -std=gnu99 -fPIC $(DFLAGS_$(d))

UNAME_$(d) := $(shell uname -s)

ifeq ($(UNAME_$(d)), Linux)
LDFLAGS_$(d) := -L$(DESTDIR)$(libdir) -llua5.2 -lrt -lm
else
LDFLAGS_$(d) := -L$(DESTDIR)$(libdir) -llua5.2
endif

ifeq ($(UNAME_$(d)), Darwin)
SOFLAGS_$(d) := -bundle -undefined dynamic_lookup
else
SOFLAGS_$(d) := -shared
endif


$(d)/cqueues.so: $(d)/cqueues.c
	$(CC) $(CFLAGS_$(@D)) $(CPPFLAGS_$(@D)) -o $< $(SOFLAGS_$(@D)) $(LDFLAGS_$(@D))


.PHONY: clean clean~ $(d)/clean $(d)/clean~

$(d)/clean:
	rm -f $(@D)/cqueues.so

$(d)/clean~: $(d)/clean
	rm -f $(@D)/*~

clean: $(d)/clean

clean~: $(d)/clean~

