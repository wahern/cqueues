# non-recursive prologue
sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(abspath $(lastword $(MAKEFILE_LIST))/..)

ifeq ($(origin GUARD_$(d)), undefined)
GUARD_$(d) := 1


all: # default target


#
# E N V I R O N M E N T  C O N F I G U R A T I O N
#
-include $(d)/.config

prefix ?= /usr/local
includedir ?= $(prefix)/include
libdir ?= $(prefix)/lib
datadir ?= $(prefix)/share
bindir ?= $(prefix)/bin
lua51cpath ?= $(libdir)/lua/5.1
lua51path ?= $(datadir)/lua/5.1
lua52cpath ?= $(libdir)/lua/5.2
lua52path ?= $(datadir)/lua/5.2

AR ?= ar
RANLIB ?= ranlib
M4 ?= m4
RM ?= rm
RMDIR ?= rmdir
MKDIR ?= mkdir
CHMOD ?= chmod
INSTALL ?= install
INSTALL_DATA ?= $(INSTALL) -m 644

.PHONY: $(d)/config

$(d)/config:
	printf 'prefix ?= $(value prefix)'"\n" >| $(@D)/.config
	printf 'includedir ?= $(value includedir)'"\n" >> $(@D)/.config
	printf 'libdir ?= $(value libdir)'"\n" >> $(@D)/.config
	printf 'datadir ?= $(value datadir)'"\n" >> $(@D)/.config
	printf 'bindir ?= $(value bindir)'"\n" >> $(@D)/.config
	printf 'lua51cpath ?= $(value lua51cpath)'"\n" >> $(@D)/.config
	printf 'lua51path ?= $(value lua51path)'"\n" >> $(@D)/.config
	printf 'lua52cpath ?= $(value lua52cpath)'"\n" >> $(@D)/.config
	printf 'lua52path ?= $(value lua52path)'"\n" >> $(@D)/.config
	printf 'CC ?= $(CC)'"\n" >> $(@D)/.config
	printf 'CPPFLAGS ?= $(value CPPFLAGS)'"\n" >> $(@D)/.config
	printf 'CFLAGS ?= $(value CFLAGS)'"\n" >> $(@D)/.config
	printf 'LDFLAGS ?= $(value LDFLAGS)'"\n" >> $(@D)/.config
	printf 'SOFLAGS ?= $(value SOFLAGS)'"\n" >> $(@D)/.config
	printf 'AR ?= $(value AR)'"\n" >> $(@D)/.config
	printf 'RANLIB ?= $(value RANLIB)'"\n" >> $(@D)/.config
	printf 'M4 ?= $(value M4)'"\n" >> $(@D)/.config
	printf 'RM ?= $(value RM)'"\n" >> $(@D)/.config
	printf 'RMDIR ?= $(value RMDIR)'"\n" >> $(@D)/.config
	printf 'MKDIR ?= $(value MKDIR)'"\n" >> $(@D)/.config
	printf 'CHMOD ?= $(value CHMOD)'"\n" >> $(@D)/.config
	printf 'INSTALL ?= $(value INSTALL)'"\n" >> $(@D)/.config
	printf 'INSTALL_DATA ?= $(value INSTALL_DATA)'"\n" >> $(@D)/.config

# add local targets if building from inside project tree
ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.PHONY: config configure

config configure: $(d)/config
endif


#
# S H A R E D  C O M P I L A T I O N  F L A G S
#
cc-option ?= $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
             > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;)

VENDOR_OS_$(d) := $(shell $(d)/mk/vendor.os)
VENDOR_CC_$(d) := $(shell env CC="$(CC)" $(d)/mk/vendor.cc)

CPPFLAGS_$(d) += -D_REENTRANT -D_THREAD_SAFE -D_GNU_SOURCE

ifeq ($(VENDOR_OS_$(d)), SunOS)
CPPFLAGS_$(d) += -Usun -D_XPG4_2 -D__EXTENSIONS__
endif

ifeq ($(VENDOR_CC_$(d)), gcc)
CFLAGS_$(d) += -O2 -std=gnu99 -fPIC
CFLAGS_$(d) += -g -Wall -Wextra $(call cc-option, -Wno-missing-field-initializers) $(call cc-option, -Wno-override-init) -Wno-unused
endif

ifeq ($(VENDOR_CC_$(d)), clang)
CFLAGS_$(d) += -O2 -std=gnu99 -fPIC
CFLAGS_$(d) += -g -Wall -Wextra -Wno-missing-field-initializers -Wno-initializer-overrides -Wno-unused
endif

ifeq ($(VENDOR_CC_$(d)), sunpro)
CFLAGS_$(d) += -xcode=pic13
CFLAGS_$(d) += -g
endif

ifeq ($(VENDOR_OS_$(d)), Darwin)
CFLAGS_$(d) += -Wno-deprecated-declarations
endif

ifeq ($(VENDOR_OS_$(d)), Darwin)
SOFLAGS_$(d) += -bundle -undefined dynamic_lookup
else
SOFLAGS_$(d) += -shared
endif


#
# P R O J E C T  R U L E S
#
include $(d)/src/GNUmakefile

#include $(d)/ext/GNUmakefile


#
# D E B I A N  R U L E S
#
ifneq "$(filter $(abspath $(d))/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""

DPKG_BUILDPACKAGE ?= dpkg-buildpackage
FAKEROOT ?= fakeroot
DPKG_BUILDPACKAGE_OPTIONS ?= -b -uc -us

.PHONY: $(d)/debian $(d)/debian-clean debian deb debian-clean deb-clean

$(d)/debian:
	cd $(@D) && $(DPKG_BUILDPACKAGE) -rfakeroot $(DPKG_BUILDPACKAGE_OPTIONS)

$(d)/debian-clean:
	cd $(@D) && $(FAKEROOT) ./debian/rules clean

debian deb: $(d)/debian

debian-clean deb-clean: $(d)/debian-clean

endif # debian guard


#
# R E D H A T  R U L E S
#
ifneq "$(filter $(abspath $(d))/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.PHONY: $(d)/redhat $(d)/redhat-clean redhat rpm redhat-clean rpm-clean

redhat rpm: $(d)/redhat

redhat-clean rpm-clean: $(d)/redhat-clean

endif # redhat guard


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
