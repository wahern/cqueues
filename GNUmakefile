# non-recursive prologue
sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(abspath $(lastword $(MAKEFILE_LIST))/..)

ifeq ($(origin GUARD_$(d)), undefined)
GUARD_$(d) := 1


#
# E N V I R O N M E N T  C O N F I G U R A T I O N
#
-include $(d)/.config

prefix ?= /usr/local
includedir ?= $(prefix)/include
libdir ?= $(prefix)/lib
datadir ?= $(prefix)/share
bindir ?= $(prefix)/bin

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
	printf 'CC ?= $(CC)'"\n" >> $(@D)/.config
	printf 'CPPFLAGS ?= $(value CPPFLAGS)'"\n" >> $(@D)/.config
	printf 'CFLAGS ?= $(value CFLAGS)'"\n" >> $(@D)/.config
	printf 'LDFLAGS ?= $(value LDFLAGS)'"\n" >> $(@D)/.config
	printf 'SOFLAGS ?= $(value SOFLAGS)'"\n" >> $(@D)/.config
	printf 'M4 ?= $(value M4)'"\n" >> $(@D)/.config
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
# P R O J E C T  R U L E S
#
include $(d)/src/GNUmakefile

include $(d)/ext/GNUmakefile


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
