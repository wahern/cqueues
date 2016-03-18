# non-recursive prologue
sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(abspath $(lastword $(MAKEFILE_LIST))/..)

ifeq ($(origin GUARD_$(d)), undefined)
GUARD_$(d) := 1


all: # default target

#
# G N U  M A K E  F U N C T I O N S
#
KNOWN_APIS = 5.1 5.2 5.3

# template for invoking luapath script
LUAPATH := $(d)/mk/luapath
LUAPATH_FN = $(shell env CC='$(subst ',\\',$(CC))' CPPFLAGS='$(subst ',\\',$(CPPFLAGS))' LDFLAGS='$(subst ',\\',$(LDFLAGS))' $(LUAPATH) -krxm3 -I'$(subst ',\\',$(DESTDIR)$(includedir))' -I/usr/include -I/usr/local/include -P'$(subst ',\\',$(DESTDIR)$(bindir))' -P'$(subst ',\\',$(bindir))' -L'$(subst ',\\',$(DESTDIR)$(libdir))' -L'$(subst ',\\',$(libdir))' -v$(1) $(2))

# check whether luapath can locate Lua $(1) headers
HAVE_API_FN = $(and $(filter $(1),$(call LUAPATH_FN,$(1),version)),$(1)$(info enabling Lua $(1)))

# check whether $(1) in LUA_APIS or $(LUA$(1:.=)_CPPFLAGS) is non-empty
WITH_API_FN = $$(and $$(or $$(filter $(1),$$(LUA_APIS)),$$(LUA$(subst .,,$(1))_CPPFLAGS)),$(1))

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
lua53cpath ?= $(libdir)/lua/5.3
lua53path ?= $(datadir)/lua/5.3

AR ?= ar
RANLIB ?= ranlib
M4 ?= m4
MV ?= mv
RM ?= rm
CP ?= cp
RMDIR ?= rmdir
MKDIR ?= mkdir
CHMOD ?= chmod
INSTALL ?= install
INSTALL_DATA ?= $(INSTALL) -m 644
TOUCH ?= touch
TEE ?= tee
TEE_A ?= $(TEE) -a

# see Lua Autodetection, below

.PHONY: $(d)/config

PRINT_$(d) = printf "%s = %s\n" '$(1)' '$(subst ',\\',$(2))' | $(TEE_A) '$(3)'

LAZY_$(d) = \
	prefix includedir libdir datadir bindir \
	lua51cpath lua51path lua52cpath lua52path lua53cpath lua53path \
	CC CPPFLAGS CFLAGS LDFLAGS SOFLAGS AR RANLIB M4 MV RM CP \
	RMDIR MKDIR CHMOD INSTALL INSTALL_DATA TOUCH TEE TEE_A

NONLAZY_$(d) = \
	LUA_APIS \
	$(foreach API,$(KNOWN_APIS),LUAC$(subst .,,$(API))) \
	$(foreach API,$(KNOWN_APIS),$(and $(call WITH_API_FN,$(API)),LUA$(subst .,,$(API))_CPPFLAGS))

$(d)/config:
	$(TOUCH) $(@D)/.config.tmp
	@$(foreach V,$(LAZY_$(@D)), $(call PRINT_$(@D),$(V),$(value $(V)),$(@D)/.config.tmp);)
	@$(foreach V,$(NONLAZY_$(@D)), $(call PRINT_$(@D),$(V),$($(V)),$(@D)/.config.tmp);)
	$(MV) $(@D)/.config.tmp $(@D)/.config

# add local targets if building from inside project tree
ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.PHONY: config configure

config configure: $(d)/config
endif


#
# L U A  A U T O D E T E C T I O N
#

# set LUA_APIS if empty or "?"
ifeq ($(or $(strip $(LUA_APIS)),?),?)
override LUA_APIS := $(call HAVE_API_FN,5.1) $(call HAVE_API_FN,5.2) $(call HAVE_API_FN,5.3)
endif

define LUAXY_template

# set luaXYcpath if empty or "?"
ifeq ($$(or $$(strip $$(lua$(subst .,,$(1))cpath)),?),?)
override lua$(subst .,,$(1))cpath := $$(or $$(call LUAPATH_FN,$(1),cdir),$$(libdir)/lua/$(1))
endif

# set luaXYpath if empty or "?"
ifeq ($$(or $$(strip $$(lua$(subst .,,$(1))path)),?),?)
override lua$(subst .,,$(1))path = $$(or $$(call LUAPATH_FN,$(1),ldir),$$(datadir)/lua/$(1))
endif

# set LUAXY_CPPFLAGS if undefined or "?" (NB: can be empty if path already in $(CPPFLAGS))
ifeq ($$(and $$(findstring undefined,$$(origin LUA$(subst .,,$(1))_CPPFLAGS)),?),?)
override LUA$(subst .,,$(1))_CPPFLAGS = $$(and $$(call WITH_API_FN,$(1)),$$(call LUAPATH_FN,$(1),cppflags))
endif

# set LUAXYC if empty or "?"
ifeq ($$(or $$(strip $$(LUAC$(subst .,,$(1)))),?),?)
override LUAC$(subst .,,$(1)) = $$(or $$(call LUAPATH_FN,$(1),luac),true)
endif

endef # LUAXY_template

$(eval $(call LUAXY_template,5.1))
$(eval $(call LUAXY_template,5.2))
$(eval $(call LUAXY_template,5.3))

#
# S H A R E D  C O M P I L A T I O N  F L A G S
#
cc-option ?= $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
             > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;)

VENDOR_OS_$(d) := $(shell $(d)/mk/vendor.os)
VENDOR_CC_$(d) := $(shell env CC="$(CC)" $(d)/mk/vendor.cc)

ifneq ($(VENDOR_OS_$(d)), OpenBSD)
CPPFLAGS_$(d) += -D_REENTRANT -D_THREAD_SAFE -D_GNU_SOURCE
endif

ifeq ($(VENDOR_OS_$(d)), SunOS)
CPPFLAGS_$(d) += -Usun -D_XPG4_2 -D__EXTENSIONS__
endif

ifeq ($(VENDOR_CC_$(d)), gcc)
CFLAGS_$(d) += -O2 -std=gnu99 -fPIC
CFLAGS_$(d) += -g -Wall -Wextra $(call cc-option, -Wno-missing-field-initializers) $(call cc-option, -Wno-override-init) -Wno-unused
endif

ifeq ($(VENDOR_CC_$(d)), clang)
CFLAGS_$(d) += -O2 -std=gnu99 -fPIC
CFLAGS_$(d) += -g -Wall -Wextra -Wno-missing-field-initializers -Wno-initializer-overrides -Wno-unused -Wno-dollar-in-identifier-extension
endif

ifeq ($(VENDOR_CC_$(d)), sunpro)
CFLAGS_$(d) += -xcode=pic13
CFLAGS_$(d) += -g
#
# Solaris Studio supports anonymous unions just fine; but it complains
# incessantly about them.
#
CFLAGS_$(d) += -erroff=E_ANONYMOUS_UNION_DECL
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
include $(d)/regress/GNUmakefile


#
# C L E A N  R U L E S
#
.PHONY: $(d)/clean~ clean~

$(d)/clean~:
	$(RM) -f $(@D)/*~

clean~: $(d)/clean~


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


#
# R E L E A S E  T A R B A L L  R U L E S
#
ifneq "$(filter $(abspath $(d))/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""

CQUEUES_VERSION := $(shell $(d)/mk/changelog version)

.PHONY: $(d)/cqueues-$(CQUEUES_VERSION).tgz release

$(d)/cqueues-$(CQUEUES_VERSION).tgz:
	cd $(@D) && git archive --format=tar --prefix=$(basename $(@F))/ HEAD | gzip -c > $@

release: $(d)/cqueues-$(CQUEUES_VERSION).tgz

endif # release guard


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
