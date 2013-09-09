# non-recursive prologue
sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(abspath $(lastword $(MAKEFILE_LIST))/..)

ifeq ($(origin GUARD_$(d)), undefined)
GUARD_$(d) := 1


#
# E N V I R O N M E N T  C O N F I G U R A T I O N
#
include $(d)/../../GNUmakefile


#
# C O M P I L I A T I O N   R U L E S
#
VENDOR_OS_$(d) = $(shell $(@D)/../../mk/vendor.os)
VENDOR_CC_$(d) = $(shell env CC="$(CC)" $(@D)/../../mk/vendor.cc)

cc-option ?= $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
             > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;)

CPPFLAGS_$(d) += -D_REENTRANT -D_THREAD_SAFE
CPPFLAGS_$(d) += -D_GNU_SOURCE -DSOCKET_DEBUG

ifeq ($(VENDOR_CC_$(d)), gcc)
DFLAGS_$(d) = -Wall -Wextra $(call cc-option, -Wno-missing-field-initializers) $(call cc-option, -Wno-override-init) -Wno-unused -g
CFLAGS_$(d) = -O2 -std=gnu99 -fPIC $(DFLAGS_$(@D))
endif

ifeq ($(VENDOR_CC_$(d)), clang)
CFLAGS_$(d) += -O2 -std=gnu99 -fPIC
CFLAGS_$(d) += -Wall -Wextra -Wno-missing-field-initializers -Wno-initializer-overrides -Wno-unused -g
endif

ifeq ($(VENDOR.CC), sunpro)
CFLAGS_$(d) += -xcode=pic13
CFLAGS_$(d) += -g
endif

ifeq ($(VENDOR.OS), SunOS)
CPPFLAGS_$(d) += -Usun -D_XPG4_2 -D__EXTENSIONS__
endif

ifeq ($(VENDOR.OS), Darwin)
CFLAGS_$(d) += -Wno-deprecated-declarations
endif

ifeq ($(VENDOR_OS_$(d)), $(filter $(VENDOR_OS_$(d)), OpenBSD NetBSD FreeBSD Darwin))
CPPFLAGS_$(d) += -DDNS_RANDOM=arc4random
else
CPPFLAGS_$(d) += -DDNS_RANDOM=RAND_bytes
endif


$(d)/lib/socket.o $(d)/lib/dns.o $(d)/lib/notify.o: $(d)/lib/%.o: $(d)/lib/%.c $(d)/lib/%.h
	$(CC) $(CFLAGS_$(@D)) $(CFLAGS) $(CPPFLAGS_$(@D)) $(CPPFLAGS) -c -o $@ $<


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
