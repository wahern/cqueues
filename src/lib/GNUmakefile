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
# C O M P I L I A T I O N   F L A G S
#
OS_$(d) := $(shell $(d)/../../mk/vendor.os)

CPPFLAGS_$(d) = $(CPPFLAGS_$(abspath $(@D)/../..)) -DSOCKET_DEBUG
CFLAGS_$(d) = $(CFLAGS_$(abspath $(@D)/../..))
LDFLAGS_$(d) = $(LDFLAGS_$(abspath $(@D)/../..))
SOFLAGS_$(d) = $(SOFLAGS_$(abspath $(@D)/../..))

ifeq ($(OS_$(d)), $(filter $(OS_$(d)), OpenBSD NetBSD FreeBSD Darwin))
CPPFLAGS_$(d) += -DDNS_RANDOM=arc4random
else
CPPFLAGS_$(d) += -DDNS_RANDOM=RAND_bytes
endif


#
# C O M P I L I A T I O N   R U L E S
#
$(d)/%.o: $(d)/%.c $(d)/%.h
	$(CC) $(CFLAGS_$(@D)) $(CFLAGS) $(CPPFLAGS_$(@D)) $(CPPFLAGS) -c -o $@ $<

$(d)/libnonlua.a: $(d)/socket.o $(d)/dns.o $(d)/notify.o
	$(AR) cr $@ $^
	$(RANLIB) $@


#
# L O C A L  R U L E S
#
ifneq "$(filter $(abspath $(d))/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""

libnonlua.a: $(d)/libnonlua.a

endif # local guard


.PHONY: $(d)/clean $(d)/clean~ clean clean~

$(d)/clean:
	rm -fr $(@D)/*.[oa] $(@D)/*.dSYM

$(d)/clean~: $(d)/clean
	rm -fr $(@D)/*~

clean: $(d)/clean

clean~: $(d)/clean~


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
