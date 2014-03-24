SOURCES = memcached-udp.cc memcached.cc
HEADERS = memcached-udp.hh

src = $(OSV_PATH)
arch = $(ARCH)
mode = $(MODE)

local-includes = -I.
INCLUDES = $(local-includes) -I$(src)/arch/$(arch) -I$(src) -I$(src)/include
INCLUDES += -isystem $(src)/include/glibc-compat

glibcbase = $(src)/external/$(arch)/glibc.bin
gccbase = $(src)/external/$(arch)/gcc.bin
miscbase = $(src)/external/$(arch)/misc.bin

gcc-inc-base = $(dir $(shell find $(gccbase)/ -name vector | grep -v -e debug/vector$$ -e profile/vector$$))
gcc-inc-base2 = $(dir $(shell find $(gccbase)/ -name unwind.h))
gcc-inc-base3 = $(dir $(shell dirname `find $(gccbase)/ -name c++config.h | grep -v /32/`))

INCLUDES += -isystem $(gcc-inc-base)
INCLUDES += -isystem $(gcc-inc-base3)
INCLUDES += -isystem $(src)/external/$(arch)/acpica/source/include
INCLUDES += -isystem $(src)/external/$(arch)/misc.bin/usr/include
INCLUDES += -isystem $(src)/include/api
INCLUDES += -isystem $(src)/include/api/$(arch)
# must be after include/api, since it includes some libc-style headers:
INCLUDES += -isystem $(gcc-inc-base2)
INCLUDES += -isystem gen/include
INCLUDES += $(post-includes-bsd)

post-includes-bsd += -isystem $(src)/bsd/sys
# For acessing machine/ in cpp xen drivers
post-includes-bsd += -isystem $(src)/bsd/
post-includes-bsd += -isystem $(src)/bsd/$(arch)

INCLUDES += -I$(src)/build/$(mode)/gen/include/


OBJ = $(SOURCES:%.cc=%.o)

autodepend = -MD -MT $@ -MP

COMMON = $(autodepend) -Wall -Werror -nostdinc -D __BSD_VISIBLE=1 -D_KERNEL \
	 -include $(src)/compiler/include/intrinsics.hh -Wformat=0 -Wno-format-security

CXXFLAGS = -std=gnu++11 $(COMMON) -shared -fPIC
LDFLAGS = -shared -fPIC

all: osv-memcached

osv-memcached: $(OBJ)
	$(CXX) $(OBJ) $(LDFLAGS) -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f *.d *.o osv-memcached

-include $(shell find -name '*.d')
