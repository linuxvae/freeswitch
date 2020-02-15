include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_agora
LIBPATH=./libs
mod_LTLIBRARIES = mod_agora.la
mod_agora_la_SOURCES  = mod_agora.cpp agora.cpp AudioFrameObserver.cpp
#mod_agora_la_SOURCES += libamf/src/amf0.c libamf/src/hash.c libamf/src/io.c libamf/src/ptrarray.c libamf/src/types.c 
#mod_agora_la_CFLAGS   = $(AM_CFLAGS)
mod_agora_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_gsmopen_la_CXXFLAGS = $(SWITCH_AM_CXXFLAGS) 
CXXFLAGS += -fpermissive -std=c++0x -fPIC -g -fno-omit-frame-pointer \                       
            -DNDEBUG=1 -Wconversion -O3 -Wall -W -fvisibility=hidden
#mod_gsmopen_la_CPPFLAGS = -I$(SPANDSP_DIR)/src -I$(SPANDSP_BUILDDIR)/src -I.
mod_agora_la_LDFLAGS  = -avoid-version -module -no-undefined -shared -pthread -lpthread -L$(LIBPATH) -Wl,-rpath=$(LIBPATH) -lagora_rtc_sdk -ldl -lrt -lasound -lpulse
#mod_h323_la_LDFLAGS  = -avoid-version -module -no-undefined -shared -L/usr/lib -lopenh323 -lpt -lrt 
