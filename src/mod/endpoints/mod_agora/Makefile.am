include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_agora
AGORALIBPATH=/root/git/freeswitch/src/mod/endpoints/mod_agora/agora_libs
mod_LTLIBRARIES = mod_agora.la
mod_agora_la_SOURCES  = mod_agora.cpp agora.cpp AgoraSdk.cpp AgoraServerSdk.cpp agora_rtm.cpp 
#mod_agora_la_SOURCES += libamf/src/amf0.c libamf/src/hash.c libamf/src/io.c libamf/src/ptrarray.c libamf/src/types.c 
#mod_agora_la_CFLAGS   = $(AM_CFLAGS)
mod_agora_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_gsmopen_la_CXXFLAGS = $(SWITCH_AM_CXXFLAGS) 
CXXFLAGS += -fpermissive -std=c++0x -fPIC -g -fno-omit-frame-pointer \                       
            -DNDEBUG=1 -Wconversion -O0 -Wall -W -fvisibility=hidden
#mod_gsmopen_la_CPPFLAGS = -I$(SPANDSP_DIR)/src -I$(SPANDSP_BUILDDIR)/src -I.
mod_agora_la_LDFLAGS  = -avoid-version -module -no-undefined -static-libgcc -std=c++11 -Wl,-rpath=$(AGORALIBPATH)  -lagora_rtm_sdk  -L$(AGORALIBPATH) -lserver -ldl -lrt -lasound -lpulse -ljansson -lcurl -pthread -lpthread 
#mod_h323_la_LDFLAGS  = -avoid-version -module -no-undefined -shared -L/usr/lib -lopenh323 -lpt -lrt 
