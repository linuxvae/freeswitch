include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_agora
mod_LTLIBRARIES = mod_agora.la
mod_agora_la_SOURCES  = mod_agora.c agora.c
#mod_agora_la_SOURCES += libamf/src/amf0.c libamf/src/hash.c libamf/src/io.c libamf/src/ptrarray.c libamf/src/types.c 
mod_agora_la_CFLAGS   = $(AM_CFLAGS)
mod_agora_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_agora_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
#mod_h323_la_LDFLAGS  = -avoid-version -module -no-undefined -shared -L/usr/lib -lopenh323 -lpt -lrt 