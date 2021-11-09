lib_LTLIBRARIES = libhadafsclient.la
noinst_HEADERS = libhadafsclient-internals.h
libhadafsclient_HEADERS = libhadafsclient.h hadafs_ioctl.h
libhadafsclientdir = $(includedir)

libhadafsclient_la_SOURCES = libhadafsclient.c
libhadafsclient_la_CFLAGS =  -fPIC -Wall -pthread 
libhadafsclient_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la
libhadafsclient_la_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D$(GF_HOST_OS) -D__USE_FILE_OFFSET64 -D_GNU_SOURCE -I$(top_srcdir)/libhadafs/src -DDATADIR=\"$(localstatedir)\" -DCONFDIR=\"$(sysconfdir)/hadafs\" $(GF_CFLAGS)
libhadafsclient_la_LDFLAGS = -shared -nostartfiles

CLEANFILES = 

$(top_builddir)/libhadafs/src/libhadafs.la:
	$(MAKE) -C $(top_builddir)/libhadafs/src/ all

