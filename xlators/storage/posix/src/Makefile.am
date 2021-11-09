
xlator_LTLIBRARIES = posix.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/storage

posix_la_LDFLAGS = -module -avoidversion

posix_la_SOURCES = posix.c
posix_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la 

noinst_HEADERS = posix.h

AM_CFLAGS = -fPIC -fno-strict-aliasing -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D$(GF_HOST_OS) -Wall \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles \
	$(GF_CFLAGS)

CLEANFILES = 

