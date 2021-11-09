
xlator_LTLIBRARIES = unify.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/cluster

unify_la_LDFLAGS = -module -avoidversion

unify_la_SOURCES = unify.c
unify_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = unify.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS) \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 

