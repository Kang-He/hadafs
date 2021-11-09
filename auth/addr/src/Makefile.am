auth_LTLIBRARIES = addr.la
authdir = $(libdir)/hadafs/$(PACKAGE_VERSION)/auth

addr_la_LDFLAGS = -module -avoidversion

addr_la_SOURCES = addr.c
addr_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la 

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 
