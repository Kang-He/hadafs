xlator_LTLIBRARIES = io-threads.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/performance

io_threads_la_LDFLAGS = -module -avoidversion 

io_threads_la_SOURCES = io-threads.c qos.c redis_subscriber.c
io_threads_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = io-threads.h qos.h redis_subscriber.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(GF_CFLAGS)\
	-lhiredis -levent

CLEANFILES = 
