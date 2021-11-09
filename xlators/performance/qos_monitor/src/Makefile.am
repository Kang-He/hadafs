xlator_LTLIBRARIES = qos_monitor.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/performance

qos_monitor_la_LDFLAGS = -module -avoidversion

qos_monitor_la_SOURCES = qos_monitor.c
qos_monitor_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = qos_monitor.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(GF_CFLAGS)\
	-lhiredis -lpthread -levent

CLEANFILES = 
