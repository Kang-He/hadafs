
xlator_LTLIBRARIES = server.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/protocol

server_la_LDFLAGS = -module -avoidversion

server_la_SOURCES = server-protocol.c server-resolve.c server-helpers.c name-server.c ohashfn.c server-update.c
server_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = server-protocol.h server-helpers.h name-server.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS) \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles -lhiredis -L/usr/lib/\
	-DDATADIR=\"$(localstatedir)\" -DCONFDIR=\"$(sysconfdir)/hadafs\"  \
	$(GF_CFLAGS)

CLEANFILES = 

