xlator_LTLIBRARIES = mem-cache.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/performance

mem_cache_la_LDFLAGS = -module -avoidversion 

mem_cache_la_SOURCES = mem-cache.c
mem_cache_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

AM_CFLAGS = -pg -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/libhadafs/src -DDATADIR=\"$(localstatedir)\" \
-shared -nostartfiles $(GF_CFLAGS)

sbin_PROGRAMS = hadafs_mc_check
hadafs_mc_check_SOURCES = check_unfinish.c

hadafs_mc_check_CFLAGS = 

CLEANFILES = 

uninstall-local:
	rm -f $(DESTDIR)$(sbindir)/hadafs_mc_check
