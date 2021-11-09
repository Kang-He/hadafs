ldpreload_LTLIBRARIES = libhadafs-booster.la
ldpreloaddir = $(libdir)/hadafs
noinst_HEADERS = booster_fstab.h booster-fd.h
libhadafs_booster_la_SOURCES = booster.c booster_stat.c booster_fstab.c booster-fd.c
libhadafs_booster_la_CFLAGS = -I$(top_srcdir)/libhadafsclient/src/ -D_GNU_SOURCE -D$(GF_HOST_OS) -fPIC -Wall \
	-pthread $(GF_BOOSTER_CFLAGS) -shared -nostartfiles
libhadafs_booster_la_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE  \
	-I$(top_srcdir)/libhadafsclient/src \
	-I$(top_srcdir)/libhadafs/src -DDATADIR=\"$(localstatedir)\" \
	-DCONFDIR=\"$(sysconfdir)/hadafs\"

libhadafs_booster_la_LDFLAGS = -module -avoidversion
libhadafs_booster_la_LIBADD =  $(top_builddir)/libhadafs/src/libhadafs.la $(top_builddir)/libhadafsclient/src/libhadafsclient.la

CLEANFILES =

uninstall-local:
	rm -f $(DESTDIR)$(ldpreloaddir)/hadafs-booster.so

install-data-hook:
	ln -sf libhadafs-booster.so $(DESTDIR)$(ldpreloaddir)/hadafs-booster.so
