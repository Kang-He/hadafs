libhadafs_la_CFLAGS = -fPIC  -Wall -g -shared -nostartfiles $(GF_CFLAGS) $(GF_DARWIN_LIBHADAFS_CFLAGS)

libhadafs_la_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D__USE_FILE_OFFSET64 -D_GNU_SOURCE -DXLATORDIR=\"$(libdir)/hadafs/$(PACKAGE_VERSION)/xlator\" -DTRANSPORTDIR=\"$(libdir)/hadafs/$(PACKAGE_VERSION)/transport\" -D$(GF_HOST_OS) -DLIBDIR=\"$(libdir)/hadafs/$(PACKAGE_VERSION)/auth\" -I$(top_srcdir)/contrib/rbtree

libhadafs_la_LIBADD = @LEXLIB@

lib_LTLIBRARIES = libhadafs.la

libhadafs_la_SOURCES = dict.c spec.lex.c y.tab.c xlator.c logging.c  hashfn.c defaults.c common-utils.c transport.c timer.c object.c call-stub.c compat.c authenticate.c fd.c compat-errno.c event.c mem-pool.c syscall.c iobuf.c $(top_srcdir)/contrib/rbtree/rb.c rbthash.c 

noinst_HEADERS = common-utils.h defaults.h dict.h hadafs.h hashfn.h logging.h protocol.h xlator.h transport.h stack.h timer.h list.h object.h call-stub.h compat.h authenticate.h fd.h revision.h compat-errno.h event.h mem-pool.h byte-order.h locking.h syscall.h iobuf.h $(top_srcdir)/contrib/rbtree/rb.h rbthash.h

EXTRA_DIST = spec.l spec.y

spec.lex.c: spec.l y.tab.h
	$(LEX) -t $(srcdir)/spec.l > $@

y.tab.c y.tab.h: spec.y
	$(YACC) -d $(srcdir)/spec.y

CLEANFILES = spec.lex.c y.tab.c y.tab.h
