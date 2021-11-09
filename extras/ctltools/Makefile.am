docdir = $(datadir)/ctltools/doc/hadafs/
SUBDIRS = init.d

EXTRA_DIST = specgen.scm MacOSX/Portfile hadafs-mode.el hadafs.vim 
dist_bin_SCRIPTS = hadafs-volgen

install-exec-hook:
	chmod 755 $(DESTDIR)$(bindir)/hadafs-volgen

CLEANFILES = 

