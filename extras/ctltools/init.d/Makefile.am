
EXTRA_DIST = hadafsd-Debian hadafsd-Redhat hadafsd-SuSE hadafs-server.plist

CLEANFILES = 

initdir = @initdir@

$(GF_DISTRIBUTION): 
	$(mkdir_p) $(DESTDIR)$(initdir)	
	$(INSTALL_PROGRAM) hadafsd-$(GF_DISTRIBUTION) $(DESTDIR)$(initdir)/hadafsd

install-exec-local: $(GF_DISTRIBUTION)

install-data-local: 
if GF_DARWIN_HOST_OS
	cp hadafs-server.plist /Library/LaunchDaemons/com.hada.hadafs.plist 
endif
