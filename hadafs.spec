# if you make changes, the it is advised to increment this number, and provide 
# a descriptive suffix to identify who owns or what the change represents
# e.g. release_version 2.MSW
%define release 2%{?dist}

# if you wish to compile an rpm without ibverbs support, compile like this...
# rpmbuild -ta hadafs-0.0.4.tar.gz --without ibverbs
%{?_without_ibverbs:%define _without_ibverbs --disable-ibverbs}

# if you wish to compile an rpm without building the client RPMs...
# rpmbuild -ta hadafs-0.0.4.tar.gz --without client
%{?_without_client:%define _without_client --disable-fuse-client}

# if you wish to compile an rpm without BDB translator...
# rpmbuild -ta hadafs-0.0.4.tar.gz --without bdb
%{?_without_bdb:%define _without_bdb --disable-bdb}

# if you wish to compile an rpm without libhadafsclient...
# rpmbuild -ta hadafs-0.0.4.tar.gz --without libglfsclient
%{?_without_libglfsclient:%define _without_libglfsclient --disable-libhadaclient}

# if you wish to compile an rpm without libhadafsclient...
# rpmbuild -ta hadafs-0.0.4.tar.gz --without epoll
%{?_without_epoll:%define _without_epoll --disable-epoll}
%{?_without_mod_glfs:%define _without_mod_glfs --disable-mod_hadafs}

Summary: Cluster File System
Name: hadafs
Version: 0.0.4
Release: %{release}
License: GPLv3+
Group: System Environment/Base
Vendor: HADA Inc
Packager: hada-users@hada.org
URL: http://www.hada.org/docs/index.php/HADAFS
Source0: ftp://ftp.hada.com/pub/hada/hadafs/2.0/0.0.4/hadafs-0.0.4.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/service, /sbin/chkconfig
Requires(postun): /sbin/service

%{!?_without_ibverbs:BuildRequires: libibverbs-devel}

BuildRequires: bison flex 
BuildRequires: gcc make
BuildRequires: redis

%description
HADAFS is a clustered file-system capable of scaling to several
peta-bytes. It aggregates various storage bricks over Infiniband RDMA
or TCP/IP interconnect into one large parallel network file
system. HADAFS is one of the most sophisticated file system in
terms of features and extensibility.  It borrows a powerful concept
called Translators from GNU Hurd kernel. Much of the code in HADAFS
is in userspace and easily manageable.

%package common
Summary: HADAFS common files for both the client and the server 
Group: System Environment/Libraries
Obsoletes: hadafs-libs <= 2.0.0
Provides: hadafs-libs = %{version}-%{release}

%description common
HADAFS is a clustered file-system capable of scaling to several
peta-bytes. It aggregates various storage bricks over Infiniband RDMA
or TCP/IP interconnect into one large parallel network file
system. HADAFS is one of the most sophisticated file system in
terms of features and extensibility.  It borrows a powerful concept
called Translators from GNU Hurd kernel. Much of the code in HADAFS
is in userspace and easily manageable.

This package includes the hadafs binary, libhadafs and hadafs
translator modules common to both HADAFS server and client framework.

%package devel
Summary: HADAFS Development Libraries
Group: Development/Libraries
Requires: %{name}-common = %{version}-%{release}

%description devel
HADAFS is a clustered file-system capable of scaling to several
peta-bytes. It aggregates various storage bricks over Infiniband RDMA
or TCP/IP interconnect into one large parallel network file
system. HADAFS is one of the most sophisticated file system in
terms of features and extensibility.  It borrows a powerful concept
called Translators from GNU Hurd kernel. Much of the code in HADAFS
is in userspace and easily manageable.

This package provides the development libraries.

# Don't strip binaries
%define __os_install_post /usr/lib/rpm/brp-compress
%define debug_package %{nil}

%prep
%setup -q -n %{name}-%{version}

%build

#%configure %{?_without_ibverbs} %{?_without_bdb} %{?_without_libglfsclient} %{?_without_client} %{?_without_epoll}
%configure %{?_without_ibverbs} %{?_without_bdb} %{?_without_libglfsclient} %{?_without_client} %{?_without_epoll} %{?_without_mod_glfs} 

# Remove rpath
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
%{__make} %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot} 
%{__make} install DESTDIR=%{buildroot}
%{__mkdir_p} %{buildroot}%{_includedir}/hadafs
%{__mkdir_p} %{buildroot}/var/log/hadafs
%{__install} -p -m 0644 libhadafs/src/*.h \
    %{buildroot}%{_includedir}/hadafs/

# Remove unwanted files from all the shared libraries
find %{buildroot}%{_libdir}/hadafs -name '*.la' | xargs rm -f

%clean
%{__rm} -rf %{buildroot}

%post common
/sbin/ldconfig -n %{_libdir}
/sbin/chkconfig --add hadafsd

%postun common
/sbin/ldconfig -n %{_libdir}

%preun common
if [ $1 -eq 0 ]; then 
    /sbin/chkconfig --del hadafsd
fi

%files common
%defattr(-,root,root)
%doc AUTHORS ChangeLog COPYING INSTALL NEWS README
%doc /usr/share/doc/hadafs
%{_bindir}/hadafs-volgen
%{_libdir}/hadafs
%{_libdir}/*.so.*
%{_libdir}/*.so
%{_sbindir}/hadafs*
%{_mandir}/man8/hadafs.8*
%dir /var/log/hadafs
%defattr(-,root,root)
%config %{_sysconfdir}/hadafs
%{_sysconfdir}/init.d/hadafsd
%{_includedir}/hadafs
%{_includedir}/libhadafsclient.h
%{_includedir}/hadafs_ioctl.h

%files devel
%defattr(-,root,root,-)
%{_includedir}/hadafs
%{_includedir}/libhadafsclient.h
%{_includedir}/hadafs_ioctl.h
%exclude %{_includedir}/hadafs/y.tab.h
%exclude %{_libdir}/*.la
%{_libdir}/*.so

%changelog
* Wed Jul 01 2009 Harshavardhana <harsha@hada.com> - 2.1
- Removed mod_hadafs.so and added new --without epoll build
  option. 

* Thu Apr 16 2009 Harshavardhana <harsha@hada.com> - 2.0
- Galore of updates including new packages added common,
  client,server splitting the original package. rpmbuild 
  fully restructured to adhere to Fedora rpm standards. 
  Older changelog removed as there were warnings when 
  tried with 'rpmlint'. 
