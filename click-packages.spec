%define name click-packages
%define version 1.4pre1
%define release 1
%define packages ip6_natpt models iias

Summary: Click modular router packages
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{version}.tar.gz
License: Various
Group: System/Networking
BuildRoot: %{_tmppath}/%{name}-buildroot
Prefix: %{_prefix}
Requires: click

%description
    This source release consists of several independent "packages" for
the Click modular software router.  You will need to compile and run
Click 1.4 before compiling these packages.

    These packages were written by independent developers and are
distributed COMPLETELY WITHOUT WARRANTY.  In particular, the main Click
developers ARE NOT RESPONSIBLE for these packages.  Send mail concerning
these packages to the individual package developers, with a cc: to the
Click mailing list <click@pdos.lcs.mit.edu>.

%prep
%setup -q

%build
for i in %{packages} ; do (
    cd $i
    autoconf
    %configure --with-click=%{_prefix}
    make
) done

%install
rm -rf $RPM_BUILD_ROOT
for i in %{packages} ; do (
    cd $i
    %makeinstall
) done

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc LICENSE README
%{_datadir}/click
%{_mandir}
%{_libdir}

%changelog
* Tue Apr 20 2004 Mark Huang <mlhuang@cs.princeton.edu>
- initial version

# end of file
