%define debug_package %{nil}
Summary: RISC-V sandbox vmod for Varnish Cache.
Name: libvmod-riscv
Version: %{versiontag}
Release: %{releasetag}%{?dist}
License: Proprietary
Group: System Environment/Daemons
Source: %{srcname}.tgz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%global varnishvcldir %(pkg-config varnishapi --variable=vcldir)
%global _missing_build_ids_terminate_build 0

BuildRequires: make
BuildRequires: python3
BuildRequires: varnish-plus-devel
BuildRequires: cmake
BuildRequires: gcc-c++
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libcurl)

%if 0%{?rhel} >= 8
BuildRequires: python3-docutils
%else
BuildRequires: python-docutils
%endif

Requires: varnish

%description
Low-latency programmable RISC-V sandbox VMOD embedding the libriscv emulator.

%prep
%setup -q -n %{srcname}

%build
%configure --prefix=/usr/
%{__make} %{?_smp_mflags} -j8

%install
[ %{buildroot} != "/" ] && %{__rm} -rf %{buildroot}
%{__make} install DESTDIR=%{buildroot}

%clean
[ %{buildroot} != "/" ] && %{__rm} -rf %{buildroot}

%files
%{_libdir}/varnis*/vmods/libvmod_riscv.so
%{_mandir}/man?/*
%{_docdir}/%{name}/*
%{_datarootdir}/varnish-plus/vcl/*
%exclude %{_libdir}/varnis*/vmods/libvmod_riscv.la
