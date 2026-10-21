AC_PREREQ([2.68])
AC_INIT([libvmod-riscv],[1.1],[],[libvmod-riscv])
AC_COPYRIGHT([Public Domain])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR(src/vmod_riscv.vcc)
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.12 -Wall foreign parallel-tests tar-pax subdir-objects])
AM_SILENT_RULES([yes])
AM_PROG_AR

AM_EXTRA_RECURSIVE_TARGETS([recheck])

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

dnl The VMOD glue (vmod_riscv.c et al.) is C; the sandbox/runtime is C++20.
AC_PROG_CC
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX([20], [noext], [mandatory])

AX_PTHREAD(,[AC_MSG_ERROR([Could not configure pthreads support])])

dnl libriscv links OpenSSL's libcrypto (sha256 etc.)
PKG_CHECK_MODULES([CRYPTO], [libcrypto], [],
	[AC_MSG_ERROR([libcrypto (OpenSSL) not found. Install libssl-dev.])])

dnl cmake is required to build the bundled libriscv engine
AC_CHECK_PROG(CMAKE_CHECK, cmake, yes)
AS_IF([test "x$CMAKE_CHECK" != "xyes"],
	[AC_MSG_ERROR([cmake is required to build the libriscv engine.])])

AC_ARG_WITH([rst2man],
	[AS_HELP_STRING(
		[--with-rst2man=PATH],
		[Location of rst2man (auto)])],
	[RST2MAN="$withval"],
	[AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], [])])

m4_ifndef([VARNISH_PREREQ], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))

VARNISH_PREREQ([6.0])
VARNISH_VMODS([riscv])

VMOD_TESTS="$(cd $srcdir/src/ && echo tests/*.vtc)"
AC_SUBST(VMOD_TESTS)

PKG_CHECK_VAR([LIBVARNISHAPI_LIBDIR], [varnishapi], [libdir])
dnl Open-source Varnish keeps its private libs in $libdir/varnish; Varnish
dnl Enterprise (Varnish Plus) uses $libdir/varnish-plus. Include both so the
dnl `make check' harness finds them regardless of which one is installed -- a
dnl non-existent entry on LD_LIBRARY_PATH is harmless.
AC_SUBST([VARNISH_LIBRARY_PATH],
	[$LIBVARNISHAPI_LIBDIR:$LIBVARNISHAPI_LIBDIR/varnish:$LIBVARNISHAPI_LIBDIR/varnish-plus])

AM_CONDITIONAL([BUILD_RISCV_FOR_VCP],
	[test -d ${LIBVARNISHAPI_LIBDIR}/varnish-plus])

dnl ECALL_FETCH uses libcurv, which only Varnish Enterprise has
AM_COND_IF([BUILD_RISCV_FOR_VCP], [
	PKG_CHECK_MODULES([CURL], [libcurl], [],
		[AC_MSG_ERROR([libcurl not found. Install libcurl4-openssl-dev or libcurl-devel.])])
])

dnl Match the static defines the CMake build bakes into config.h
AC_DEFINE([HAVE_OBJITERATE_F], [1], [Define if ObjIterate has the final flag])
AC_DEFINE([HAVE_GETPEEREID], [1], [Define if getpeereid() is available])
AC_DEFINE([HAVE_SETPPRIV], [1], [Define if setppriv() is available])
AC_DEFINE([HAVE_CACHE_CACHE_VARNISHD_H], [1],
	[Define if cache/cache_varnishd.h is available])

AC_CONFIG_FILES([
	Makefile
	libriscv-engine/Makefile
	src/Makefile
])

AC_OUTPUT

AS_ECHO(["
  ==== $PACKAGE_STRING ====

    varnishd      : $VARNISH_VERSION
    vmod install  : $vmoddir
    C++ standard  : C++20 ($CXX)
    libcrypto     : $CRYPTO_LIBS
    build for VCP : $(test -d ${LIBVARNISHAPI_LIBDIR}/varnish-plus && echo yes || echo no)
"])
