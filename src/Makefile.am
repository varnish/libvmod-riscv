## libvmod_riscv -- the RISC-V sandbox VMOD.
##
## The VMOD glue is C; the sandbox/runtime is C++20. The bundled libriscv
## emulator is built as a static archive by ../libriscv-engine and linked in
## here. This Makefile.am lives alongside the (untouched) CMakeLists.txt so the
## CMake developer build keeps working; automake and cmake ignore each other.

RISCV_ENGINE_LIB = $(top_builddir)/libriscv-engine/build/libriscv.a

AM_CPPFLAGS = \
	-I$(srcdir) \
	-I$(builddir) \
	-I$(top_srcdir)/src/libriscv/lib \
	-I$(top_builddir)/libriscv-engine/build/lib \
	-I$(top_srcdir)/ext/json/single_include \
	-DVMOD=1 \
	-D_GNU_SOURCE \
	-DRISCV_SYSCALLS_MAX=601 \
	$(CRYPTO_CFLAGS)

## -Wa,-I lets vcl/vclc_blob.c .incbin the sandboxed VCL compiler.
AM_CFLAGS   = $(VARNISHAPI_CFLAGS) -Wall -Wa,-I$(top_srcdir)/vcl
AM_CXXFLAGS = $(VARNISHAPI_CFLAGS) -Wall
AM_LDFLAGS  = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

if BUILD_RISCV_FOR_VCP
AM_CPPFLAGS += -DVARNISH_PLUS=1
endif

vmod_LTLIBRARIES = libvmod_riscv.la

if BUILD_RISCV_FOR_VCP
libvmod_riscv_la_LDFLAGS = \
	-module -export-dynamic -avoid-version -shared \
	-R $(libdir)/varnish-plus $(AM_LDFLAGS)
else
libvmod_riscv_la_LDFLAGS = \
	-module -export-dynamic -avoid-version -shared $(AM_LDFLAGS)
endif

libvmod_riscv_la_SOURCES = \
	builder/builder.cpp \
	builder/builder_rust.cpp \
	backend.cpp \
	live_update.cpp \
	machine_instance.cpp \
	sandbox_tenant.cpp \
	script.cpp \
	script_debug.cpp \
	script_functions.cpp \
	script_sha256.cpp \
	tenancy.cpp \
	varnish_cpp_interface.cpp \
	vmod_cpp_interface.cpp \
	varnish_interface.c \
	vmod_riscv_backend.c \
	vmod_riscv.c \
	vmod_riscv_post.c \
	vmod_riscv_update.c \
	vcl/compiler.cpp \
	vcl/vcl_program.cpp \
	vcl/vcl_stats.cpp \
	vcl/vcl_syscalls.cpp \
	vcl/vcl_varnish.c \
	vcl/vclc_blob.c

nodist_libvmod_riscv_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

libvmod_riscv_la_LIBADD = \
	$(RISCV_ENGINE_LIB) \
	$(CRYPTO_LIBS) \
	$(PTHREAD_LIBS)

noinst_HEADERS = \
	builder/builder.hpp \
	machine_instance.hpp \
	memarea.hpp \
	riscv_backend.h \
	script.hpp \
	script_cache.hpp \
	script_functions.hpp \
	sandbox_tenant.hpp \
	tenant.hpp \
	timing.hpp \
	update_result.h \
	varnish.hpp \
	varnish_interface.h \
	vmod_riscv.h \
	vmod_riscv_sandbox.h \
	vmod_util.h \
	vcl/abi.hpp \
	vcl/compiler.hpp \
	vcl/vcl_program.hpp \
	vcl/vcl_stats.hpp \
	vcl/vcl_varnish.h

dist_man_MANS = vmod_riscv.3

## The embedded compiler is an .incbin, which dependency tracking cannot see.
vcl/vclc_blob.lo: $(top_srcdir)/vcl/vclc.elf

## --- VCC interface + man page generation ---------------------------------
## The sources #include "vcc_if.h" (CMake's base name), so we generate
## vcc_if.{c,h} explicitly rather than using @BUILD_VMOD_RISCV@ (which would
## produce vcc_riscv_if.*). BUILT_SOURCES forces the header before any TU.

BUILT_SOURCES = vcc_if.h

vcc_if.h vmod_riscv.rst vmod_riscv.man.rst: vcc_if.c

## $Addon is a Varnish Enterprise stanza, unknown to open-source vmodtool.
vcc_if.c: $(srcdir)/vmod_riscv.vcc
	if grep -q AddonStanza $(VMODTOOL); then \
		$(PYTHON) $(VMODTOOL) -o vcc_if $(srcdir)/vmod_riscv.vcc; \
	else \
		sed '/^\$$Addon/d' $(srcdir)/vmod_riscv.vcc > vmod_riscv_oss.vcc && \
		$(PYTHON) $(VMODTOOL) -o vcc_if vmod_riscv_oss.vcc; \
	fi

vmod_riscv.3: vmod_riscv.man.rst
	$(RST2MAN) vmod_riscv.man.rst $@

## --- tests ---------------------------------------------------------------
AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
## Wrapper injects -Dtestname=<basename> per test (varnishtest has no native
## ${testname} macro; CMake passes it explicitly). See tests/vtc-runner.sh.
VTC_LOG_COMPILER = $(srcdir)/tests/vtc-runner.sh
AM_VTC_LOG_FLAGS = \
	-p vmod_path="$(abs_builddir)/.libs" \
	-Dtopsrc="$(abs_top_srcdir)" \
	-DVMOD_SO="\"$(abs_builddir)/.libs/libvmod_riscv.so\""

TESTS = $(VMOD_TESTS)

EXTRA_DIST = \
	vmod_riscv.vcc \
	tests/vtc-runner.sh \
	tests/build.sh \
	builder/builder.sh \
	builder/builder.sh.h \
	machine/crc32_embedded.hpp \
	machine/include_api.hpp \
	machine/syscalls.h \
	$(VMOD_TESTS)

CLEANFILES = \
	vcc_if.c vcc_if.h vmod_riscv_oss.vcc \
	vmod_riscv.rst vmod_riscv.man.rst vmod_riscv.3
