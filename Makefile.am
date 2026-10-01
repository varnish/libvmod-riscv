ACLOCAL_AMFLAGS = -I m4 -I ${VARNISHAPI_DATAROOTDIR}/aclocal

# Build the bundled libriscv engine (static lib) before the VMOD links it.
SUBDIRS = . libriscv-engine src

# Install README + LICENSE under $(docdir), mirroring how sledge ships its
# dist_doc_DATA -- the redhat spec packages %{_docdir}/%{name}/*.
dist_doc_DATA = README.md LICENSE

# Keep the CMake-based developer build shippable inside the dist tarball.
# src/libriscv is the bundled engine (a git submodule); it must be in the
# tarball or libriscv-engine's cmake step has nothing to build from a release.
EXTRA_DIST = \
	get_version \
	vcp.version \
	build.sh \
	CMakeLists.txt \
	ext \
	src/libriscv \
	vcl/vclc.elf \
	demo

# Ship the demo/example VCL alongside the module.
vcldir = $(datarootdir)/varnish-plus/vcl
dist_vcl_DATA = \
	demo/demo.vcl \
	demo/demo-docker.vcl
