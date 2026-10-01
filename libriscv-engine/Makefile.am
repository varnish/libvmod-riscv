## Builds the bundled libriscv RISC-V emulator (src/libriscv) as a static
## archive that the VMOD links into libvmod_riscv.so.
##
## This mirrors how sledge builds its engine (sledgejsengine) out-of-band:
## the engine keeps its own (CMake) build system and we drive it from an
## all-local hook, then the VMOD links the resulting archive.
##
## NOTE: RISCV_SYSCALLS_MAX must match the value used when compiling the VMOD
## sources (see src/Makefile.am: AM_CPPFLAGS).

ENGINE_SRC   = $(abs_top_srcdir)/src/libriscv
ENGINE_BUILD = $(abs_builddir)/build
ENGINE_LIB   = $(ENGINE_BUILD)/libriscv.a

RISCV_CMAKE_FLAGS = \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
	-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(ENGINE_BUILD) \
	-DRISCV_32I=OFF \
	-DRISCV_64I=ON \
	-DRISCV_EXT_C=ON \
	-DRISCV_BINARY_TRANSLATION=OFF \
	-DRISCV_LIBTCC=OFF \
	-DRISCV_FLAT_RW_ARENA=OFF \
	-DCMAKE_CXX_FLAGS="-DRISCV_SYSCALLS_MAX=601"

all-local: $(ENGINE_LIB)

## Rebuilt when this Makefile changes, so a changed RISCV_CMAKE_FLAGS (such
## as RISCV_SYSCALLS_MAX) never leaves a stale archive that disagrees with
## the VMOD about the system call table's size. cmake --build is incremental.
$(ENGINE_LIB): Makefile
	@test -f $(ENGINE_SRC)/CMakeLists.txt || { \
		echo "error: src/libriscv is empty -- run 'git submodule update --init --recursive'"; \
		exit 1; }
	cmake -S $(ENGINE_SRC) -B $(ENGINE_BUILD) $(RISCV_CMAKE_FLAGS)
	cmake --build $(ENGINE_BUILD) --target riscv -j

clean-local:
	rm -rf $(ENGINE_BUILD)
