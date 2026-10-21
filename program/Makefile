.PHONY: blob

# The VMOD embeds js.elf (src/js/js_blob.c), the QuickJS guest (cpp/js.cpp),
# so that a tenant can be a .js file: the VMOD loads this program and passes
# the file as its last argument. It never builds the image on demand, so
# building the VMOD needs no RISC-V toolchain. The blob is committed.
#
# Rebuild after a change to cpp/js.cpp, the micro API/libc (cpp/micro) or
# QuickJS, fmt, nlohmann/json or tinyxml2.
#
# The sources are copied to a fixed staging path and built there, because
# the build directory and source paths reach the binary (__FILE__, and the
# order of the objects). A fixed path is what makes the blob come out
# identical for everyone. Debug info (zig's musl and libc++ carry the path
# zig is installed at) and assembler temporaries are stripped, but not
# .symtab: the host resolves fast_exit by name, and names functions in
# backtraces. `zig objcopy` cannot do this, so it takes llvm-objcopy (set
# OBJCOPY if it is not found).
ROOT := $(abspath ..)

STAGE ?= /tmp/libvmod-riscv-js-blob

export ZIG ?= zig
GCC_TRIPLE := riscv64-linux-musl
OBJCOPY ?= $(firstword $(foreach v,llvm-objcopy llvm-objcopy-20 \
  llvm-objcopy-19 llvm-objcopy-18,$(shell command -v $(v))))

blob:
	@test -n '$(OBJCOPY)' || { echo 'llvm-objcopy not found (set OBJCOPY)' >&2; exit 1; }
	rm -rf $(STAGE)
	mkdir -p $(STAGE)
	cd $(ROOT) && tar -c --exclude=.git \
	  program/cpp ext/json ext/tinyxml2 src/libriscv/binaries/barebones/libc \
	  | tar -x -C $(STAGE)
	cd $(STAGE) && \
	  CC='$(ZIG) cc -target $(GCC_TRIPLE)' CXX='$(ZIG) c++ -target $(GCC_TRIPLE)' \
	  cmake -S program/cpp -B build -DGCC_TRIPLE=$(GCC_TRIPLE) \
	    -DCMAKE_TOOLCHAIN_FILE=micro/toolchain.cmake
	$(MAKE) -C $(STAGE)/build js
	$(OBJCOPY) --strip-debug --discard-locals $(STAGE)/build/js js.elf
	rm -rf $(STAGE)
