.PHONY: blob

# The VMOD embeds ../vclc.elf (src/vcl/vclc_blob.c); it never builds this
# image on demand, so building the VMOD needs no Rust or RISC-V toolchain.
# The blob is committed.
#
# Rebuild after a change to any of:
#   vcl/compiler/      the compiler itself
#   vcl/runtime/       the runtime image the compiler embeds (runtime.elf)
#   vcl/vclc/          this program, its profile, its toolchain pin
#
# The flags live here rather than in .cargo/config.toml because RUSTFLAGS
# replaces that file's rustflags wholesale, so this has to be the single
# place that carries all of them.
#
# The sources are copied to a fixed staging path and built there: cargo
# derives each crate's disambiguator from a path dependency's *absolute*
# path, and that reaches every symbol name and so the layout of .text. A
# fixed path is what makes the blob come out identical for everyone.
# Zig's __anon_<N> symbols (from the musl it links in) are stripped: since
# 0.17 N carries the id of the compiler thread that made it.
ROOT := $(abspath ..)
CHECKOUT_TARGET := $(CURDIR)/target

STAGE ?= /tmp/libvmod-riscv-vclc-blob

export ZIG ?= zig
SYSROOT := $(shell rustc --print sysroot)
OBJCOPY := $(SYSROOT)/lib/rustlib/$(shell rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy
RUST_SRC_REMAP := $(SYSROOT)/lib/rustlib/src/rust=/rustc/$(shell rustc -vV | sed -n 's/^commit-hash: //p')

GUEST_RUSTFLAGS := -C target-feature=+crt-static
GUEST_RUSTFLAGS += -C linker=$(STAGE)/vclc/zig-cc
GUEST_RUSTFLAGS += -C link-self-contained=no
GUEST_RUSTFLAGS += -C link-arg=-Wl,--no-gc-sections
GUEST_RUSTFLAGS += -C link-arg=-Wl,-u,fast_exit
GUEST_RUSTFLAGS += --remap-path-prefix=$(STAGE)=/vcl
GUEST_RUSTFLAGS += --remap-path-prefix=$(RUST_SRC_REMAP)

blob:
	rm -rf $(STAGE)
	mkdir -p $(STAGE)
	cd $(ROOT) && tar -c --exclude=target --exclude=vclc.elf \
	  compiler runtime vclc | tar -x -C $(STAGE)
	cd $(STAGE)/vclc && \
	  RUSTFLAGS='$(GUEST_RUSTFLAGS)' CARGO_TARGET_DIR='$(CHECKOUT_TARGET)' \
	  cargo build --release
	$(OBJCOPY) --strip-debug --discard-locals --wildcard --strip-symbol='__anon_*' \
	  $(CHECKOUT_TARGET)/riscv64gc-unknown-linux-musl/release/vclc ../vclc.elf
	rm -rf $(STAGE)
