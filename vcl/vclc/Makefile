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
ROOT := $(abspath ..)
CHECKOUT_TARGET := $(CURDIR)/target

STAGE ?= /tmp/libvmod-riscv-vclc-blob

GUEST_RUSTFLAGS := -C target-feature=+crt-static
GUEST_RUSTFLAGS += -C link-arg=-Wl,--no-gc-sections
GUEST_RUSTFLAGS += -C link-arg=-Wl,--undefined=fast_exit
GUEST_RUSTFLAGS += -C link-arg=-Wl,--wrap=memcpy
GUEST_RUSTFLAGS += -C link-arg=-Wl,--wrap=memset
GUEST_RUSTFLAGS += -C link-arg=-Wl,--wrap=memmove
GUEST_RUSTFLAGS += -C link-arg=-Wl,--wrap=memcmp
GUEST_RUSTFLAGS += -C link-arg=-Wl,--wrap=__memcmpeq
GUEST_RUSTFLAGS += -C link-arg=-Wl,--wrap=bcmp
GUEST_RUSTFLAGS += --remap-path-prefix=$(STAGE)=/vcl

blob:
	rm -rf $(STAGE)
	mkdir -p $(STAGE)
	cd $(ROOT) && tar -c --exclude=target --exclude=vclc.elf \
	  compiler runtime vclc | tar -x -C $(STAGE)
	cd $(STAGE)/vclc && \
	  RUSTFLAGS='$(GUEST_RUSTFLAGS)' CARGO_TARGET_DIR='$(CHECKOUT_TARGET)' \
	  cargo build --release
	cp $(CHECKOUT_TARGET)/riscv64gc-unknown-linux-gnu/release/vclc ../vclc.elf
	rm -rf $(STAGE)
