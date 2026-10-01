.PHONY: blob

# The compiler embeds ../runtime.elf; it never builds this image on demand.
# Rebuild after a change to ../src or to link.ld, then commit the blob and
# rebuild the compiler guest (../../vclc), which embeds the compiler.
#
# The build flags live here rather than in .cargo/config.toml because one of
# them is not a constant: a panic location in vcl-rt reaches the image as an
# absolute path, so an unremapped build is only reproducible on the machine
# that made it. RUSTFLAGS replaces config.toml's rustflags wholesale, so this
# is the single place that carries all three.
ROOT := $(abspath ../..)

blob:
	RUSTFLAGS='-C relocation-model=static -C link-arg=-Tlink.ld --remap-path-prefix=$(ROOT)=/vcl' \
	  cargo build --release
	cp target/riscv64gc-unknown-none-elf/release/vcl-rt-guest ../runtime.elf
