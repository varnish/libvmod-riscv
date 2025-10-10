#!/usr/bin/env sh
TYPE=release
FILE=target/riscv64gc-unknown-none-elf/$TYPE/rusty
set -e

# Rustc
cargo +nightly build --$TYPE --color never
