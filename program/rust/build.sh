#!/usr/bin/env sh
TYPE=release
set -e

# Rustc
cargo build --$TYPE --color never
