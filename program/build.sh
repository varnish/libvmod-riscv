#!/bin/bash
set -e
export GCC_TRIPLE="riscv64-unknown-elf"
source "detect_compiler.sh"

mkdir -p $GCC_TRIPLE
pushd $GCC_TRIPLE
cmake ../cpp -DGCC_TRIPLE=$GCC_TRIPLE -DCMAKE_TOOLCHAIN_FILE=micro/toolchain.cmake
make -j4
popd
