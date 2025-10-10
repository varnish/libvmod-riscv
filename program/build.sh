#!/bin/bash
set -e
source "detect_compiler.sh"

mkdir -p $GCC_TRIPLE
pushd $GCC_TRIPLE
cmake ../cpp -DGCC_TRIPLE=$GCC_TRIPLE -DCMAKE_TOOLCHAIN_FILE=micro/toolchain.cmake
make -j4
popd
