#!/usr/bin/env bash
set -e

export GCC_TRIPLE="$1"
PROGPATH="$2"
FILE="$3"
FINALFILE="$4"

PROGRAMS="$PROGPATH/program"
TOOLCHAIN="$PROGRAMS/cpp/micro/toolchain.cmake"

CODETMPDIR=${FINALFILE}.d
mkdir -p $CODETMPDIR
trap 'rm -rf -- "$CODETMPDIR"' EXIT

pushd $CODETMPDIR > /dev/null
ln -s $FILE program.cpp

cat <<\EOT >CMakeLists.txt
cmake_minimum_required(VERSION 3.12)
project(programs CXX)

include(${PROGRAMS}/cpp/micro/micro.cmake)

add_micro_binary(program program.cpp)
EOT

source $PROGRAMS/detect_compiler.sh

cmake . -DGCC_TRIPLE="$GCC_TRIPLE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" -DPROGRAMS="$PROGRAMS" 2>&1
make -j8 2>&1
popd > /dev/null

mv $CODETMPDIR/program $FINALFILE
#echo "Moved $CODETMPDIR/program to $FINALFILE"
