#!/bin/bash
set -e
cmake_extra=""
do_32bit="OFF"
do_64bit="ON"
do_bintr="ON"
do_jit="ON"
do_cext="ON"
build_type="Release"
varnish_plus="OFF"

usage() {
	echo "Usage: $0 [-v] [--enterprise]"
	echo "  -v            verbose build"
	echo "  --enterprise  build for Varnish Enterprise"
	exit 1
}

for i in "$@"; do
	case $i in
		--32)
			do_32bit="ON"
			do_64bit="OFF"
			shift
			;;
		--64)
			do_32bit="OFF"
			do_64bit="ON"
			shift
			;;
		--enterprise)
            varnish_plus="ON"
            shift
            ;;
		--jit)
			do_bintr="ON"
			do_jit="ON"
			shift
			;;
		--no-jit)
			do_jit="OFF"
			shift
			;;
		--bintr)
			do_bintr="ON"
			shift
			;;
		--no-bintr)
			do_bintr="OFF"
			shift
			;;
		--C)
			do_cext="ON"
			shift
			;;
		--no-C)
			do_cext="OFF"
			shift
			;;
		--native)
			cmake_extra="$cmake_extra -DNATIVE=ON"
			shift
			;;
		--no-native)
			cmake_extra="$cmake_extra -DNATIVE=OFF"
			shift
			;;
		--sanitize)
			build_type="Debug"
			cmake_extra="$cmake_extra -DSANITIZE=ON"
			shift
			;;
		--no-sanitize)
			build_type="Release"
			cmake_extra="$cmake_extra -DSANITIZE=OFF"
			shift
			;;
		--debug)
			build_type="Debug"
			cmake_extra="$cmake_extra -DSANITIZE=OFF"
			shift
			;;
		--release)
			build_type="Release"
			cmake_extra="$cmake_extra -DSANITIZE=OFF"
			shift
			;;
		-v)
			export VERBOSE=1
			shift
			;;
		-*|--*)
			echo "Unknown option $i"
			exit 1
			;;
		*)
		;;
	esac
done

# If ext/json is missing, update submodules
if [ ! -f ext/json/CMakeLists.txt ]; then
	echo "Updating git submodules"
	git submodule update --init --recursive
fi

mkdir -p .build
pushd .build
cmake .. -DCMAKE_BUILD_TYPE=$build_type -DVARNISH_PLUS=$varnish_plus -DRISCV_32I=$do_32bit -DRISCV_64I=$do_64bit -DRISCV_EXT_C=$do_cext -DRISCV_BINARY_TRANSLATION=$do_bintr -DRISCV_LIBTCC=$do_jit $cmake_extra
cmake --build . -j6
popd

VPATH="/usr/lib/varnish/vmods/"
VEPATH="/usr/lib/varnish-plus/vmods/"
if [ "$varnish_plus" == "ON" ]; then
	VPATH=$VEPATH
fi

echo "Installing vmod into $VPATH"
sudo cp .build/libvmod_*.so $VPATH
