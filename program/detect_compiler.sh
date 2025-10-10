# System-provided GCC variants
if [ -z "$GCC_TRIPLE" ]; then
	export GCC_TRIPLE="riscv32-unknown-elf"
	echo "Using default GCC_TRIPLE: $GCC_TRIPLE"
fi
export CC="$GCC_TRIPLE-gcc"
export CXX="$GCC_TRIPLE-g++"
# Check for existence of the compiler
if command -v $CC >/dev/null 2>&1; then
	echo "Using compiler: $CC"
elif command -v $CC-12 >/dev/null 2>&1; then
	export CC="$CC-12"
	export CXX="$CXX-12"
	echo "Using compiler: $CC"
elif command -v $CC-13 >/dev/null 2>&1; then
	export CC="$CC-13"
	export CXX="$CXX-13"
	echo "Using compiler: $CC"
elif command -v $CC-14 >/dev/null 2>&1; then
	export CC="$CC-14"
	export CXX="$CXX-14"
	echo "Using compiler: $CC"
else
	echo "Error: Compiler $CC not found" >&2
	exit 1
fi

# Check for ccache
if command -v ccache >/dev/null 2>&1; then
	export CC="ccache $CC"
	export CXX="ccache $CXX"
fi
