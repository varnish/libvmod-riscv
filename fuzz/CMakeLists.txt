cmake_minimum_required(VERSION 3.16)
project(vmod_riscv_fuzz C CXX)
## libFuzzer harness for the tenant scripting API. Build with ./build.sh.

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	message(FATAL_ERROR "libFuzzer needs Clang: run ./build.sh, or pass -DCMAKE_CXX_COMPILER=clang++")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS ON)
set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/../src)

## Everything, libriscv included, gets coverage and sanitizers
set(SANITIZERS "-fsanitize=address,undefined -fno-sanitize=function,alignment -fno-sanitize-recover=all")
set(FUZZ_FLAGS "-g -fno-omit-frame-pointer -ffunction-sections -fdata-sections ${SANITIZERS} -fsanitize=fuzzer-no-link")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${FUZZ_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FUZZ_FLAGS} -DRISCV_SYSCALLS_MAX=601")

## Same emulator configuration as libriscv-engine/Makefile.am
set(RISCV_32I OFF CACHE BOOL "" FORCE)
set(RISCV_64I ON CACHE BOOL "" FORCE)
set(RISCV_EXT_C ON CACHE BOOL "" FORCE)
set(RISCV_BINARY_TRANSLATION OFF CACHE BOOL "" FORCE)
set(RISCV_LIBTCC OFF CACHE BOOL "" FORCE)
set(RISCV_FLAT_RW_ARENA OFF CACHE BOOL "" FORCE)
add_subdirectory(${SRC}/libriscv/lib libriscv)

find_package(PkgConfig REQUIRED)
pkg_check_modules(VARNISHAPI REQUIRED IMPORTED_TARGET varnishapi)
pkg_check_modules(PCRE REQUIRED IMPORTED_TARGET libpcre)
find_package(OpenSSL REQUIRED)

## The guest program, built like the tenant programs in tests/build.sh
string(REGEX MATCH "^[0-9]+" CLANG_MAJOR ${CMAKE_CXX_COMPILER_VERSION})
find_program(GUEST_LD NAMES ld.lld-${CLANG_MAJOR} ld.lld REQUIRED)
set(GUEST_ELF ${CMAKE_CURRENT_BINARY_DIR}/guest.elf)
add_custom_command(
	OUTPUT ${GUEST_ELF}
	COMMAND ${CMAKE_CXX_COMPILER} -O1 -Wall -target riscv64 -march=rv64imafdc
		-ffreestanding -nostdlib -fno-exceptions -fno-rtti
		-I${CMAKE_CURRENT_SOURCE_DIR}/../tests
		-c ${CMAKE_CURRENT_SOURCE_DIR}/guest.cpp -o guest.o
	COMMAND ${GUEST_LD} -Ttext=0x120000 guest.o -o ${GUEST_ELF}
	DEPENDS guest.cpp ../tests/riscv_api.hpp ../src/machine/syscalls.h
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_source_files_properties(fuzz_api.cpp PROPERTIES OBJECT_DEPENDS ${GUEST_ELF})

add_executable(fuzz_api
	fuzz_api.cpp
	fake_varnish.cpp
	${SRC}/script.cpp
	${SRC}/script_functions.cpp
	${SRC}/script_base64.cpp
	${SRC}/script_fetch.cpp
	${SRC}/script_sha256.cpp
	${SRC}/script_debug.cpp
	${SRC}/machine_instance.cpp
	${SRC}/sandbox_tenant.cpp
	${SRC}/builder/builder.cpp
	${SRC}/builder/builder_rust.cpp
	${SRC}/vcl/compiler.cpp
	${SRC}/vcl/vcl_program.cpp
	${SRC}/vcl/vcl_stats.cpp
	${SRC}/vcl/vcl_varnish.c
	${SRC}/vcl/vclc_blob.c
)
target_include_directories(fuzz_api PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${SRC}
	${SRC}/../ext/json/single_include
)
target_compile_definitions(fuzz_api PRIVATE
	VMOD=1 _GNU_SOURCE VARNISH_PLUS=1
	FUZZ_GUEST_ELF="${GUEST_ELF}"
)
## ECALL_FETCH needs libcurv in varnishd: the fuzzer gets the FETCH_ENOSYS stub
set_source_files_properties(${SRC}/script_fetch.cpp PROPERTIES
	COMPILE_DEFINITIONS "FETCH_SUPPORTED=0")
set_source_files_properties(${SRC}/vcl/vclc_blob.c PROPERTIES
	COMPILE_DEFINITIONS "VCLC_ELF_PATH=\"${SRC}/../vcl/vclc.elf\"")
## Only the VCL glue the scripting API reaches is linked in: the rest of
## vcl_varnish.c needs varnishd, and --gc-sections drops it.
separate_arguments(SANITIZER_LIST UNIX_COMMAND "${SANITIZERS}")
target_link_options(fuzz_api PRIVATE
	-fsanitize=fuzzer ${SANITIZER_LIST} -fuse-ld=lld -Wl,--gc-sections)
target_link_libraries(fuzz_api riscv PkgConfig::VARNISHAPI PkgConfig::PCRE OpenSSL::Crypto)
