cmake_minimum_required(VERSION 3.11.0)
project(builder C CXX)
#set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(LTO         "Link-time optimizations" OFF)
option(GCSECTIONS  "Garbage collect empty sections" OFF)
option(DEBUGGING   "Add debugging information" OFF)
set(VERSION_FILE   "symbols.map" CACHE STRING "Retained symbols file")
option(STRIP_SYMBOLS "Remove all symbols except the public API" OFF)

#
# Build configuration
#
set (BINPATH "${CMAKE_SOURCE_DIR}")
set (APIPATH "${CMAKE_CURRENT_LIST_DIR}/api")
set (UTILPATH "${CMAKE_CURRENT_LIST_DIR}/src/util")

set(WARNINGS  "-Wall -Wextra -Werror=return-type -Wno-unused")
set(COMMON    "-fno-math-errno -fno-stack-protector")
set(COMMON    "${COMMON} -fno-builtin-memcpy -fno-builtin-memset -fno-builtin-memmove -fno-builtin-memcmp")
set(COMMON    "${COMMON} -fno-builtin-strlen -fno-builtin-strcmp -fno-builtin-strncmp")
if (DEBUGGING)
	set (COMMON "${COMMON} -ggdb3 -O0")
else()
	set (COMMON "${COMMON} -ggdb3 -O2 -ffast-math")
endif()

# we have a linker script with separated text and rodata
if (GCC_TRIPLE STREQUAL "riscv64-linux-gnu")
	set(COMMON "-march=rv64gc_zba_zbb_zbc_zbs_zicond -mabi=lp64d ${COMMON}")
elseif (GCC_TRIPLE STREQUAL "riscv64-unknown-elf")
	set(COMMON "-march=rv64g_zba_zbb_zbc_zbs_zicond -mabi=lp64d ${COMMON}")
	set (XO_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/script64.ld")
else()
	set(COMMON "-march=rv32g_zba_zbb_zbc_zbs_zicond -mabi=ilp32d ${COMMON}")
	set (XO_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/script32.ld")
endif()
if (XO_SCRIPT)
	set(EXECUTE_ONLY TRUE)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--script=${XO_SCRIPT}")
endif()
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Ttext 0x120000")
set(FLAGS "${WARNINGS} ${RISCV_ABI} ${COMMON}")

if (LTO)
	set(FLAGS "${FLAGS} -flto -ffat-lto-objects")
endif()

if (GCSECTIONS)
	set(FLAGS "${FLAGS} -ffunction-sections -fdata-sections")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-gc-sections")
endif()

set(CMAKE_CXX_FLAGS "-std=gnu++23 -fno-threadsafe-statics ${FLAGS}")
set(CMAKE_C_FLAGS   "-std=gnu2x ${FLAGS}")

set(BUILD_SHARED_LIBS OFF)
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "") # remove -rdynamic
set(USE_NEWLIB ON)

# enforce correct global include order for our tiny libc
option(LIBC_WRAP_NATIVE "" ON)
include_directories(${CMAKE_CURRENT_LIST_DIR}/libc)
set (BBLIBCPATH "${CMAKE_CURRENT_LIST_DIR}/ext/libriscv/binaries/barebones/libc")
include_directories(${BBLIBCPATH})

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/ext  ext)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libc libc)
target_include_directories(libc PUBLIC ${APIPATH})
target_include_directories(libc PUBLIC ${UTILPATH})

set(CHPERM  ${CMAKE_CURRENT_LIST_DIR}/chperm)

function (add_micro_binary NAME)
	add_executable(${NAME} ${ARGN})
	if (LIBC_WRAP_NATIVE)
	target_link_libraries(${NAME} -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=_sbrk)
	target_link_libraries(${NAME} -Wl,--wrap=_malloc_r,--wrap=_calloc_r,--wrap=_realloc_r,--wrap=_free_r)
	target_link_libraries(${NAME} -Wl,--wrap=memalign,--wrap=posix_memalign,--wrap=aligned_alloc)
	target_link_libraries(${NAME} -Wl,--wrap=_memalign_r)
	endif()
	target_link_libraries(${NAME} -static -Wl,--whole-archive libc -Wl,--no-whole-archive)
	target_link_libraries(${NAME} fmt nlohmann_json tinyxml2 qjs)
	# strip symbols but keep public API
	if (STRIP_SYMBOLS AND NOT DEBUGGING)
		add_custom_command(TARGET ${NAME} POST_BUILD
		COMMAND ${CMAKE_STRIP} --strip-debug -R .note -R .comment -- ${CMAKE_BINARY_DIR}/${NAME})
	endif()
	if (EXECUTE_ONLY)
		add_custom_command(
			TARGET ${NAME} POST_BUILD
			COMMAND ${CHPERM} ${CMAKE_CURRENT_BINARY_DIR}/${NAME} 1 x
		)
	endif()
endfunction()
