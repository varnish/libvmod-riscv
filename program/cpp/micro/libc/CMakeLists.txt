set(LIBC_SOURCES
	engine.cpp
	write.cpp
	${BBLIBCPATH}/libc.cpp
	${BBLIBCPATH}/libcxx.cpp
  )
if (GCC_TRIPLE STREQUAL "riscv32-unknown-elf" OR GCC_TRIPLE STREQUAL "riscv64-unknown-elf")
	list(APPEND LIBC_SOURCES
		assert.cpp
		${BBLIBCPATH}/heap.cpp
	)
else()
	# musl and glibc: the native heap, see micro.cmake
	list(APPEND LIBC_SOURCES heap_linux.cpp)
endif()
if (NOT USE_NEWLIB)
	list(APPEND LIBC_SOURCES start.cpp)
endif()

set_source_files_properties(${BBLIBCPATH}/libc.cpp
	PROPERTIES COMPILE_FLAGS -fno-builtin)


add_library(libc STATIC ${LIBC_SOURCES})
target_include_directories(libc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(libc PUBLIC
	NATIVE_MEM_SYSCALLS=580
)
# micro.cmake wraps the C library's allocator with the native heap
target_compile_definitions(libc PRIVATE
	WRAP_NATIVE_SYSCALLS=1)

if (GCC_TRIPLE STREQUAL "riscv64-linux-musl")
	target_compile_definitions(libc PRIVATE
		LIBC_MUSL=1)
endif()

if (USE_NEWLIB)
	target_compile_definitions(libc PUBLIC
		USE_NEWLIB=1
	)
endif()
target_link_libraries(libc PUBLIC fmt)
