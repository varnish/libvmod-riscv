option(LIBC_WRAP_NATIVE "" OFF)

set(LIBC_SOURCES
	engine.cpp
	write.cpp
	${BBLIBCPATH}/libc.cpp
	${BBLIBCPATH}/libcxx.cpp
  )
if (GCC_TRIPLE STREQUAL "riscv32-unknown-elf")
	# There is a problem with heap on 64-bit
	list(APPEND LIBC_SOURCES
		assert.cpp
		${BBLIBCPATH}/heap.cpp
	)
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
if (LIBC_WRAP_NATIVE)
	target_compile_definitions(libc PRIVATE
		WRAP_NATIVE_SYSCALLS=1)
endif()

if (USE_NEWLIB)
	target_compile_definitions(libc PUBLIC
		USE_NEWLIB=1
	)
endif()
target_link_libraries(libc PUBLIC fmt)
