add_vmod(vmod_riscv vmod_riscv.vcc "Low-Latency Configuration VMOD"
	builder/builder.cpp
	builder/builder_rust.cpp
	backend.cpp
	bench_fork.cpp
	live_update.cpp
	machine_instance.cpp
	sandbox_tenant.cpp
	script.cpp
	script_debug.cpp
	script_functions.cpp
	script_base64.cpp
	script_sha256.cpp
	tenancy.cpp
	varnish_cpp_interface.cpp
	varnish_interface.c
	vmod_cpp_interface.cpp
	vmod_riscv_backend.c
	vmod_riscv_deliver.c
	vmod_riscv.c
	vmod_riscv_post.c
	vmod_riscv_update.c
	vcl/compiler.cpp
	vcl/vcl_program.cpp
	vcl/vcl_stats.cpp
	vcl/vcl_syscalls.cpp
	vcl/vcl_varnish.c
	vcl/vclc_blob.c
	js/js_program.cpp
	js/js_blob.c
)
# vcl/vclc_blob.c embeds the sandboxed VCL compiler with .incbin
set(VCLC_ELF "${CMAKE_CURRENT_SOURCE_DIR}/../vcl/vclc.elf")
set_source_files_properties(vcl/vclc_blob.c PROPERTIES
	COMPILE_DEFINITIONS "VCLC_ELF_PATH=\"${VCLC_ELF}\""
	OBJECT_DEPENDS "${VCLC_ELF}")
# js/js_blob.c embeds the QuickJS guest the same way
set(JS_ELF "${CMAKE_CURRENT_SOURCE_DIR}/../program/js.elf")
set_source_files_properties(js/js_blob.c PROPERTIES
	COMPILE_DEFINITIONS "JS_ELF_PATH=\"${JS_ELF}\""
	OBJECT_DEPENDS "${JS_ELF}")
#add_vmod_vsc(vmod_riscv VSC_vmod_kvm.vsc)

# RISC-V sandbox library
option(RISCV_FLAT_RW_ARENA "" OFF)
option(RISCV_ASMJIT "" ON)
set(RISCV_ASMJIT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ext/asmjit" CACHE PATH "")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_subdirectory(libriscv)
target_compile_definitions(riscv PUBLIC RISCV_SYSCALLS_MAX=601)
add_subdirectory(../ext/json ext_json)
find_package(OpenSSL REQUIRED)
target_link_libraries(vmod_riscv riscv nlohmann_json::nlohmann_json OpenSSL::Crypto)

# Find mimalloc (optional)
find_package(mimalloc QUIET)
if (mimalloc_FOUND)
	target_link_libraries(vmod_riscv mimalloc)
	message(STATUS "Using mimalloc")
else()
	message(STATUS "mimalloc not found, using system malloc")
endif()

# Compute tests
enable_testing()
file(GLOB VMOD_TESTS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.vtc)
add_vmod_tests(vmod_riscv vmod_riscv ${VMOD_TESTS})
