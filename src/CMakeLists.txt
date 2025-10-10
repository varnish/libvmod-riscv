add_vmod(vmod_riscv vmod_riscv.vcc "Low-Latency Configuration VMOD"
	builder/builder.cpp
	builder/builder_rust.cpp
	backend.cpp
	live_update.cpp
	machine_instance.cpp
	sandbox_tenant.cpp
	script.cpp
	script_debug.cpp
	script_functions.cpp
	script_sha256.cpp
	tenancy.cpp
	varnish_cpp_interface.cpp
	varnish_interface.c
	vmod_cpp_interface.cpp
	vmod_riscv_backend.c
	vmod_riscv.c
	vmod_riscv_post.c
	vmod_riscv_update.c
)
#add_vmod_vsc(vmod_riscv VSC_vmod_kvm.vsc)

# RISC-V sandbox library
option(RISCV_FLAT_RW_ARENA "" OFF)
add_subdirectory(libriscv)
target_compile_definitions(riscv PUBLIC RISCV_SYSCALLS_MAX=600)
target_compile_options(riscv PUBLIC -fPIC)
add_subdirectory(../ext/json ext_json)
target_link_libraries(vmod_riscv riscv nlohmann_json::nlohmann_json)

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
add_vmod_tests(vmod_riscv vmod_riscv
	tests/empty.vtc
	tests/faulty_loop.vtc
	tests/hello_backend_world.vtc
	tests/hello_synth_world.vtc
)
