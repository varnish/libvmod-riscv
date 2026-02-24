#include "engine.hpp"
#include <api.h>

__attribute__((noinline)) void halt()
{
	asm (".insn i SYSTEM, 0, x0, x0, 0x7ff" ::: "memory");
}

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)
#define GENERATE_SYSCALL_WRAPPER(name, number) \
	asm(".global " #name "\n" #name ":\n  li a7, " STRINGIFY(number) "\n  ecall\n  ret\n");

asm(".pushsection .text, \"ax\", @progbits\n");
GENERATE_SYSCALL_WRAPPER(sys_register_callback, ECALL_REGISTER_CB);
GENERATE_SYSCALL_WRAPPER(sys_field_retrieve,    ECALL_FIELD_RETRIEVE);
GENERATE_SYSCALL_WRAPPER(sys_field_retrieve_str, ECALL_FIELD_RETRIEVE_STR);
GENERATE_SYSCALL_WRAPPER(sys_field_set,         ECALL_FIELD_SET);
GENERATE_SYSCALL_WRAPPER(sys_field_append,      ECALL_FIELD_APPEND);
asm(".popsection\n");

extern "C" __attribute__((noinline))
void breakpoint() {
	register long syscall_id asm("a7") = ECALL_BREAKPOINT;

	asm volatile ("ecall" : : "r"(syscall_id));
}

extern "C" __attribute__((used, retain))
void fast_exit() {
	halt();
}

extern "C"
api::response backend_trampoline(api::backend_function_b func)
{
	constexpr auto bereq  = api::Request  {api::HDR_BEREQ};
	constexpr auto beresp = api::Response {api::HDR_BERESP};
	return func(bereq, beresp);
}
extern "C"
api::response backend_trampoline_post(api::backend_function_c func, void* data, size_t size)
{
	constexpr auto bereq  = api::Request  {api::HDR_BEREQ};
	constexpr auto beresp = api::Response {api::HDR_BERESP};
	return func(bereq, beresp, data, size);
}

extern "C" void flockfile(FILE *) {}
extern "C" void funlockfile(FILE *) {}
