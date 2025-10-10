#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

extern "C" {
__attribute__((noreturn)) void _exit(int);
__attribute__((noreturn)) void panic(const char* reason);
int  print_backtrace();
}

#include "syscall.hpp"
#include <syscalls.h>

inline int sys_write(const char* data, size_t len)
{
	return syscall(ECALL_WRITE, (long) data, len);
}

inline int print_backtrace()
{
	return syscall(SYSCALL_BACKTRACE);
}

inline void writestr(const char* text)
{
	syscall(ECALL_WRITE, (long) text, __builtin_strlen(text));
}

#include <fmt/format.h>

template <typename... Args>
inline long fmt_print(fmt::format_string<Args...> format, Args&&... args)
{
	char buffer[2048];
	auto result = fmt::format_to_n(buffer, sizeof(buffer)-1, format, std::forward<Args>(args)...);
	*result.out = '\0'; // null-terminate
	const size_t size = result.size;

	register const char* a0 asm("a0") = buffer;
	register size_t      a1 asm("a1") = size;
	register long syscall_id asm("a7") = ECALL_WRITE;
	register long        a0_out asm("a0");

	asm volatile ("ecall" : "=r"(a0_out)
		: "r"(a0), "m"(*(const char(*)[size]) a0), "r"(a1), "r"(syscall_id));
	return a0_out;
}
