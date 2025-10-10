#pragma once
#include <include/syscall.hpp>
#include <tuple>

inline std::tuple<long, long>
syscall_ll(long n)
{
	register long a0 asm("a0");
	register long a1 asm("a1");
	register long syscall_id asm("a7") = n;

	asm volatile ("scall" : "=r"(a0), "=r"(a1) : "r"(syscall_id));

	return std::make_tuple(long{a0}, long{a1});
}

inline std::tuple<long, long>
syscall_ll(long n, long arg0, long arg1)
{
	register long a0 asm("a0") = arg0;
	register long a1 asm("a1") = arg1;
	register long syscall_id asm("a7") = n;

	asm volatile ("scall" : "+r"(a0), "+r"(a1) : "r"(syscall_id));

	return std::make_tuple(long{a0}, long{a1});
}

inline std::tuple<float, float>
fsyscallff(long n, float farg0, float farg1)
{
	register float fa0 asm("fa0") = farg0;
	register float fa1 asm("fa1") = farg1;
	register long syscall_id asm("a7") = n;

	asm volatile ("scall"
		: "+f"(fa0), "+f"(fa1) : "r"(syscall_id) : "a0");

	return std::make_tuple(float{fa0}, float{fa1});
}

inline std::tuple<float, float>
fsyscallff(long n, float farg0, float farg1, float farg2)
{
	register float fa0 asm("fa0") = farg0;
	register float fa1 asm("fa1") = farg1;
	register float fa2 asm("fa2") = farg2;
	register long syscall_id asm("a7") = n;

	asm volatile ("scall"
		: "+f"(fa0), "+f"(fa1) : "f"(fa2), "r"(syscall_id) : "a0");

	return {float{fa0}, float{fa1}};
}
