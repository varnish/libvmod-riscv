#pragma once
#include <cassert>
#include <new>
#include <utility>
#include <include/libc.hpp>
#include <include/function.hpp>
#include <include/tuplecall.hpp>
#if __has_include(<reent.h>)
#define IS_NEWLIB 1
#else
#define IS_NEWLIB 0
#endif

#define string_hash(x) crc32(value)

inline auto hart_id()
{
	uint64_t id;
	asm ("csrr %0, mhartid\n" : "=r"(id));
	return id;
}

#if __riscv_xlen == 32

inline auto rdcycle()
{
	union {
		uint64_t whole;
		uint32_t word[2];
	};
	asm ("rdcycleh %0\n rdcycle %1\n" : "=r"(word[1]), "=r"(word[0]) :: "memory");
	return whole;
}
inline auto rdtime()
{
	union {
		uint64_t whole;
		uint32_t word[2];
	};
	asm ("rdtimeh %0\n rdtime %1\n" : "=r"(word[1]), "=r"(word[0]) :: "memory");
	return whole;
}

#else

inline auto rdcycle()
{
	uint64_t whole;
	asm ("rdcycle %1" : "=r"(whole));
	return whole;
}
inline auto rdtime()
{
	uint64_t whole;
	asm ("rdtime %0" : "=r"(whole));
	return whole;
}

#endif
