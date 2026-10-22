/**
 * The native heap for guests built against a Linux C library (musl, glibc).
 *
 * The host allocates guest memory on the native heap (fetch responses,
 * header iteration, storage call results, live update state), and forks
 * get their own arena starting where the master left off. malloc and free,
 * and so operator new and delete, must use that same heap: with the C
 * library's allocator alongside it, a pointer freed on the other heap is
 * a crash ("Possible double-free" from the host, or a libc abort).
 *
 * micro.cmake links with --wrap for every symbol defined here, which
 * redirects all references to them in the program, libc++/libstdc++ and
 * the C library itself. The C library's allocator is then left without
 * users and is not linked in at all.
**/
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <heap.hpp>

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)
#define GENERATE_SYSCALL_WRAPPER(name, number) \
	asm(".global " #name "\n" #name ":\n  li a7, " STRINGIFY(number) "\n  ecall\n  ret\n");

asm(".pushsection .text, \"ax\", @progbits\n");
GENERATE_SYSCALL_WRAPPER(__wrap_malloc,  SYSCALL_MALLOC);
GENERATE_SYSCALL_WRAPPER(__wrap_calloc,  SYSCALL_CALLOC);
GENERATE_SYSCALL_WRAPPER(__wrap_realloc, SYSCALL_REALLOC);
GENERATE_SYSCALL_WRAPPER(__wrap_free,    SYSCALL_FREE);
/* The C library's internal names: musl allocates locales, time zones and
   atexit handlers with these, and glibc's allocator goes by them too. */
GENERATE_SYSCALL_WRAPPER(__wrap___libc_malloc,  SYSCALL_MALLOC);
GENERATE_SYSCALL_WRAPPER(__wrap___libc_calloc,  SYSCALL_CALLOC);
GENERATE_SYSCALL_WRAPPER(__wrap___libc_realloc, SYSCALL_REALLOC);
GENERATE_SYSCALL_WRAPPER(__wrap___libc_free,    SYSCALL_FREE);
asm(".popsection\n");

/* The arena aligns every chunk to 16 bytes. For more than that, fill the
   space before the next aligned address with a placeholder of exactly that
   size, until a chunk lands aligned. When the placeholder lands there, the
   next chunk from that hole is aligned. When it fills a hole elsewhere,
   the hole the chunk came from is still free and would be picked again:
   it is taken too, and held. Everything taken is held until the end, so
   each round uses up some of the heap, and the loop ends when the heap
   does at the latest. The held chunks are a list threaded through
   themselves (a chunk is at least 16 bytes). */
static void* native_memalign(size_t align, size_t bytes)
{
	if (align <= 16)
		return sys_malloc(bytes);
	void* held = nullptr;
	auto hold = [&held] (void* chunk) {
		*(void**)chunk = held;
		held = chunk;
	};
	auto aligned = [align] (void* p) {
		return ((uintptr_t)p & (align-1)) == 0;
	};
	void* ptr = sys_malloc(bytes);
	while (ptr != nullptr && !aligned(ptr))
	{
		const size_t gap = (-(uintptr_t)ptr) & (align-1);
		sys_free(ptr);
		void* placeholder = sys_malloc(gap);
		if (placeholder == nullptr) {
			ptr = nullptr;
			break;
		}
		hold(placeholder);
		if (placeholder != ptr) {
			void* rejected = sys_malloc(bytes);
			if (rejected == nullptr || aligned(rejected)) {
				ptr = rejected;
				break;
			}
			hold(rejected);
		}
		ptr = sys_malloc(bytes);
	}
	while (held != nullptr) {
		void* next = *(void**)held;
		sys_free(held);
		held = next;
	}
	return ptr;
}

static bool valid_alignment(size_t align)
{
	return align != 0 && (align & (align-1)) == 0;
}

extern "C" void* __wrap_memalign(size_t align, size_t bytes)
{
	if (!valid_alignment(align)) {
		errno = EINVAL;
		return nullptr;
	}
	return native_memalign(align, bytes);
}
extern "C" void* __wrap___libc_memalign(size_t align, size_t bytes)
{
	return __wrap_memalign(align, bytes);
}
extern "C" void* __wrap_aligned_alloc(size_t align, size_t bytes)
{
	return __wrap_memalign(align, bytes);
}
extern "C" int __wrap_posix_memalign(void** memptr, size_t align, size_t bytes)
{
	if (!valid_alignment(align) || align % sizeof(void*) != 0)
		return EINVAL;
	void* ptr = native_memalign(align, bytes);
	if (ptr == nullptr)
		return ENOMEM;
	*memptr = ptr;
	return 0;
}
extern "C" void* __wrap_valloc(size_t bytes)
{
	return native_memalign(4096, bytes);
}

/* The arena does not tell the guest the size of a chunk. Callers must
   then treat it as unknown: QuickJS does, as it does on platforms
   without malloc_usable_size. */
extern "C" size_t __wrap_malloc_usable_size(void*)
{
	return 0;
}
