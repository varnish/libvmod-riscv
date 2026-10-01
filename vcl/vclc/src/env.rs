//! What a libriscv guest has to bring itself: a heap the host shares, the
//! block memory operations, and an exit function.
//!
//! The global allocator is the one that matters. It points `String` and
//! `Vec` at the host's arena, so the length-prefixed answer `vclc_compile`
//! returns is a block the host can read straight out of guest memory.
//!
//! Numbers follow the VMOD, not Carapace: `Script::machine_setup` installs
//! the native heap at `NATIVE_SYSCALLS_BASE` (580) and the memory helpers
//! five above it, and `src/vcl/compiler.cpp` does the same for this guest.

use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;

/// `NATIVE_SYSCALLS_BASE` in `src/script.cpp`: malloc, calloc, realloc, free
/// at +0..+3.
const HEAP_SYSCALLS_BASE: usize = 580;

/// The native memory operations, installed at heap base + 5.
const MEMORY_SYSCALLS_BASE: usize = HEAP_SYSCALLS_BASE + 5;

/// The arena hands out 16-byte aligned blocks and ignores the alignment
/// argument (`native_heap.hpp`: `ALIGNMENT = 16`). Anything asking for more
/// has to be refused, not silently mis-aligned.
const ARENA_ALIGNMENT: usize = 16;

struct ArenaAllocator;

unsafe impl GlobalAlloc for ArenaAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > ARENA_ALIGNMENT {
            return core::ptr::null_mut();
        }
        let ret: *mut u8;
        unsafe {
            asm!("ecall",
                in("a7") HEAP_SYSCALLS_BASE,
                inlateout("a0") layout.size() => ret,
                in("a1") layout.align());
        }
        ret
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.align() > ARENA_ALIGNMENT {
            return core::ptr::null_mut();
        }
        let ret: *mut u8;
        unsafe {
            asm!("ecall",
                in("a7") HEAP_SYSCALLS_BASE + 1,
                inlateout("a0") 1usize => ret,
                in("a1") layout.size());
        }
        ret
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        let ret: *mut u8;
        unsafe {
            asm!("ecall",
                in("a7") HEAP_SYSCALLS_BASE + 2,
                inlateout("a0") ptr => ret,
                in("a1") new_size);
        }
        ret
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe {
            asm!("ecall",
                in("a7") HEAP_SYSCALLS_BASE + 3,
                inlateout("a0") ptr => _);
        }
    }
}

#[global_allocator]
static ALLOCATOR: ArenaAllocator = ArenaAllocator;

// The link step passes `--wrap=memcpy` and friends, so every reference in
// the program — Rust's and static glibc's — reaches these, and the host does
// the copy natively instead of emulating a byte loop. The bodies are inline
// assembly because a hand-written loop would be recognised by LLVM as a
// memcpy and turned back into a call to this very function.

/// # Safety
/// Same contract as C `memcpy`.
#[no_mangle]
pub unsafe extern "C" fn __wrap_memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        asm!("ecall", in("a7") MEMORY_SYSCALLS_BASE,
            in("a0") dest, in("a1") src, in("a2") n, lateout("a0") _);
    }
    dest
}

/// # Safety
/// Same contract as C `memset`.
#[no_mangle]
pub unsafe extern "C" fn __wrap_memset(dest: *mut u8, value: i32, n: usize) -> *mut u8 {
    unsafe {
        asm!("ecall", in("a7") MEMORY_SYSCALLS_BASE + 1,
            in("a0") dest, in("a1") value, in("a2") n, lateout("a0") _);
    }
    dest
}

/// # Safety
/// Same contract as C `memmove`.
#[no_mangle]
pub unsafe extern "C" fn __wrap_memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        asm!("ecall", in("a7") MEMORY_SYSCALLS_BASE + 2,
            in("a0") dest, in("a1") src, in("a2") n, lateout("a0") _);
    }
    dest
}

/// # Safety
/// Same contract as C `memcmp`.
#[no_mangle]
pub unsafe extern "C" fn __wrap_memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let result: i32;
    unsafe {
        asm!("ecall", in("a7") MEMORY_SYSCALLS_BASE + 3,
            in("a0") s1, in("a1") s2, in("a2") n, lateout("a0") result);
    }
    result
}

// Slice equality goes to an equality-only entry point rather than memcmp —
// `__memcmpeq` on a current toolchain, `bcmp` on an older one. A memcmp
// result satisfies both.

/// # Safety
/// Same contract as `__memcmpeq`.
#[no_mangle]
pub unsafe extern "C" fn __wrap___memcmpeq(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe { __wrap_memcmp(s1, s2, n) }
}

/// # Safety
/// Same contract as C `bcmp`.
#[no_mangle]
pub unsafe extern "C" fn __wrap_bcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe { __wrap_memcmp(s1, s2, n) }
}

/// Where `main` ends up, and where the host's vmcall returns to.
///
/// Stopping here rather than returning from `main` leaves the runtime
/// initialised: returning would run std's shutdown. The host resolves the
/// symbol by name, which is why `-Wl,--undefined=fast_exit` keeps it.
#[no_mangle]
pub extern "C" fn fast_exit(_code: i32) -> ! {
    loop {
        unsafe { asm!("wfi") };
    }
}
