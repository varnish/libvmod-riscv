use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;

const NATIVE_SYSCALLS_BASE: i32 = 580;

struct SysAllocator;

unsafe impl GlobalAlloc for SysAllocator {
	#[inline]
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		let ret: *mut u8;
		asm!("ecall", in("a7") NATIVE_SYSCALLS_BASE + 0,
			in("a0") layout.size(), in("a1") layout.align(),
			lateout("a0") ret);
		return ret;
	}
	#[inline]
	unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
		let ret: *mut u8;
		asm!("ecall", in("a7") NATIVE_SYSCALLS_BASE + 1,
			in("a0") layout.size(), in("a1") 1, lateout("a0") ret);
		return ret;
	}
	#[inline]
	unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
		let ret: *mut u8;
		asm!("ecall", in("a7") NATIVE_SYSCALLS_BASE + 2,
			in("a0") ptr, in("a1") new_size, lateout("a0") ret);
		return ret;
	}
	#[inline]
	unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
		asm!("ecall", in("a7") NATIVE_SYSCALLS_BASE + 3,
			in("a0") ptr, lateout("a0") _);
	}
}

#[global_allocator]
static A: SysAllocator = SysAllocator;

// Overrides for:
// memcpy, memmove, memset, strcpy, strncpy, strcmp, strncmp, strlen
#[no_mangle]
pub unsafe extern "C" fn __wrap_memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
	let mut result;
	asm!("ecall",
		in("a7") NATIVE_SYSCALLS_BASE + 5,
		in("a0") dest,
		in("a1") src,
		in("a2") n,
		lateout("a0") result
	);
	return result;
}

#[no_mangle]
pub unsafe extern "C" fn __wrap_memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
	let mut result;
	asm!("ecall",
		in("a7") NATIVE_SYSCALLS_BASE + 6,
		in("a0") s,
		in("a1") c,
		in("a2") n,
		lateout("a0") result
	);
	return result;
}

#[no_mangle]
pub unsafe extern "C" fn __wrap_memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
	let mut result;
	asm!("ecall",
		in("a7") NATIVE_SYSCALLS_BASE + 7,
		in("a0") dest,
		in("a1") src,
		in("a2") n,
		lateout("a0") result
	);
	return result;
}

#[no_mangle]
pub unsafe extern "C" fn __wrap_memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
	let mut result;
	asm!("ecall",
		in("a7") NATIVE_SYSCALLS_BASE + 8,
		in("a0") s1,
		in("a1") s2,
		in("a2") n,
		lateout("a0") result
	);
	return result;
}

#[no_mangle]
pub unsafe extern "C" fn __wrap_strlen(s: *const u8) -> usize {
	let mut result;
	asm!("ecall",
		in("a7") NATIVE_SYSCALLS_BASE + 10,
		in("a0") s,
		lateout("a0") result
	);
	return result;
}

// Special override for __memcmpeq function
#[no_mangle]
pub unsafe extern "C" fn __wrap___memcmpeq(s1: *const u8, s2: *const u8, n: usize) -> i32 {
	return __wrap_memcmp(s1, s2, n);
}
