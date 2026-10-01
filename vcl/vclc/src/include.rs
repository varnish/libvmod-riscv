//! The one host call the compiler guest makes: read an included library.
//!
//! The compiler discovers include names while preprocessing, and the host
//! must not run a preprocessor over untrusted bytes to learn them first, so
//! it has to ask. The call is answered only while the host is running a
//! compile on the calling thread (`src/vcl/compiler.cpp`); a tenant policy
//! that makes it gets a refusal.
//!
//! Measure, then fill, so neither side depends on the other's string layout:
//! the first call passes no buffer and learns the size, the second passes a
//! buffer of exactly that size. The host remembers the last answer, so the
//! file is read once.

use core::arch::asm;

/// The VCL typed ABI slot (carapace's 510, shifted to the VMOD's free range).
const SYS_TYPED: usize = 560;
/// The sub-command, unchanged from carapace's `TYPED_BATCH_READ`.
const TYPED_INCLUDE_READ: usize = 28;

/// `>= 0`: the source is that many bytes. `< 0`: the host refused, and the
/// reason is `-(n + 1)` bytes. Either is copied into `out` when it fits.
fn raw(name: &str, out: &mut [u8]) -> isize {
    let ret: isize;
    unsafe {
        asm!("ecall",
            in("a7") SYS_TYPED,
            inlateout("a0") TYPED_INCLUDE_READ => ret,
            in("a1") name.as_ptr(),
            in("a2") name.len(),
            in("a3") out.as_mut_ptr(),
            in("a4") out.len());
    }
    ret
}

/// Ask the host for one library, by the relative name the compiler has
/// already normalised and confined.
pub fn read(name: &str) -> Result<String, String> {
    let measured = raw(name, &mut []);
    let (len, ok) = if measured >= 0 {
        (measured as usize, true)
    } else {
        ((-(measured + 1)) as usize, false)
    };
    let mut buffer = vec![0u8; len];
    if len > 0 {
        let filled = raw(name, &mut buffer);
        if filled != measured {
            return Err(format!("include '{name}' changed while it was being read"));
        }
    }
    let text = String::from_utf8(buffer).map_err(|_| format!("include '{name}' is not UTF-8"));
    match (ok, text) {
        (true, text) => text,
        (false, Ok(reason)) => Err(reason),
        (false, Err(error)) => Err(error),
    }
}
