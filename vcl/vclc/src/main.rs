//! The VCL compiler, built as a libvmod-riscv guest.
//!
//! `vcl-compiler` compiled for RISC-V and linked against a small guest
//! environment: the arena allocator, the native `memcpy` wrappers,
//! `fast_exit`, and one host call. The VMOD embeds the resulting ELF,
//! builds a fresh machine per compile (`src/vcl/compiler.cpp`) and calls
//! [`vclc_compile`] once per policy, so a tenant's VCL is *compiled* inside
//! the same kind of sandbox its compiled policy will *run* in.
//!
//! Nothing about the compiler changes here. That is the contract — identical
//! output whether a policy compiles natively or in the sandbox — and this
//! file is the whole of the difference: decode the request, answer includes
//! through the host call instead of through a file descriptor, render
//! diagnostics, encode the answer.
//!
//! # Why diagnostics are rendered here
//!
//! Rendering quotes untrusted source text and does arithmetic over untrusted
//! spans. Doing it in the guest means the host receives one capped string it
//! only ever passes through, and never formats a byte of tenant source
//! itself.
//!
//! # Rebuilding
//!
//! `make -C vcl/vclc blob`, then commit `vcl/vclc.elf`. See the Makefile for
//! what changes require it.

mod env;
mod include;

use std::path::Path;

use vcl_compiler::wire::{Request, Response};
use vcl_compiler::{CompileOptions, IncludeResolver};

fn main() {
    // Stop with the runtime initialised rather than returning, which would
    // run std's shutdown and tear the machine down.
    env::fast_exit(0);
}

/// Compile one policy.
///
/// `addr`/`len` describe a [`Request`] encoding the host wrote into this
/// guest's arena. The answer is a length-prefixed [`Response`] buffer whose
/// address is returned; the host reads it and then drops the whole VM.
///
/// # Panics
///
/// On a request it cannot decode. A compiler that cannot read its own input
/// has no diagnostics to render and nothing true to say, and `panic =
/// "abort"` makes this a machine exception the host reports as a failed
/// compile — never a host failure.
///
/// # Safety
///
/// `addr` must point at `len` readable bytes in this guest's arena, which is
/// what the host writes there.
#[no_mangle]
pub unsafe extern "C" fn vclc_compile(addr: *const u8, len: usize) -> *const u8 {
    let input = if addr.is_null() || len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(addr, len) }
    };
    let request = match Request::decode(input) {
        Ok(request) => request,
        Err(error) => panic!("the VCL compiler guest was handed a request it cannot read: {error}"),
    };

    let response = compile(&request);
    let framed = vcl_compiler::wire::prefixed(&response.encode());
    let addr = framed.as_ptr();
    // Deliberately leaked. The host reads this buffer and then drops the VM,
    // so returning the block to the arena would be work with no observer —
    // and a freed block is one the host might read after the allocator has
    // handed it out again.
    core::mem::forget(framed);
    addr
}

fn compile(request: &Request) -> Response {
    // The root is display only: it prefixes the path a diagnostic tells the
    // operator to open. The *name* is what crosses to the host, which
    // confines it against the policy's directory.
    let resolver = IncludeResolver::new(&request.root, |relative: &Path| match relative.to_str() {
        Some(name) => include::read(name),
        None => Err("include path is not UTF-8".to_string()),
    });
    let mut options = CompileOptions::default()
        .with_variant_headers(&request.variant_headers)
        .with_include_resolver(resolver);
    if let Some((grace, keep)) = request.stale_caps {
        options = options.with_stale_caps(grace, keep);
    }
    options.verify_ir = request.verify_ir;
    options.optimization = request.optimization;

    match vcl_compiler::compile(&request.source, options) {
        // Warnings are rendered here for the same reason diagnostics are.
        Ok(compiled) => Response::from_compiled(&compiled, &request.filename),
        Err(diagnostics) => Response::Err {
            rendered: diagnostics.render(&request.filename),
        },
    }
}
