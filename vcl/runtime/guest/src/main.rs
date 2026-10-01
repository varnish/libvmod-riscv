#![no_std]
#![no_main]

use vcl_rt::{
    rt_acl_match, rt_collect, rt_cookie_count, rt_cookie_read, rt_cookie_transform,
    rt_duration_parse, rt_fnmatch, rt_header_commit, rt_header_count, rt_header_read,
    rt_header_transform, rt_int_parse, rt_ip_format, rt_querysort, rt_setcookie_count,
    rt_setcookie_read, rt_setcookie_transform, rt_str_edit, rt_str_split, rt_str_test,
    rt_time_format, rt_time_parse, rt_uri_read, rt_uri_transform, rt_url_count, rt_url_read,
    rt_url_transform, Routine,
};
use core::arch::global_asm;

/// Ordinary relocations to every entry point.
///
/// A `global_asm!` reference alone does not make rustc pull an otherwise
/// unused rlib member into the final link, so each symbol needs a reference
/// Rust itself can see.  They are function pointers rather than calls: an
/// earlier version wrote a `keep_*` wrapper per routine to satisfy a single
/// array type, which meant every new routine needed a hand-written call with
/// plausible arguments.  Erasing the type to a data pointer removes that.
///
/// The array is `Routine::COUNT` long, so a routine added to the enum without
/// an entry here -- or a jump-table slot below -- fails to build.  The section
/// is discarded by the linker script, so none of this reaches the image.
struct Keep(#[allow(dead_code)] [*const (); Routine::COUNT]);

// The pointers are never dereferenced and the value is never read; it exists
// so the linker keeps the symbols.
unsafe impl Sync for Keep {}

#[used]
#[link_section = ".runtime.keep"]
static RUNTIME_KEEP: Keep = Keep([
    rt_int_parse as *const (),
    rt_duration_parse as *const (),
    rt_time_parse as *const (),
    rt_time_format as *const (),
    rt_fnmatch as *const (),
    rt_querysort as *const (),
    rt_cookie_read as *const (),
    rt_cookie_count as *const (),
    rt_cookie_transform as *const (),
    rt_url_read as *const (),
    rt_url_count as *const (),
    rt_url_transform as *const (),
    rt_header_read as *const (),
    rt_header_count as *const (),
    rt_header_transform as *const (),
    rt_header_commit as *const (),
    rt_collect as *const (),
    rt_acl_match as *const (),
    rt_ip_format as *const (),
    rt_str_test as *const (),
    rt_str_edit as *const (),
    rt_str_split as *const (),
    rt_setcookie_read as *const (),
    rt_setcookie_count as *const (),
    rt_setcookie_transform as *const (),
    rt_uri_read as *const (),
    rt_uri_transform as *const (),
]);

// The first `8 * Routine::COUNT` bytes are the fixed jump table used by
// vcl-compiler, in `Routine` order.  Each entry is an `auipc`/`jalr` pair
// rather than a `jal`: its target may sit anywhere in this load image, not
// merely within J-type range.  The paired PC-relative relocations are fully
// resolved by the static link, so the final ELF has no relocation sections.
global_asm!(
    ".section .text.start,\"ax\"\n\
     .option push\n\
     .option norvc\n\
     .global _start\n\
     .type _start,@function\n\
     _start:\n\
     1:\n\
       auipc t0, %pcrel_hi(rt_int_parse)\n\
       jalr x0, t0, %pcrel_lo(1b)\n\
     2:\n\
       auipc t0, %pcrel_hi(rt_duration_parse)\n\
       jalr x0, t0, %pcrel_lo(2b)\n\
     3:\n\
       auipc t0, %pcrel_hi(rt_time_parse)\n\
       jalr x0, t0, %pcrel_lo(3b)\n\
     4:\n\
       auipc t0, %pcrel_hi(rt_time_format)\n\
       jalr x0, t0, %pcrel_lo(4b)\n\
     5:\n\
       auipc t0, %pcrel_hi(rt_fnmatch)\n\
       jalr x0, t0, %pcrel_lo(5b)\n\
     6:\n\
       auipc t0, %pcrel_hi(rt_querysort)\n\
       jalr x0, t0, %pcrel_lo(6b)\n\
     7:\n\
       auipc t0, %pcrel_hi(rt_cookie_read)\n\
       jalr x0, t0, %pcrel_lo(7b)\n\
     8:\n\
       auipc t0, %pcrel_hi(rt_cookie_count)\n\
       jalr x0, t0, %pcrel_lo(8b)\n\
     9:\n\
       auipc t0, %pcrel_hi(rt_cookie_transform)\n\
       jalr x0, t0, %pcrel_lo(9b)\n\
     10:\n\
       auipc t0, %pcrel_hi(rt_url_read)\n\
       jalr x0, t0, %pcrel_lo(10b)\n\
     11:\n\
       auipc t0, %pcrel_hi(rt_url_count)\n\
       jalr x0, t0, %pcrel_lo(11b)\n\
     12:\n\
       auipc t0, %pcrel_hi(rt_url_transform)\n\
       jalr x0, t0, %pcrel_lo(12b)\n\
     13:\n\
       auipc t0, %pcrel_hi(rt_header_read)\n\
       jalr x0, t0, %pcrel_lo(13b)\n\
     14:\n\
       auipc t0, %pcrel_hi(rt_header_count)\n\
       jalr x0, t0, %pcrel_lo(14b)\n\
     15:\n\
       auipc t0, %pcrel_hi(rt_header_transform)\n\
       jalr x0, t0, %pcrel_lo(15b)\n\
     16:\n\
       auipc t0, %pcrel_hi(rt_header_commit)\n\
       jalr x0, t0, %pcrel_lo(16b)\n\
     17:\n\
       auipc t0, %pcrel_hi(rt_collect)\n\
       jalr x0, t0, %pcrel_lo(17b)\n\
     18:\n\
       auipc t0, %pcrel_hi(rt_acl_match)\n\
       jalr x0, t0, %pcrel_lo(18b)\n\
     19:\n\
       auipc t0, %pcrel_hi(rt_ip_format)\n\
       jalr x0, t0, %pcrel_lo(19b)\n\
     20:\n\
       auipc t0, %pcrel_hi(rt_str_test)\n\
       jalr x0, t0, %pcrel_lo(20b)\n\
     21:\n\
       auipc t0, %pcrel_hi(rt_str_edit)\n\
       jalr x0, t0, %pcrel_lo(21b)\n\
     22:\n\
       auipc t0, %pcrel_hi(rt_str_split)\n\
       jalr x0, t0, %pcrel_lo(22b)\n\
     23:\n\
       auipc t0, %pcrel_hi(rt_setcookie_read)\n\
       jalr x0, t0, %pcrel_lo(23b)\n\
     24:\n\
       auipc t0, %pcrel_hi(rt_setcookie_count)\n\
       jalr x0, t0, %pcrel_lo(24b)\n\
     25:\n\
       auipc t0, %pcrel_hi(rt_setcookie_transform)\n\
       jalr x0, t0, %pcrel_lo(25b)\n\
     26:\n\
       auipc t0, %pcrel_hi(rt_uri_read)\n\
       jalr x0, t0, %pcrel_lo(26b)\n\
     27:\n\
       auipc t0, %pcrel_hi(rt_uri_transform)\n\
       jalr x0, t0, %pcrel_lo(27b)\n\
     .4byte {version}\n\
     .size _start, .-_start\n\
     .option pop\n",
    version = const vcl_rt::IMAGE_VERSION,
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
