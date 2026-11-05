use core::arch::asm;
use core::str;
use std::borrow::Cow;
use std::ffi::{c_char, CStr};
pub enum SysCalls {
	Print = 500 + 2,
	RegisterCallback = 500 + 9,
	SetDecision = 500 + 10,
	BackendDecision = 500 + 12,
	HeaderFieldRetrieve = 500 + 21,
	HeaderFieldAppend = 500 + 22,
	HeaderFieldSet = 500 + 23,
	HeaderFieldFind = 500 + 30,
	HashData = 500 + 14,
}
#[allow(unused)]
pub enum CachingDecision {
	Uncached = 0,
	Cached = 1,
}
pub struct BackendResponse {
	pub status: u16,
	pub content_type: &'static str,
	pub body: Vec<u8>,
}
pub struct DeliverResponse<'a> {
	pub status: u16,
	pub content_type: &'a str,
	pub body: Cow<'a, [u8]>,
}

#[allow(unused)]
pub fn print(msg: &str) {
    let _ret: i32;
    unsafe {
        asm!("ecall",
            in("a7") SysCalls::Print as i32,
            in("a0") msg.as_ptr(),
            in("a1") msg.len(),
            lateout("a0") _ret
        );
    }
}

/// Returns the whole field ("Name: value"), or an empty string when
/// there is no field at index (eg. u32::MAX from header_find()).
pub fn get_header_field(where_from: u32, index: u32) -> String {
	let mut len: i32;
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::HeaderFieldRetrieve as i32,
			in("a0") where_from,
			in("a1") index,
			in("a2") 0,
			in("a3") 0,
			lateout("a0") len
		);
	}
	if len < 0 {
		return String::new();
	}
	let mut buf: Vec<u8> = Vec::with_capacity(len as usize);
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::HeaderFieldRetrieve as i32,
			in("a0") where_from,
			in("a1") index,
			in("a2") buf.as_mut_ptr(),
			in("a3") buf.capacity(),
			lateout("a0") len
		);
		if len < 0 || len as usize > buf.capacity() {
			return String::new();
		}
		buf.set_len(len as usize);
		String::from_utf8_unchecked(buf)
	}
}
#[allow(unused)]
pub fn get_url() -> String {
	get_header_field(0, 1) // HDR_REQ, index 1 is URL
}

#[allow(unused)]
pub fn header_find(where_from: u32, key: &str) -> u32 {
	let mut index: u32;
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::HeaderFieldFind as i32,
			in("a0") where_from,
			in("a1") key.as_ptr(),
			in("a2") key.len(),
			lateout("a0") index
		);
	}
	return index;
}

#[allow(unused)]
pub fn get_req_header(key: &str) -> String {
	let index = header_find(0, key); // HDR_REQ
	if (index == u32::MAX) {
		return String::new();
	}
	return get_header_field(0, index);
}

fn set_header_field(where_from: u32, index: u32, value: &str) {
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::HeaderFieldSet as i32,
			in("a0") where_from,
			in("a1") index,
			in("a2") value.as_ptr(),
			in("a3") value.len()
		);
	}
}
#[allow(unused)]
pub fn set_url(url: &str) {
	set_header_field(0, 1, url); // HDR_REQ, index 1 is URL
}

pub fn header_append(where_from: u32, value: &str) {
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::HeaderFieldAppend as i32,
			in("a0") where_from,
			in("a1") value.as_ptr(),
			in("a2") value.len()
		);
	}
}
#[allow(unused)]
pub fn add_full_req_header(header: &str) {
	header_append(0, header); // HDR_REQ == 0
}
#[allow(unused)]
pub fn add_req_header(name: &str, value: &str) {
	let header = format!("{}: {}", name, value);
	header_append(0, &header); // HDR_REQ == 0
}
#[allow(unused)]
pub fn add_full_resp_header(header: &str) {
	header_append(2, header); // HDR_RESP == 2
}
#[allow(unused)]
pub fn add_resp_header(name: &str, value: &str) {
	let header = format!("{}: {}", name, value);
	header_append(2, &header); // HDR_RESP == 2
}

fn forge_response(resp: &BackendResponse) {
	let ctype_bytes = resp.content_type.as_bytes();
	let body_bytes = resp.body.as_slice();

	unsafe {
		asm!(".insn i SYSTEM, 0, a0, x0, 0x7ff",
			in("a0") resp.status as u32,
			in("a1") ctype_bytes.as_ptr(),
			in("a2") ctype_bytes.len(),
			in("a3") body_bytes.as_ptr(),
			in("a4") body_bytes.len()
		);
	}
	unreachable!();
}
#[allow(unused)]
pub fn backend_response(status: u16, content_type: &str, body: &[u8]) -> !
{
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::BackendDecision as i32,
			in("a0") status as u32,
			in("a1") content_type.as_ptr(),
			in("a2") content_type.len(),
			in("a3") body.as_ptr(),
			in("a4") body.len()
		);
	}
	unreachable!();
}

#[allow(unused)]
pub fn deliver_response(status: u16, content_type: &str, body: &[u8]) -> !
{
	unsafe {
		asm!(".insn i SYSTEM, 0, x0, x0, 0x7ff",
			in("a0") status as u32,
			in("a1") content_type.as_ptr(),
			in("a2") content_type.len(),
			in("a3") body.as_ptr(),
			in("a4") body.len(),
			options(noreturn)
		);
	}
}

#[allow(unused)]
#[doc(hidden)]
pub unsafe fn deliver_trampoline(arg: *const c_char, data: *mut u8, len: usize,
	func: for<'a> fn(&'a str, &'a mut [u8]) -> Option<DeliverResponse<'a>>)
{
	let arg = str::from_utf8_unchecked(CStr::from_ptr(arg).to_bytes());
	let body: &mut [u8] = if len == 0 { &mut [] } else { core::slice::from_raw_parts_mut(data, len) };
	if let Some(resp) = func(arg, body) {
		deliver_response(resp.status, resp.content_type, &resp.body);
	}
}

#[allow(unused)]
#[doc(hidden)]
pub fn register_deliver_transform(name: &str, func: extern "C" fn(*const c_char, *mut u8, usize))
{
	unsafe {
		asm!("ecall",
			in("a7") 573,
			in("a0") name.as_ptr(),
			in("a1") name.len(),
			in("a2") func as *const ()
		);
	}
}

#[macro_export]
macro_rules! deliver_transform {
	($name:expr, $func:path) => {{
		extern "C" fn deliver_entry(arg: *const std::ffi::c_char, data: *mut u8, len: usize) {
			unsafe { $crate::varnish::deliver_trampoline(arg, data, len, $func) }
		}
		$crate::varnish::register_deliver_transform($name, deliver_entry);
	}};
}

fn trampoline(func: fn(u32, u32) -> BackendResponse) {
	const BEREQ:  u32 = 4; // HDR_BEREQ
	const BERESP: u32 = 5; // HDR_BERESP
	let response = func(BEREQ, BERESP);
	forge_response(&response);
	unreachable!();
}

#[allow(unused)]
pub fn forge(cached: CachingDecision, func: fn(u32, u32) -> BackendResponse) -> !
{
    unsafe {
        asm!("ecall",
            in("a7") SysCalls::BackendDecision as i32,
            in("a0") cached as u32,
            in("a1") trampoline as *const (),
            in("a2") func as *const (),
            in("a3") 0 // paused
        );
    }
    unreachable!();
}

#[allow(unused)]
fn trampoline_post(func: fn(u32, u32, &[u8]) -> BackendResponse, data_ptr: *const u8, data_len: usize) {
	const BEREQ:  u32 = 4; // HDR_BEREQ
	const BERESP: u32 = 5; // HDR_BERESP
	let response = func(BEREQ, BERESP, unsafe { core::slice::from_raw_parts(data_ptr, data_len) });
	forge_response(&response);
	unreachable!();
}

#[allow(unused)]
pub fn forge_with_post(cached: CachingDecision, func: fn(u32, u32, &[u8]) -> BackendResponse) -> !
{
    unsafe {
        asm!("ecall",
            in("a7") SysCalls::BackendDecision as i32,
            in("a0") cached as u32,
            in("a1") trampoline_post as *const (),
            in("a2") func as *const (),
            in("a3") 0 // paused
        );
    }
    unreachable!();
}

#[allow(unused)]
#[inline]
pub fn response(ctype: &str, resp: &str) -> !
{
    unsafe {
        asm!("ebreak",
            in("a0") ctype.as_ptr(),
            in("a1") ctype.len(),
            in("a2") resp.as_ptr(),
            in("a3") resp.len()
        );
    }
    unreachable!();
}

#[allow(unused)]
pub fn hash_data(data: &str)
{
    let _ret: i32;
    unsafe {
        asm!("ecall",
            in("a7") SysCalls::HashData as i32,
            in("a0") data.as_ptr(),
            in("a1") data.len(),
            lateout("a0") _ret
        );
    }
}

#[allow(unused)]
pub fn self_request(data: &str) -> i32
{
    return 200;
}

#[allow(unused)]
fn register_callback(idx: u32, callback: fn(u32, u32))
{
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::RegisterCallback as i32,
			in("a0") idx,
			in("a1") callback as *const ()
		);
	}
}

#[allow(unused)]
pub fn register_function(name: &str, func: extern "C" fn(*const std::ffi::c_char, usize) -> *const std::ffi::c_char)
{
	unsafe {
		asm!("ecall",
			in("a7") 539, // REGISTER_FUNC
			in("a0") name.as_ptr(),
			in("a1") name.len(),
			in("a2") func as *const ()
		);
	}
}

#[allow(unused)]
pub fn set_on_deliver(callback: fn(u32, u32))
{
	register_callback(7, callback); // 7 = on_deliver
}

core::arch::global_asm!(
	".pushsection .text.varnish_fast_exit, \"ax\", @progbits",
	".cfi_startproc",
	".cfi_undefined ra",
	"nop",
	".global varnish_fast_exit",
	"varnish_fast_exit:",
	".insn i SYSTEM, 0, x0, x0, 0x7ff",
	"j varnish_fast_exit",
	".cfi_endproc",
	".popsection",
);
extern "C" {
	fn varnish_fast_exit() -> !;
}

#[allow(unused)]
pub fn wait_for_requests(callback: fn(u32, u32))
{
	unsafe {
		asm!("ecall",
			in("a7") SysCalls::SetDecision as i32,
			in("a0") callback as *const (),
			in("a1") varnish_fast_exit as *const ()
		);
	}
}

#[macro_export]
macro_rules! print {
    () => { ... };
    ($($arg:tt)*) => {
        let text = format!($( $arg )*);
        varnish::print(&text);
    };
}

#[allow(unused)]
pub const BASE64_URL: u32 = 0x2;
#[allow(unused)]
pub const BASE64_NOPAD: u32 = 0x4;
const BASE64_DECODE: u32 = 0x1;

fn base64_call(flags: u32, input: &[u8], out: &mut Vec<u8>) -> bool {
	let len: isize;
	unsafe {
		asm!("ecall",
			in("a7") 570, // BASE64
			inlateout("a0") flags as usize => len,
			in("a1") input.as_ptr(),
			in("a2") input.len(),
			in("a3") out.as_mut_ptr(),
			in("a4") out.capacity()
		);
		if len < 0 || len as usize > out.capacity() {
			return false;
		}
		out.set_len(len as usize);
	}
	true
}

#[allow(unused)]
pub fn base64_encode(input: &[u8], flags: u32) -> String {
	let mut out = Vec::with_capacity((input.len() + 2) / 3 * 4);
	base64_call(flags & !BASE64_DECODE, input, &mut out);
	unsafe { String::from_utf8_unchecked(out) }
}

#[allow(unused)]
pub fn base64_decode(input: &[u8], flags: u32) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
	base64_call(flags | BASE64_DECODE, input, &mut out).then_some(out)
}

#[allow(unused)]
pub fn decode_base64(input: &[u8]) -> Vec<u8> {
	base64_decode(input, 0).unwrap_or_default()
}

#[allow(unused)]
pub fn sha256(input: &[u8]) -> [u8; 32] {
	let mut digest = [0u8; 32];
	unsafe {
		asm!("ecall",
			in("a7") 536, // SHA256
			inlateout("a0") input.as_ptr() => _,
			in("a1") input.len(),
			in("a2") digest.as_mut_ptr(),
			in("a3") digest.len()
		);
	}
	digest
}
