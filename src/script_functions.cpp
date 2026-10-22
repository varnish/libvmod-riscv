#include <libriscv/rv32i_instr.hpp>
#include <openssl/evp.h>
#include <algorithm>
#include <climits>
#include <cstring>
#include "script_functions.hpp"
#include "machine/include_api.hpp"
#include "machine_instance.hpp"
#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#include "vcl/vcl_varnish.h"
extern "C" {
# include "varnish_interface.h"
# include "update_result.h"
#ifndef VARNISH_PLUS
# include <vrt_obj.h>
#endif
}

namespace rvs {
	static const uint64_t REMOTE_CALL_COST = 4000;
	static const uint16_t DEBUG_PORT = 2159;

//#define ENABLE_TIMING
#ifdef ENABLE_TIMING
#define TIMING_LOCATION(x) \
	asm("" ::: "memory"); \
	auto x = time_now();  \
	asm("" ::: "memory");
static timespec time_now();
static long nanodiff(timespec start_time, timespec end_time);
#endif

struct guest_header_field {
	int where;
	uint32_t index;
	bool     deleted = false;
	bool     foreach = false;
};

inline void foreach(http* hp, const std::function<void(http*, txt&, size_t)>& cb)
{
	for (size_t i = 0; i < hp->nhd; i++) {
		cb(hp, hp->hd[i], i);
	}
}

inline bool is_invalid(unsigned idx) {
	return idx == HDR_INVALID;
}
inline bool is_valid_index(const http* hp, unsigned idx) {
	return idx < hp->nhd;
}

inline http*
get_http(VRT_CTX, int where)
{
	struct http* hp = nullptr;
	switch (where) {
	case GUEST_HDR_REQ:
		hp = ctx->http_req;
		break;
	case GUEST_HDR_REQ_TOP:
		hp = ctx->http_req_top;
		break;
	case GUEST_HDR_BEREQ:
		hp = ctx->http_bereq;
		break;
	case GUEST_HDR_BERESP:
		hp = ctx->http_beresp;
		break;
	case GUEST_HDR_RESP:
		hp = ctx->http_resp;
		break;
	case GUEST_HDR_OBJ:
		throw std::runtime_error("Object headers (HDR_OBJ) are not supported");
	}
	if (UNLIKELY(hp == nullptr))
		throw std::runtime_error("Selected HTTP not available at this time: " + std::to_string(where));
	return hp;
}
inline std::tuple<http*, txt&>
get_field(VRT_CTX, int where, uint32_t index)
{
	auto* hp = get_http(ctx, where);

	if (is_valid_index(hp, index))
	{
		return {hp, hp->hd[index]};
	}
	throw std::out_of_range("Header field index not in bounds");
}
static unsigned
http_findhdr(const struct http *hp, unsigned l, const char *hdr)
{
	for (unsigned u = HDR_FIRST; u < hp->nhd; u++)
	{
		if (hp->hd[u].e < hp->hd[u].b + l + 1)
			continue;
		if (hp->hd[u].b[l] != ':')
			continue;
		if (strncasecmp(hdr, hp->hd[u].b, l))
			continue;
		return u;
	}
	return 0;
}
static void
http_unsetat(struct http *hp, unsigned idx)
{
	unsigned count;

	assert(idx >= HDR_FIRST); /* Avoid proto fields */
	assert(idx < hp->nhd); /* Out of bounds */

	if (hp->vsl != NULL) {
		const int i = (HTTP_HDR_UNSET - HTTP_HDR_METHOD) + hp->logtag;
		VSLbt(hp->vsl, (enum VSL_tag_e)i, hp->hd[idx]);
	}

	/* Inefficient, but preserves order (assuming sorted?) */
	count = hp->nhd - idx - 1;
	memmove(&hp->hd[idx], &hp->hd[idx + 1], count * sizeof *hp->hd);
	memmove(&hp->hdf[idx], &hp->hdf[idx + 1], count * sizeof *hp->hdf);
	hp->nhd--;
}

inline uint32_t field_length(const txt& field)
{
	return field.e - field.b;
}

/* An RFC 9110 token: what a header name (or a method) may be. */
static bool valid_token(std::string_view name)
{
	if (name.empty())
		return false;
	for (unsigned char c : name) {
		if (isalnum(c))
			continue;
		if (c == '\0' || !strchr("!#$%&'*+-.^_`|~", c))
			return false;
	}
	return true;
}
/* A CR, LF or NUL would end the line, and let a tenant add header fields,
   or a whole request, of its own. */
static bool valid_value(std::string_view value)
{
	return value.find_first_of(std::string_view("\r\n\0", 3)) == std::string_view::npos;
}
/* A field the guest writes at an index. A header is "Name: value", with
   a token for the name, and the request or status line fields are values. */
static bool valid_field(unsigned index, std::string_view field)
{
	if (!valid_value(field))
		return false;
	if (index == HTTP_HDR_METHOD)
		return valid_token(field);
	if (index < HDR_FIRST)
		return true;
	const size_t colon = field.find(':');
	return colon != std::string_view::npos && valid_token(field.substr(0, colon));
}

/* An empty slot (never compiled, or deleted) is NULL, and VRE asserts on it */
inline struct vre* get_regex(machine_t& machine, size_t idx)
{
	auto* vre = get_script(machine).regex().get(idx);
	if (UNLIKELY(vre == nullptr))
		throw std::out_of_range("No regex at index " + std::to_string(idx));
	return vre;
}

/**
 *  These are all system call handlers, which get called by the guest,
 *  and so they have to maintain the integrity of Varnish by checking
 *  everything, and placing sane limits on requests. Additionally,
 *  some system calls are so expensive that they should increment
 *  the guests instruction counter, to make sure that it reflects the
 *  amount of work being done.
**/

APICALL(fail)
{
	auto [buffer] = machine.sysargs<riscv::Buffer> ();
	machine.stop();
	throw std::runtime_error("Assertion failed: " + buffer.to_string());
}
APICALL(assertion_failed)
{
	auto [expr, file, line, func] =
		machine.sysargs<std::string, std::string, int, std::string> ();
	/* TODO: Use VSLb here */
	fprintf(stderr, ">>> assertion failed: %s in %s:%d, function %s\n",
		expr.c_str(), file.c_str(), line, func.c_str());
	machine.stop();
	throw std::runtime_error("Assertion failed");
}
APICALL(print)
{
	const auto [buffer] = machine.sysargs<riscv::Buffer> ();
	auto& script = get_script(machine);
	if (buffer.is_sequential()) {
		script.print({buffer.c_str(), buffer.size()});
	} else {
		script.print(buffer.to_string());
	}
	machine.set_result(buffer.size());
}
APICALL(shm_log)
{
	auto [string, len] = machine.sysargs<gaddr_t, uint32_t> ();
	const auto* ctx = get_ctx(machine);

	/* Fallback (with potential slow-path) */
	auto buffer = machine.memory.membuffer(string, len);
	if (buffer.is_sequential()) {
		VSLb(ctx->vsl, SLT_VCL_Log, "%.*s", (int) buffer.size(), buffer.c_str());
		machine.set_result(len);
		return;
	}
	// TODO: slow-path
	machine.set_result(-1);
}
APICALL(breakpoint)
{
	auto& script = get_script(machine);
	auto* ctx = script.ctx();
	if (script.is_debug()) {
		VSLb(ctx->vsl, SLT_Debug,
			"VM breakpoint at 0x%lX", (long) machine.cpu.pc());
		script.open_debugger(DEBUG_PORT);
	} else {
		VSLb(ctx->vsl, SLT_Debug,
			"Skipped VM breakpoint at 0x%lX (debug not enabled)",
			(long) machine.cpu.pc());
	}
}
APICALL(signal)
{
	auto [sig, handler] = machine.sysargs<int, gaddr_t> ();
	get_script(machine).set_sigaction(sig, handler);
}
APICALL(is_storage)
{
	machine.set_result(get_script(machine).is_storage());
}
struct StorageStack {
	Script::machine_t& machine;
	const Script::gaddr_t sp;
	StorageStack(Script& storage)
		: machine(storage.machine()), sp(machine.cpu.reg(riscv::REG_SP)) {}
	~StorageStack() { machine.cpu.reg(riscv::REG_SP) = sp; }
};
APICALL(remote_call)
{
	auto [func] = machine.sysargs <gaddr_t> ();
	auto& script = get_script(machine);
	auto& instance = script.program();
	auto& remote = instance.storage;
	// Get machine registers
	auto& myregs = machine.cpu.registers();
	auto& stregs = remote.machine().cpu.registers();

	// === Serialized access to storage === //
	std::scoped_lock lock(instance.storage_mtx);
	StorageCtx lease(remote, script.ctx());
	StorageStack stack(remote);
	for (int i = 0; i < 4; i++) {
		// Integer registers
		stregs.get(10 + i) = myregs.get(11 + i);
	}
	/* For the length of the call, the storage VM reads this fork's pages
	   and writes into its heap. The fork and its pages end with the
	   request, while the storage VM lives on: whatever happens in the
	   call, neither the handlers that reach the fork nor the page caches
	   that may point into its pages may outlive it. */
	struct Borrow {
		riscv::Memory<Script::MARCH>& mem;
		riscv::Memory<Script::MARCH>::page_readf_cb_t readf;
		riscv::Memory<Script::MARCH>::page_fault_cb_t fault;
		~Borrow() {
			mem.set_page_readf_handler(std::move(readf));
			mem.set_page_fault_handler(std::move(fault));
			mem.invalidate_reset_cache();
		}
	};
	auto& rmem = remote.machine().memory;
	Borrow borrow { rmem,
	// Page-sharing mechanisms
	rmem.set_page_readf_handler(
		[&m = machine.memory] (const auto&, size_t pageno) -> const auto& {
			// This works because the default return value for
			// missing pages is a CoW zero-page (in both machines).
			return m.get_pageno(pageno);
		}),
	rmem.set_page_fault_handler(
		[&s = script] (auto& mem, const size_t pageno, bool) -> auto& {
			const gaddr_t addr = pageno * riscv::Page::size();
			if (s.within_heap(addr) && !s.within_stack(addr)) {
				auto& pg = s.machine().memory.create_writable_pageno(pageno);
				// The page is created on the source Machine, but we need
				// to invalidate the page on the remote Machine too:
				mem.invalidate_cache(pageno, &pg);
				return pg;
			}
			// Check memory limits before allocating new page
			if (LIKELY(mem.pages_active() < s.max_memory() / riscv::Page::size())) {
				return mem.allocate_page(pageno);
			}
			throw riscv::MachineException(riscv::OUT_OF_MEMORY,
				"Out of memory", s.max_memory());
		}) };
	// Reset instruction counter for measuring purposes
	remote.machine().reset_instruction_counter();
	// Make storage VM function call
	remote.call(func);
	// Accumulate instruction counting from the remote machine
	// plus some extra because remote calls are expensive
	machine.increment_counter(REMOTE_CALL_COST
		+ remote.machine().instruction_counter());

	for (int i = 0; i < 4; i++) {
		myregs.get(10 + i) = stregs.get(10 + i);
	}
	// Short-circuit the ret pseudo-instruction:
	machine.cpu.jump(machine.cpu.reg(riscv::REG_RA) - 4);
}
APICALL(remote_strcall)
{
	auto [tramp, func, data, len] =
		machine.sysargs <gaddr_t, gaddr_t, gaddr_t, int> ();
	//printf("Remote stringcall: tramp=0x%X func=0x%X data=0x%X len=%d\n",
	//	tramp, func, data, len);
	auto& script = get_script(machine);
	auto& instance = script.program();
	auto& remote = instance.storage;

	// All arguments have to be valid, and we
	// can't call this from the storage machine
	if (script.is_storage() || tramp == 0 || data == 0 || len < 0 || len == INT_MAX) {
		gaddr_t resdata = script.guest_alloc(1);
		script.machine().memory.write<uint8_t> (resdata, 0);
		machine.set_result(resdata, 0);
		return;
	}

	// === Serialized access to storage === //
	std::scoped_lock lock(instance.storage_mtx);
	StorageCtx lease(remote, script.ctx());
	StorageStack stack(remote);

	gaddr_t gaddr = remote.guest_alloc(len+1);
	if (gaddr == 0) {
		throw riscv::MachineException(riscv::OUT_OF_MEMORY,
			"Remote call: Remote machine out of memory");
	}
	// copy the string to the remote machine
	remote.machine().memory.memcpy(gaddr, machine, data, len+1);

	// Storage VM function call
	remote.machine().reset_instruction_counter();
	remote.call((gaddr_t) tramp, (gaddr_t) func, (gaddr_t) gaddr, (int) len);

	// copy a result string back
	const auto [raddr, rlen] = remote.machine().sysargs<gaddr_t, unsigned> ();
	if (raddr == 0) {
		throw std::runtime_error(
			"Null-pointer returned from remote during remote call");
	}

	// copy over the data returned from storage
	const gaddr_t resdata = script.guest_alloc(rlen+1);
	if (resdata == 0) {
		throw riscv::MachineException(riscv::OUT_OF_MEMORY,
			"Remote call: Tenant machine out of memory");
	}
	machine.memory.memcpy(resdata, remote.machine(), raddr, rlen+1);
	// set result now, even if there's an exception in storage
	// we have already gotten our result
	machine.set_result(resdata, rlen);

	// Finish up: let the guest destroy stuff on its own
	// We set aside a few thousand instructions for cleanup
	// NOTE: They will still count against the totals
	remote.resume(64000);
	// free string passed to storage
	remote.guest_free(gaddr);
	//printf("Resume completed  gaddr=0x%X  raddr=0x%X  instr=%zu\n",
	//	gaddr, raddr, remote.machine().instruction_counter());
	// accumulate instruction counting from the remote machine
	// plus some extra because remote calls are expensive
	machine.increment_counter(REMOTE_CALL_COST + remote.machine().instruction_counter());
}

APICALL(register_callback)
{
	const auto [idx, addr] =
		machine.sysargs<uint32_t, gaddr_t>();
	auto& script = get_script(machine);
	if (idx == ~0u)
	{
		// Custom exit address
		script.machine().memory.set_exit_address(addr);
		machine.set_result(0);
		return;
	}
	else if (idx >= script.program().callback_entries.size()) {
		throw std::out_of_range("register_callback: Callback index out of range");
	}
	script.program().callback_entries.at(idx) = addr;
	machine.set_result(0);
}
APICALL(register_func)
{
	const auto [nameptr, namelen, addr] =
		machine.sysargs<gaddr_t, uint32_t, gaddr_t>();
	if (namelen > 256) {
		throw std::runtime_error("Function name too long in register_func");
	}
	std::string name(namelen, '\0');
	machine.memory.memcpy_out(name.data(), nameptr, namelen);
	auto& script = get_script(machine);
	script.program().function_map.insert_or_assign(name, addr);
}
APICALL(set_decision)
{
	if (machine.is_forked())
	{
		// A forked VM in any VCL stage
		auto [result, status, paused] =
			machine.sysargs<riscv::Buffer, gaddr_t, bool> ();
		auto& script = get_script(machine);
		script.set_result(result.to_string(), status, paused);
		if (script.ctx()->vsl != nullptr)
			VSLb(script.ctx()->vsl, SLT_VCL_Log,
				"[%s] Decision: %.*s (status: %d)",
				script.name().c_str(),
				(int) result.size(), result.c_str(),
				(int) status);
	} else {
		// An initializing tenant VM
		auto [on_recv, on_exit] = machine.sysargs<gaddr_t, gaddr_t>();
		// Set the tenant as paused
		auto& script = get_script(machine);
		script.pause();
		// Overwrite the on_recv function, if set
		if (on_recv != 0x0) {
			auto& inst = script.program();
			inst.callback_entries.at(1) = on_recv;
		}
		if (on_exit != 0x0) {
			machine.memory.set_exit_address(on_exit);
		}
	}
	machine.stop();
}
/* Only a backend that VCL gave this machine, in the tenant's "backends"
   or with riscv.add_backend(). An empty slot would clear the backend hint. */
static long select_backend(Script& script, unsigned be)
{
	if (be >= script.directors().size() || script.directors().get(be) == nullptr)
		return -1;
	return riscv_SetBackend(script.ctx(), script.directors().get(be));
}
APICALL(set_backend)
{
	auto [be] = machine.sysargs<unsigned> ();
	machine.set_result(select_backend(get_script(machine), be));
}
APICALL(find_backend)
{
	auto [addr, len, select] = machine.sysargs<gaddr_t, gaddr_t, int> ();
	auto& script = get_script(machine);
	/* No name is this long */
	if (len > 256) {
		machine.set_result(-1);
		return;
	}
	/* Read-only: a string literal is in pages a fork may not write */
	const auto buffer = machine.memory.membuffer(addr, len);
	const std::string copy = buffer.is_sequential() ? std::string() : buffer.to_string();
	const std::string_view name = buffer.is_sequential() ? buffer.strview() : copy;
	/* The tenant's "backends" take the first slots, in this order. Also
	   answers during initialization, before any backend is given. */
	const auto& names = script.tenant().config.group.backends;
	const auto it = std::find(names.begin(), names.end(), name);
	if (it == names.end()) {
		machine.set_result(-1);
		return;
	}
	const unsigned be = it - names.begin();
	/* With select, also make it the backend, in the same call */
	machine.set_result(select ? select_backend(script, be) : be);
}
APICALL(backend_decision)
{
	auto [caching, func, farg, farglen] =
		machine.sysargs<unsigned, gaddr_t, gaddr_t, gaddr_t> ();
	auto& script = get_script(machine);
	if (func != 0x0) {
		script.set_results("backend", {caching, func, farg}, true);
	} else {
		script.set_results("compute", {caching, farg, farglen}, true);
	}
	machine.stop();
}
APICALL(ban)
{
	auto [buffer] = machine.sysargs<std::string> ();
	auto* ctx = get_ctx(machine);

	VRT_ban_string(ctx, buffer.c_str());
}
APICALL(hash_data)
{
	auto [buffer] = machine.sysargs<riscv::Buffer> ();
	auto& script = get_script(machine);

	if (buffer.is_sequential())
		script.hash_buffer(buffer.c_str(), buffer.size());
	else
		script.hash_buffer(buffer.to_string().c_str(), buffer.size());
}
APICALL(purge)
{
	machine.set_result(-1);
}

#ifdef VARNISH_PLUS
static char* synth_zero_copy(machine_t& machine, gaddr_t addr, gaddr_t len)
{
	constexpr gaddr_t PMASK = riscv::Page::size() - 1;
	if (len == 0)
		return nullptr;
	const gaddr_t end = addr + len;
	if (UNLIKELY(end < addr))
		return nullptr;
	const gaddr_t first = addr / riscv::Page::size();
	const gaddr_t last = end / riscv::Page::size();
	char* body = nullptr;
	for (gaddr_t pageno = first; pageno <= last; pageno++) {
		const auto& page = machine.memory.get_pageno(pageno);
		if (!page.attr.write)
			return nullptr;
		char* host = (char *)page.data();
		if (pageno == first)
			body = host + (addr & PMASK);
		else if (host != body + (pageno * riscv::Page::size() - addr))
			return nullptr;
	}
	if (body[len] != 0)
		return nullptr;
	return body;
}
#endif

APICALL(synth)
{
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t0);
#endif
	const auto* ctx = get_ctx(machine);
	if (ctx->method == VCL_MET_SYNTH ||
		ctx->method == VCL_MET_BACKEND_ERROR)
	{
		// Synth responses are always using HDR_RESP
		auto* hp = get_http(ctx, GUEST_HDR_RESP);
		const auto [status, type, data_addr, data_len] = machine.sysargs<uint16_t, riscv::Buffer, gaddr_t, gaddr_t> ();
		if (UNLIKELY(data_len > 16ul << 20))
			throw std::runtime_error("Synth content too large");
		/* http_SetStatus() asserts on the last three digits */
		if (UNLIKELY(status % 1000 < 100))
			throw std::runtime_error("Invalid synth status code: " + std::to_string(status));
		/* The Content-Type goes into a header line as is */
		if (UNLIKELY(!valid_value(type.to_string())))
			throw std::runtime_error("Invalid synth Content-Type");

#ifdef VARNISH_PLUS
		http_SetStatus(hp, status);
#else
		const char *reason = http_Status2Reason(status, NULL);
		http_SetStatus(hp, status, reason ? reason : "Unknown reason");
#endif
		http_PrintfHeader(hp, "Content-Length: %u", (unsigned)data_len);
		if (type.is_sequential())
			http_PrintfHeader(hp, "Content-Type: %.*s", (int)type.size(), type.data());
		else
			http_PrintfHeader(hp, "Content-Type: %.*s", (int)type.size(), type.to_string().c_str());

#ifndef VARNISH_PLUS
#if __has_include("cache/cache_int.h")
		auto* body = (char *)WS_Alloc(ctx->ws, data_len + 1);
		if (UNLIKELY(body == nullptr))
			throw std::runtime_error("Out of workspace for synth content");
		machine.memory.memcpy_out(body, data_addr, data_len);
		VCL_BLOB blob = VRT_blob(ctx, "riscv.synth", body, data_len, 0);
#else
		std::string buf(data_len, '\0');
		machine.memory.memcpy_out(buf.data(), data_addr, data_len);
		VCL_BLOB blob = VRT_blob(ctx, "riscv.synth", buf.data(), buf.size(), 0);
#endif
		if (UNLIKELY(blob == nullptr))
			throw std::runtime_error("Out of workspace for synth content");
		if (ctx->method == VCL_MET_SYNTH)
			VRT_l_resp_body(ctx, LBODY_SET_BLOB, nullptr, blob);
		else
			VRT_l_beresp_body(ctx, LBODY_SET_BLOB, nullptr, blob);
#else
		auto* vsb = (struct vsb *)ctx->specific;
		assert(vsb != nullptr);

		// Varnish writes a NUL after the body in VSB_finish(), so the
		// body is only used in place when that byte is already a zero
		// in a page this fork owns. Otherwise it would land past the end
		// of a guest page, or in a page every fork shares with the master
		// (rodata, or the zero page). The copy has room for that zero.
		const int keep = vsb->s_flags & (VSB_DYNSTRUCT | VSB_AUTOEXTEND);
		if (char* body = synth_zero_copy(machine, data_addr, data_len)) {
			if (vsb->s_flags & VSB_DYNAMIC)
				free(vsb->s_buf);
			vsb->s_buf = body;
			vsb->s_flags = keep;
		} else {
			char* new_buffer = (char *)((vsb->s_flags & VSB_DYNAMIC)
				? realloc(vsb->s_buf, data_len+1) : malloc(data_len+1));
			if (UNLIKELY(new_buffer == nullptr))
				throw std::runtime_error("Unable to allocate room for synth content buffer");
			vsb->s_buf = new_buffer;
			vsb->s_flags = keep | VSB_DYNAMIC;
			vsb->s_size = data_len+1;
			vsb->s_len  = 0;
			machine.memory.memcpy_out(new_buffer, data_addr, data_len);
		}
		vsb->s_size = data_len+1;
		vsb->s_len  = data_len;
#endif
		machine.stop();
#ifdef ENABLE_TIMING
		TIMING_LOCATION(t1);
		printf("Time spent in synth syscall: %ld ns\n", nanodiff(t0, t1));
#endif
		return;
	} else if (ctx->method == VCL_MET_RECV) {
		auto& script = get_script(machine);
		// Pause the program until VCL_MET_SYNTH.
		script.set_result("synth", 100, true);
		// This will cause a retrigger of this system call once
		// we are in VCL_MET_SYNTH.
		machine.cpu.increment_pc(-4);
		machine.stop();
		return;
	}
	throw std::runtime_error(
		"Synth can only be used in vcl_synth or vcl_backend_error");
}
APICALL(cacheable)
{
	const auto* ctx = get_ctx(machine);
	if (ctx->method == VCL_MET_BACKEND_RESPONSE)
	{
		auto [set, val] = machine.sysargs<int, int> ();
		if (set) {
			riscv_SetCacheable(ctx, val);
		}
		machine.set_result(!riscv_GetCacheable(ctx));
		return;
	}
	machine.set_result(0);
}
APICALL(ttl)
{
	const auto* ctx = get_ctx(machine);
	if (ctx->method == VCL_MET_BACKEND_RESPONSE)
	{
		auto [set, val] = machine.sysargs<int, float> ();
		if (set) {
			riscv_SetTTL(ctx, val);
		}
		machine.set_result(riscv_GetTTL(ctx));
		return;
	}
	machine.set_result(0.0f);
}

APICALL(foreach_header_field)
{
	auto [where, func, data] = machine.sysargs<int, gaddr_t, gaddr_t> ();

	const auto* ctx = get_ctx(machine);
	auto* hp = get_http(ctx, where);

	auto& script = get_script(machine);

	const gaddr_t first = script.guest_alloc(hp->nhd * sizeof(guest_header_field));
	gaddr_t iterator = first;
	int acount = 0;

	/* Iterate each header field */
	for (unsigned idx = HDR_FIRST; idx < hp->nhd; idx++) {
		const auto& field = hp->hd[idx];
		const uint32_t len = field_length(field);
		/* Ignore empty fields (?) */
		if (len == 0)
			continue;

		const guest_header_field gf {where, idx, false, true};
		machine.copy_to_guest(iterator, &gf, sizeof(gf));
		iterator += sizeof(gf);
		acount ++; /* Actual */
	}

	/* Call into the machine using pre-emption */
	script.preempt((gaddr_t) func, (gaddr_t) data, (gaddr_t) first, (int) acount);

	/* Check if any were deleted */
	int dcount = 0;
	for (int i = 0; i < acount; i++)
	{
		const gaddr_t addr = first + i*sizeof(guest_header_field);
		const bool deleted = machine.memory.read<uint8_t>
			(addr + offsetof(guest_header_field, deleted));
		/* Deleted entries moves everything back */
		if (deleted) {
			const unsigned idx = machine.memory.read<uint32_t>
				(addr + offsetof(guest_header_field, index));
			if (idx >= HDR_FIRST + dcount && is_valid_index(hp, idx - dcount)) {
				http_unsetat(hp, idx - dcount++);
			}
		}
	}

	script.guest_free(first);
	machine.set_result(acount);
}

APICALL(http_find_name)
{
	const auto [where, fieldname] = machine.sysargs<int, riscv::Buffer> ();
	auto* ctx = get_ctx(machine);
	auto* hp = get_http(ctx, where);

	if (fieldname.is_sequential())
	{
		/* Find the header field by its name */
		unsigned index
			= http_findhdr(hp, fieldname.size(), fieldname.c_str());
		if (index > 0) {
			machine.set_result(index);
			return;
		}
	} else {
		/* Find the header field by its name */
		unsigned index
			= http_findhdr(hp, fieldname.size(), fieldname.to_string().c_str());
		if (index > 0) {
			machine.set_result(index);
			return;
		}
	}
	/* Not found -> invalid header field */
	machine.set_result(HDR_INVALID);
}
APICALL(http_copy_from)
{
	const auto [where, index, dest]
		= machine.sysargs<int, unsigned, int> ();
	auto* ctx = get_ctx(machine);
	/* Ignore invalid header fields?? */
	if (is_invalid(index)) {
		machine.set_result(HDR_INVALID);
		return;
	}

	auto [hp_from, field_from] = get_field(ctx, where, index);
	auto* hp_dest = get_http(ctx, dest);

	/* An unset field, eg. the status of a request */
	if (field_from.b == nullptr) {
		machine.set_result(HDR_INVALID);
		return;
	}
	const size_t len = field_length(field_from);
	/* Avoid overflowing dest */
	if (UNLIKELY(hp_dest->nhd >= hp_dest->shd)) {
		VSLb(hp_dest->vsl, SLT_LostHeader,
			"%.*s", (int) len, field_from.b);
		machine.set_result(HDR_INVALID);
		return;
	}

	const int idx_dest = hp_dest->nhd++;
	http_SetH(hp_dest, idx_dest, field_from.b);
	machine.set_result(idx_dest);
}

APICALL(http_set_status)
{
	const auto [where, status] = machine.sysargs<int, int> ();

	auto* ctx = get_ctx(machine);
	auto [hp, field] = get_field(ctx, where, 3);
	/* Getter does not want to set status */
	if (status < 0) {
		machine.set_result(hp->status);
		return;
	}
	/* Do the workspace allocation before making changes */
	const char* string = (const char*)WS_Printf(ctx->ws, "%u", status);
	if (UNLIKELY(!string))
		throw std::runtime_error("Out of workspace");
	hp->status = status;
	/* We have to overwrite the header field too */
	field.b = string;
	field.e = field.b + strlen(string);
	machine.set_result(status);
}

APICALL(http_unset_re)
{
	const auto [where, index] = machine.sysargs<int, int> ();
	auto* vre = get_regex(machine, index);

	auto* ctx = get_ctx(machine);
	auto* hp = get_http(ctx, where);

	/* Unset header fields from the top down */
	size_t mcount = 0;
	for (int i = hp->nhd-1; i >= HDR_FIRST; i--)
	{
		auto& field = hp->hd[i];
		machine.penalize(VCLV_REGEX_MATCH_LIMIT);
#ifdef VARNISH_PLUS
		if ( VRE_exec(vre, field.b, field.e - field.b,
			0, 0, nullptr, 0, vclv_regex_limits()) >= 0 ) {
			http_unsetat(hp, i);
			mcount ++;
		}
#else
		if ( VRE_match(vre, field.b, field.e - field.b, 0, vclv_regex_limits()) >= 0 ) {
			http_unsetat(hp, i);
			mcount ++;
		}
#endif
	}
	machine.set_result(mcount);
}

APICALL(http_rollback)
{
	const auto [where] = machine.sysargs<int> ();
	auto* ctx = get_ctx(machine);
	/* Varnish can only roll back req and bereq, and panics otherwise */
	if (where != GUEST_HDR_REQ && where != GUEST_HDR_BEREQ)
		throw std::runtime_error("Rollback is only possible for req and bereq");
	auto* hp = get_http(ctx, where);

#if __has_include("cache/cache_int.h") || (defined(VARNISH_PLUS) && VRT_MAJOR_VERSION >= 6013U)
	(void)hp;
	VRT_Rollback(ctx);
#else
	VRT_Rollback(ctx, hp);
#endif
}

APICALL(header_field_get)
{
	machine.set_result(-1);
}

APICALL(header_field_retrieve)
{
	const auto [where, index, buffer, buflen]
		= machine.sysargs<int, uint32_t, gaddr_t, uint32_t> ();

	const auto* hp = get_http(get_ctx(machine), where);

	if (is_valid_index(hp, index))
	{
		const auto& field = hp->hd[index];
		const size_t len = field_length(field);
		if (buffer == 0 && buflen == 0) {
			machine.set_result(len);
			return;
		} else if (len > buflen) {
			machine.set_result(-1);
			return;
		}
		machine.copy_to_guest(buffer, field.b, len);
		machine.set_result(len);
		return;
	}
	/* Null pointers */
	machine.set_result(-1);
}
APICALL(header_field_retrieve_str)
{
	const auto [where, index, straddr]
		= machine.sysargs<int, uint32_t, gaddr_t> ();

	const auto* hp = get_http(get_ctx(machine), where);

	if (is_valid_index(hp, index))
	{
		const auto& field = hp->hd[index];
		const size_t len = field_length(field);
		riscv::GuestStdString<Script::MARCH> gstr(machine, straddr);
		gstr.set_string(machine, straddr, field.b ? field.b : "", len, false);
		machine.copy_to_guest(straddr, &gstr, sizeof(gstr));
		machine.set_result(len);
		return;
	}
	/* Null pointers */
	machine.set_result(-1);
}

APICALL(header_field_append)
{
	auto [where, field, len] = machine.sysargs<int, gaddr_t, uint32_t> ();
	const auto* ctx = get_ctx(machine);
	auto* hp = get_http(ctx, where);

	/* len+1 must not wrap around to a zero-sized allocation */
	if (UNLIKELY(len == UINT32_MAX))
		throw std::runtime_error("HTTP header field too long");
	auto* val = (char*) WS_Alloc(ctx->ws, len+1);
	if (val == nullptr)
		throw std::runtime_error("Unable to make room for HTTP header field");
	machine.memory.memcpy_out(val, (gaddr_t) field, len);
	val[len] = 0;
	if (UNLIKELY(!valid_field(HDR_FIRST, std::string_view(val, len))))
		throw std::runtime_error("Invalid HTTP header field");

	if (UNLIKELY(hp->nhd >= hp->shd)) {
		VSLb(hp->vsl, SLT_LostHeader, "%.*s", (int) len, val);
		machine.set_result(HDR_INVALID);
		return;
	}

	const int idx = hp->nhd++;
	//http_SetH(hp, idx, val);
	hp->hd[idx].b = val;
	hp->hd[idx].e = val + len;
	hp->hdf[idx] = 0;
	machine.set_result(idx);
}

APICALL(header_field_set)
{
	auto [where, index, buffer]
		= machine.sysargs<int, unsigned, riscv::Buffer> ();

	const auto* ctx = get_ctx(machine);
	auto* hp = get_http(ctx, where);

	if (is_valid_index(hp, index))
	{
		/* Allocate and extract the new field value */
		auto* val = (char*) WS_Alloc(ctx->ws, buffer.size()+1);
		if (val == nullptr)
			throw std::runtime_error("Unable to make room for HTTP header field");

		buffer.copy_to(val, buffer.size());
		val[buffer.size()] = 0;
		if (UNLIKELY(!valid_field(index, std::string_view(val, buffer.size()))))
			throw std::runtime_error("Invalid HTTP header field");

		/* Apply it at the given index */
		http_SetH(hp, index, val);
		machine.set_result(buffer.size());
		return;
	}
	else if (index == HDR_INVALID) {
		machine.set_result(-1);
		return;
	}
	/* This will halt execution */
	throw std::out_of_range("Header field index not in bounds");
}

APICALL(header_field_copy)
{
	auto [where, index, src_where, src_index]
		= machine.sysargs<int, unsigned, int, unsigned> ();

	const auto* ctx = get_ctx(machine);
	auto* hp = get_http(ctx, where);
	auto* src_hp = get_http(ctx, src_where);

	if (is_valid_index(hp, index))
	{
		if (is_valid_index(src_hp, src_index))
		{
			const auto& src_field = src_hp->hd[src_index];

			/* Apply it at the given index */
			hp->hd[index].b = src_field.b;
			hp->hd[index].e   = src_field.e;
			hp->hdf[index] = 0;

			machine.set_result(field_length(src_field));
			return;
		}
		else if (index >= HDR_FIRST) /* In VCL you can unset a header field by assigning it
			to a non-existing other header field. */
		{
			http_unsetat(hp, index);
			machine.set_result(HDR_INVALID);
			return;
		}
	}
	else if (index == HDR_INVALID || src_index == HDR_INVALID) {
		machine.set_result(HDR_INVALID);
		return;
	}
	/* This will halt execution */
	throw std::out_of_range("Header field index not in bounds");
}

APICALL(header_field_unset)
{
	auto [where, index] = machine.sysargs<int, unsigned> ();

	const auto* ctx = get_ctx(machine);
	auto* hp = get_http(ctx, where);

	/* You are not allowed to unset proto fields */
	if (is_valid_index(hp, index) && index >= HDR_FIRST)
	{
		http_unsetat(hp, index);
		machine.set_result(index);
		return;
	} else if (index == HDR_INVALID) {
		/* Silently ignored */
		machine.set_result(HDR_INVALID);
		return;
	}
	throw std::out_of_range("Header field index not in bounds");
}

APICALL(regex_compile)
{
	auto [pbuffer] = machine.sysargs<riscv::Buffer> ();
	auto pattern = pbuffer.to_string();

	const uint32_t hash = riscv::crc32(pattern.c_str(), pattern.size());
	const int idx = get_script(machine).regex().find(hash);
	if (idx >= 0) {
		machine.set_result(idx);
		return;
	}

	/* A full cache refuses before compiling, or the pattern would leak */
	if (UNLIKELY(get_script(machine).regex().full()))
		throw std::out_of_range("Too many cached regex patterns");

	/* Compile new regex pattern */
#ifdef VARNISH_PLUS
	const char* error = "";
	int         error_offset = 0;
	auto* re = VRE_compile(pattern.c_str(), 0, &error, &error_offset);
	/* TODO: log errors here */
	if (re == nullptr) {
		printf("Regex compile error: %s\n", error);
		throw std::runtime_error(
			"The regex pattern did not compile: " + pattern);
	}
#else
	int error        = 0;
	int error_offset = 0;
	auto* re = VRE_compile(pattern.c_str(), pattern.size(), &error, &error_offset, 0);
	if (re == nullptr) {
		throw std::runtime_error(
			"The regex pattern did not compile: " + pattern);
	}
#endif
	/* Return the regex handle */
	machine.set_result(
		get_script(machine).regex().manage(re, hash));
}
APICALL(regex_match)
{
	auto [index, buffer] = machine.sysargs<uint32_t, riscv::Buffer> ();
	auto* vre = get_regex(machine, index);
	/* A match may cost the host up to the match limit in backtracking. */
	machine.penalize(VCLV_REGEX_MATCH_LIMIT);
	/* VRE_exec(const vre_t *code, const char *subject, int length,
		int startoffset, int options, int *ovector, int ovecsize,
		const volatile struct vre_limits *lim) */
	if (buffer.is_sequential()) {
#ifdef VARNISH_PLUS
		machine.set_result(
			VRE_exec(vre, buffer.c_str(), buffer.size(), 0,
				0, nullptr, 0, vclv_regex_limits()) >= 0);
#else
		machine.set_result(
			VRE_match(vre, buffer.c_str(), buffer.size(), 0, vclv_regex_limits()) >= 0);
#endif
		return;
	}
	auto subject = buffer.to_string();
#ifdef VARNISH_PLUS
	machine.set_result(
		VRE_exec(vre, subject.c_str(), subject.size(), 0,
		0, nullptr, 0, vclv_regex_limits()) >= 0);
#else
	machine.set_result(
		VRE_match(vre, subject.c_str(), subject.size(), 0, vclv_regex_limits()) >= 0);
#endif
}
/* regsub() or regsuball() under the regex limits, charging each match the
   way a single regex_match is charged, and bounded by the budget left.
   VRT_regsub runs one uncounted match per replacement, up to one per byte. */
static struct vsb* charged_regsub(machine_t& machine, bool all,
	const std::string& subject, const void* re, const std::string& subst)
{
	if (subst.find('\0') != std::string::npos)
		return nullptr;
	const uint64_t left = machine.max_instructions() > machine.instruction_counter()
		? machine.max_instructions() - machine.instruction_counter() : 0;
	unsigned execs = unsigned(std::clamp<uint64_t>(left / VCLV_REGEX_MATCH_LIMIT, 1, UINT_MAX));
	struct vsb* result = nullptr;
	const int rc = vclv_regsub(all, subject.c_str(), strnlen(subject.c_str(), subject.size()),
		re, subst.c_str(), 16u << 20, &execs, &result);
	machine.penalize(uint64_t(execs) * VCLV_REGEX_MATCH_LIMIT + subject.size());
	return rc == 0 ? result : nullptr;
}
APICALL(regex_subst)
{
	auto [index, tbuffer, sbuffer, dst, maxlen]
		= machine.sysargs<uint32_t, riscv::Buffer, riscv::Buffer, gaddr_t, uint32_t> ();
	auto* re = get_regex(machine, index);

	/* Run the regsub using existing 're' */
	const bool all = (maxlen & 0x80000000);
	auto* result = charged_regsub(machine, all, tbuffer.to_string(), re,
		sbuffer.to_string());
	if (result == nullptr) {
		machine.set_result(-1);
		return;
	}

	/* Copied out first: writing to a bad destination throws */
	const std::string text(VSB_data(result), VSB_len(result));
	VSB_destroy(&result);

	/* This call only supports dest buffer being in the RW area */
	const size_t len =
		std::min((size_t) maxlen & 0x7FFFFFFF, text.size()+1);
	machine.copy_to_guest(dst, text.c_str(), len);
	/* The last byte is the zero, not reporting that */
	machine.set_result(len-1);
}
APICALL(regex_subst_hdr)
{
	auto [ridx, where, index, subst, all]
		= machine.sysargs<uint32_t, int, uint32_t, riscv::Buffer, int> ();
	auto* re = get_regex(machine, ridx);
	auto* ctx = get_ctx(machine);
	if (index == HDR_INVALID) {
		machine.set_result(-1);
		return;
	}
	auto [hp, field] = get_field(ctx, where, index);

	/* Run the regsub using existing 're' */
	auto* sub = charged_regsub(machine, all, std::string(field.b, field.e - field.b), re,
		subst.to_string());
	if (sub == nullptr) {
		machine.set_result(-1);
		return;
	}
	const size_t sublen = VSB_len(sub);
	/* The substitution replaces the whole field, name included */
	if (UNLIKELY(!valid_field(index, std::string_view(VSB_data(sub), sublen)))) {
		VSB_destroy(&sub);
		throw std::runtime_error("Invalid HTTP header field");
	}
	auto* result = static_cast<const char*>(WS_Copy(ctx->ws, VSB_data(sub), sublen + 1));
	VSB_destroy(&sub);
	if (result == nullptr) {
		machine.set_result(-1);
		return;
	}

	http_SetH(hp, index, result);
	machine.set_result(sublen);
}
APICALL(regex_delete)
{
	auto [index] = machine.sysargs<uint32_t> ();
	auto* re = get_script(machine).regex().free((uint32_t) index);
	if (re != nullptr)
		VRE_free(&re);
}

void sha256(machine_t&);
void base64(machine_t&);
void fetch(machine_t&);

APICALL(base64_decode)
{
	auto [src_buffer, dst_addr, dst_size]
		= machine.sysargs<riscv::Buffer, gaddr_t, uint32_t> ();
	if (dst_size < src_buffer.size()) {
		// Destination buffer too small
		machine.set_result(-1);
		return;
	}
	std::array<riscv::vBuffer, 64> buffers;
	const size_t dst_buffers = machine.memory.gather_writable_buffers_from_range(
		buffers.size(), buffers.data(), dst_addr, dst_size
	);

	if (!src_buffer.is_sequential() || dst_buffers != 1) {
		std::string src = src_buffer.to_string();
		std::vector<uint8_t> decoded(src.size());
		const auto len =
			EVP_DecodeBlock(decoded.data(), (const uint8_t *)src.data(), src.size());
		if (len > 0) {
			size_t remaining = len;
			size_t offset = 0;
			for (size_t i = 0; i < dst_buffers && remaining > 0; i++) {
				const size_t to_copy = std::min(remaining, buffers[i].len);
				memcpy(buffers[i].ptr, decoded.data() + offset, to_copy);
				remaining -= to_copy;
				offset += to_copy;
			}
		}
		machine.set_result(len);
		return;
	}

	// Both buffers are sequential
	const size_t len = EVP_DecodeBlock(
			(uint8_t *) buffers[0].ptr,
			(const uint8_t *) src_buffer.data(),
			src_buffer.size());
	machine.set_result(len);
}

void Script::setup_syscall_interface()
{
	static_assert(ECALL_LAST <= RISCV_SYSCALLS_MAX,
		"Not enough space for all syscalls");
	#define FPTR(x) machine_t::syscall_t { x }
	static constexpr std::array<const machine_t::syscall_t, ECALL_LAST - SYSCALL_BASE> handlers {
		FPTR(fail),
		FPTR(assertion_failed),
		FPTR(rvs::print),
		FPTR(shm_log),
		FPTR(breakpoint),
		FPTR(signal),
		FPTR(rvs::is_storage),
		FPTR(remote_call),
		FPTR(remote_strcall),

		FPTR(register_callback),
		FPTR(set_decision),
		FPTR(set_backend),
		FPTR(backend_decision),
		FPTR(ban),
		FPTR(hash_data),
		FPTR(purge),
		FPTR(synth),
		FPTR(cacheable),
		FPTR(ttl),

		FPTR(foreach_header_field),
		FPTR(header_field_get),
		FPTR(header_field_retrieve),
		FPTR(header_field_append),
		FPTR(header_field_set),
		FPTR(header_field_copy),
		FPTR(header_field_unset),

		FPTR(http_rollback),
		FPTR(http_copy_from),
		FPTR(http_set_status),
		FPTR(http_unset_re),
		FPTR(http_find_name),

		FPTR(regex_compile),
		FPTR(regex_match),
		FPTR(regex_subst),
		FPTR(regex_subst_hdr),
		FPTR(regex_delete),

		FPTR(sha256),
		FPTR(header_field_retrieve_str),
		FPTR(base64_decode),
		FPTR(register_func),
	};
	for (size_t i = 0; i < handlers.size(); i++) {
		machine_t::install_syscall_handler(SYSCALL_BASE + i, handlers[i]);
	}
	machine_t::install_syscall_handler(ECALL_BASE64, base64);
	machine_t::install_syscall_handler(ECALL_FETCH, fetch);
	machine_t::install_syscall_handler(ECALL_FIND_BACKEND, find_backend);

	// A custom intruction used to handle indexed dynamic calls.
	using namespace riscv;
	static const Instruction<MARCH> unchecked_syscall_instruction {
		[](CPU<MARCH>& cpu, rv32i_instruction instr)
		{
			handlers[instr.Itype.imm](cpu.machine());
		},
		[](char* buffer, size_t len, const CPU<MARCH>&, rv32i_instruction instr) -> int
		{
			return snprintf(buffer, len,
				"SYSCALL: 4-byte idx=%u  raw=0x%08X",
				uint32_t(instr.Itype.imm),
				instr.whole
			);
		}};
	// Override the machines unimplemented instruction handling,
	// in order to use the custom instruction instead.
	CPU<MARCH>::on_unimplemented_instruction
		= [](rv32i_instruction instr) -> const Instruction<MARCH>&
	{
		if (instr.opcode() == 0b1011011 && instr.Itype.rs1 == 0 && instr.Itype.rd == 0)
		{
			if (instr.Itype.imm < (int)handlers.size())
				return unchecked_syscall_instruction;
		}
		return CPU<MARCH>::get_unimplemented_instruction();
	};
}

timespec time_now()
{
	timespec t;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
	return t;
}
long nanodiff(timespec start_time, timespec end_time)
{
	assert(end_time.tv_sec == 0); /* We should never use seconds */
	return end_time.tv_nsec - start_time.tv_nsec;
}

} // rvs
