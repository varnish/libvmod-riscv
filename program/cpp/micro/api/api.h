/**
 *  API shared between Varnish and RISC-V binaries
 *
**/
#pragma once
#include <engine.hpp>
#include <array>
#include <memory>
#include <optional>
#include <span>
#include "api_structs.h"
#define PPT() template <typename... Args>

namespace api {

PPT() void print(fmt::format_string<Args...> format, Args&&... args);

PPT() void log(fmt::format_string<Args...> format, Args&&... args);

/* Make a VCL decision, such as "lookup" */
void decision(std::string_view, int status = 403);
/* Make a VCL decision, then pause machine (for synth) */
void pause_for(std::string_view, int status = 403);

/* Bans */
PPT() void ban(Args&&... args);

/* Hashing */
void hash_data(std::string_view buffer);
void hash_data(const HeaderField&);

/* Caching */
void make_uncacheable_for(float secs);

/* Base64 (RFC 4648), flags: BASE64_FLAG_URL, BASE64_FLAG_NOPAD */
std::string base64_encode(std::string_view data, unsigned flags = 0);
std::optional<std::string> base64_decode(std::string_view text, unsigned flags = 0);

/* SHA-256 */
std::array<uint8_t, 32> sha256(std::string_view data);

/* Outgoing HTTP(S) requests (Varnish Enterprise), to the URLs the tenant's
   "fetch" allow list permits. Start several, then wait for any or all. */
struct FetchResponse {
	/* The HTTP status, 0 when the transfer failed */
	int status() const noexcept { return m_status; }
	/* 0 on success, a CURLcode when the transfer failed, FETCH_EPENDING
	   until fetch_wait() completes it, or a negative FETCH_E* when the
	   request was refused (only from fetch()) */
	int error() const noexcept { return m_error; }
	bool ok() const noexcept { return m_error == 0; }
	std::string_view body() const noexcept { return {m_body, m_body_len}; }
	/* "Name: value\n" lines */
	std::string_view headers() const noexcept { return {m_headers, m_headers_len}; }
	std::optional<std::string_view> header(std::string_view name) const;

	FetchResponse() = default;
	explicit FetchResponse(int error) : m_error(error) {}
	FetchResponse(FetchResponse&&) noexcept;
	FetchResponse& operator=(FetchResponse&&) noexcept;
	~FetchResponse();
private:
	/* The layout of struct fetch_response (syscalls.h). The system call
	   allocates body and headers on the native heap, which is also where
	   malloc and operator new allocate (libc/heap_linux.cpp, heap.cpp). */
	int32_t m_status = 0;
	int32_t m_error = FETCH_EPENDING;
	char*   m_body = nullptr;
	size_t  m_body_len = 0;
	char*   m_headers = nullptr;
	size_t  m_headers_len = 0;
};
/* Start a request: a handle, or a negative FETCH_E*. flags: FETCH_FLAG_INSECURE
   accepts any TLS certificate. Headers are "Name: value" lines. */
int fetch_get(std::string_view url, std::string_view headers = {}, unsigned flags = 0);
int fetch_post(std::string_view url, std::string_view body, std::string_view headers = {}, unsigned flags = 0);
/* Wait for all of the handles, or with FETCH_FLAG_ANY for at least one of
   them, at most timeout_ms (< 0: until done, 0: poll). A finished handle
   becomes -1, and its response is at the same index. Returns how many
   finished, or a negative FETCH_E*. */
long fetch_wait(std::span<int32_t> handles, std::span<FetchResponse> responses,
	unsigned flags = 0, int timeout_ms = -1);
/* Abandon a request */
void fetch_free(int handle);
/* One GET, waited for */
FetchResponse fetch(std::string_view url, std::string_view headers = {}, unsigned flags = 0);

/* Regular expressions */
struct Regex {
	Regex(const std::string& pattern);
	bool good() const noexcept { return idx >= 0; }
	int  index() const noexcept { return idx; }

	int match(std::string_view subject) const;
	std::string replace(std::string_view text, const std::string& subst, bool all = false) const;
	std::string replace(const std::string& text, const std::string& subst, bool all = false) const;
	int replace(HeaderField& hdr, const std::string& subst, bool all = false) const;

private:
	int idx;
};

struct HeaderField {
	std::string to_string() const;
	std::string value() const;

	HeaderField& set(const char*, size_t);
	HeaderField& set(const HeaderField&);
	PPT() HeaderField& set(fmt::format_string<Args...> format, Args&&... args);
	PPT() HeaderField& operator = (Args&&... args);

	HeaderField& regsub(const std::string& pattern, const std::string& subst, bool all = false);
	HeaderField& regsub(const Regex&, const std::string& subst, bool all = false);
	/* Do *NOT* use this header field after calling unset */
	void unset();

	HeaderField append_to(struct HTTP&) const;
	HTTP http() const;

	operator bool () const noexcept { return is_valid(); }
	bool is_valid() const noexcept { return index != UINT32_MAX; }

	HeaderField(gethdr_e where, size_t idx);
private:
	gethdr_e   where;
	uint32_t   index;
	bool       deleted;
	bool       foreach;
	friend struct Regex;
};

using header_iterator_t = Function<void(HeaderField&)>;
using header_citerator_t = Function<void(const HeaderField&)>;

struct HTTP {
	HeaderField find(const std::string&) const;
	HeaderField operator [](const std::string&) const;
	HeaderField operator +=(const std::string&);
	HeaderField operator +=(HeaderField other);

	std::string url() const;
	std::string proto() const;
	uint16_t status() const;
	uint16_t set_status(uint16_t code);
	bool is_error() const;

	HeaderField append(const HeaderField&);
	HeaderField append(std::string_view);
	PPT() HeaderField appendf(fmt::format_string<Args...> format, Args&&... args); /* Formatted */

	void foreach(header_iterator_t);
	void foreach(header_citerator_t) const;
	size_t unset(const Regex&); /* Returns number of entries unset */
	/* NOTE: Rollback will invalidate all header fields. */
	void rollback();

	const char* name() const;
	constexpr HTTP(enum gethdr_e e) : where(e) {}
	const gethdr_e where;
};
struct HTTP_Req : public HTTP {
	std::string method() const;
	void set_backend(int);
};
struct HTTP_Resp : public HTTP {
	std::string reason() const;
	static void set_cacheable(bool c);
	static bool cacheable();
	static void  set_ttl(float secs);
	static float ttl();
};

struct Request : public HTTP_Req {
	constexpr Request(gethdr_e w) : HTTP_Req{w} {}
};
struct Response : public HTTP_Resp {
	constexpr Response(gethdr_e w) : HTTP_Resp{w} {}
};

/* Forge a backend response */
void forge(Cache c, response (*generator) (Request));

/* Compute using KVM */
void kvm_compute(Cache c, const std::string& arg);

enum Callback {
	CALLBACK_INVALID = 0,
	CALLBACK_ON_RECV,
	CALLBACK_ON_HASH,
	CALLBACK_ON_SYNTH,
	CALLBACK_ON_BACKEND_FETCH,
	CALLBACK_ON_BACKEND_RESPONSE,
	CALLBACK_ON_BACKEND_ERROR,
	CALLBACK_ON_DELIVER,
	CALLBACK_ON_HIT,
	CALLBACK_ON_MISS,
	CALLBACK_ON_LIVE_UPDATE,
	CALLBACK_ON_RESUME_UPDATE,
	CALLBACK_MAX
};
void set_on_deliver(void (*func)(Request, Response));
void set_on_deliver(void (*func)(Request, Response, const char*));

/* Make a function callable from VCL with riscv.call(name, arg) */
using function_t = const char* (*)(const char* arg, size_t len);
void register_function(std::string_view name, function_t func);

/*  */
inline bool is_storage() {
	register long a0 asm("a0");
	register long syscall_id asm("a7") = ECALL_IS_STORAGE;

	asm volatile ("ecall" : "+r"(a0) : "r"(syscall_id));

	return a0;
}
inline bool is_debug() {
	const char* dbg = getenv("RISCV_DEBUG");
	return dbg != nullptr;
}

/* Implementation */
#include "api_impl.h"

extern "C" void sys_register_callback(int which, void(*func)());
inline void set_on_deliver(void(*func)(Request, Response)) {
	sys_register_callback(CALLBACK_ON_DELIVER, (void(*)())func);
}
inline void set_on_deliver(void(*func)(Request, Response, const char*)) {
	sys_register_callback(CALLBACK_ON_DELIVER, (void(*)())func);
}
}
