/**
 *  API shared between Varnish and RISC-V binaries
 *
**/
#pragma once
#include <engine.hpp>
#include <memory>
#include "api_structs.h"
#define PPT() template <typename... Args>

namespace api {

PPT() void print(fmt::format_string<Args...> format, Args&&... args);

PPT() void log(fmt::format_string<Args...> format, Args&&... args);

/* Make a VCL decision, such as "lookup" */
void decision(const std::string&, int status = 403);
/* Make a VCL decision, then pause machine (for synth) */
void pause_for(const std::string&, int status = 403);

/* Bans */
PPT() void ban(Args&&... args);

/* Hashing */
void hash_data(const std::string& buffer);
void hash_data(const HeaderField&);

/* Caching */
void make_uncacheable_for(float secs);

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
void set_on_deliver(void(*func)(Response));

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
}
