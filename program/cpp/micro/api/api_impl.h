#pragma once
#include "strace.h"
extern "C" {
	void breakpoint();
}

template <typename Expr>
inline void expect_check(Expr expr, const char* strexpr,
	const char* file, int line, const char* func)
{
	if (UNLIKELY(!expr())) {
		asm ("" ::: "memory"); // prevent dead-store optimization
		syscall(ECALL_ASSERT_FAIL, (long) strexpr, (long) file, (long) line, (long) func);
		__builtin_unreachable();
	}
}
#define EXPECT(expr) \
	api::expect_check([&] { return (expr); }, #expr, __FILE__, __LINE__, __FUNCTION__)

PPT() inline
void print(fmt::format_string<Args...> format, Args&&... args)
{
	fmt_print(format, std::forward<Args> (args)...);
}

PPT() inline
void log(fmt::format_string<Args...> format, Args&&... args)
{
	strace("log(", args..., ")");
	char buffer[4096];
	const auto res = fmt::format_to_n(buffer, sizeof(buffer)-1, format, std::forward<Args> (args)...);
	const size_t len = res.size;
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_LOG, (long) buffer, len);
}

extern "C" void fast_exit();
inline void wait_for_requests(void(*on_recv)(Request))
{
	register void (*a0)() asm("a0") = (void(*)())on_recv;
	register long a1 asm("a1") = (long)fast_exit;
	register long syscall_id asm("a7") = ECALL_SET_DECISION;

	asm volatile ("ecall" : : "r"(a0), "r"(a1), "m"(*a0), "r"(syscall_id) : "memory");
}
inline void wait_for_requests(void(*on_recv)(Request, Response, const char*))
{
	register void (*a0)() asm("a0") = (void(*)())on_recv;
	register long a1 asm("a1") = (long)fast_exit;
	register long syscall_id asm("a7") = ECALL_SET_DECISION;

	asm volatile ("ecall" : : "r"(a0), "r"(a1), "m"(*a0), "r"(syscall_id) : "memory");
}

inline void sys_register_callback(Callback idx, void(*cb)())
{
	register unsigned a0     asm("a0") = (int)idx;
	register void(*a1)()     asm("a1") = cb;
	register long syscall_id asm("a7") = ECALL_REGISTER_CB;

	asm volatile ("ecall" : : "r"(a0), "r"(a1), "m"(*a1), "r"(syscall_id) : "memory");
}

inline void decision(std::string_view dec, int status)
{
	strace("decision({}, {})", dec, status);
	register const char* a0 asm("a0") = dec.data();
	register size_t      a1 asm("a1") = dec.size();
	register int         a2 asm("a2") = status;
	register int         a3 asm("a3") = false; // paused
	register int 	     a7 asm("a7") = ECALL_SET_DECISION;

	asm volatile("ecall" : : "r"(a0), "m"(*(const char (*)[a1])a0), "r"(a1), "r"(a2), "r"(a3), "r"(a7) : "memory");
	//__builtin_unreachable();
}
inline void pause_for(std::string_view dec, int status)
{
	strace("decision({}, {}, paused={})", dec, status, true);
	register const char* a0 asm("a0") = dec.data();
	register size_t      a1 asm("a1") = dec.size();
	register int         a2 asm("a2") = status;
	register int         a3 asm("a3") = true; // paused
	register int 	     a7 asm("a7") = ECALL_SET_DECISION;

	asm volatile ("ecall" : : "r"(a0), "m"(*(const char (*)[a1])a0), "r"(a1), "r"(a2), "r"(a3), "r"(a7) : "memory");
}
using backend_function_a = response(*)();
using backend_function_b = response(*)(Request, Response);
using backend_function_c = response(*)(Request, Response, void*, size_t);
extern "C" response backend_trampoline(backend_function_b);
extern "C" response backend_trampoline_post(backend_function_c);
inline void forge(Cache c, backend_function_a func)
{
	strace("forge(backend(), {})", (void*)func);
	syscall(ECALL_BACKEND_DECISION, (int) c, (long)backend_trampoline, (long)func);
}
inline void forge(Cache c, backend_function_b func)
{
	strace("forge(backend, {})", (void*) func);
	syscall(ECALL_BACKEND_DECISION, (int) c, (long)backend_trampoline, (long)func);
}
inline void forge(Cache c, backend_function_c func)
{
	strace("forge(backend, {})", (void*) func);
	syscall(ECALL_BACKEND_DECISION, (int) c, (long)backend_trampoline_post, (long)func);
}
inline void forge(void(*func)(void(*)()), long farg)
{
	strace("forge(backend, callback {})", (void*) func);
	syscall(ECALL_BACKEND_DECISION, (long) func, farg);
}

inline void kvm_compute(Cache c, const std::string& arg)
{
	strace("kvm_compute({}, {})", (int)c, arg);
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_BACKEND_DECISION, (int)c, 0x0, (long)arg.c_str(), arg.size());
	//__builtin_unreachable();
}

inline void synth(uint16_t status)
{
	strace("synth(status={})", status);
	syscall(ECALL_SYNTH, status, 0, 0, 0, 0);
}
inline void synth(uint16_t status, const char* ctype, size_t clen, const char* data, size_t dlen)
{
	strace("synth(status={}, ctype=\"{}\", len={}, data={}, dlen={})",
		status, ctype, clen, (void*) data, dlen);
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_SYNTH, status, (long) ctype, clen, (long) data, dlen);
	__builtin_unreachable();
}
inline void synth(uint16_t status, const std::string& ctype, const std::string& cont)
{
	return synth(status, ctype.data(), ctype.size(), cont.data(), cont.size());
}
inline void synth(uint16_t status, const char* ctype, size_t clen,
	const char* data, size_t dlen, std::function<void(Response)> content_function)
{
	strace("synth(status={}, ctype=\"{}\", len={}, callback={})",
		status, ctype, dlen, (void*) &content_function);
	content_function({HDR_RESP});
	synth(status, ctype, clen, data, dlen);
}
inline void synth(uint16_t status, const std::string& ctype,
	const std::string& content, std::function<void(Response)> content_function)
{
	return synth(status, ctype.data(), ctype.size(),
		content.data(), content.size(), std::move(content_function));
}

PPT() inline void ban(fmt::format_string<Args...> format, Args&&... args)
{
	strace("ban(", args..., ")");
	char buffer[500];
	const auto res = fmt::format_to_n(buffer, sizeof(buffer)-1, format, std::forward<Args>(args)...);
	const size_t len = res.size;
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_BAN, (long) buffer, len);
}

inline void hash_data(std::string_view buffer)
{
	strace("hash_data(", buffer, ")");
	const size_t size = buffer.size();
	register const char* a0 asm("a0") = buffer.data();
	register size_t      a1 asm("a1") = size;
	register long syscall_id asm("a7") = ECALL_HASH_DATA;

	asm volatile ("ecall"
	: :	"r"(a0), "m"(*(const char(*)[size]) a0),
		"r"(a1), "r"(syscall_id));
}
inline void hash_data(const HeaderField& hf)
{
	const std::string data = hf.to_string();
	hash_data(data);
}

inline HeaderField::HeaderField(gethdr_e wh, size_t idx)
	: where(wh), index(idx)
{
	strace("HeaderField(", wstr(wh), ", ", HFIDX(idx), ")");
}

inline void HeaderField::unset()
{
	strace("HeaderField(", wstr(where), ", ", HFIDX(index), ")::unset()");
	/* During foreach we must delay unset to avoid index confusion */
	if (!this->foreach) {
		syscall(ECALL_FIELD_UNSET, this->where, this->index);
	}
	this->index = UINT32_MAX;
	this->deleted = true;
}

extern "C" int sys_field_retrieve(int where, uint32_t index, char* buffer, size_t buflen);
extern "C" int sys_field_retrieve_str(int where, uint32_t index, std::string *out);
inline std::string HeaderField::to_string() const
{
	std::string val;
	if (IS_NEWLIB) {
		register int      a0 asm("a0") = this->where;
		register uint32_t a1 asm("a1") = this->index;
		register std::string* a2 asm("a2") = &val;

		asm volatile(".insn i 0b1011011, 0, x0, x0, %4" // dyncall
			:	"+r"(a0), "=m"(*a2)
			:	"r"(a1), "r"(a2), "I"(ECALL_FIELD_RETRIEVE_STR - SYSCALL_BASE));
	} else {
		int len = sys_field_retrieve(this->where, this->index, nullptr, 0);
		if (len < 0)
			return "";
		val.resize(len);
		sys_field_retrieve(this->where, this->index, val.data(), val.size());
	}

	strace("HeaderField(", wstr(where), ", ", HFIDX(index), ")::to_string() = \"", val, "\"");
	return val;
}
inline std::string HeaderField::value() const
{
	const auto line = to_string();
	auto it = line.find(": ");
	if (it != std::string::npos)
		return line.substr(it + 2);
	return "";
}

inline
HeaderField& HeaderField::set(const char* buffer, size_t len)
{
	strace("HeaderField({}, {})::set({}, {})", wstr(where), HFIDX(index), std::string_view(buffer, len));
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_FIELD_SET, this->where, this->index, (long) buffer, len);
	return *this;
}
inline
HeaderField& HeaderField::set(const HeaderField& other)
{
	strace("HeaderField({}, {})::set(HeaderField({}, {}))",
		wstr(where), HFIDX(index), wstr(other.where), HFIDX(other.index));
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_FIELD_COPY, where, index, other.where, other.index);
	return *this;
}
extern "C" int sys_field_set(int where, uint32_t index, const char* buffer, size_t len);
PPT() inline
HeaderField& HeaderField::set(fmt::format_string<Args...> format, Args&&... args)
{
	strace("HeaderField({}, {})::set(", wstr(where), ", ", HFIDX(index), ")", args..., ")");
	char buffer[4096];
	auto res = fmt::format_to_n(buffer, sizeof(buffer)-1, format, std::forward<Args>(args)...);

	sys_field_set(this->where, this->index, buffer, res.size());
	return *this;
}
PPT() inline
HeaderField& HeaderField::operator = (Args&&... args) {
	return this->set(std::forward<Args> (args)...);
}
inline HeaderField& HeaderField::regsub(
	const Regex& re, const std::string& subst, bool all)
{
	strace("HeaderField(", wstr(where), ", ", HFIDX(index), ")::regsub(", re.index(), ", \"", subst, "\", ", all, ")");
	re.replace(*this, subst, all);
	return *this;
}
inline HeaderField& HeaderField::regsub(
	const std::string& pattern, const std::string& subst, bool all)
{
	strace("HeaderField(", wstr(where), ", ", HFIDX(index), ")::regsub(\"", pattern, "\", \"", subst, "\", ", all, ")");
	return regsub(Regex{pattern}, subst, all);
}

inline HeaderField HeaderField::append_to(HTTP& dest) const
{
	strace("HeaderField(", wstr(where), ", ", HFIDX(index), ")::append_to(", wstr(dest.where), ")");
	uint32_t idx = syscall(ECALL_HTTP_COPY, this->where, this->index, dest.where);
	/* Clobbering memory would do nothing here */
	return {this->where, idx};
}

inline const char* HTTP::name() const {
	return wstr(this->where);
}
inline HeaderField HTTP::find(const std::string& name) const
{
	asm("" ::: "memory"); /* Dead-store optimization */
	unsigned idx =
		syscall(ECALL_HTTP_FIND, this->where, (long) name.c_str(), name.size());
	strace("HTTP(", wstr(where), ")::find(\"", name, "\") => ", HFIDX(idx));
	return {this->where, (unsigned) idx};
}
inline HeaderField HTTP::operator [](const std::string& name) const {
	return find(name);
}

inline std::string HTTP_Req::method() const {
	return HeaderField{this->where, 0}.to_string();
}
inline std::string HTTP::url() const {
	return HeaderField{this->where, 1}.to_string();
}
inline std::string HTTP::proto() const {
	return HeaderField{this->where, 2}.to_string();
}
inline std::string HTTP_Resp::reason() const {
	return HeaderField{this->where, 4}.to_string();
}

inline void HTTP_Req::set_backend(int be) {
	syscall(ECALL_SET_BACKEND, be);
}

inline void HTTP_Resp::set_cacheable(bool c) {
	syscall(ECALL_CACHEABLE, 1, c);
}
inline bool HTTP_Resp::cacheable() {
	return syscall(ECALL_CACHEABLE, 0);
}
inline void HTTP_Resp::set_ttl(float val) {
	register float fa0 asm("fa0") = val;
	register long a0 asm("a0") = 1;
	register long syscall_id asm("a7") = ECALL_TTL;

	asm volatile ("ecall"
	 	: "+f"(fa0) : "r"(a0), "r"(syscall_id));
}
inline float HTTP_Resp::ttl() {
	register float fa0 asm("fa0");
	register long a0 asm("a0") = 0;
	register long syscall_id asm("a7") = ECALL_TTL;

	asm volatile ("ecall"
	 	: "+f"(fa0) : "r"(a0), "r"(syscall_id));

	return fa0;
}
inline void make_uncacheable_for(float secs) {
	Response::set_cacheable(false);
	Response::set_ttl(secs);
}

inline uint16_t HTTP::status() const
{
	strace("HTTP(", wstr(where), ")::status()");
	return syscall(ECALL_HTTP_SET_STATUS, this->where, -1);
}
inline uint16_t HTTP::set_status(uint16_t code)
{
	strace("HTTP(", wstr(where), ")::set_status(", code, ")");
	return syscall(ECALL_HTTP_SET_STATUS, this->where, code);
}

inline HTTP from_where(gethdr_e where) {
	switch (where) {
		case HDR_REQ:
		case HDR_BEREQ:
			return Request{where};
		case HDR_RESP:
		case HDR_BERESP:
			return Response{where};
		default:
			assert(false && "Invalid header field");
	}
}
inline HTTP HeaderField::http() const {
	strace("HTTP(", wstr(where), ")::http()");
	return from_where(where);
}

inline HeaderField HTTP::append(const HeaderField& hf)
{
	return hf.append_to(*this);
}
extern "C" int sys_field_append(int where, const char* buffer, size_t len);
inline HeaderField HTTP::append(const std::string_view str)
{
	strace("HTTP(", wstr(where), ")::append(", str, ")");

	if (IS_NEWLIB) {
		register uint32_t a0 asm("a0") = where;
		register const char* a1 asm("a1") = str.begin();
		register size_t  a2 asm("a2") = str.size();

		asm volatile(".insn i 0b1011011, 0, x0, x0, %4" // dyncall
			:	"+r"(a0)
			:	"r"(a1), "r"(a2), "m"(*a1), "I"(ECALL_FIELD_APPEND - SYSCALL_BASE));

		return {this->where, a0};
	} else {
		const int idx = sys_field_append(this->where, str.data(), str.size());
		return {this->where, (unsigned) idx};
	}
}
PPT() inline HeaderField HTTP::appendf(fmt::format_string<Args...> format, Args&&... args)
{
	strace("HTTP(", wstr(where), ")::append(", args..., ")");
	auto buffer = fmt::format(format, std::forward<Args>(args)...);
	register uint32_t a0 asm("a0") = where;
	register const char* a1 asm("a1") = buffer.data();
	register size_t  a2 asm("a2")     = buffer.size();
	register long syscall_id asm("a7") = ECALL_FIELD_APPEND;
	asm volatile("ecall"
		:	"+r"(a0)
		:	"r"(a1), "r"(a2), "m"(*a1), "r"(syscall_id));
	return {this->where, a0};
}
inline HeaderField HTTP::operator += (const std::string& text)
{
	return this->append(text);
}
inline HeaderField HTTP::operator += (HeaderField other)
{
	return this->append(other);
}

inline void foreach_callback(header_iterator_t* func, HeaderField* hf, int count)
{
	for (int i = 0; i < count; i++)
		(*func)(hf[i]);
}
inline void HTTP::foreach(header_iterator_t func)
{
	strace("HTTP(", wstr(where), ")::foreach(...)");
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_FOREACH_FIELD,
		(int) where, (long) foreach_callback, (long) &func);
}
inline void HTTP::foreach(header_citerator_t func) const
{
	strace("HTTP(", wstr(where), ")::foreach(...)");
	asm ("" ::: "memory"); // prevent dead-store optimization
	syscall(ECALL_FOREACH_FIELD,
		(int) where, (long) foreach_callback, (long) &func);
}

inline size_t HTTP::unset(const Regex& regex)
{
	strace("HTTP(", wstr(where), ")::unset(Regex = ", regex.index(), ")");
	return syscall(ECALL_HTTP_UNSET_RE, this->where, regex.index());
}

inline void HTTP::rollback()
{
	strace("HTTP(", wstr(where), ")::rollback()");
	syscall(ECALL_HTTP_ROLLBACK, this->where);
}


inline Regex::Regex(const std::string& pattern)
{
	asm ("" ::: "memory"); // prevent dead-store optimization
	this->idx = syscall(ECALL_REGEX_COMPILE, (long) pattern.c_str(), pattern.size());
}
inline int Regex::match(std::string_view text) const
{
	register int a0 asm("a0") = this->idx;
	register const char* a1 asm("a1") = text.data();
	register size_t      a2 asm("a2") = text.size();

	asm volatile(".insn i 0b1011011, 0, x0, x0, %4" // dyncall
		:	"+r"(a0)
		:	"r"(a1), "r"(a2), "m"(*a1), "I"(ECALL_REGEX_MATCH - SYSCALL_BASE));
	return a0;
}
inline std::string
Regex::replace(std::string_view text, const std::string& subst, bool all) const
{
	strace("Regex(", idx, ")::replace(\"", text, "\", \"", subst, "\", all=", all, ")");
	std::array<char, 4096> buffer;
	int len = syscall(ECALL_REGEX_SUBST, this->idx,
		(long) text.begin(), text.size(),
		(long) subst.c_str(), subst.size(),
		(long) buffer.data(), buffer.size() | (all ? 0x80000000 : 0));
	asm ("" ::: "memory");
	return std::string(buffer.data(), len);
}
inline std::string Regex::replace(const std::string& text, const std::string& subst, bool all) const
{
	return replace(std::string_view{text}, subst, all);
}
inline int
Regex::replace(HeaderField& hdr, const std::string& subst, bool all) const
{
	strace("Regex(", idx, ")::replace(HeaderField(", wstr(hdr.where), ", ", HFIDX(hdr.index), "), \"", subst, "\", all=", all, ")");
	asm ("" ::: "memory"); // prevent dead-store optimization
	int len = syscall(ECALL_REGSUB_HDR, this->idx,
		hdr.where, hdr.index, (long) subst.c_str(), (long) subst.size(), all);
	return len;
}
