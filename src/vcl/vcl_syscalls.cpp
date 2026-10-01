/**
 * The policy ABI (abi.hpp) that VCL-compiled tenant programs call.
 *
 * Ported from Carapace's scripting host, with one structural difference:
 * Carapace records a phase's header edits and replays them afterwards,
 * while here each hook runs inside the Varnish subroutine it is named for,
 * so edits go straight to Varnish's header maps and variables.
 *
 * The compiler already refuses what a phase may not do, with a source
 * diagnostic. Every gate is checked again here, because the compiled ELF is
 * the tenant's and the host trusts nothing about it.
 */
#include "abi.hpp"
#include "vcl_program.hpp"
#include "vcl_varnish.h"
#include "../script_functions.hpp"
#include "../machine_instance.hpp"
#include "../varnish.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <climits>
#include <cctype>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace rvs::vcl {
using namespace abi;

/* The compiler guest's include read, installed by compiler.cpp. */
void include_read(machine_t&);

namespace {

/* Headers a policy never writes: they describe the message framing, which
   Varnish owns. Mirrors FRAMING_HEADERS in vcl/compiler/src/vcl_vars.def. */
constexpr std::string_view FRAMING_HEADERS[] = {
	"connection", "content-length", "keep-alive", "proxy-authenticate",
	"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
};

bool iequals(std::string_view a, std::string_view b)
{
	return a.size() == b.size() && strncasecmp(a.data(), b.data(), a.size()) == 0;
}

bool is_framing_header(std::string_view name)
{
	for (auto framing : FRAMING_HEADERS)
		if (iequals(name, framing)) return true;
	return false;
}

/* An RFC 9110 token: what a header name may be. */
bool valid_name(std::string_view name)
{
	if (name.empty())
		return false;
	for (unsigned char c : name) {
		if (isalnum(c))
			continue;
		if (!strchr("!#$%&'*+-.^_`|~", c) || c == '\0')
			return false;
	}
	return true;
}

/* A header value or URL must not end the line it is on: a CR or LF would
   let a tenant add header fields, or a whole request, of its own. */
bool valid_value(std::string_view value)
{
	return value.find_first_of(std::string_view("\r\n\0", 3)) == std::string_view::npos;
}

Script& script_of(machine_t& m) { return *m.get_userdata<Script>(); }
const vrt_ctx* ctx_of(machine_t& m) { return script_of(m).ctx(); }

/* Copy a guest (pointer, length) string out, or fail on a length past max.
   Copying rather than viewing: a fork's pages come from the workspace one
   at a time, so a string crossing a page boundary is not contiguous. */
bool read_str(machine_t& m, gaddr_t addr, gaddr_t len, size_t max, std::string& out)
{
	if (len > max)
		return false;
	out.resize(len);
	if (len > 0)
		m.memory.memcpy_out(out.data(), addr, len);
	m.penalize(len);
	return true;
}

/* Write a result into a guest buffer, truncated to the buffer. Returns the
   full length, so a caller that measured with a null buffer learns it. */
uint64_t write_str(machine_t& m, gaddr_t buf, gaddr_t buflen, std::string_view data)
{
	if (buf != 0 && buflen != 0) {
		const size_t n = std::min<size_t>(data.size(), buflen);
		if (n > 0)
			m.copy_to_guest(buf, data.data(), n);
		m.penalize(n);
	}
	return data.size();
}

void refuse(machine_t& m, const char* what)
{
	auto* ctx = ctx_of(m);
	if (ctx && ctx->vsl)
		VSLb(ctx->vsl, SLT_VCL_Error, "[%s] vcl: %s refused in this subroutine",
			script_of(m).name().c_str(), what);
	m.set_result(FAILED);
}

/* The header map a side means in this phase, or null when the phase has
   none: a response before there is one, or the backend side's maps from
   the client side. Varnish lets every subroutine that has a map write it. */
http* side_http(const vrt_ctx* ctx, bool response)
{
	return vclv_http(ctx, response ? VCL_SIDE_RESPONSE : VCL_SIDE_REQUEST);
}

bool backend_side(const vrt_ctx* ctx)
{
	return (ctx->method & (VCL_MET_BACKEND_FETCH | VCL_MET_BACKEND_RESPONSE
		| VCL_MET_BACKEND_ERROR)) != 0;
}

/* The client's Host picked the tenant (the Varnish VCL forks by it), so a
   tenant may not change it: that would hand its request, and its backend
   fetch, to another tenant. The origin's Host is bereq.http.Host. */
bool routing_header(const vrt_ctx* ctx, bool response, std::string_view name)
{
	return !response && !backend_side(ctx) && iequals(name, "host");
}

/* ── Request line, headers, status ──────────────────────────────────── */

void sys_req_get_method(machine_t& m)
{
	const auto [buf, buflen] = m.sysargs<gaddr_t, gaddr_t>();
	http* hp = side_http(ctx_of(m), false);
	if (hp == nullptr) {
		m.set_result(write_str(m, buf, buflen, ""));
		return;
	}
	size_t len;
	const char* method = vclv_method(hp, &len);
	m.set_result(write_str(m, buf, buflen, {method, len}));
}

void sys_req_get_url(machine_t& m)
{
	const auto [buf, buflen] = m.sysargs<gaddr_t, gaddr_t>();
	http* hp = side_http(ctx_of(m), false);
	if (hp == nullptr) {
		m.set_result(write_str(m, buf, buflen, ""));
		return;
	}
	size_t len;
	const char* url = vclv_url(hp, &len);
	m.set_result(write_str(m, buf, buflen, {url, len}));
}

void get_header(machine_t& m, bool response)
{
	const auto [nptr, nlen, buf, buflen] = m.sysargs<gaddr_t, gaddr_t, gaddr_t, gaddr_t>();
	std::string name;
	if (!read_str(m, nptr, nlen, MAX_NAME, name)) {
		m.set_result(FAILED);
		return;
	}
	http* hp = side_http(ctx_of(m), response);
	const char* value;
	size_t vlen;
	if (hp == nullptr || vclv_get(hp, name.data(), name.size(), &value, &vlen) < 0) {
		m.set_result(FAILED);
		return;
	}
	m.set_result(write_str(m, buf, buflen, {value, vlen}));
}

void set_header(machine_t& m, bool response)
{
	const auto [nptr, nlen, vptr, vlen] = m.sysargs<gaddr_t, gaddr_t, gaddr_t, gaddr_t>();
	std::string name, value;
	if (!read_str(m, nptr, nlen, MAX_NAME, name) || !read_str(m, vptr, vlen, MAX_VALUE, value)
		|| !valid_name(name) || !valid_value(value)) {
		m.set_result(FAILED);
		return;
	}
	const auto* ctx = ctx_of(m);
	if (is_framing_header(name) || routing_header(ctx, response, name)) {
		refuse(m, "a framing or routing header write");
		return;
	}
	http* hp = side_http(ctx, response);
	if (hp == nullptr) {
		refuse(m, response ? "a response header write" : "a request header write");
		return;
	}
	m.set_result(vclv_set(ctx, hp, name.data(), name.size(),
		value.data(), value.size()) == 0 ? 0 : FAILED);
}

void remove_header(machine_t& m, bool response)
{
	const auto [cmd, nptr, nlen] = m.sysargs<int64_t, gaddr_t, gaddr_t>();
	(void)cmd;
	std::string name;
	if (!read_str(m, nptr, nlen, MAX_NAME, name) || name.empty()) {
		m.set_result(FAILED);
		return;
	}
	const auto* ctx = ctx_of(m);
	if (is_framing_header(name) || routing_header(ctx, response, name)) {
		refuse(m, "a framing or routing header removal");
		return;
	}
	http* hp = side_http(ctx, response);
	if (hp == nullptr) {
		refuse(m, response ? "a response header removal" : "a request header removal");
		return;
	}
	vclv_unset(hp, name.data(), name.size());
	m.set_result(0);
}

void sys_req_get_header(machine_t& m)  { get_header(m, false); }
void sys_resp_get_header(machine_t& m) { get_header(m, true); }
void sys_req_set_header(machine_t& m)  { set_header(m, false); }
void sys_resp_set_header(machine_t& m) { set_header(m, true); }

void sys_req_set_url(machine_t& m)
{
	const auto [uptr, ulen] = m.sysargs<gaddr_t, gaddr_t>();
	std::string url;
	if (!read_str(m, uptr, ulen, MAX_VALUE, url) || url.empty() || !valid_value(url)
		|| url.find(' ') != std::string::npos) {
		m.set_result(FAILED);
		return;
	}
	/* req.url on the client side, bereq.url on the backend side, as
	   Varnish allows. */
	const auto* ctx = ctx_of(m);
	http* hp = side_http(ctx, false);
	if (hp == nullptr) {
		refuse(m, "a URL write");
		return;
	}
	m.set_result(vclv_set_url(ctx, hp, url.data(), url.size()) == 0 ? 0 : FAILED);
}

void sys_resp_get_status(machine_t& m)
{
	auto* hp = side_http(ctx_of(m), true);
	m.set_result(hp ? vclv_status(hp) : 0u);
}

void sys_log(machine_t& m)
{
	const auto [ptr, len] = m.sysargs<gaddr_t, gaddr_t>();
	std::string msg;
	if (!read_str(m, ptr, len, MAX_VALUE, msg)) {
		m.set_result(FAILED);
		return;
	}
	/* Named, like every other line the VMOD writes for a tenant, so one
	   tenant cannot write lines that read as another's. */
	msg.insert(0, "[" + script_of(m).name() + "] ");
	vclv_log(ctx_of(m), msg.data(), msg.size());
	m.set_result(0);
}

/* ── Outcomes ───────────────────────────────────────────────────────── */

/* What a hook asked for, as want_result() reports it, and the Varnish
   subroutines that may ask for it: Varnish's own return table, less
   restart, retry, pipe, purge and vcl. The compiler refuses the same. */
struct Outcome { const char* result; unsigned methods; };
constexpr unsigned ALL_METHODS = VCL_MET_RECV | VCL_MET_HASH | VCL_MET_HIT
	| VCL_MET_MISS | VCL_MET_PASS | VCL_MET_DELIVER | VCL_MET_SYNTH
	| VCL_MET_BACKEND_FETCH | VCL_MET_BACKEND_RESPONSE | VCL_MET_BACKEND_ERROR;
constexpr Outcome OUTCOMES[] = {
	/* ACTION_NEXT */    {"", ALL_METHODS},
	/* ACTION_PASS */    {"pass", VCL_MET_RECV | VCL_MET_HIT | VCL_MET_MISS
		| VCL_MET_BACKEND_RESPONSE},
	/* ACTION_DELIVER */ {"deliver", VCL_MET_HIT | VCL_MET_DELIVER | VCL_MET_SYNTH
		| VCL_MET_BACKEND_RESPONSE | VCL_MET_BACKEND_ERROR},
	/* ACTION_SYNTH */   {"synth", VCL_MET_RECV | VCL_MET_HIT | VCL_MET_MISS
		| VCL_MET_PASS | VCL_MET_DELIVER},
	/* ACTION_ABANDON */ {"abandon", VCL_MET_BACKEND_FETCH | VCL_MET_BACKEND_RESPONSE
		| VCL_MET_BACKEND_ERROR},
	/* ACTION_HASH */    {"hash", VCL_MET_RECV},
	/* ACTION_LOOKUP */  {"lookup", VCL_MET_HASH},
	/* ACTION_FETCH */   {"fetch", VCL_MET_MISS | VCL_MET_PASS | VCL_MET_BACKEND_FETCH},
	/* ACTION_MISS */    {"miss", VCL_MET_HIT},
	/* ACTION_ERROR */   {"error", VCL_MET_BACKEND_FETCH | VCL_MET_BACKEND_RESPONSE},
	/* ACTION_FAIL */    {"fail", ALL_METHODS},
};
static_assert(std::size(OUTCOMES) == ACTION_FAIL + 1, "one row per action code");


void set_outcome(machine_t& m, int64_t code, uint64_t status, gaddr_t reason, gaddr_t rlen)
{
	auto& script = script_of(m);
	const auto* ctx = script.ctx();
	script.set_result("", 0, false);
	if (code < 0 || code >= int64_t(std::size(OUTCOMES))
		|| (OUTCOMES[code].methods & ctx->method) == 0) {
		refuse(m, "a return action");
		return;
	}
	if (code == ACTION_SYNTH || code == ACTION_ERROR) {
		/* Three digits: Varnish's custom-reason encoding past 999 is not
		   part of the policy ABI. A refused synth or error must still end
		   the request: falling through would serve what the tenant denied. */
		if (status < 100 || status > 999) {
			refuse(m, "a synthetic response status");
			vclv_fail(ctx, "VCL tenant returned an invalid synthetic status");
			script.set_result(OUTCOMES[ACTION_FAIL].result, 0, false);
			return;
		}
		/* A reason that is too long or would end the status line is
		   dropped for Varnish's default one, keeping the synth. */
		std::string text;
		if (!read_str(m, reason, rlen, MAX_VALUE, text) || !valid_value(text)) {
			if (ctx->vsl)
				VSLb(ctx->vsl, SLT_VCL_Error, "[%s] vcl: synthetic reason dropped",
					script.name().c_str());
			text.clear();
		}
		script.vcl_task().reason = std::move(text);
	}
	if (code == ACTION_FAIL)
		vclv_fail(ctx, "VCL tenant returned fail");
	script.set_result(OUTCOMES[code].result,
		(code == ACTION_SYNTH || code == ACTION_ERROR) ? status : 0, false);
}

void sys_return_action(machine_t& m)
{
	const auto [code, status, reason, rlen] = m.sysargs<int64_t, uint64_t, gaddr_t, gaddr_t>();
	set_outcome(m, code, status, reason, rlen);
	m.stop();
}

void sys_set_outcome_plain(machine_t& m)
{
	const auto [cmd, code, status, reason, rlen] =
		m.sysargs<int64_t, int64_t, uint64_t, gaddr_t, gaddr_t>();
	(void)cmd;
	set_outcome(m, code, status, reason, rlen);
	m.set_result(0);
}

/* ── Cache metadata ─────────────────────────────────────────────────── */

bool valid_seconds(uint64_t raw)
{
	return int64_t(raw) >= 0 && raw <= MAX_TTL_SECONDS;
}

void set_duration(machine_t& m, vcl_duration which, uint64_t seconds)
{
	const auto* ctx = ctx_of(m);
	if ((ctx->method & (VCL_MET_BACKEND_RESPONSE | VCL_MET_BACKEND_ERROR)) == 0) {
		refuse(m, "a cache duration write");
		return;
	}
	if (!valid_seconds(seconds)) {
		m.set_result(FAILED);
		return;
	}
	vclv_set_duration(ctx, which, double(seconds));
	m.set_result(0);
}

void sys_set_ttl(machine_t& m)
{
	set_duration(m, VCL_TTL, m.sysarg<uint64_t>(0));
}

void sys_cache_duration(machine_t& m)
{
	const auto selector = m.sysarg<uint64_t>(1);
	const auto* ctx = ctx_of(m);
	if ((ctx->method & (VCL_MET_BACKEND_RESPONSE | VCL_MET_BACKEND_ERROR)) == 0) {
		refuse(m, "a cache duration read");
		return;
	}
	if (selector > VCL_KEEP) {
		m.set_result(FAILED);
		return;
	}
	const double value = vclv_get_duration(ctx, vcl_duration(selector));
	/* Whole seconds, like the setter: a negative TTL reads as 0. */
	m.set_result(uint64_t(std::clamp(value, 0.0, double(MAX_TTL_SECONDS))));
}

void sys_cache_status(machine_t& m)
{
	const int status = vclv_cache_status(ctx_of(m));
	if (status < 0) {
		refuse(m, "a cache status read");
		return;
	}
	m.set_result(uint64_t(status));
}

void sys_client_ip(machine_t& m)
{
	const auto out_ptr = m.sysarg<gaddr_t>(1);
	const auto out_cap = m.sysarg<gaddr_t>(2);
	unsigned char octets[16];
	const int family = vclv_client_ip(ctx_of(m), octets);
	if (family < 0 || out_ptr == 0 || out_cap < sizeof(octets)) {
		m.set_result(FAILED);
		return;
	}
	m.copy_to_guest(out_ptr, octets, sizeof(octets));
	m.set_result(uint64_t(family));
}

/* ── Header snapshots and commits (the headerplus vmod) ─────────────── */

/* The header list a side holds now, as (name, value) pairs. */
std::vector<std::pair<std::string_view, std::string_view>>
header_list(const vrt_ctx* ctx, bool response, http*& hp)
{
	std::vector<std::pair<std::string_view, std::string_view>> out;
	hp = side_http(ctx, response);
	if (hp != nullptr) {
		unsigned cursor = 0;
		const char *name, *value;
		size_t nlen, vlen;
		while (vclv_next(hp, &cursor, &name, &nlen, &value, &vlen) == 0)
			out.emplace_back(std::string_view{name, nlen}, std::string_view{value, vlen});
	}
	return out;
}

void put_u32(std::string& out, uint32_t v)
{
	out.append(reinterpret_cast<const char*>(&v), 4); // little-endian host
}

void sys_headers_snapshot(machine_t& m)
{
	const auto map  = m.sysarg<uint64_t>(1);
	const auto nptr = m.sysarg<gaddr_t>(2);
	const auto nlen = m.sysarg<gaddr_t>(3);
	const auto out  = m.sysarg<gaddr_t>(4);
	const auto cap  = m.sysarg<gaddr_t>(5);
	std::string filter;
	if (map > 1 || !read_str(m, nptr, nlen, MAX_NAME, filter)) {
		m.set_result(FAILED);
		return;
	}
	http* hp = nullptr;
	const auto list = header_list(ctx_of(m), map == 1, hp);
	if (list.size() > MAX_HEADERS) {
		m.set_result(FAILED);
		return;
	}
	std::string packed;
	for (auto& [name, value] : list) {
		if (!filter.empty() && !iequals(name, filter))
			continue;
		if (name.size() > MAX_NAME || value.size() > MAX_VALUE) {
			m.set_result(FAILED);
			return;
		}
		put_u32(packed, name.size());
		put_u32(packed, value.size());
		packed.append(name);
		packed.append(value);
	}
	/* A short buffer is never partially written: the caller measured. */
	if (out != 0 && cap >= packed.size() && !packed.empty())
		m.copy_to_guest(out, packed.data(), packed.size());
	m.penalize(packed.size());
	m.set_result(packed.size());
}

/* Apply a committed header vector: every name whose values differ from the
   list the side holds now is replaced, and every name missing from the
   vector is removed. Entries the runtime did not mark dirty are present
   but untouched. All names are checked before any is applied. */
void headers_commit(machine_t& m, bool response)
{
	const auto addr = m.sysarg<gaddr_t>(1);
	auto& script = script_of(m);

	GuestVec vec;
	m.memory.memcpy_out(&vec, addr, sizeof(vec));
	if (vec.len > MAX_HEADERS) {
		m.set_result(FAILED);
		return;
	}
	std::vector<GuestHeader> raw(vec.len);
	if (vec.len > 0)
		m.memory.memcpy_out(raw.data(), vec.ptr, vec.len * sizeof(GuestHeader));

	struct Entry { std::string name; std::string value; bool dirty; };
	std::vector<Entry> entries;
	entries.reserve(raw.size());
	for (auto& h : raw) {
		Entry e;
		e.dirty = h.dirty != 0;
		if (!read_str(m, h.name.ptr, h.name.len, MAX_NAME, e.name)
			|| (e.dirty && !read_str(m, h.value.ptr, h.value.len, MAX_VALUE, e.value))) {
			m.set_result(FAILED);
			return;
		}
		entries.push_back(std::move(e));
	}

	http* hp = nullptr;
	/* Copies: applying edits to a Varnish header map moves its fields. */
	std::vector<std::pair<std::string, std::string>> before;
	for (auto& [n, v] : header_list(script.ctx(), response, hp))
		before.emplace_back(n, v);
	if (hp == nullptr) {
		refuse(m, response ? "a response header commit" : "a request header commit");
		return;
	}

	/* Names compare case-insensitively. Keyed sets keep this linear: the
	   vector holds up to MAX_HEADERS entries, and the host's work here is
	   not charged to the instruction budget. */
	auto lower = [](std::string_view name) {
		std::string out(name);
		for (auto& c : out) c = char(tolower((unsigned char)c));
		return out;
	};
	std::unordered_map<std::string, std::vector<std::string_view>> values;
	for (auto& [n, v] : before)
		values[lower(n)].push_back(v);
	/* Work out the edits first, so a refused name changes nothing. */
	struct Edit { enum { Set, Add, Remove } op; std::string name; std::string value; };
	std::vector<Edit> edits;
	std::unordered_set<std::string> present, written;
	for (auto& e : entries) {
		const auto key = lower(e.name);
		present.insert(key);
		if (!e.dirty)
			continue;
		if (written.insert(key).second) {
			auto it = values.find(key);
			if (it == values.end() || it->second.size() != 1 || it->second[0] != e.value)
				edits.push_back({Edit::Set, e.name, e.value});
		} else {
			edits.push_back({Edit::Add, e.name, e.value});
		}
	}
	for (auto& [n, v] : before) {
		const auto key = lower(n);
		if (!present.count(key) && written.insert(key).second) // remove each name once
			edits.push_back({Edit::Remove, n, {}});
	}
	for (auto& edit : edits) {
		if (is_framing_header(edit.name) || routing_header(script.ctx(), response, edit.name)) {
			refuse(m, "a framing or routing header write");
			return;
		}
		if (!valid_name(edit.name) || !valid_value(edit.value)) {
			m.set_result(FAILED);
			return;
		}
	}

	for (auto& edit : edits) {
		int rc = 0;
		switch (edit.op) {
		case Edit::Set:
			rc = vclv_set(script.ctx(), hp, edit.name.data(), edit.name.size(),
				edit.value.data(), edit.value.size());
			break;
		case Edit::Add:
			rc = vclv_add(script.ctx(), hp, edit.name.data(), edit.name.size(),
				edit.value.data(), edit.value.size());
			break;
		case Edit::Remove:
			vclv_unset(hp, edit.name.data(), edit.name.size());
			break;
		}
		if (rc != 0) {
			m.set_result(FAILED);
			return;
		}
	}
	m.set_result(0);
}

/* ── Regular expressions ────────────────────────────────────────────── */

/* The compiled pattern for a guest pattern string. Every literal the
   policy uses was compiled at load; anything else is refused. */
const void* lookup_pattern(machine_t& m, gaddr_t ptr, gaddr_t len)
{
	std::string pattern;
	if (!read_str(m, ptr, len, MAX_PATTERN, pattern))
		return nullptr;
	const auto& program = script_of(m).program().vcl_program;
	const void* re = program ? program->pattern(pattern) : nullptr;
	if (re == nullptr) {
		/* The compiler lists every pattern it emits, so a miss is a
		   compiler/host disagreement worth a line, not a quiet refusal. */
		auto* ctx = ctx_of(m);
		if (ctx && ctx->vsl)
			VSLb(ctx->vsl, SLT_VCL_Error, "[%s] vcl: regex '%s' was not compiled at load",
				script_of(m).name().c_str(), pattern.c_str());
	}
	return re;
}

/* One match, as the policy sees it: 1, 0, or -1 when PCRE gave up at its
   backtracking limits. A match is charged what those limits let it cost,
   one instruction per backtracking step, so a policy cannot buy seconds of
   host CPU with a slow pattern and a few instructions per call. */
int charged_match(machine_t& m, const void* re, const char* subject, size_t len)
{
	m.penalize(VCLV_REGEX_MATCH_LIMIT);
	const int rc = vclv_regex_match(re, subject, len);
	if (rc < 0) {
		auto* ctx = ctx_of(m);
		if (ctx && ctx->vsl)
			VSLb(ctx->vsl, SLT_VCL_Error, "[%s] vcl: regex match ran past its backtracking limit",
				script_of(m).name().c_str());
	}
	return rc;
}

void sys_regex_match(machine_t& m)
{
	const auto [pptr, plen, sptr, slen, caps, maxcaps] =
		m.sysargs<gaddr_t, gaddr_t, gaddr_t, gaddr_t, gaddr_t, gaddr_t>();
	(void)caps;
	/* Generated VCL never asks for captures. */
	const void* re = maxcaps == 0 ? lookup_pattern(m, pptr, plen) : nullptr;
	std::string subject;
	if (re == nullptr || !read_str(m, sptr, slen, MAX_SUBJECT, subject)) {
		m.set_result(REGEX_REFUSED);
		return;
	}
	/* An undecided match traps at its VCL line, like a refused pattern:
	   reading it as "no match" would let a deny rule fail open. */
	const int rc = charged_match(m, re, subject.data(), subject.size());
	m.set_result(rc > 0 ? 0 : rc == 0 ? FAILED : REGEX_REFUSED);
}

struct Descriptor { uint64_t f[5]; };

void sys_regsub(machine_t& m)
{
	const auto pptr = m.sysarg<gaddr_t>(1);
	const auto plen = m.sysarg<gaddr_t>(2);
	const auto sptr = m.sysarg<gaddr_t>(3);
	const auto slen = m.sysarg<gaddr_t>(4);
	const auto dptr = m.sysarg<gaddr_t>(5);
	Descriptor d;
	m.memory.memcpy_out(&d, dptr, sizeof(d));
	const auto out = d.f[2], cap = d.f[3];
	const bool all = d.f[4] != 0;

	const void* re = lookup_pattern(m, pptr, plen);
	std::string subject, replacement;
	if (re == nullptr || !read_str(m, sptr, slen, MAX_SUBJECT, subject)
		|| !read_str(m, d.f[0], d.f[1], MAX_VALUE, replacement)) {
		m.set_result(FAILED);
		return;
	}
	/* Varnish's regsub semantics, so `\1` in the replacement means what it
	   means in the VCL around the policy. It works on C strings, and
	   neither side can hold a NUL: header values and URLs cannot. */
	if (subject.find('\0') != std::string::npos || replacement.find('\0') != std::string::npos) {
		m.set_result(FAILED);
		return;
	}
	/* A regsuball runs one match per replacement, up to one per byte of
	   the subject. Each is charged like a single match, and the budget the
	   policy has left bounds how many may run. */
	const uint64_t left = m.max_instructions() > m.instruction_counter()
		? m.max_instructions() - m.instruction_counter() : 0;
	unsigned execs = unsigned(std::clamp<uint64_t>(left / VCLV_REGEX_MATCH_LIMIT, 1, UINT_MAX));
	vsb* result = nullptr;
	const int rc = vclv_regsub(all, subject.data(), subject.size(), re,
		replacement.c_str(), MAX_VALUE, &execs, &result);
	m.penalize(uint64_t(execs) * VCLV_REGEX_MATCH_LIMIT + subject.size());
	if (rc < 0) {
		auto* ctx = ctx_of(m);
		if (ctx && ctx->vsl)
			VSLb(ctx->vsl, SLT_VCL_Error, "[%s] vcl: regsub ran past its limits",
				script_of(m).name().c_str());
		m.set_result(FAILED);
		return;
	}
	const size_t len = VSB_len(result);
	if (out != 0 && len > cap) {
		VSB_destroy(&result);
		m.set_result(FAILED);
		return;
	}
	if (out != 0 && len > 0)
		m.copy_to_guest(out, VSB_data(result), len);
	VSB_destroy(&result);
	m.penalize(len);
	m.set_result(len);
}

void sys_regex_match_list(machine_t& m)
{
	const auto pptr = m.sysarg<gaddr_t>(1);
	const auto plen = m.sysarg<gaddr_t>(2);
	const auto rptr = m.sysarg<gaddr_t>(3);
	const auto rlen = m.sysarg<gaddr_t>(4);
	const auto dptr = m.sysarg<gaddr_t>(5);
	Descriptor d;
	m.memory.memcpy_out(&d, dptr, sizeof(d));
	const uint64_t flags = d.f[4];
	if ((flags & ~(REGEX_LIST_FIELD_VALUE | REGEX_LIST_ALL)) != 0 || rlen > MAX_LIST_BYTES) {
		m.set_result(FAILED);
		return;
	}
	const void* re = lookup_pattern(m, pptr, plen);
	if (re == nullptr) {
		m.set_result(REGEX_REFUSED);
		return;
	}
	std::string records;
	read_str(m, rptr, rlen, MAX_LIST_BYTES, records);

	/* The packed record format headers_snapshot emits. A list this host
	   would not have produced is refused, not parsed short. */
	std::string bits;
	uint64_t matched = 0, index = 0;
	for (size_t at = 0; at < records.size(); index++) {
		uint32_t nlen, vlen;
		if (index >= MAX_HEADERS || records.size() - at < 8) {
			m.set_result(FAILED);
			return;
		}
		memcpy(&nlen, &records[at], 4);
		memcpy(&vlen, &records[at + 4], 4);
		if (nlen > MAX_NAME || vlen > MAX_VALUE
			|| records.size() - at - 8 < uint64_t(nlen) + vlen) {
			m.set_result(FAILED);
			return;
		}
		const char* name = &records[at + 8];
		const bool value_field = flags & REGEX_LIST_FIELD_VALUE;
		const char* subject = value_field ? name + nlen : name;
		const size_t sublen = value_field ? vlen : nlen;
		if (bits.size() <= index / 8)
			bits.push_back('\0');
		/* Each match is charged, but the charge only stops the policy
		   when the call returns: stop matching once the budget is spent,
		   so one call cannot run thousands of matches past it. */
		if (m.instruction_counter() >= m.max_instructions()) {
			m.set_result(REGEX_REFUSED);
			return;
		}
		const int rc = charged_match(m, re, subject, sublen);
		if (rc < 0) {
			m.set_result(REGEX_REFUSED);
			return;
		}
		if (rc > 0) {
			bits[index / 8] |= char(1u << (index % 8));
			matched++;
		}
		at += 8 + size_t(nlen) + vlen;
	}
	if (d.f[2] != 0) {
		if (d.f[3] < bits.size()) {
			m.set_result(FAILED);
			return;
		}
		if (!bits.empty())
			m.copy_to_guest(d.f[2], bits.data(), bits.size());
	}
	m.set_result(matched);
}

/* ── Hashing and signing (the digest vmod) ──────────────────────────── */

const EVP_MD* algorithm(uint64_t alg, bool keyed)
{
	switch (alg) {
	case 1:  return keyed ? nullptr : EVP_sha256();
	case 2:  return keyed ? nullptr : EVP_sha512();
	case 16: return keyed ? EVP_sha256() : nullptr;
	case 17: return keyed ? EVP_sha512() : nullptr;
	}
	return nullptr;
}

void sys_hash(machine_t& m)
{
	const auto alg = m.sysarg<uint64_t>(1);
	const auto ptr = m.sysarg<gaddr_t>(2);
	const auto len = m.sysarg<gaddr_t>(3);
	const auto out = m.sysarg<gaddr_t>(4);
	const EVP_MD* md = algorithm(alg, false);
	std::string data;
	if (md == nullptr || out == 0 || !read_str(m, ptr, len, MAX_CRYPTO_INPUT, data)) {
		m.set_result(FAILED);
		return;
	}
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	if (!EVP_Digest(data.data(), data.size(), digest, &dlen, md, nullptr)) {
		m.set_result(FAILED);
		return;
	}
	m.copy_to_guest(out, digest, dlen);
	m.set_result(dlen);
}

bool hmac(machine_t& m, const EVP_MD*& md, unsigned char* mac, unsigned int& maclen)
{
	const auto alg  = m.sysarg<uint64_t>(1);
	const auto kptr = m.sysarg<gaddr_t>(2);
	const auto klen = m.sysarg<gaddr_t>(3);
	const auto mptr = m.sysarg<gaddr_t>(4);
	const auto mlen = m.sysarg<gaddr_t>(5);
	md = algorithm(alg, true);
	std::string key, msg;
	if (md == nullptr || !read_str(m, kptr, klen, MAX_CRYPTO_INPUT, key)
		|| !read_str(m, mptr, mlen, MAX_CRYPTO_INPUT, msg))
		return false;
	return HMAC(md, key.data(), int(key.size()),
		reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
		mac, &maclen) != nullptr;
}

void sys_sign(machine_t& m)
{
	const auto out = m.sysarg<gaddr_t>(6);
	const EVP_MD* md;
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = 0;
	if (out == 0 || !hmac(m, md, mac, maclen)) {
		m.set_result(FAILED);
		return;
	}
	m.copy_to_guest(out, mac, maclen);
	m.set_result(maclen);
}

void sys_verify(machine_t& m)
{
	const auto tag_ptr = m.sysarg<gaddr_t>(6);
	const EVP_MD* md;
	unsigned char mac[EVP_MAX_MD_SIZE], tag[EVP_MAX_MD_SIZE];
	unsigned int maclen = 0;
	if (!hmac(m, md, mac, maclen)) {
		m.set_result(FAILED);
		return;
	}
	m.memory.memcpy_out(tag, tag_ptr, maclen);
	m.set_result(CRYPTO_memcmp(mac, tag, maclen) == 0 ? 1 : 0);
}

/* ── Variables, hashing, synthetic bodies ───────────────────────────── */

/* A guest string as a C string for a VRT setter, or false: NUL cannot be
   in a header value, URL or reason, and the VRT setters take C strings. */
bool read_cstr(machine_t& m, gaddr_t ptr, gaddr_t len, size_t max, std::string& out)
{
	return read_str(m, ptr, len, max, out) && out.find('\0') == std::string::npos;
}

void sys_var_get_string(machine_t& m)
{
	const auto id  = m.sysarg<int64_t>(1);
	const auto buf = m.sysarg<gaddr_t>(2);
	const auto cap = m.sysarg<gaddr_t>(3);
	const char* value;
	if (id <= 0 || id > INT32_MAX || vclv_var_get_string(ctx_of(m), int(id), &value) < 0) {
		refuse(m, "a variable read");
		return;
	}
	m.set_result(write_str(m, buf, cap, value));
}

void sys_var_get_scalar(machine_t& m)
{
	const auto id = m.sysarg<int64_t>(1);
	int64_t value;
	if (id <= 0 || id > INT32_MAX || vclv_var_get_int(ctx_of(m), int(id), &value) < 0) {
		refuse(m, "a variable read");
		return;
	}
	m.set_result(uint64_t(value));
}

void sys_var_set_scalar(machine_t& m)
{
	const auto id    = m.sysarg<int64_t>(1);
	const auto value = m.sysarg<int64_t>(2);
	if (id <= 0 || id > INT32_MAX || vclv_var_set_int(ctx_of(m), int(id), value) < 0) {
		refuse(m, "a variable write");
		return;
	}
	m.set_result(0);
}

void sys_var_set_string(machine_t& m)
{
	const auto id  = m.sysarg<int64_t>(1);
	const auto ptr = m.sysarg<gaddr_t>(2);
	const auto len = m.sysarg<gaddr_t>(3);
	std::string value;
	if (!read_cstr(m, ptr, len, MAX_VALUE, value) || !valid_value(value)) {
		m.set_result(FAILED);
		return;
	}
	/* A method is a token: no spaces, and never empty. */
	if (id == VCLV_METHOD && (value.empty() || !valid_name(value))) {
		m.set_result(FAILED);
		return;
	}
	if (id <= 0 || id > INT32_MAX || vclv_var_set_string(ctx_of(m), int(id), value.c_str()) < 0) {
		refuse(m, "a variable write");
		return;
	}
	m.set_result(0);
}

void sys_hash_data(machine_t& m)
{
	const auto ptr = m.sysarg<gaddr_t>(1);
	const auto len = m.sysarg<gaddr_t>(2);
	std::string data;
	if (!read_cstr(m, ptr, len, MAX_VALUE, data)) {
		m.set_result(FAILED);
		return;
	}
	if (vclv_hash_data(ctx_of(m), data.c_str()) < 0) {
		refuse(m, "hash_data()");
		return;
	}
	m.set_result(0);
}

void sys_synth_body(machine_t& m)
{
	const auto replace = m.sysarg<int64_t>(1);
	const auto ptr = m.sysarg<gaddr_t>(2);
	const auto len = m.sysarg<gaddr_t>(3);
	std::string body;
	if (!read_cstr(m, ptr, len, MAX_BODY, body)) {
		m.set_result(FAILED);
		return;
	}
	if (vclv_synth_body(ctx_of(m), replace != 0, body.c_str()) < 0) {
		refuse(m, "a synthetic body");
		return;
	}
	m.set_result(0);
}

/* ── The typed slot ─────────────────────────────────────────────────── */

void sys_typed(machine_t& m)
{
	switch (m.sysarg<int64_t>(0)) {
	case TYPED_REQ_HEADERS_COMMIT:  return headers_commit(m, false);
	case TYPED_RESP_HEADERS_COMMIT: return headers_commit(m, true);
	case TYPED_HASH:                return sys_hash(m);
	case TYPED_SIGN:                return sys_sign(m);
	case TYPED_VERIFY:              return sys_verify(m);
	case TYPED_SET_GRACE:           return set_duration(m, VCL_GRACE, m.sysarg<uint64_t>(1));
	case TYPED_SET_KEEP:            return set_duration(m, VCL_KEEP, m.sysarg<uint64_t>(1));
	case TYPED_REQ_REMOVE_HEADER:   return remove_header(m, false);
	case TYPED_RESP_REMOVE_HEADER:  return remove_header(m, true);
	case TYPED_SET_OUTCOME_PLAIN:   return sys_set_outcome_plain(m);
	case TYPED_REGSUB:              return sys_regsub(m);
	case TYPED_HEADERS_SNAPSHOT:    return sys_headers_snapshot(m);
	case TYPED_REGEX_MATCH_LIST:    return sys_regex_match_list(m);
	case TYPED_CLIENT_IP:           return sys_client_ip(m);
	case TYPED_CACHE_DURATION:      return sys_cache_duration(m);
	case TYPED_INCLUDE_READ:        return include_read(m);
	case TYPED_CACHE_STATUS:        return sys_cache_status(m);
	case TYPED_VAR_GET_STRING:      return sys_var_get_string(m);
	case TYPED_VAR_GET_SCALAR:      return sys_var_get_scalar(m);
	case TYPED_VAR_SET_SCALAR:      return sys_var_set_scalar(m);
	case TYPED_VAR_SET_STRING:      return sys_var_set_string(m);
	case TYPED_HASH_DATA:           return sys_hash_data(m);
	case TYPED_SYNTH_BODY:          return sys_synth_body(m);
	default:
		m.set_result(FAILED);
		return;
	}
}

} // anonymous namespace

/* The handler table is per machine *type*, so these are reachable from
   every tenant program, VCL or not. That is harmless: each handler works
   on the calling Script and its ctx, like the VMOD API does, and the
   compiler guest's include read is gated by a per-thread session. */
void install_syscalls()
{
	machine_t::install_syscall_handlers({
		{SYS_REQ_GET_METHOD,  sys_req_get_method},
		{SYS_REQ_GET_URL,     sys_req_get_url},
		{SYS_REQ_GET_HEADER,  sys_req_get_header},
		{SYS_REQ_SET_HEADER,  sys_req_set_header},
		{SYS_REQ_SET_URL,     sys_req_set_url},
		{SYS_RESP_GET_HEADER, sys_resp_get_header},
		{SYS_RESP_SET_HEADER, sys_resp_set_header},
		{SYS_RESP_GET_STATUS, sys_resp_get_status},
		{SYS_LOG,             sys_log},
		{SYS_RETURN_ACTION,   sys_return_action},
		{SYS_SET_TTL,         sys_set_ttl},
		{SYS_REGEX_MATCH,     sys_regex_match},
		{SYS_TYPED,           sys_typed},
	});
}

} // rvs::vcl
