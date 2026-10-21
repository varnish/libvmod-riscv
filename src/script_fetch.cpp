#include "script_functions.hpp"
#include "machine/syscalls.h"
#include "sandbox_tenant.hpp"
#include "tenant.hpp"
#include "varnish.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>
/* A build without libcurv (the fuzzer) defines FETCH_SUPPORTED=0 */
#ifndef FETCH_SUPPORTED
# ifdef VARNISH_PLUS
extern "C" {
#  include <vtim.h>
#  include <vtree.h>
#  include "vcp/curv.h"
}
/* curl_url() and CURLU_DEFAULT_PORT */
#  define FETCH_SUPPORTED (LIBCURL_VERSION_NUM >= 0x073e00)
# else
#  define FETCH_SUPPORTED 0
# endif
#endif

/**
 * ECALL_FETCH: outgoing HTTP(S) requests, run by libcurv's engine threads,
 * the same that run vmod_http's requests. A request is started with GET or
 * POST, which returns a handle, and the guest collects it later with WAIT,
 * so that several requests can be in flight at once. A tenant may only
 * reach the origins in its "fetch" allow list.
 *
 * libcurv buffers a response on its engine thread. It is copied into the
 * guest when WAIT sees it finished, with one allocation of the exact size
 * on the guest's native heap for each of body and headers: nothing writes
 * guest memory while the guest may be running.
**/
namespace rvs {

/* Handles index the in-flight tasks; a slot is free when null */
struct FetchState {
#if FETCH_SUPPORTED
	std::vector<struct curv_task*> slots;
#endif
	uint32_t started = 0;
};

/* What struct fetch_response is in the guest (see machine/syscalls.h) */
struct GuestFetchResponse {
	int32_t status;
	int32_t error;
	gaddr_t body;
	gaddr_t body_len;
	gaddr_t headers;
	gaddr_t headers_len;
};
static constexpr size_t FETCH_WAIT_MAX = 64;
static constexpr size_t FETCH_URL_MAX = 8192;
static constexpr size_t FETCH_HEADERS_MAX = 65536;
/* Waiting for any of several requests, how long at most between looks */
static constexpr int FETCH_POLL_MAX_MS = 16;

FetchState& Script::fetch_state()
{
	if (m_fetch == nullptr)
		m_fetch = new FetchState;
	return *m_fetch;
}

/* The task is over: requests still in flight are abandoned, and libcurv
   frees them when they finish. */
void Script::fetch_reset()
{
	if (m_fetch == nullptr)
		return;
#if FETCH_SUPPORTED
	for (auto*& task : m_fetch->slots)
		if (task != nullptr)
			curv_engine_detach(&task);
#endif
	delete m_fetch;
	m_fetch = nullptr;
}

#if FETCH_SUPPORTED

struct CurlFree {
	void operator()(char* p) const { curl_free(p); }
	void operator()(CURLU* u) const { curl_url_cleanup(u); }
};
using curl_string = std::unique_ptr<char, CurlFree>;

static std::string lowercase(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(),
		[] (unsigned char c) { return std::tolower(c); });
	return s;
}

static std::optional<std::string> url_part(CURLU* u, CURLUPart what, unsigned flags = 0)
{
	char* part = nullptr;
	if (curl_url_get(u, what, &part, flags) != CURLUE_OK)
		return std::nullopt;
	curl_string owner(part);
	return std::string(part);
}

/* A URL split by curl, and put back together by it */
struct ParsedURL {
	FetchRule   origin;
	std::string url;
};
static std::optional<ParsedURL> parse_url(const std::string& url)
{
	std::unique_ptr<CURLU, CurlFree> u(curl_url());
	if (u == nullptr || curl_url_set(u.get(), CURLUPART_URL, url.c_str(), 0) != CURLUE_OK)
		return std::nullopt;
	auto scheme = url_part(u.get(), CURLUPART_SCHEME);
	auto host = url_part(u.get(), CURLUPART_HOST);
	auto port = url_part(u.get(), CURLUPART_PORT, CURLU_DEFAULT_PORT);
	auto path = url_part(u.get(), CURLUPART_PATH);
	auto full = url_part(u.get(), CURLUPART_URL);
	if (!scheme || !host || !port || !path || !full)
		return std::nullopt;
	ParsedURL result;
	result.origin.scheme = lowercase(*scheme);
	result.origin.host = lowercase(*host);
	result.origin.port = std::stoul(*port);
	result.origin.path = *path;
	result.url = std::move(*full);
	if (result.origin.scheme != "http" && result.origin.scheme != "https")
		return std::nullopt;
	return result;
}

/* For the log: without user and password */
static std::string loggable_url(const char* url)
{
	std::unique_ptr<CURLU, CurlFree> u(curl_url());
	if (url == nullptr || u == nullptr || curl_url_set(u.get(), CURLUPART_URL, url, 0) != CURLUE_OK)
		return "";
	curl_url_set(u.get(), CURLUPART_USER, nullptr, 0);
	curl_url_set(u.get(), CURLUPART_PASSWORD, nullptr, 0);
	return url_part(u.get(), CURLUPART_URL).value_or("");
}

void FetchConfig::compile()
{
	if (timeout_ms == 0)
		throw std::runtime_error("fetch: timeout_ms must be above zero");
	rules.clear();
	for (const auto& entry : allow) {
		auto parsed = parse_url(entry);
		if (!parsed)
			throw std::runtime_error("fetch: invalid allow entry (an http or https URL): " + entry);
		rules.push_back(std::move(parsed->origin));
	}
	/* A request that its task abandoned runs on in libcurv, which calls
	   body_limit_cb until it ends, even after the last VCL is gone */
	if (!rules.empty())
		SandboxTenant::pin_vmod();
}

/* Path prefixes are compared as they are written: an entry should end
   with a slash, unless any path that starts with it is fine. They are
   no boundary for a server that decodes %2e%2e in a path. */
static bool allowed(const FetchConfig& cfg, const FetchRule& origin)
{
	for (const auto& rule : cfg.rules) {
		if (rule.scheme == origin.scheme && rule.host == origin.host
			&& rule.port == origin.port && origin.path.starts_with(rule.path))
			return true;
	}
	return false;
}

/* Headers that frame the message or pick the virtual host are curl's to
   write: from the guest they would reach another host than the allow list
   says, or desync a connection that other tasks then reuse. */
static bool reserved_header(std::string_view name)
{
	static constexpr std::array<std::string_view, 10> reserved {
		"host", "content-length", "transfer-encoding", "connection",
		"keep-alive", "proxy-connection", "te", "trailer", "upgrade",
		"expect",
	};
	return std::find(reserved.begin(), reserved.end(), lowercase(std::string(name)))
		!= reserved.end();
}

/* "Name: value" lines, separated by \n or \r\n. A CR or other control
   character left inside a line is refused by curv_req_set_reqheader(),
   which with validate=1 allows only tchars in names and VCHAR, SP and
   HTAB in values: it must stay on, or "X: a\rHost: b" is one line here
   and two to some servers. */
static bool add_headers(struct curv_req* req, std::string_view block)
{
	if (block.find('\0') != block.npos)
		return false;
	while (!block.empty()) {
		const size_t eol = block.find('\n');
		std::string_view line = block.substr(0, eol);
		block = (eol == block.npos) ? std::string_view() : block.substr(eol + 1);
		if (!line.empty() && line.back() == '\r')
			line.remove_suffix(1);
		if (line.empty())
			continue;
		const size_t colon = line.find(':');
		if (colon == line.npos || colon == 0)
			return false;
		std::string_view value = line.substr(colon + 1);
		while (!value.empty() && value.front() == ' ')
			value.remove_prefix(1);
		const std::string name(line.substr(0, colon));
		if (reserved_header(name))
			return false;
		if (curv_req_set_reqheader(req, name.c_str(), std::string(value).c_str(), 1) != 0)
			return false;
	}
	return true;
}

struct ReqGuard {
	struct curv_req* req;
	~ReqGuard() { if (req != nullptr) curv_req_destroy(&req); }
};

/* curl before 8.4 does not stop a chunked response at CURLOPT_MAXFILESIZE.
   The progress callback runs on the engine thread that owns the request,
   after body data arrives, and aborts the transfer as soon as libcurv has
   buffered more than the limit. */
struct BodyLimit {
	struct curv_req* req;
	size_t max;
};
static int body_limit_cb(void* priv, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
{
	const auto* limit = (const BodyLimit*)priv;
	const struct vsb* body = limit->req->resp_body;
	return body != nullptr && size_t(VSB_len(body)) > limit->max;
}

static long fetch_send(machine_t& machine, Script& script, unsigned op, unsigned flags)
{
	auto [opflags, url_buf, hdr_buf] =
		machine.sysargs<unsigned, riscv::Buffer, riscv::Buffer> ();
	(void)opflags;
	/* A GET leaves a5 and a6 as they were */
	riscv::Buffer body_buf;
	if (op == FETCH_POST)
		body_buf = machine.sysarg<riscv::Buffer>(5);
	const auto& fetch = script.config().group.fetch;
	/* Only a task's fork: the master and storage VMs outlive every task,
	   and so would their requests */
	if (fetch == nullptr || fetch->rules.empty() || !script.is_fork())
		return FETCH_EACCES;
	const FetchConfig& cfg = *fetch;
	if (flags & ~unsigned(FETCH_FLAG_INSECURE))
		return FETCH_EINVAL;
	if ((flags & FETCH_FLAG_INSECURE) && !cfg.allow_insecure)
		return FETCH_EACCES;
	if (url_buf.size() > FETCH_URL_MAX || hdr_buf.size() > FETCH_HEADERS_MAX)
		return FETCH_EINVAL;
	if (op == FETCH_POST && body_buf.size() > cfg.max_request_body)
		return FETCH_EINVAL;
	auto& state = script.fetch_state();
	if (state.started >= cfg.max_requests)
		return FETCH_ELIMIT;

	auto parsed = parse_url(url_buf.to_string());
	if (!parsed)
		return FETCH_EINVAL;
	const auto* ctx = script.ctx();
	if (!allowed(cfg, parsed->origin)) {
		if (ctx != nullptr && ctx->vsl != nullptr)
			VSLb(ctx->vsl, SLT_VCL_Error, "[%s] fetch: URL not allowed: %s",
				script.name().c_str(), loggable_url(parsed->url.c_str()).c_str());
		return FETCH_EACCES;
	}

	ReqGuard guard{curv_req_new(CURV_LABEL_OBJECT, "riscv.fetch")};
	auto* req = guard.req;
	if (!add_headers(req, hdr_buf.to_string()))
		return FETCH_EINVAL;
	char* url = (char *)curv_req_alloc(req, parsed->url.size() + 1);
	std::memcpy(url, parsed->url.c_str(), parsed->url.size() + 1);
	CURL_EASYSET(req, CURLOPT_URL, url);
	if (op == FETCH_POST) {
		/* libcurv makes it a POST when there is a body */
		req->req_body = VSB_new_auto();
		AN(req->req_body);
		const auto body = body_buf.to_string();
		VSB_bcat(req->req_body, body.data(), body.size());
		AZ(VSB_finish(req->req_body));
		/* Do not wait for a 100 Continue that may never come */
		curv_req_set_reqheader(req, "Expect", nullptr, 0);
	}
#if LIBCURL_VERSION_NUM >= 0x075500
	CURL_EASYSET(req, CURLOPT_PROTOCOLS_STR, "http,https");
#else
	CURL_EASYSET(req, CURLOPT_PROTOCOLS, long(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
	/* A redirect could leave the allow list */
	CURL_EASYSET(req, CURLOPT_FOLLOWLOCATION, 0L);
	CURL_EASYSET(req, CURLOPT_TIMEOUT_MS, long(cfg.timeout_ms));
	CURL_EASYSET(req, CURLOPT_CONNECTTIMEOUT_MS, long(cfg.connect_timeout_ms));
	/* To curl, 0 is no limit at all */
	if (cfg.max_response_body > 0)
		CURL_EASYSET(req, CURLOPT_MAXFILESIZE_LARGE, curl_off_t(cfg.max_response_body));
	auto* limit = (BodyLimit *)curv_req_alloc(req, sizeof(BodyLimit));
	*limit = {req, cfg.max_response_body};
	CURL_EASYSET(req, CURLOPT_XFERINFOFUNCTION, body_limit_cb);
	CURL_EASYSET(req, CURLOPT_XFERINFODATA, limit);
	CURL_EASYSET(req, CURLOPT_NOPROGRESS, 0L);
	if (flags & FETCH_FLAG_INSECURE) {
		CURL_EASYSET(req, CURLOPT_SSL_VERIFYPEER, 0L);
		CURL_EASYSET(req, CURLOPT_SSL_VERIFYHOST, 0L);
	}
	if (req->cc != CURLE_OK)
		return FETCH_EINVAL;

	/* Every handle in use is a request in flight */
	auto slot = std::find(state.slots.begin(), state.slots.end(), nullptr);
	if (slot == state.slots.end())
		slot = state.slots.insert(slot, nullptr);
	if (curv_engine_exec(&guard.req, &*slot, 0, 0) != nullptr) {
		/* It did not take the request */
		return FETCH_EBUSY;
	}
	state.started++;
	return slot - state.slots.begin();
}

static gaddr_t copy_out(machine_t& machine, Script& script, const char* data, size_t len)
{
	const gaddr_t addr = script.guest_alloc(len + 1);
	if (addr == 0)
		return 0;
	machine.copy_to_guest(addr, data, len);
	machine.memory.write<uint8_t>(addr + len, 0);
	return addr;
}

/* Hand a finished request over to the guest */
static void deliver(machine_t& machine, Script& script, struct curv_req* req, gaddr_t dst)
{
	const FetchConfig& cfg = *script.config().group.fetch;
	GuestFetchResponse resp {};
	CURLcode cc = req->cc;
	long status = 0;
	if (cc == CURLE_OK)
		curl_easy_getinfo(req->easy, CURLINFO_RESPONSE_CODE, &status);
	const char* body = "";
	size_t body_len = 0;
	if (req->resp_body != nullptr) {
		body = VSB_data(req->resp_body);
		body_len = VSB_len(req->resp_body);
	}
	/* body_limit_cb is the only callback that aborts, and it may let a
	   little more than the limit through before it does */
	if (cc == CURLE_ABORTED_BY_CALLBACK
		|| (cc == CURLE_OK && body_len > cfg.max_response_body))
		cc = CURLE_FILESIZE_EXCEEDED;
	if (cc == CURLE_OK) {
		std::string headers;
		const struct curv_header* hdr;
		VTAILQ_FOREACH(hdr, &req->resp_headers, list) {
			headers.append(hdr->name);
			headers.append(": ");
			headers.append(hdr->resp_value);
			headers.push_back('\n');
		}
		resp.body = copy_out(machine, script, body, body_len);
		resp.headers = copy_out(machine, script, headers.data(), headers.size());
		if (resp.body == 0 || resp.headers == 0) {
			if (resp.body != 0)
				script.guest_free(resp.body);
			if (resp.headers != 0)
				script.guest_free(resp.headers);
			resp = {};
			cc = CURLE_OUT_OF_MEMORY;
		} else {
			resp.body_len = body_len;
			resp.headers_len = headers.size();
			resp.status = status;
		}
	}
	resp.error = cc;
	machine.copy_to_guest(dst, &resp, sizeof(resp));

	const auto* ctx = script.ctx();
	if (ctx != nullptr && ctx->vsl != nullptr) {
		char* url = nullptr;
		curl_easy_getinfo(req->easy, CURLINFO_EFFECTIVE_URL, &url);
		VSLb(ctx->vsl, SLT_VCL_Log, "[%s] fetch %s: %ld %s (%.3fs)",
			script.name().c_str(), loggable_url(url).c_str(), status,
			curl_easy_strerror(cc), double(req->elapsed));
	}
}

static long fetch_wait(machine_t& machine, Script& script, unsigned flags)
{
	auto [opflags, handles_addr, count, resps_addr, timeout_ms] =
		machine.sysargs<unsigned, gaddr_t, unsigned, gaddr_t, int> ();
	(void)opflags;
	if ((flags & ~unsigned(FETCH_FLAG_ANY)) || count > FETCH_WAIT_MAX)
		return FETCH_EINVAL;
	if (count == 0)
		return 0;
	auto& state = script.fetch_state();
	std::array<int32_t, FETCH_WAIT_MAX> handles;
	machine.memory.memcpy_out(handles.data(), handles_addr, count * sizeof(int32_t));
	for (unsigned i = 0; i < count; i++) {
		const int32_t h = handles[i];
		if (h == -1)
			continue;
		if (h < 0 || size_t(h) >= state.slots.size() || state.slots[h] == nullptr)
			return FETCH_EINVAL;
		for (unsigned j = 0; j < i; j++)
			if (handles[j] == h)
				return FETCH_EINVAL;
	}

	long completed = 0;
	auto finish = [&] (unsigned i, struct curv_req* req) {
		/* The slot is free now: until it is destroyed, the request is
		   only here, and writing guest memory may throw */
		ReqGuard guard{req};
		AZ(state.slots[handles[i]]);
		handles[i] = -1;
		machine.memory.write<int32_t>(handles_addr + i * sizeof(int32_t), -1);
		deliver(machine, script, req,
			resps_addr + i * sizeof(GuestFetchResponse));
		completed++;
	};
	const bool any = flags & FETCH_FLAG_ANY;
	const vtim_real deadline = VTIM_real() + timeout_ms / 1e3;
	int poll_ms = 1;
	while (true) {
		unsigned pending = 0, first = 0;
		for (unsigned i = 0; i < count; i++) {
			if (handles[i] == -1)
				continue;
			if (auto* req = curv_engine_wait(&state.slots[handles[i]], 0))
				finish(i, req);
			else if (pending++ == 0)
				first = i;
		}
		if (pending == 0 || (any && completed > 0) || timeout_ms == 0)
			break;
		/* libcurv can only wait on one task at a time. Waiting for any of
		   several, wait on one and look at the others in between, at first
		   every millisecond and then less often, up to FETCH_POLL_MAX_MS:
		   a quick response is seen quickly, and slow ones do not keep
		   waking the worker. Requests always end, with CURLOPT_TIMEOUT_MS. */
		int wait_ms = -1;
		if (timeout_ms > 0) {
			wait_ms = int((deadline - VTIM_real()) * 1e3);
			if (wait_ms <= 0)
				break;
		}
		if (any && pending > 1) {
			wait_ms = (wait_ms < 0) ? poll_ms : std::min(wait_ms, poll_ms);
			poll_ms = std::min(poll_ms * 2, FETCH_POLL_MAX_MS);
		}
		if (auto* req = curv_engine_wait(&state.slots[handles[first]], wait_ms))
			finish(first, req);
	}
	return completed;
}

static long fetch_free(machine_t& machine, Script& script)
{
	auto [opflags, handle] = machine.sysargs<unsigned, int> ();
	(void)opflags;
	auto& state = script.fetch_state();
	if (handle < 0 || size_t(handle) >= state.slots.size() || state.slots[handle] == nullptr)
		return FETCH_EINVAL;
	curv_engine_detach(&state.slots[handle]);
	return 0;
}

void fetch(machine_t& machine)
{
	auto& script = get_script(machine);
	const unsigned opflags = machine.cpu.reg(riscv::REG_ARG0);
	const unsigned op = opflags & FETCH_OP_MASK;
	const unsigned flags = opflags & ~unsigned(FETCH_OP_MASK);
	switch (op) {
	case FETCH_GET:
	case FETCH_POST:
		machine.set_result(fetch_send(machine, script, op, flags));
		return;
	case FETCH_WAIT:
		machine.set_result(fetch_wait(machine, script, flags));
		return;
	case FETCH_FREE:
		machine.set_result(fetch_free(machine, script));
		return;
	}
	machine.set_result(FETCH_EINVAL);
}

#else // FETCH_SUPPORTED

/* Not a reason to refuse the tenant: without rules every request is
   refused, and the system call returns FETCH_ENOSYS anyway. */
void FetchConfig::compile()
{
	rules.clear();
#ifdef VARNISH_PLUS
	VSL(SLT_Error, RISCV_NO_VXID,
		"fetch: requires libcurl 7.62 or newer, ECALL_FETCH is disabled");
#else
	VSL(SLT_Error, RISCV_NO_VXID,
		"fetch: requires Varnish Enterprise, ECALL_FETCH is disabled");
#endif
}

void fetch(machine_t& machine)
{
	machine.set_result(FETCH_ENOSYS);
}

#endif // FETCH_SUPPORTED

} // rvs
