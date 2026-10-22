#include "script_functions.hpp"
#include "machine/syscalls.h"
#include "sandbox_tenant.hpp"
#include "tenant.hpp"
#include "varnish.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
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

#if FETCH_SUPPORTED
using FetchHeaders = std::vector<std::pair<std::string, std::string>>;

/* A request as the guest gave it, kept while it is in flight only when
   its redirects are followed: each hop is sent again from it. The body of
   a POST is in the curv_req, and goes from one hop to the next. */
struct FetchRequest {
	unsigned     op = FETCH_GET;
	unsigned     flags = 0;
	FetchHeaders headers;
	FetchRule    origin;            // of the URL it was last sent to
	uint32_t     max_redirects = 0; // when it was sent, 0: not kept
	uint32_t     redirects = 0;     // followed so far
	long         timeout_ms = 0;    // left of timeout_ms, for the hops to come
	vtim_dur     elapsed = 0;       // of the hops before this one
};

/* A slot is free when its task is null */
struct FetchSlot {
	struct curv_task* task = nullptr;
	FetchRequest      request;
};
#endif

/* Handles index the slots of the in-flight tasks */
struct FetchState {
#if FETCH_SUPPORTED
	std::vector<FetchSlot> slots;
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
/* As curl's own default limit is 30 */
static constexpr uint32_t FETCH_REDIRECTS_MAX = 20;
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
	for (auto& slot : m_fetch->slots)
		if (slot.task != nullptr)
			curv_engine_detach(&slot.task);
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

struct VsbFree {
	void operator()(struct vsb* v) const { VSB_destroy(&v); }
};
using vsb_ptr = std::unique_ptr<struct vsb, VsbFree>;

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

/* The files are read by curl at each new connection, on an engine thread
   of the worker process: check now that this process can open them, as
   curl will. A file that goes away later fails the requests that need
   it, and deliver() logs those as errors. */
static void check_tls_file(const std::string& url, const char* what, const std::string& path)
{
	if (path.empty())
		return;
	if (path.front() != '/')
		throw std::runtime_error("fetch: " + std::string(what) + " must be an absolute path: " + path);
	const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		throw std::runtime_error("fetch: can not read " + std::string(what) + " "
			+ path + " (for " + url + "): " + std::strerror(errno));
	struct stat st;
	const bool regular = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
	close(fd);
	if (!regular)
		throw std::runtime_error("fetch: " + std::string(what) + " is not a file: " + path);
}

static bool same_prefix(const FetchRule& a, const FetchRule& b)
{
	return a.scheme == b.scheme && a.host == b.host
		&& a.port == b.port && a.path == b.path;
}

void FetchConfig::compile(const std::vector<FetchAllow>& allow)
{
	if (timeout_ms == 0)
		throw std::runtime_error("fetch: timeout_ms must be above zero");
	if (max_redirects > FETCH_REDIRECTS_MAX)
		throw std::runtime_error("fetch: max_redirects must be at most "
			+ std::to_string(FETCH_REDIRECTS_MAX));
	rules.clear();
	for (const auto& entry : allow) {
		auto parsed = parse_url(entry.url);
		if (!parsed)
			throw std::runtime_error("fetch: invalid allow entry (an http or https URL): " + entry.url);
		const FetchTLS& tls = entry.tls;
		if (!tls.empty() && parsed->origin.scheme != "https")
			throw std::runtime_error("fetch: TLS files on an allow entry that is not https: " + entry.url);
		/* Without the slash, "/mtls" would give its files to "/mtlsX" */
		if (!tls.empty() && !parsed->origin.path.ends_with('/'))
			throw std::runtime_error("fetch: the path of an allow entry with TLS files must end with a slash: " + entry.url);
		if (!tls.client_key.empty() && tls.client_cert.empty())
			throw std::runtime_error("fetch: client_key without client_cert: " + entry.url);
		check_tls_file(entry.url, "ca_file", tls.ca_file);
		check_tls_file(entry.url, "client_cert", tls.client_cert);
		check_tls_file(entry.url, "client_key", tls.client_key);
		parsed->origin.tls = tls;
		/* Only one of them would ever be used */
		for (const auto& rule : rules)
			if (same_prefix(rule, parsed->origin) && rule.tls != tls)
				throw std::runtime_error("fetch: allow entries for the same URL with other TLS files: " + entry.url);
		rules.push_back(std::move(parsed->origin));
	}
	/* A request that its task abandoned runs on in libcurv, which calls
	   body_limit_cb until it ends, even after the last VCL is gone */
	if (!rules.empty())
		SandboxTenant::pin_vmod();
}

/* Path prefixes are compared as they are written: an entry should end
   with a slash, unless any path that starts with it is fine. Of the
   rules that allow a URL, the one with the longest prefix gives its TLS
   files. A path that a server could take above the prefix is refused by
   fetch_send(), see climbs_up(). */
static const FetchRule* allowed(const FetchConfig& cfg, const FetchRule& origin)
{
	const FetchRule* best = nullptr;
	for (const auto& rule : cfg.rules) {
		if (rule.scheme == origin.scheme && rule.host == origin.host
			&& rule.port == origin.port && origin.path.starts_with(rule.path)
			&& (best == nullptr || rule.path.size() > best->path.size()))
			best = &rule;
	}
	return best;
}

/* curl removes the "." and ".." segments of a path, but a server may
   decode %2e%2e or %2f into one, split segments at a backslash too, or
   take "..;x" as ".." with a parameter. Decoded until nothing changes,
   for servers that decode twice. */
static bool climbs_up(std::string_view path)
{
	auto hex = [] (char c) -> int {
		if (c >= '0' && c <= '9')
			return c - '0';
		c |= 0x20;
		return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
	};
	std::string decoded(path);
	while (decoded.find('%') != decoded.npos) {
		std::string next;
		next.reserve(decoded.size());
		for (size_t i = 0; i < decoded.size(); i++) {
			int hi, lo;
			if (decoded[i] == '%' && i + 2 < decoded.size()
				&& (hi = hex(decoded[i+1])) >= 0 && (lo = hex(decoded[i+2])) >= 0) {
				next.push_back(char(hi << 4 | lo));
				i += 2;
			} else {
				next.push_back(decoded[i]);
			}
		}
		if (next == decoded)
			break;
		decoded = std::move(next);
	}
	size_t start = 0;
	while (start <= decoded.size()) {
		size_t end = decoded.find_first_of("/\\", start);
		if (end == decoded.npos)
			end = decoded.size();
		std::string_view segment(decoded.data() + start, end - start);
		if (segment.substr(0, segment.find(';')) == "..")
			return true;
		start = end + 1;
	}
	return false;
}

/* The allow entry that gives a URL its TLS files, or null and why not */
static const FetchRule* permitted(const FetchConfig& cfg, const FetchRule& origin,
	unsigned flags, const char*& why)
{
	const FetchRule* rule = allowed(cfg, origin);
	if (rule == nullptr)
		why = "URL not allowed";
	else if (rule->path != "/" && climbs_up(origin.path))
		why = "URL not allowed (a .. segment)";
	/* The TLS files of an entry pin its origin, and a client certificate
	   is not for a server that was not verified */
	else if ((flags & FETCH_FLAG_INSECURE) && !rule->tls.empty())
		why = "insecure request to an origin with TLS files";
	else
		return rule;
	return nullptr;
}

static void log_refused(const Script& script, bool redirect, const char* why, const std::string& url)
{
	const auto* ctx = script.ctx();
	if (ctx != nullptr && ctx->vsl != nullptr)
		VSLb(ctx->vsl, SLT_VCL_Error, "[%s] fetch%s: %s: %s", script.name().c_str(),
			redirect ? " (redirect)" : "", why, loggable_url(url.c_str()).c_str());
}

/* curl before 7.83.1 could reuse a connection, or resume a TLS session,
   made with other TLS files (CVE-2022-27782). libcurv's connections are
   shared by every tenant and vmod_http: another request to the origin
   could go out with this client certificate, or this one over a
   connection that was verified with other CAs. */
static bool tls_reuse_is_safe()
{
	static const bool safe =
		curl_version_info(CURLVERSION_NOW)->version_num >= 0x075301;
	return safe;
}

static void set_tls_files(struct curv_req* req, const FetchTLS& tls)
{
	if (tls.empty())
		return;
	if (!tls.ca_file.empty()) {
		/* These CAs only, not the system's as well. A TLS backend
		   without CA paths refuses even to unset one, and has none. */
		CURL_EASYSET(req, CURLOPT_CAINFO, tls.ca_file.c_str());
		(void)curl_easy_setopt(req->easy, CURLOPT_CAPATH, (const char *)nullptr);
#if LIBCURL_VERSION_NUM >= 0x075700
		/* curl caches one CA store per multi handle, by file name. Not
		   using it reads the file at each new connection, so that a new
		   one is seen at once, and leaves the store of other requests
		   (the system CAs of vmod_http) in the cache. A libcurl older
		   than the headers has no such cache, and refuses the option. */
		(void)curl_easy_setopt(req->easy, CURLOPT_CA_CACHE_TIMEOUT, 0L);
#endif
	}
	if (!tls.client_cert.empty()) {
		CURL_EASYSET(req, CURLOPT_SSLCERT, tls.client_cert.c_str());
		if (!tls.client_key.empty())
			CURL_EASYSET(req, CURLOPT_SSLKEY, tls.client_key.c_str());
	}
	if (!tls_reuse_is_safe()) {
		CURL_EASYSET(req, CURLOPT_FRESH_CONNECT, 1L);
		CURL_EASYSET(req, CURLOPT_FORBID_REUSE, 1L);
		CURL_EASYSET(req, CURLOPT_SSL_SESSIONID_CACHE, 0L);
	}
}

/* names are in lowercase */
static bool header_is(std::string_view name, std::initializer_list<std::string_view> names)
{
	return std::any_of(names.begin(), names.end(), [name] (std::string_view n) {
		return n.size() == name.size() && strncasecmp(n.data(), name.data(), n.size()) == 0;
	});
}

/* Headers that frame the message or pick the virtual host are curl's to
   write: from the guest they would reach another host than the allow list
   says, or desync a connection that other tasks then reuse. */
static bool reserved_header(std::string_view name)
{
	return header_is(name, {
		"host", "content-length", "transfer-encoding", "connection",
		"keep-alive", "proxy-connection", "te", "trailer", "upgrade",
		"expect",
	});
}

/* "Name: value" lines, separated by \n or \r\n. A CR or other control
   character left inside a line is refused by curv_req_set_reqheader(),
   which with validate=1 allows only tchars in names and VCHAR, SP and
   HTAB in values: it must stay on, or "X: a\rHost: b" is one line here
   and two to some servers. */
static std::optional<FetchHeaders> parse_headers(std::string_view block)
{
	if (block.find('\0') != block.npos)
		return std::nullopt;
	FetchHeaders headers;
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
			return std::nullopt;
		std::string_view value = line.substr(colon + 1);
		while (!value.empty() && value.front() == ' ')
			value.remove_prefix(1);
		std::string name(line.substr(0, colon));
		if (reserved_header(name))
			return std::nullopt;
		headers.emplace_back(std::move(name), std::string(value));
	}
	return headers;
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

/* Hand a request, the guest's or a redirect of it, to libcurv in its
   slot. The URL must be one that rule permits, and the body of a POST is
   the request's from now on. Nothing throws once libcurv has it. */
static long fetch_exec(const FetchConfig& cfg, FetchSlot& slot, const FetchRule& rule,
	const std::string& url, long timeout_ms, vsb_ptr body)
{
	const FetchRequest& request = slot.request;
	ReqGuard guard{curv_req_new(CURV_LABEL_OBJECT, "riscv.fetch")};
	auto* req = guard.req;
	req->req_body = body.release();
	for (const auto& [name, value] : request.headers)
		if (curv_req_set_reqheader(req, name.c_str(), value.c_str(), 1) != 0)
			return FETCH_EINVAL;
	char* curl_url = (char *)curv_req_alloc(req, url.size() + 1);
	std::memcpy(curl_url, url.c_str(), url.size() + 1);
	CURL_EASYSET(req, CURLOPT_URL, curl_url);
	/* libcurv makes it a POST when there is a body */
	if (req->req_body != nullptr) {
		/* Do not wait for a 100 Continue that may never come */
		curv_req_set_reqheader(req, "Expect", nullptr, 0);
	}
#if LIBCURL_VERSION_NUM >= 0x075500
	CURL_EASYSET(req, CURLOPT_PROTOCOLS_STR, "http,https");
#else
	CURL_EASYSET(req, CURLOPT_PROTOCOLS, long(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
	/* A redirect could leave the allow list: fetch_follow() checks it */
	CURL_EASYSET(req, CURLOPT_FOLLOWLOCATION, 0L);
	CURL_EASYSET(req, CURLOPT_TIMEOUT_MS, timeout_ms);
	CURL_EASYSET(req, CURLOPT_CONNECTTIMEOUT_MS, long(cfg.connect_timeout_ms));
	/* To curl, 0 is no limit at all */
	if (cfg.max_response_body > 0)
		CURL_EASYSET(req, CURLOPT_MAXFILESIZE_LARGE, curl_off_t(cfg.max_response_body));
	auto* limit = (BodyLimit *)curv_req_alloc(req, sizeof(BodyLimit));
	*limit = {req, cfg.max_response_body};
	CURL_EASYSET(req, CURLOPT_XFERINFOFUNCTION, body_limit_cb);
	CURL_EASYSET(req, CURLOPT_XFERINFODATA, limit);
	CURL_EASYSET(req, CURLOPT_NOPROGRESS, 0L);
	set_tls_files(req, rule.tls);
	if (request.flags & FETCH_FLAG_INSECURE) {
		CURL_EASYSET(req, CURLOPT_SSL_VERIFYPEER, 0L);
		CURL_EASYSET(req, CURLOPT_SSL_VERIFYHOST, 0L);
	}
	if (req->cc != CURLE_OK)
		return FETCH_EINVAL;
	if (curv_engine_exec(&guard.req, &slot.task, 0, 0) != nullptr) {
		/* It did not take the request */
		return FETCH_EBUSY;
	}
	return 0;
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
	const char* why = nullptr;
	const FetchRule* rule = permitted(cfg, parsed->origin, flags, why);
	if (rule == nullptr) {
		log_refused(script, false, why, parsed->url);
		return FETCH_EACCES;
	}
	auto headers = parse_headers(hdr_buf.to_string());
	if (!headers)
		return FETCH_EINVAL;

	/* Every handle in use is a request in flight */
	auto slot = std::find_if(state.slots.begin(), state.slots.end(),
		[] (const FetchSlot& s) { return s.task == nullptr; });
	if (slot == state.slots.end())
		slot = state.slots.emplace(slot);
	slot->request = FetchRequest {
		.op = op,
		.flags = flags,
		.headers = std::move(*headers),
		.origin = std::move(parsed->origin),
		.max_redirects = cfg.max_redirects,
		.timeout_ms = long(cfg.timeout_ms),
	};
	vsb_ptr body;
	if (op == FETCH_POST) {
		body.reset(VSB_new_auto());
		AN(body);
		body_buf.foreach([vsb = body.get()] (const char* data, size_t len) {
			VSB_bcat(vsb, data, len);
		});
		AZ(VSB_finish(body.get()));
	}
	const long res = fetch_exec(cfg, *slot, *rule, parsed->url, cfg.timeout_ms, std::move(body));
	/* Kept only to follow redirects */
	if (res < 0 || cfg.max_redirects == 0)
		slot->request = {};
	if (res < 0)
		return res;
	state.started++;
	return slot - state.slots.begin();
}

static bool same_origin(const FetchRule& a, const FetchRule& b)
{
	return a.scheme == b.scheme && a.host == b.host && a.port == b.port;
}

/* A finished request that is a redirect, which may be followed: it goes on
   in its slot, to the next URL, and the guest's handle with it. A redirect
   that is not followed is the response. Whether redirects are followed is
   decided when the guest sends the request, and the config of now may
   only lower the limit. */
static bool fetch_follow(Script& script, const FetchConfig& cfg, FetchSlot& slot,
	struct curv_req* req)
{
	FetchRequest& request = slot.request;
	if (request.max_redirects == 0 || req->cc != CURLE_OK)
		return false;
	long status = 0;
	curl_easy_getinfo(req->easy, CURLINFO_RESPONSE_CODE, &status);
	if (status != 301 && status != 302 && status != 303 && status != 307 && status != 308)
		return false;
	/* The Location, resolved against the URL of the request by curl */
	char* location = nullptr;
	curl_easy_getinfo(req->easy, CURLINFO_REDIRECT_URL, &location);
	if (location == nullptr)
		return false;
	/* What is left of timeout_ms is what the hops took on the network,
	   by curl's monotonic clock: not the time the guest took to wait */
	curl_off_t hop_us = 0;
	curl_easy_getinfo(req->easy, CURLINFO_TOTAL_TIME_T, &hop_us);
	const long timeout_ms = request.timeout_ms - long(hop_us / 1000);
	const size_t location_len = std::strlen(location);
	std::optional<ParsedURL> parsed;
	const char* why = nullptr;
	const FetchRule* rule = nullptr;
	if (request.redirects >= std::min(request.max_redirects, cfg.max_redirects))
		why = "too many redirects";
	/* As the guest's own URLs, before and after curl normalizes it */
	else if (location_len > FETCH_URL_MAX)
		why = "URL too long";
	else if (!(parsed = parse_url(location)))
		why = "not an http or https URL";
	else if (parsed->url.size() > FETCH_URL_MAX)
		why = "URL too long";
	else if (timeout_ms <= 0)
		why = "timed out";
	else
		rule = permitted(cfg, parsed->origin, request.flags, why);
	if (rule == nullptr) {
		log_refused(script, true, why, (parsed && parsed->url.size() <= FETCH_URL_MAX)
			? parsed->url : std::string(location, std::min(location_len, FETCH_URL_MAX)));
		return false;
	}

	const auto* ctx = script.ctx();
	const bool logged = ctx != nullptr && ctx->vsl != nullptr;
	/* For the log, made first: if it throws, the request is as it was,
	   and nothing may throw once it is sent */
	std::string from, to;
	if (logged) {
		char* url = nullptr;
		curl_easy_getinfo(req->easy, CURLINFO_EFFECTIVE_URL, &url);
		from = loggable_url(url);
		to = loggable_url(parsed->url.c_str());
	}

	/* As browsers and curl do, a POST becomes a GET after a 301, 302 or
	   303, and the headers that describe its body go with it */
	vsb_ptr body;
	if (request.op == FETCH_POST && status != 307 && status != 308) {
		request.op = FETCH_GET;
		std::erase_if(request.headers, [] (const auto& h) {
			return header_is(h.first, {"content-type", "content-encoding",
				"content-language", "content-location"});
		});
	} else {
		/* Not needed by deliver(): it goes on to the next hop */
		body.reset(std::exchange(req->req_body, nullptr));
	}
	/* Credentials are for the origin the guest sent them to */
	if (!same_origin(request.origin, parsed->origin)) {
		std::erase_if(request.headers, [] (const auto& h) {
			return header_is(h.first, {"authorization", "proxy-authorization", "cookie"});
		});
	}
	request.origin = std::move(parsed->origin);
	if (fetch_exec(cfg, slot, *rule, parsed->url, timeout_ms, std::move(body)) < 0) {
		log_refused(script, true, "could not be sent", parsed->url);
		return false;
	}
	request.redirects++;
	request.timeout_ms = timeout_ms;
	request.elapsed += req->elapsed;
	if (logged)
		VSLb(ctx->vsl, SLT_VCL_Log, "[%s] fetch %s: %ld redirect to %s",
			script.name().c_str(), from.c_str(), status, to.c_str());
	return true;
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

/* Hand a finished request over to the guest. With the redirects it
   followed, the log has their number and the time of every hop. */
static void deliver(machine_t& machine, Script& script, struct curv_req* req, gaddr_t dst,
	uint32_t redirects, vtim_dur elapsed)
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
		/* The TLS files of an allow entry, gone or changed since the
		   VCL was loaded: the operator's to fix */
		const bool bad_file = cc == CURLE_SSL_CERTPROBLEM
			|| cc == CURLE_SSL_CACERT_BADFILE;
		char hops[32] = "";
		if (redirects > 0)
			snprintf(hops, sizeof(hops), ", %u redirect%s",
				unsigned(redirects), redirects > 1 ? "s" : "");
		VSLb(ctx->vsl, bad_file ? SLT_VCL_Error : SLT_VCL_Log,
			"[%s] fetch %s: %ld %s%s (%.3fs%s)",
			script.name().c_str(), loggable_url(url).c_str(), status,
			curl_easy_strerror(cc),
			bad_file ? " (the TLS files of its allow entry)" : "",
			double(elapsed), hops);
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
		if (h < 0 || size_t(h) >= state.slots.size() || state.slots[h].task == nullptr)
			return FETCH_EINVAL;
		for (unsigned j = 0; j < i; j++)
			if (handles[j] == h)
				return FETCH_EINVAL;
	}

	long completed = 0;
	/* A request is done unless it was a redirect that is followed */
	auto finish = [&] (unsigned i, struct curv_req* req) {
		/* The slot is free now: until it is destroyed, the request is
		   only here, and writing guest memory may throw */
		ReqGuard guard{req};
		FetchSlot& slot = state.slots[handles[i]];
		AZ(slot.task);
		try {
			if (fetch_follow(script, *script.config().group.fetch, slot, req))
				return false;
		} catch (const std::exception& e) {
			/* Not sent, as fetch_exec() does not throw once it is:
			   the redirect is the response */
			AZ(slot.task);
			const auto* ctx = script.ctx();
			if (ctx != nullptr && ctx->vsl != nullptr)
				VSLb(ctx->vsl, SLT_VCL_Error, "[%s] fetch (redirect): %s",
					script.name().c_str(), e.what());
		}
		const uint32_t redirects = slot.request.redirects;
		const vtim_dur elapsed = slot.request.elapsed + req->elapsed;
		slot.request = {};
		handles[i] = -1;
		machine.memory.write<int32_t>(handles_addr + i * sizeof(int32_t), -1);
		deliver(machine, script, req,
			resps_addr + i * sizeof(GuestFetchResponse), redirects, elapsed);
		completed++;
		return true;
	};
	const bool any = flags & FETCH_FLAG_ANY;
	const vtim_real deadline = VTIM_mono() + timeout_ms / 1e3;
	int poll_ms = 1;
	while (true) {
		unsigned pending = 0, first = 0;
		for (unsigned i = 0; i < count; i++) {
			if (handles[i] == -1)
				continue;
			auto* req = curv_engine_wait(&state.slots[handles[i]].task, 0);
			if (req != nullptr && finish(i, req))
				continue;
			if (pending++ == 0)
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
			wait_ms = int((deadline - VTIM_mono()) * 1e3);
			if (wait_ms <= 0)
				break;
		}
		if (any && pending > 1) {
			wait_ms = (wait_ms < 0) ? poll_ms : std::min(wait_ms, poll_ms);
			poll_ms = std::min(poll_ms * 2, FETCH_POLL_MAX_MS);
		}
		if (auto* req = curv_engine_wait(&state.slots[handles[first]].task, wait_ms))
			finish(first, req);
	}
	return completed;
}

static long fetch_free(machine_t& machine, Script& script)
{
	auto [opflags, handle] = machine.sysargs<unsigned, int> ();
	(void)opflags;
	auto& state = script.fetch_state();
	if (handle < 0 || size_t(handle) >= state.slots.size() || state.slots[handle].task == nullptr)
		return FETCH_EINVAL;
	curv_engine_detach(&state.slots[handle].task);
	state.slots[handle].request = {};
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
void FetchConfig::compile(const std::vector<FetchAllow>&)
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
