#include <api.h>
#include <sys/random.h>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <ctime>
namespace varnish = api;

/* Personalize HLS and DASH manifests from a single cached copy.

   vcl_recv:    set req.http.X-Token = riscv.call("authorize", req.url);
   vcl_deliver: riscv.deliver_transform("personalize", req.http.X-Token);

   A manifest request without a token starts a session with a random viewer ID
   and a token scoped to the manifest's directory. Authorized manifest requests
   renew the session. Rewriting adds the viewer's token to supported manifest
   URIs. All other requests require a valid token. VCL removes the token from
   the URL before the cache lookup, so all viewers share one cached copy of
   each object.

   Token: <viewer id>.<expires>.<scope depth>.<HMAC-SHA256/128>
   Tenant arguments: [secret, session lifetime in seconds]. */
static varnish::HmacSha256 hmac {"change-me-varnish-manifest-secret"};
static long lifetime = 300;

static constexpr unsigned B64URL = BASE64_FLAG_URL | BASE64_FLAG_NOPAD;
static constexpr std::string_view SESSION_DATA_ID = "com.varnish.viewer-id";
static constexpr size_t VIEWER_ID_BYTES = 12;
static constexpr size_t MAC_BYTES = 16;
static constexpr long MAX_DEPTH = 32;
static constexpr long MAX_LIFETIME = 10L * 365 * 24 * 3600;

static bool token_char(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		|| (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}

static bool parse_number(std::string_view s, long& out)
{
	if (s.empty() || s.size() > 12)
		return false;
	out = 0;
	for (const char c : s) {
		if (c < '0' || c > '9')
			return false;
		out = out * 10 + (c - '0');
	}
	return true;
}

/* Reject dot segments, empty segments, percent escapes, and backslashes:
   origin normalization could move these paths outside the signed scope. */
static bool path_safe(std::string_view path)
{
	if (path.empty() || path[0] != '/')
		return false;
	if (path.find('%') != path.npos || path.find('\\') != path.npos)
		return false;
	size_t p = 1;
	while (p <= path.size()) {
		size_t e = path.find('/', p);
		if (e == path.npos)
			e = path.size();
		const std::string_view seg = path.substr(p, e - p);
		if (seg == "." || seg == ".." || (seg.empty() && e < path.size()))
			return false;
		p = e + 1;
	}
	return true;
}

/* Return the first depth directories as a path prefix, or std::nullopt if
   the path is too short. */
static std::optional<std::string_view> scope_of(std::string_view path, long depth)
{
	size_t end = 0;
	for (long i = 0; i < depth; i++) {
		end = path.find('/', end + 1);
		if (end == path.npos)
			return std::nullopt;
	}
	if (end + 1 >= path.size())
		return std::nullopt;
	return path.substr(0, end + 1);
}

static long directory_depth(std::string_view path)
{
	long depth = 0;
	for (const char c : path)
		depth += (c == '/');
	return depth - 1;
}

static bool ends_with_nocase(std::string_view s, std::string_view suffix)
{
	if (s.size() < suffix.size())
		return false;
	s = s.substr(s.size() - suffix.size());
	for (size_t i = 0; i < s.size(); i++) {
		char c = s[i];
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
		if (c != suffix[i])
			return false;
	}
	return true;
}

static bool is_manifest(std::string_view path)
{
	return ends_with_nocase(path, ".m3u8") || ends_with_nocase(path, ".mpd");
}

static std::string_view query_param(std::string_view query, std::string_view key)
{
	while (!query.empty()) {
		size_t amp = query.find('&');
		const std::string_view pair = query.substr(0, amp);
		if (pair.size() > key.size() && pair.starts_with(key) && pair[key.size()] == '=')
			return pair.substr(key.size() + 1);
		if (amp == query.npos)
			break;
		query.remove_prefix(amp + 1);
	}
	return {};
}

static std::string sign(std::string_view viewer, long expires, long depth, std::string_view scope)
{
	std::string token;
	token.reserve(80);
	token.append(viewer);
	token += '.';
	token += std::to_string(expires);
	token += '.';
	token += std::to_string(depth);
	const auto mac = hmac({token, "\n", scope});
	token += '.';
	token += varnish::base64_encode({(const char*) mac.data(), MAC_BYTES}, B64URL);
	return token;
}

struct Session {
	std::string_view viewer;
	long depth;
};

static std::optional<Session> verify(std::string_view token, std::string_view path, long now)
{
	if (token.size() > 128)
		return std::nullopt;
	std::array<std::string_view, 4> part;
	size_t p = 0;
	for (size_t i = 0; i < part.size(); i++) {
		const size_t dot = token.find('.', p);
		if ((dot == token.npos) != (i == part.size() - 1))
			return std::nullopt;
		part[i] = token.substr(p, dot == token.npos ? token.npos : dot - p);
		p = dot + 1;
	}
	long expires, depth;
	if (part[0].empty() || !parse_number(part[1], expires) || !parse_number(part[2], depth))
		return std::nullopt;
	if (depth > MAX_DEPTH || now >= expires)
		return std::nullopt;
	const auto scope = scope_of(path, depth);
	if (!scope)
		return std::nullopt;

	const std::string_view mac = part[3];
	const std::string_view signed_part = token.substr(0, token.size() - mac.size() - 1);
	const auto expected = hmac({signed_part, "\n", *scope});
	if (!varnish::equal_constant_time(mac, varnish::base64_encode({(const char*) expected.data(), MAC_BYTES}, B64URL)))
		return std::nullopt;
	return Session{part[0], depth};
}

/* Return a new, renewed, or unchanged viewer token for this request,
   or nullptr if authorization fails. */
static const char* authorize(const char* arg, size_t len)
{
	static std::string result;
	const std::string_view url(arg, len);
	const size_t q = url.find('?');
	const std::string_view path = url.substr(0, q);
	if (!path_safe(path))
		return nullptr;
	const std::string_view token =
		(q != url.npos) ? query_param(url.substr(q + 1), "token") : std::string_view{};
	const bool manifest = is_manifest(path);
	const long now = std::time(nullptr);

	if (token.empty()) {
		if (!manifest)
			return nullptr;
		std::array<uint8_t, VIEWER_ID_BYTES> id;
		if (getrandom(id.data(), id.size(), 0) != (ssize_t) id.size())
			return nullptr;
		const long depth = std::min(directory_depth(path), MAX_DEPTH);
		const std::string viewer = varnish::base64_encode({(const char*) id.data(), id.size()}, B64URL);
		result = sign(viewer, now + lifetime, depth, *scope_of(path, depth));
		return result.c_str();
	}

	const auto session = verify(token, path, now);
	if (!session)
		return nullptr;
	if (manifest) {
		const std::string viewer(session->viewer);
		result = sign(viewer, now + lifetime, session->depth, *scope_of(path, session->depth));
	} else {
		result = token;
	}
	return result.c_str();
}

using word_t = uintptr_t;
using aliased_word = word_t __attribute__((may_alias));
static constexpr size_t WORD = sizeof(word_t);
static constexpr uintptr_t ALIGN_MASK = WORD - 1;

static constexpr word_t splat(char c)
{
	return word_t(~word_t(0)) / 0xFF * (unsigned char) c;
}

[[gnu::always_inline]] static inline word_t match_byte(word_t w, word_t pattern)
{
	const word_t x = w ^ pattern;
#ifdef __riscv_zbb
	word_t y;
	asm("orc.b %0, %1" : "=r"(y) : "r"(x));
	return ~y;
#else
	return ~(((x & splat(0x7f)) + splat(0x7f)) | x | splat(0x7f));
#endif
}

template <char... Cs>
struct Bytes {
	[[gnu::always_inline]] word_t operator() (word_t w) const
	{
		return (match_byte(w, splat(Cs)) | ...);
	}
};

struct Byte {
	word_t pattern;
	[[gnu::always_inline]] word_t operator() (word_t w) const
	{
		return match_byte(w, pattern);
	}
};

template <typename Match>
[[gnu::always_inline]] static inline size_t scan(const char* base, size_t from, size_t to, Match match)
{
	if (from >= to)
		return to;
	const uintptr_t start = uintptr_t(base + from);
	const uintptr_t end = uintptr_t(base + to);
	const aliased_word* w = (const aliased_word*) (start & ~ALIGN_MASK);
	word_t m = match(*w) & (~word_t(0) << (8 * (start & ALIGN_MASK)));
	while (m == 0) {
		if (uintptr_t(++w) >= end)
			return to;
		m = match(*w);
	}
	const uintptr_t pos = uintptr_t(w) + (__builtin_ctzl(m) >> 3);
	return pos < end ? pos - uintptr_t(base) : to;
}

[[gnu::always_inline]] static inline void copy_words(char* d, const char* s, size_t n)
{
	const uintptr_t dofs = uintptr_t(d) & ALIGN_MASK;
	aliased_word* dw = (aliased_word*) (uintptr_t(d) - dofs);
	aliased_word* const dlast = (aliased_word*) ((uintptr_t(d) + n - 1) & ~ALIGN_MASK);
	const uintptr_t src = uintptr_t(s) - dofs;
	const uintptr_t first = uintptr_t(s) & ~ALIGN_MASK;
	const uintptr_t last = (uintptr_t(s) + n - 1) & ~ALIGN_MASK;
	const word_t keep = (word_t(1) << (8 * dofs)) - 1;
	const unsigned shift = 8 * (src & ALIGN_MASK);
	const aliased_word* sw = (const aliased_word*) (src & ~ALIGN_MASK);
	if (shift == 0) {
		dw[0] = (dw[0] & keep) | (sw[0] & ~keep);
		while (dw != dlast)
			*++dw = *++sw;
		return;
	}
	word_t lo = (uintptr_t(sw) >= first) ? sw[0] : 0;
	word_t hi = (uintptr_t(sw + 1) <= last) ? sw[1] : 0;
	const word_t w = (lo >> shift) | (hi << (8 * WORD - shift));
	dw[0] = (dw[0] & keep) | (w & ~keep);
	if (dw == dlast)
		return;
	sw++;
	lo = hi;
	while (++dw != dlast) {
		hi = *++sw;
		*dw = (lo >> shift) | (hi << (8 * WORD - shift));
		lo = hi;
	}
	hi = (uintptr_t(sw + 1) <= last) ? sw[1] : 0;
	*dw = (lo >> shift) | (hi << (8 * WORD - shift));
}

struct Insert {
	const aliased_word* words = nullptr;
	size_t size = 0;
	size_t stride = 0;

	void assign(std::string_view s)
	{
		size = s.size();
		stride = (size + 2 * WORD - 1) / WORD;
		aliased_word* buf = (aliased_word*) std::malloc(WORD * stride * WORD);
		if (buf == nullptr)
			varnish::forge_response(500, "", 0, nullptr, 0);
		buf[stride - 1] = 0;
		copy_words((char*) buf, s.data(), size);
		for (size_t k = 1; k < WORD; k++) {
			aliased_word* slot = buf + k * stride;
			slot[0] = buf[0] << (8 * k);
			for (size_t i = 1; i < stride; i++)
				slot[i] = (buf[i] << (8 * k)) | (buf[i - 1] >> (8 * (WORD - k)));
		}
		words = buf;
	}

	[[gnu::always_inline]] void copy(char* d) const
	{
		const uintptr_t dofs = uintptr_t(d) & ALIGN_MASK;
		aliased_word* dw = (aliased_word*) (uintptr_t(d) - dofs);
		const aliased_word* sw = words + dofs * stride;
		const aliased_word* const send = sw + (dofs + size - 1) / WORD;
		const word_t keep = (word_t(1) << (8 * dofs)) - 1;
		dw[0] = (dw[0] & keep) | (sw[0] & ~keep);
		while (sw != send)
			*++dw = *++sw;
	}
};

struct Inserts {
	Insert query;   /* ?token=... */
	Insert bare;    /* token=... */
	Insert param;   /* &token=... (or &amp;token=...) */
	std::string_view viewer;
};

/* Copy unchanged input ranges in bulk and insert each token with one copy
   to reduce the number of guest memcpy calls during manifest rewriting. */
struct Output {
	char*  buf;
	size_t len;
	size_t cap;
};

struct Buffer {
	char*  buf;
	size_t cap;
};

[[gnu::noinline]] static Buffer grow(char* buf, size_t cap, size_t want)
{
	want = std::max(cap * 2, want);
	char* nbuf = (char*) std::realloc(buf, want);
	if (nbuf == nullptr)
		varnish::forge_response(500, "", 0, nullptr, 0);
	return {nbuf, want};
}

static bool starts_with_at(std::string_view in, size_t pos, std::string_view prefix)
{
	if (in.size() - pos < prefix.size())
		return false;
	for (size_t i = 0; i < prefix.size(); i++)
		if (in[pos + i] != prefix[i])
			return false;
	return true;
}

static bool is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

struct Rewriter {
	const char* base;
	size_t size;
	const Inserts* inserts;
	Output out;
	size_t copied;

	[[gnu::always_inline]] void reserve(size_t n)
	{
		if (out.len + n + WORD > out.cap) [[unlikely]] {
			const Buffer b = grow(out.buf, out.cap, out.len + n + WORD);
			out.buf = b.buf;
			out.cap = b.cap;
		}
	}

	[[gnu::always_inline]] void put(const char* s, size_t n)
	{
		reserve(n);
		if (n >= 256)
			std::memcpy(out.buf + out.len, s, n);
		else if (n > 0)
			copy_words(out.buf + out.len, s, n);
		out.len += n;
	}
	[[gnu::always_inline]] void put(std::string_view s) { put(s.data(), s.size()); }

	[[gnu::always_inline]] void put(const Insert& a)
	{
		reserve(a.size);
		a.copy(out.buf + out.len);
		out.len += a.size;
	}

	[[gnu::always_inline]] void copy_to(size_t pos)
	{
		put(base + copied, pos - copied);
		copied = pos;
	}

	/* Add the token to the URI in the input range [start, end).
	   Only HTTP(S) and relative URIs receive tokens; other schemes, such as
	   skd: and data:, remain unchanged. */
	[[gnu::always_inline]] void tokenize(size_t start, size_t end)
	{
		if (start >= end)
			return;
		size_t pos = scan(base, start, end, Bytes<'#', '?', '/', ':'> {});
		if (pos < end && base[pos] == ':') {
			const std::string_view scheme(base + start, pos - start);
			if (!((scheme.size() == 4 && ends_with_nocase(scheme, "http"))
				|| (scheme.size() == 5 && ends_with_nocase(scheme, "https"))))
				return;
		}
		if (pos < end && base[pos] != '#' && base[pos] != '?')
			pos = scan(base, pos + 1, end, Bytes<'#', '?'> {});
		const bool has_query = pos < end && base[pos] == '?';
		if (has_query)
			pos = scan(base, pos + 1, end, Bytes<'#'> {});
		copy_to(pos);
		if (!has_query)
			put(inserts->query);
		else if (base[pos - 1] == '?' || base[pos - 1] == '&')
			put(inserts->bare);
		else
			put(inserts->param);
	}
};

[[gnu::noinline]] static void tokenize_uri_attributes(Rewriter& r, size_t base, std::string_view line)
{
	const size_t quote = scan(line.data(), 0, line.size(), Bytes<'"'> {});
	if (quote == line.size() || line.find("URI=\"") == line.npos)
		return;
	size_t a = line.find(':');
	if (a == line.npos)
		return;
	for (a++; a < line.size(); ) {
		const size_t eq = line.find('=', a);
		if (eq == line.npos)
			return;
		const std::string_view name = line.substr(a, eq - a);
		size_t ve;
		if (eq + 1 < line.size() && line[eq + 1] == '"') {
			ve = line.find('"', eq + 2);
			if (ve == line.npos)
				return;
			if (name == "URI")
				r.tokenize(base + eq + 2, base + ve);
			ve = line.find(',', ve);
		} else {
			ve = line.find(',', eq + 1);
		}
		if (ve == line.npos)
			return;
		a = ve + 1;
	}
}

[[gnu::noinline]] static void insert_session_data(Rewriter& r, size_t pos, bool crlf)
{
	r.copy_to(pos);
	r.put("#EXT-X-SESSION-DATA:DATA-ID=\"");
	r.put(SESSION_DATA_ID);
	r.put("\",VALUE=\"");
	r.put(r.inserts->viewer);
	r.put(crlf ? "\"\r\n" : "\"\n");
}

static bool is_blank(char c)
{
	return c == ' ' || c == '\t';
}

[[gnu::noinline]] static Output rewrite_hls(const Rewriter& start)
{
	Rewriter r = start;
	const std::string_view in(r.base, r.size);
	const char* const base = r.base;
	const size_t size = in.size();
	bool session_data = false;
	size_t p = starts_with_at(in, 0, "\xEF\xBB\xBF") ? 3 : 0;
	while (p < size) {
		const size_t e = scan(base, p, size, Bytes<'\n'> {});
		size_t ts = p;
		while (ts < e && is_blank(base[ts]))
			ts++;
		if (ts < e && base[ts] == '#') {
			if (e - ts > 4 && base[ts + 4] == '-' && starts_with_at(in, ts, "#EXT-X-")) {
				const size_t n = (base[e - 1] == '\r') ? e - 1 : e;
				size_t te = n;
				while (te > ts && is_blank(base[te - 1]))
					te--;
				Rewriter cold = r;
				if (!session_data && starts_with_at(in, ts, "#EXT-X-STREAM-INF:")) {
					insert_session_data(cold, p, n < e);
					session_data = true;
				}
				tokenize_uri_attributes(cold, ts, in.substr(ts, te - ts));
				r = cold;
			}
		} else if (ts < e) {
			size_t te = (base[e - 1] == '\r') ? e - 1 : e;
			while (te > ts && is_blank(base[te - 1]))
				te--;
			r.tokenize(ts, te);
		}
		p = e + 1;
	}
	r.copy_to(size);
	return r.out;
}

static std::string_view local_name(std::string_view name)
{
	size_t start = 0;
	for (size_t colon; (colon = scan(name.data(), start, name.size(), Bytes<':'> {})) < name.size(); )
		start = colon + 1;
	return name.substr(start);
}

static size_t find_byte(std::string_view s, size_t from, char c)
{
	const size_t pos = scan(s.data(), from, s.size(), Byte {splat(c)});
	return pos < s.size() ? pos : s.npos;
}

enum class UriAttributes { None, SegmentTemplate, SegmentURL, SourceURL, XLink };

static UriAttributes uri_attributes(std::string_view element)
{
	if (element == "SegmentTemplate")
		return UriAttributes::SegmentTemplate;
	if (element == "SegmentURL")
		return UriAttributes::SegmentURL;
	if (element == "Initialization" || element == "RepresentationIndex"
		|| element == "BitstreamSwitching")
		return UriAttributes::SourceURL;
	if (element == "Period" || element == "AdaptationSet"
		|| element == "SegmentList" || element == "EventStream")
		return UriAttributes::XLink;
	return UriAttributes::None;
}

static bool is_uri_attribute(UriAttributes kind, std::string_view attr)
{
	switch (kind) {
	case UriAttributes::SegmentTemplate:
		return attr == "media" || attr == "initialization"
			|| attr == "index" || attr == "bitstreamSwitching";
	case UriAttributes::SegmentURL:
		return attr == "media" || attr == "index";
	case UriAttributes::SourceURL:
		return attr == "sourceURL";
	case UriAttributes::XLink:
		return attr != "href" && local_name(attr) == "href";
	default:
		return false;
	}
}

/* Rewrite URI attributes in SegmentTemplate, SegmentURL, Initialization,
   RepresentationIndex and BitstreamSwitching, xlink:href on Period,
   AdaptationSet, SegmentList and EventStream, plus Location, PatchLocation
   and ContentSteering text and BaseURL values that refer to files. */
[[gnu::noinline]] static Output rewrite_dash(const Rewriter& start)
{
	Rewriter r = start;
	const std::string_view in(r.base, r.size);
	const char* const base = r.base;
	const size_t size = r.size;
	size_t p = 0;
	while (p < in.size()) {
		const size_t start = scan(base, p, size, Bytes<'<'> {});
		if (start == size)
			break;
		if (starts_with_at(in, start, "<!--")) {
			const size_t end = in.find("-->", start + 4);
			p = (end == in.npos) ? in.size() : end + 3;
			continue;
		}
		const size_t end = scan(base, start, size, Bytes<'>'> {});
		if (end == size)
			break;
		const std::string_view tag = in.substr(start + 1, end - start - 1);
		p = end + 1;
		if (tag.empty() || tag[0] == '/' || tag[0] == '?' || tag[0] == '!')
			continue;

		const size_t name_end = scan(tag.data(), 0, tag.size(),
			Bytes<' ', '\t', '\r', '\n', '/'> {});
		const std::string_view name = local_name(tag.substr(0, name_end));

		const UriAttributes kind = uri_attributes(name);
		if (kind != UriAttributes::None)
		{
			size_t a = name_end;
			while (a < tag.size()) {
				const size_t eq = find_byte(tag, a, '=');
				if (eq == tag.npos)
					break;
				size_t ns = eq;
				while (ns > a && is_space(tag[ns - 1]))
					ns--;
				size_t nb = ns;
				while (nb > a && !is_space(tag[nb - 1]))
					nb--;
				const std::string_view attr = tag.substr(nb, ns - nb);
				size_t vq = eq + 1;
				while (vq < tag.size() && is_space(tag[vq]))
					vq++;
				if (vq >= tag.size() || (tag[vq] != '"' && tag[vq] != '\''))
					break;
				const size_t ve = find_byte(tag, vq + 1, tag[vq]);
				if (ve == tag.npos)
					break;
				if (is_uri_attribute(kind, attr))
					r.tokenize(start + 1 + vq + 1, start + 1 + ve);
				a = ve + 1;
			}
		} else if ((name == "BaseURL" || name == "Location" || name == "PatchLocation"
			|| name == "ContentSteering") && tag.back() != '/') {
			const size_t text_end = scan(base, end, size, Bytes<'<'> {});
			size_t ts = end + 1, te = text_end;
			while (ts < te && is_space(in[ts])) ts++;
			while (te > ts && is_space(in[te - 1])) te--;
			/* A BaseURL ending in / is a directory against which segment
			   URIs are resolved. Its query string would be discarded. */
			if (te > ts && (name != "BaseURL" || in[te - 1] != '/'))
				r.tokenize(ts, te);
			p = text_end;
		}
	}
	r.copy_to(in.size());
	return r.out;
}

static void personalize(const char* arg, const char* data, size_t len)
{
	const std::string_view token(arg);
	const size_t dot = token.find('.');
	bool valid = token.size() <= 128 && dot != token.npos && dot > 0;
	for (size_t i = 0; valid && i < token.size(); i++)
		valid = token_char(token[i]);
	if (!valid) {
		static constexpr std::string_view denied = "Missing or invalid viewer token";
		varnish::forge_response(403, "text/plain", 10, denied.data(), denied.size());
	}

	const std::string_view in(data, len);
	size_t s = 0;
	if (starts_with_at(in, 0, "\xEF\xBB\xBF"))
		s = 3;
	while (s < in.size() && is_space(in[s]))
		s++;
	const bool hls = starts_with_at(in, s, "#EXTM3U");
	if (!hls && !starts_with_at(in, s, "<"))
		varnish::forge_response(200, "", 0, data, len);

	std::string query = "?token=";
	query.append(token);
	std::string param = hls ? "&" : "&amp;";
	param.append(query, 1);
	Inserts inserts;
	inserts.query.assign(query);
	inserts.bare.assign(std::string_view(query).substr(1));
	inserts.param.assign(param);
	inserts.viewer = token.substr(0, dot);

	const size_t initial = len + std::min(len, size_t(1) << 20) + 4096;
	char* buf = (char*) std::malloc(initial);
	Rewriter r {data, len, &inserts, {buf, 0, buf ? initial : 0}, 0};
	const Output out = hls ? rewrite_hls(r) : rewrite_dash(r);
	varnish::forge_response(200, "", 0, out.buf, out.len);
}

static void on_recv(varnish::Request)
{
}

int main(int argc, char** argv)
{
	if (argc > 1 && argv[1][0] != '\0')
		hmac = varnish::HmacSha256(argv[1]);
	if (argc > 2) {
		const long secs = std::strtol(argv[2], nullptr, 10);
		if (secs > 0)
			lifetime = std::min(secs, MAX_LIFETIME);
	}
	varnish::register_function("authorize", authorize);
	varnish::register_transform("personalize", personalize);
	varnish::wait_for_requests(on_recv);
}
