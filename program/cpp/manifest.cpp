#include <api.h>
#include <sys/random.h>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include <cstring>
#include <ctime>
namespace varnish = api;

/* Personalize HLS and DASH manifests from a single cached copy.

   vcl_recv:    set req.http.X-Token = riscv.call("authorize", req.url);
   vcl_deliver: riscv.deliver_transform("personalize", req.http.X-Token);

   A manifest request without a token starts a session with a random viewer ID.
   Authorized manifest requests renew the session. Rewriting signs each
   supported manifest URI for the viewer, so a token is only valid for the
   path it was issued for. All other requests require a valid token. VCL
   removes the token from the URL before the cache lookup, so all viewers
   share one cached copy of each object.

   Token:    <viewer id>.<expires>.<HMAC-SHA256/128 of "<viewer id>.<expires>\n<path>">
   Template: <viewer id>.<expires>.<P>.<S>.<HMAC of "<viewer id>.<expires>.<P>.<S>\n<prefix><slashes><suffix>">
             DASH SegmentTemplate URIs sign the P bytes before the first $
             and the S bytes after the last $ of the resolved path, plus
             the / characters between them. Template tokens are not valid
             for manifests.
   authorize returns a token for the manifest path, which personalize
   verifies against req.url before signing anything with it.
   Tenant arguments: [secret, session lifetime in seconds]. */
static varnish::HmacSha256 hmac {"change-me-varnish-manifest-secret"};
static long lifetime = 300;

static constexpr std::string_view SESSION_DATA_ID = "com.varnish.viewer-id";
static constexpr size_t VIEWER_ID_BYTES = 12;
static constexpr size_t MAC_BYTES = 16;
static constexpr long MAX_LIFETIME = 10L * 365 * 24 * 3600;

static constexpr size_t base64url_size(size_t n)
{
	return (4 * n + 2) / 3;
}
static constexpr size_t MAC_CHARS = base64url_size(MAC_BYTES);

[[gnu::always_inline]] static inline void base64url_encode(const uint8_t* d, size_t n, char* out)
{
	static constexpr char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t i = 0;
	for (; i + 3 <= n; i += 3) {
		const uint32_t v = (d[i] << 16) | (d[i + 1] << 8) | d[i + 2];
		*out++ = alphabet[(v >> 18) & 63];
		*out++ = alphabet[(v >> 12) & 63];
		*out++ = alphabet[(v >> 6) & 63];
		*out++ = alphabet[v & 63];
	}
	if (n - i == 1) {
		*out++ = alphabet[d[i] >> 2];
		*out++ = alphabet[(d[i] & 3) << 4];
	} else if (n - i == 2) {
		const uint32_t v = (d[i] << 8) | d[i + 1];
		*out++ = alphabet[v >> 10];
		*out++ = alphabet[(v >> 4) & 63];
		*out++ = alphabet[(v & 15) << 2];
	}
}

static void encode_mac(const std::array<uint8_t, 32>& digest, char* out)
{
	base64url_encode(digest.data(), MAC_BYTES, out);
}

static bool viewer_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		|| (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static std::string slashes_in(std::string_view s)
{
	return std::string(std::count(s.begin(), s.end(), '/'), '/');
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

static std::optional<std::string_view> verify(std::string_view token, std::string_view path, long now)
{
	if (token.size() > 128)
		return std::nullopt;
	std::array<std::string_view, 5> part;
	size_t n = 0, p = 0;
	while (true) {
		if (n == part.size())
			return std::nullopt;
		const size_t dot = token.find('.', p);
		part[n++] = token.substr(p, dot == token.npos ? token.npos : dot - p);
		if (dot == token.npos)
			break;
		p = dot + 1;
	}
	long expires;
	if ((n != 3 && n != 5) || part[0].empty() || !parse_number(part[1], expires) || now >= expires)
		return std::nullopt;
	if (!std::all_of(part[0].begin(), part[0].end(), viewer_char))
		return std::nullopt;

	const std::string_view mac = part[n - 1];
	const std::string_view signed_part = token.substr(0, token.size() - mac.size() - 1);
	std::array<uint8_t, 32> digest;
	if (n == 3) {
		digest = hmac({signed_part, "\n", path});
	} else {
		long prefix, suffix;
		if (is_manifest(path) || !parse_number(part[2], prefix) || !parse_number(part[3], suffix)
			|| size_t(prefix) > path.size() || size_t(suffix) > path.size() - prefix)
			return std::nullopt;
		const std::string slashes = slashes_in(path.substr(prefix, path.size() - prefix - suffix));
		digest = hmac({signed_part, "\n", path.substr(0, prefix), slashes,
			path.substr(path.size() - suffix)});
	}
	char expected[MAC_CHARS];
	encode_mac(digest, expected);
	if (!varnish::equal_constant_time(mac, {expected, MAC_CHARS}))
		return std::nullopt;
	return part[0];
}

/* Return a new or renewed token for a manifest, the verified token for
   anything else, or nullptr if authorization fails. */
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

	char id[base64url_size(VIEWER_ID_BYTES)];
	std::string_view viewer;
	if (token.empty()) {
		if (!manifest)
			return nullptr;
		std::array<uint8_t, VIEWER_ID_BYTES> bytes;
		if (getrandom(bytes.data(), bytes.size(), 0) != (ssize_t) bytes.size())
			return nullptr;
		base64url_encode(bytes.data(), bytes.size(), id);
		viewer = {id, sizeof(id)};
	} else {
		const auto verified = verify(token, path, now);
		if (!verified)
			return nullptr;
		if (!manifest) {
			result = token;
			return result.c_str();
		}
		viewer = *verified;
	}
	result = viewer;
	result += '.';
	result += std::to_string(now + lifetime);
	char mac[MAC_CHARS];
	encode_mac(hmac({result, "\n", path}), mac);
	result += '.';
	result.append(mac, MAC_CHARS);
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

struct Uri {
	size_t path_start;
	size_t path_end;
	bool authority;
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

/* Copy unchanged input ranges in bulk and insert each token with one copy
   to reduce the number of guest memcpy calls during manifest rewriting. */
struct Output {
	char*  buf = nullptr;
	size_t len = 0;
	size_t cap = 0;

	[[gnu::always_inline]] void reserve(size_t n)
	{
		if (len + n + WORD > cap) [[unlikely]] {
			const Buffer b = grow(buf, cap, len + n + WORD);
			buf = b.buf;
			cap = b.cap;
		}
	}
	[[gnu::always_inline]] void put(const char* s, size_t n)
	{
		reserve(n);
		if (n >= 256)
			std::memcpy(buf + len, s, n);
		else if (n > 0)
			copy_words(buf + len, s, n);
		len += n;
	}
	[[gnu::always_inline]] void put(std::string_view s) { put(s.data(), s.size()); }
	[[gnu::always_inline]] void push(char c)
	{
		reserve(1);
		buf[len++] = c;
	}
	std::string_view view(size_t from = 0) const { return {buf + from, len - from}; }
};

static bool has_dot_segment(std::string_view ref)
{
	size_t pos = 0;
	while ((pos = scan(ref.data(), pos, ref.size(), Bytes<'.'> {})) < ref.size()) {
		if (pos == 0 || ref[pos - 1] == '/')
			return true;
		pos++;
	}
	return false;
}

static size_t remove_dot_segments(char* p, size_t n)
{
	size_t w = 0, r = 0;
	while (r < n) {
		size_t e = r + 1;
		while (e < n && p[e] != '/')
			e++;
		const char* seg = p + r + 1;
		const size_t len = e - r - 1;
		if (len == 1 && seg[0] == '.') {
			if (e == n)
				p[w++] = '/';
		} else if (len == 2 && seg[0] == '.' && seg[1] == '.') {
			while (w > 0 && p[--w] != '/') {}
			if (e == n)
				p[w++] = '/';
		} else {
			for (size_t i = r; i < e; i++)
				p[w++] = p[i];
		}
		r = e;
	}
	return w;
}

struct Signer {
	std::string_view session;
	std::string_view doc;
	std::string_view dir;
	Output msg;
	size_t head;
	char token[64];
	size_t token_len;

	explicit Signer(std::string_view s) : session(s)
	{
		msg.put(session);
		msg.push('\n');
		head = msg.len;
	}

	void set_base(std::string_view path)
	{
		doc = path;
		dir = path.substr(0, path.rfind('/') + 1);
	}

	std::string_view path() const { return msg.view(head); }

	void resolve(std::string_view ref, bool authority)
	{
		msg.len = head;
		if (ref.empty()) {
			msg.put(authority ? std::string_view("/") : doc);
		} else {
			if (ref[0] != '/')
				msg.put(dir);
			msg.put(ref);
			if (has_dot_segment(ref))
				msg.len = head + remove_dot_segments(msg.buf + head, msg.len - head);
		}
	}

	void sign(std::string_view ref, bool authority, bool templ)
	{
		resolve(ref, authority);
		const std::string_view path = this->path();
		const size_t first = templ ? path.find('$') : path.npos;
		if (first == path.npos) {
			encode_mac(hmac({msg.view()}), token);
			token_len = MAC_CHARS;
			return;
		}
		const size_t last = path.rfind('$');
		const size_t suffix = path.size() - last - 1;
		std::string fields = std::to_string(first);
		fields += '.';
		fields += std::to_string(suffix);
		const std::string slashes = slashes_in(path.substr(first, last + 1 - first));
		encode_mac(hmac({session, ".", fields, "\n", path.substr(0, first), slashes,
			path.substr(last + 1)}), token + fields.size() + 1);
		std::memcpy(token, fields.data(), fields.size());
		token[fields.size()] = '.';
		token_len = fields.size() + 1 + MAC_CHARS;
	}
};

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
	Signer* signer;
	Output out;
	size_t copied;

	[[gnu::always_inline]] void put(const char* s, size_t n) { out.put(s, n); }
	[[gnu::always_inline]] void put(std::string_view s) { out.put(s); }

	[[gnu::always_inline]] void put(const Insert& a)
	{
		out.reserve(a.size);
		a.copy(out.buf + out.len);
		out.len += a.size;
	}

	[[gnu::always_inline]] void copy_to(size_t pos)
	{
		put(base + copied, pos - copied);
		copied = pos;
	}

	[[gnu::always_inline]] std::optional<Uri> parse(size_t start, size_t end) const
	{
		if (start >= end)
			return std::nullopt;
		const size_t pos = scan(base, start, end, Bytes<'#', '?', '/', ':'> {});
		Uri uri {start, 0, false};
		if (pos < end && base[pos] == ':') {
			const std::string_view scheme(base + start, pos - start);
			if (!((scheme.size() == 4 && ends_with_nocase(scheme, "http"))
				|| (scheme.size() == 5 && ends_with_nocase(scheme, "https"))))
				return std::nullopt;
			uri.path_start = pos + 1;
		}
		if (end - uri.path_start >= 2 && base[uri.path_start] == '/' && base[uri.path_start + 1] == '/') {
			uri.path_start = scan(base, uri.path_start + 2, end, Bytes<'/', '?', '#'> {});
			uri.authority = true;
		}
		uri.path_end = scan(base, uri.path_start, end, Bytes<'#', '?'> {});
		return uri;
	}

	[[gnu::always_inline]] bool resolve(size_t start, size_t end)
	{
		const auto uri = parse(start, end);
		if (uri)
			signer->resolve({base + uri->path_start, uri->path_end - uri->path_start}, uri->authority);
		return uri.has_value();
	}

	/* Sign the URI in the input range [start, end) for the viewer, leaving
	   its resolved path in the signer. Only HTTP(S) and relative URIs
	   receive tokens; other schemes, such as skd: and data:, remain unchanged. */
	[[gnu::always_inline]] bool tokenize(size_t start, size_t end, bool templ = false)
	{
		const auto uri = parse(start, end);
		if (!uri)
			return false;
		signer->sign({base + uri->path_start, uri->path_end - uri->path_start}, uri->authority, templ);
		size_t pos = uri->path_end;
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
		put(signer->token, signer->token_len);
		return true;
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
	struct Base {
		long level;
		std::string doc;
	};
	std::vector<Base> bases;
	bases.push_back({0, std::string(r.signer->doc)});
	long depth = 0;
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
		if (!tag.empty() && tag[0] == '/') {
			depth--;
			if (bases.back().level > depth) {
				while (bases.size() > 1 && bases.back().level > depth)
					bases.pop_back();
				r.signer->set_base(bases.back().doc);
			}
			continue;
		}
		if (tag.empty() || tag[0] == '?' || tag[0] == '!')
			continue;
		const bool open = tag.back() != '/';

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
					r.tokenize(start + 1 + vq + 1, start + 1 + ve,
						kind == UriAttributes::SegmentTemplate);
				a = ve + 1;
			}
		} else if ((name == "BaseURL" || name == "Location" || name == "PatchLocation"
			|| name == "ContentSteering") && open) {
			const size_t text_end = scan(base, end, size, Bytes<'<'> {});
			size_t ts = end + 1, te = text_end;
			while (ts < te && is_space(in[ts])) ts++;
			while (te > ts && is_space(in[te - 1])) te--;
			/* A BaseURL ending in / is a directory against which segment
			   URIs are resolved. Its query string would be discarded. */
			const bool directory = name == "BaseURL" && te > ts && in[te - 1] == '/';
			const bool resolved = directory ? r.resolve(ts, te) : r.tokenize(ts, te);
			if (name == "BaseURL" && resolved) {
				const std::string_view path = r.signer->path();
				if (bases.back().level < depth) {
					bases.push_back({depth, std::string(path)});
					r.signer->set_base(bases.back().doc);
				} else if (directory && path != r.signer->dir && starts_with_at(in, text_end, "</")) {
					size_t after = scan(base, text_end, size, Bytes<'>'> {});
					if (after < size) {
						after++;
						while (after < size && is_space(in[after]))
							after++;
						r.copy_to(start);
						r.copied = after;
						p = after;
						continue;
					}
				}
			}
			p = text_end;
		}
		if (open)
			depth++;
	}
	r.copy_to(in.size());
	return r.out;
}

static void personalize(const char* arg, const char* data, size_t len)
{
	const std::string url = varnish::Request(varnish::HDR_REQ).url();
	const std::string_view path = std::string_view(url).substr(0, url.find('?'));
	const std::string_view token(arg);
	if (!path_safe(path) || !is_manifest(path) || !verify(token, path, std::time(nullptr))) {
		static constexpr std::string_view denied = "Missing or invalid viewer token";
		varnish::forge_response(403, "text/plain", 10, denied.data(), denied.size());
	}
	const std::string_view session = token.substr(0, token.rfind('.'));

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
	query.append(session);
	query += '.';
	std::string param = hls ? "&" : "&amp;";
	param.append(query, 1);
	Inserts inserts;
	inserts.query.assign(query);
	inserts.bare.assign(std::string_view(query).substr(1));
	inserts.param.assign(param);
	inserts.viewer = session.substr(0, session.find('.'));
	Signer signer {session};
	signer.set_base(path);

	const size_t initial = len + std::min(len, size_t(1) << 20) + 4096;
	char* buf = (char*) std::malloc(initial);
	Rewriter r {data, len, &inserts, &signer, {buf, 0, buf ? initial : 0}, 0};
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
