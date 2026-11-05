#include <api.h>
#include <nlohmann/json.hpp>
#include <sys/random.h>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include <cstring>
#include <ctime>
namespace varnish = api;
using json = nlohmann::json;

/* Personalize HLS and DASH manifests from a single cached copy.

   vcl_recv:    set req.http.X-Client-IP = client.ip;
                set req.http.X-Token = riscv.call("authorize", req.url);
                set req.http.X-Variant = riscv.call("watermark", req.http.X-Token);
   vcl_deliver: riscv.deliver_transform("personalize", req.http.X-Token);

   A session starts with a manifest request that carries an entitlement
   from the subscriber's authentication service: an HS256 JWT in the auth
   parameter, with required sub and exp claims. An optional path claim
   restricts access to manifest paths that start with that prefix.
   Rewriting signs each supported manifest URI for the session, so a token
   is only valid for the path it was issued for. All other requests require
   a valid token. VCL removes the auth and token parameters from the URL
   before the cache lookup, so all viewers share one cached copy of each object.

   Token:    <key id>.<subscriber>.<session>.<expires>.<HMAC-SHA256/128 of
             "<key id>.<subscriber>.<session>.<expires>\n<network>\n<padding><path>">
   Template: <key id>.<subscriber>.<session>.<expires>.<P>.<S>.<HMAC of
             "<key id>.<subscriber>.<session>.<expires>.<P>.<S>\n<network>\n<padding><prefix><slashes><suffix>">
             Newline padding brings the preceding text to a multiple of 64
             bytes, allowing that prefix to be hashed once per manifest.
             DASH SegmentTemplate URIs sign the P bytes before the first $
             and the S bytes after the last $ of the resolved path, plus
             the / characters between them. Template tokens are not valid
             for manifests.
   The subscriber pseudonym is the first 12 bytes of an HMAC of the sub
   claim using subscriber_key. The session ID consists of 12 random bytes.
   Both are base64url-encoded. Manifest URIs expire with the session.
   Segment URIs in live playlists expire after the segment lifetime or
   when the session expires, whichever comes first, and are renewed on
   every playlist refresh. Segment URIs in VOD playlists (ending in
   EXT-X-ENDLIST) and static MPDs expire with the session. The network is
   the client address in X-Client-IP, masked to the configured prefix length,
   or empty when bind_network is not configured.

   watermark selects the A/B variant of the requested path for the session
   for forensic watermarking at the edge. Let d = HMAC-SHA256 of the path
   using watermark_key, and i = big-endian(d[0..3]) % 96. Using zero-based
   indices, take bit i % 6 of the numeric base64url value of session ID
   character i / 6, then XOR it with the low bit of d[4]. A result of 0
   selects A; 1 selects B.

   Config files:
     settings     JSON: keys (key IDs mapped to URL signing secrets), signing_key
                  (the ID of the key used to sign new tokens), entitlement_keys
                  (key IDs mapped to HS256 secrets; the JWT kid header must
                  identify the signing key if multiple keys are configured),
                  subscriber_key, watermark_key (optional),
                  session_lifetime (default 21600), segment_lifetime
                  (default 120), bind_network (optional, {"ipv4": 24, "ipv6": 48})
     revocations  Optional. Subscriber IDs (sub claims) and session IDs, one per
                  line. Blank lines and lines starting with # are ignored. */
struct Key {
	std::string id;
	varnish::HmacSha256 hmac;
};
static std::vector<Key> keys;
static const Key* signing = nullptr;
static std::vector<Key> entitlement_keys;
static std::optional<varnish::HmacSha256> subscriber_hmac;
static std::optional<varnish::HmacSha256> watermark_hmac;
static long session_lifetime = 6 * 3600;
static long segment_lifetime = 120;
static int bind_ipv4 = 0;
static int bind_ipv6 = 0;
static std::vector<std::string> revoked;

static constexpr std::string_view SESSION_DATA_ID = "com.varnish.viewer-id";
static constexpr size_t ID_BYTES = 12;
static constexpr size_t MAC_BYTES = 16;
static constexpr size_t MAX_KEY_ID = 16;
static constexpr size_t MAX_TOKEN = 160;
static constexpr long MAX_LIFETIME = 10L * 365 * 24 * 3600;
static constexpr unsigned B64URL = BASE64_FLAG_URL | BASE64_FLAG_NOPAD;

static constexpr size_t base64url_size(size_t n)
{
	return (4 * n + 2) / 3;
}
static constexpr size_t MAC_CHARS = base64url_size(MAC_BYTES);
static constexpr size_t ID_CHARS = base64url_size(ID_BYTES);
static constexpr char alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

[[gnu::always_inline]] static inline void base64url_encode(const uint8_t* d, size_t n, char* out)
{
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

static bool id_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		|| (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static bool valid_id(std::string_view s, size_t min, size_t max)
{
	return s.size() >= min && s.size() <= max && std::all_of(s.begin(), s.end(), id_char);
}

static int base64url_value(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	return c == '-' ? 62 : 63;
}

static std::string slashes_in(std::string_view s)
{
	return std::string(std::count(s.begin(), s.end(), '/'), '/');
}

static std::string_view padding(size_t len)
{
	static constexpr char newlines[64] = {
		'\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',
		'\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',
		'\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',
		'\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n'};
	return {newlines, (64 - len % 64) % 64};
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

static std::string_view as_view(const std::array<uint8_t, 32>& digest)
{
	return {(const char*) digest.data(), digest.size()};
}

static std::string pseudonym(std::string_view subject)
{
	const auto digest = (*subscriber_hmac)({"subscriber\n", subject});
	std::string out(ID_CHARS, '\0');
	base64url_encode(digest.data(), ID_BYTES, out.data());
	return out;
}

static bool is_revoked(std::string_view id)
{
	return std::binary_search(revoked.begin(), revoked.end(), id, std::less<> {});
}

static const Key* find_key(const std::vector<Key>& ring, std::string_view id)
{
	for (const auto& key : ring)
		if (key.id == id)
			return &key;
	return nullptr;
}

static bool parse_ipv4(std::string_view s, uint8_t* out)
{
	for (int i = 0; i < 4; i++) {
		const size_t dot = (i < 3) ? s.find('.') : s.size();
		if (dot == s.npos || dot == 0 || dot > 3)
			return false;
		long v;
		if (!parse_number(s.substr(0, dot), v) || v > 255 || (dot > 1 && s[0] == '0'))
			return false;
		out[i] = v;
		s.remove_prefix(i < 3 ? dot + 1 : dot);
	}
	return s.empty();
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static bool parse_ipv6(std::string_view s, uint8_t* out)
{
	std::array<uint16_t, 8> groups {};
	int n = 0, gap = -1;
	if (s.starts_with("::")) {
		gap = 0;
		s.remove_prefix(2);
	}
	while (!s.empty()) {
		const size_t colon = s.find(':');
		const std::string_view group = s.substr(0, colon);
		if (colon == s.npos && group.find('.') != group.npos) {
			uint8_t v4[4];
			if (n > 6 || !parse_ipv4(group, v4))
				return false;
			groups[n++] = (v4[0] << 8) | v4[1];
			groups[n++] = (v4[2] << 8) | v4[3];
			break;
		}
		if (n == 8 || group.empty() || group.size() > 4)
			return false;
		uint16_t v = 0;
		for (const char c : group) {
			const int h = hex_value(c);
			if (h < 0)
				return false;
			v = (v << 4) | h;
		}
		groups[n++] = v;
		if (colon == s.npos)
			break;
		s.remove_prefix(colon + 1);
		if (s.starts_with(":")) {
			if (gap >= 0)
				return false;
			gap = n;
			s.remove_prefix(1);
		} else if (s.empty()) {
			return false;
		}
	}
	if (gap < 0 ? n != 8 : n > 7)
		return false;
	std::array<uint16_t, 8> full {};
	const int head = gap < 0 ? n : gap;
	for (int i = 0; i < head; i++)
		full[i] = groups[i];
	for (int i = head; i < n; i++)
		full[8 - (n - i)] = groups[i];
	for (int i = 0; i < 8; i++) {
		out[2 * i] = full[i] >> 8;
		out[2 * i + 1] = full[i] & 0xFF;
	}
	return true;
}

static constexpr size_t TAIL_MAX = 48;

static std::optional<std::string_view> network_tail(char* buf)
{
	if (bind_ipv4 == 0 && bind_ipv6 == 0)
		return std::string_view("\n\n");
	const auto field = varnish::Request(varnish::HDR_REQ).find("X-Client-IP");
	if (!field)
		return std::nullopt;
	const std::string address = field.value();
	uint8_t bytes[16];
	int bits;
	char family;
	if (parse_ipv4(address, bytes)) {
		bits = bind_ipv4;
		family = '4';
	} else if (parse_ipv6(address, bytes)) {
		bits = bind_ipv6;
		family = '6';
	} else {
		return std::nullopt;
	}
	if (bits == 0)
		return std::string_view("\n\n");
	char* p = buf;
	*p++ = '\n';
	*p++ = family;
	*p++ = '/';
	if (bits >= 100)
		*p++ = '0' + bits / 100;
	if (bits >= 10)
		*p++ = '0' + bits / 10 % 10;
	*p++ = '0' + bits % 10;
	*p++ = '/';
	for (int i = 0; 8 * i < bits; i++) {
		const int keep = std::min(8, bits - 8 * i);
		const uint8_t b = bytes[i] & uint8_t(0xFF << (8 - keep));
		*p++ = "0123456789abcdef"[b >> 4];
		*p++ = "0123456789abcdef"[b & 15];
	}
	*p++ = '\n';
	return std::string_view(buf, p - buf);
}

struct Session {
	std::string_view subscriber;
	std::string_view id;
	long expires;
};

static std::optional<Session> verify(std::string_view token, std::string_view path,
	long now, std::string_view tail)
{
	if (token.size() > MAX_TOKEN)
		return std::nullopt;
	std::array<std::string_view, 7> part;
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
	if ((n != 5 && n != 7) || !parse_number(part[3], expires) || now >= expires)
		return std::nullopt;
	if (!valid_id(part[1], ID_CHARS, ID_CHARS) || !valid_id(part[2], ID_CHARS, ID_CHARS))
		return std::nullopt;
	const Key* key = find_key(keys, part[0]);
	if (key == nullptr)
		return std::nullopt;

	const std::string_view mac = part[n - 1];
	const std::string_view signed_part = token.substr(0, token.size() - mac.size() - 1);
	std::array<uint8_t, 32> digest;
	if (n == 5) {
		digest = key->hmac({signed_part, tail, padding(signed_part.size() + tail.size()), path});
	} else {
		long prefix, suffix;
		if (is_manifest(path) || !parse_number(part[4], prefix) || !parse_number(part[5], suffix)
			|| size_t(prefix) > path.size() || size_t(suffix) > path.size() - prefix)
			return std::nullopt;
		const std::string slashes = slashes_in(path.substr(prefix, path.size() - prefix - suffix));
		digest = key->hmac({signed_part, tail, padding(signed_part.size() + tail.size()),
			path.substr(0, prefix), slashes, path.substr(path.size() - suffix)});
	}
	char expected[MAC_CHARS];
	encode_mac(digest, expected);
	if (!varnish::equal_constant_time(mac, {expected, MAC_CHARS}))
		return std::nullopt;
	return Session {part[1], part[2], expires};
}

static const json* member(const json& obj, const char* key)
{
	const auto it = obj.find(key);
	return it != obj.end() ? &*it : nullptr;
}

static bool header_safe(std::string_view text)
{
	if (text.empty() || text.size() > 256)
		return false;
	for (const unsigned char c : text)
		if (c < 0x20 || c == 0x7f)
			return false;
	return true;
}

static std::optional<std::string> entitlement(std::string_view jwt, std::string_view path, long now)
{
	if (jwt.size() > 4096)
		return std::nullopt;
	const size_t dot1 = jwt.find('.');
	if (dot1 == jwt.npos)
		return std::nullopt;
	const size_t dot2 = jwt.find('.', dot1 + 1);
	if (dot2 == jwt.npos || jwt.find('.', dot2 + 1) != jwt.npos)
		return std::nullopt;

	const auto signature = varnish::base64_decode(jwt.substr(dot2 + 1), B64URL);
	if (!signature)
		return std::nullopt;
	const Key* key = nullptr;
	for (const auto& candidate : entitlement_keys) {
		if (varnish::equal_constant_time(*signature, as_view(candidate.hmac(jwt.substr(0, dot2))))) {
			key = &candidate;
			break;
		}
	}
	if (key == nullptr)
		return std::nullopt;

	const auto header = varnish::base64_decode(jwt.substr(0, dot1), B64URL);
	const auto payload = varnish::base64_decode(jwt.substr(dot1 + 1, dot2 - dot1 - 1), B64URL);
	if (!header || !payload)
		return std::nullopt;
	const json hdr = json::parse(*header, nullptr, false);
	if (!hdr.is_object())
		return std::nullopt;
	const json* alg = member(hdr, "alg");
	if (!alg || !alg->is_string() || alg->get_ref<const std::string&>() != "HS256")
		return std::nullopt;
	const json* kid = member(hdr, "kid");
	if (kid ? (!kid->is_string() || kid->get_ref<const std::string&>() != key->id)
		: entitlement_keys.size() != 1)
		return std::nullopt;

	const json claims = json::parse(*payload, nullptr, false);
	if (!claims.is_object())
		return std::nullopt;
	const json* exp = member(claims, "exp");
	if (!exp || !exp->is_number() || now >= exp->get<double>())
		return std::nullopt;
	const json* nbf = member(claims, "nbf");
	if (nbf && (!nbf->is_number() || now < nbf->get<double>()))
		return std::nullopt;
	const json* scope = member(claims, "path");
	if (scope && (!scope->is_string() || !path.starts_with(scope->get_ref<const std::string&>())))
		return std::nullopt;
	const json* sub = member(claims, "sub");
	if (!sub || !sub->is_string() || !header_safe(sub->get_ref<const std::string&>()))
		return std::nullopt;
	return sub->get<std::string>();
}

/* Return the existing token if it is valid, or issue a new token for a
   manifest request with a valid entitlement. Return nullptr on failure. */
static const char* authorize(const char* arg, size_t len)
{
	static std::string result;
	const std::string_view url(arg, len);
	const size_t q = url.find('?');
	const std::string_view path = url.substr(0, q);
	if (!path_safe(path))
		return nullptr;
	const std::string_view query = (q != url.npos) ? url.substr(q + 1) : std::string_view{};
	const std::string_view token = query_param(query, "token");
	const long now = std::time(nullptr);
	char network[TAIL_MAX];
	const auto tail = network_tail(network);
	if (!tail)
		return nullptr;

	if (!token.empty()) {
		const auto session = verify(token, path, now, *tail);
		if (!session || is_revoked(session->subscriber) || is_revoked(session->id))
			return nullptr;
		result = token;
		return result.c_str();
	}
	if (!is_manifest(path))
		return nullptr;
	const auto subject = entitlement(query_param(query, "auth"), path, now);
	if (!subject)
		return nullptr;
	const std::string subscriber = pseudonym(*subject);
	if (is_revoked(subscriber))
		return nullptr;
	std::array<uint8_t, ID_BYTES> bytes;
	if (getrandom(bytes.data(), bytes.size(), 0) != (ssize_t) bytes.size())
		return nullptr;
	char id[ID_CHARS];
	base64url_encode(bytes.data(), bytes.size(), id);

	result = signing->id;
	result += '.';
	result += subscriber;
	result += '.';
	result.append(id, ID_CHARS);
	result += '.';
	result += std::to_string(now + session_lifetime);
	char mac[MAC_CHARS];
	encode_mac(signing->hmac({result, *tail, padding(result.size() + tail->size()), path}), mac);
	result += '.';
	result.append(mac, MAC_CHARS);
	varnish::log("Session {} for subscriber {}", std::string_view(id, ID_CHARS), *subject);
	return result.c_str();
}

static const char* watermark(const char* arg, size_t len)
{
	if (!watermark_hmac)
		return nullptr;
	const std::string_view token(arg, len);
	const size_t a = token.find('.');
	const size_t b = (a == token.npos) ? a : token.find('.', a + 1);
	const size_t c = (b == token.npos) ? b : token.find('.', b + 1);
	if (c == token.npos || c - b - 1 != ID_CHARS)
		return nullptr;
	const std::string_view session = token.substr(b + 1, ID_CHARS);
	const std::string url = varnish::Request(varnish::HDR_REQ).url();
	const auto d = (*watermark_hmac)(std::string_view(url).substr(0, url.find('?')));
	const uint32_t index = ((uint32_t(d[0]) << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) % (8 * ID_BYTES);
	const int bit = ((base64url_value(session[index / 6]) >> (index % 6)) ^ d[4]) & 1;
	return bit ? "B" : "A";
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

struct TokenInserts {
	Insert query;   /* ?token=... */
	Insert bare;    /* token=... */
	Insert param;   /* &token=... (or &amp;token=...) */

	void assign(std::string_view session, bool hls)
	{
		std::string q = "?token=";
		q.append(session);
		q += '.';
		std::string p = hls ? "&" : "&amp;";
		p.append(q, 1);
		query.assign(q);
		bare.assign(std::string_view(q).substr(1));
		param.assign(p);
	}
};

struct Inserts {
	TokenInserts segment;
	TokenInserts manifest;
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
	const varnish::HmacSha256* hmac;
	varnish::HmacSha256 segment_hmac;
	std::string_view session;
	std::string_view manifest;
	std::string_view tail;
	std::string_view doc;
	std::string_view dir;
	Output msg;
	size_t head = 0;
	char token[64];
	size_t token_len;

	Signer(const varnish::HmacSha256& h, std::string_view padded_session,
		std::string_view s, std::string_view m, std::string_view t)
		: hmac(&h), segment_hmac(h.with_prefix(padded_session)), session(s), manifest(m), tail(t)
	{
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

	void sign(std::string_view ref, bool authority, bool templ, bool for_manifest)
	{
		resolve(ref, authority);
		const std::string_view path = this->path();
		const size_t first = templ ? path.find('$') : path.npos;
		if (first == path.npos) {
			if (for_manifest)
				encode_mac((*hmac)({manifest, tail, padding(manifest.size() + tail.size()), path}), token);
			else
				encode_mac(segment_hmac({path}), token);
			token_len = MAC_CHARS;
			return;
		}
		const size_t last = path.rfind('$');
		const size_t suffix = path.size() - last - 1;
		std::string fields = std::to_string(first);
		fields += '.';
		fields += std::to_string(suffix);
		const std::string slashes = slashes_in(path.substr(first, last + 1 - first));
		encode_mac((*hmac)({session, ".", fields, tail,
			padding(session.size() + 1 + fields.size() + tail.size()),
			path.substr(0, first), slashes, path.substr(last + 1)}), token + fields.size() + 1);
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
	[[gnu::always_inline]] bool tokenize(size_t start, size_t end, bool templ = false,
		bool for_manifest = false)
	{
		const auto uri = parse(start, end);
		if (!uri)
			return false;
		signer->sign({base + uri->path_start, uri->path_end - uri->path_start}, uri->authority,
			templ, for_manifest);
		const TokenInserts& ins = for_manifest ? inserts->manifest : inserts->segment;
		size_t pos = uri->path_end;
		const bool has_query = pos < end && base[pos] == '?';
		if (has_query)
			pos = scan(base, pos + 1, end, Bytes<'#'> {});
		copy_to(pos);
		if (!has_query)
			put(ins.query);
		else if (base[pos - 1] == '?' || base[pos - 1] == '&')
			put(ins.bare);
		else
			put(ins.param);
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
			if (name == "URI" && r.resolve(base + eq + 2, base + ve))
				r.tokenize(base + eq + 2, base + ve, false, is_manifest(r.signer->path()));
			ve = line.find(',', ve);
		} else {
			ve = line.find(',', eq + 1);
		}
		if (ve == line.npos)
			return;
		a = ve + 1;
	}
}

[[gnu::noinline]] static bool tokenize_playlist(Rewriter& r, size_t ts, size_t te)
{
	return r.tokenize(ts, te, false, true);
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
	bool playlist_next = false;
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
				if (starts_with_at(in, ts, "#EXT-X-STREAM-INF:")) {
					if (!session_data)
						insert_session_data(cold, p, n < e);
					session_data = true;
					playlist_next = true;
				}
				tokenize_uri_attributes(cold, ts, in.substr(ts, te - ts));
				r = cold;
			}
		} else if (ts < e) {
			size_t te = (base[e - 1] == '\r') ? e - 1 : e;
			while (te > ts && is_blank(base[te - 1]))
				te--;
			if (playlist_next) [[unlikely]] {
				Rewriter cold = r;
				tokenize_playlist(cold, ts, te);
				r = cold;
				playlist_next = false;
			} else {
				r.tokenize(ts, te);
			}
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
				if (!is_uri_attribute(kind, attr))
					;
				else if (kind == UriAttributes::XLink)
					tokenize_playlist(r, start + 1 + vq + 1, start + 1 + ve);
				else
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
			const bool resolved = directory ? r.resolve(ts, te)
				: name == "BaseURL" ? r.tokenize(ts, te) : tokenize_playlist(r, ts, te);
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

static bool hls_ended(std::string_view in)
{
	size_t e = in.size();
	while (e > 0 && is_space(in[e - 1]))
		e--;
	const size_t nl = (e > 0) ? in.rfind('\n', e - 1) : in.npos;
	size_t b = (nl == in.npos) ? 0 : nl + 1;
	while (b < e && is_blank(in[b]))
		b++;
	return in.substr(b, e - b).starts_with("#EXT-X-ENDLIST");
}

static bool dash_dynamic(std::string_view in)
{
	size_t p = 0;
	while ((p = in.find('<', p)) != in.npos) {
		if (starts_with_at(in, p, "<!--")) {
			p = in.find("-->", p + 4);
			continue;
		}
		const size_t end = in.find('>', p);
		if (end == in.npos)
			return false;
		if (p + 1 < in.size() && (in[p + 1] == '?' || in[p + 1] == '!')) {
			p = end;
			continue;
		}
		const std::string_view tag = in.substr(p, end - p);
		for (size_t t = tag.find("type"); t != tag.npos; t = tag.find("type", t + 4)) {
			if (!is_space(tag[t - 1]))
				continue;
			size_t v = t + 4;
			while (v < tag.size() && is_space(tag[v]))
				v++;
			if (v >= tag.size() || tag[v] != '=')
				continue;
			v++;
			while (v < tag.size() && is_space(tag[v]))
				v++;
			const std::string_view value = tag.substr(v);
			return value.starts_with("\"dynamic\"") || value.starts_with("'dynamic'");
		}
		return false;
	}
	return false;
}

static std::string session_prefix(const Session& session, long expires)
{
	std::string prefix = signing->id;
	prefix += '.';
	prefix += session.subscriber;
	prefix += '.';
	prefix += session.id;
	prefix += '.';
	prefix += std::to_string(expires);
	return prefix;
}

static void personalize(const char* arg, const char* data, size_t len)
{
	const std::string url = varnish::Request(varnish::HDR_REQ).url();
	const std::string_view path = std::string_view(url).substr(0, url.find('?'));
	const std::string_view token(arg);
	const long now = std::time(nullptr);
	char network[TAIL_MAX];
	const auto tail = network_tail(network);
	const auto session = (tail && path_safe(path) && is_manifest(path))
		? verify(token, path, now, *tail) : std::nullopt;
	if (!session) {
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

	const bool vod = hls ? hls_ended(in) : !dash_dynamic(in);
	const long segment_expires = vod ? session->expires
		: std::min(now + segment_lifetime, session->expires);
	const std::string manifest = session_prefix(*session, session->expires);
	const std::string segment = session_prefix(*session, segment_expires);
	Inserts inserts;
	inserts.segment.assign(segment, hls);
	inserts.manifest.assign(manifest, hls);
	inserts.viewer = session->id;
	std::string padded = segment;
	padded += *tail;
	padded += padding(padded.size());
	Signer signer {signing->hmac, padded, segment, manifest, *tail};
	signer.set_base(path);

	const size_t initial = len + std::min(len, size_t(1) << 20) + 4096;
	char* buf = (char*) std::malloc(initial);
	Rewriter r {data, len, &inserts, &signer, {buf, 0, buf ? initial : 0}, 0};
	const Output out = hls ? rewrite_hls(r) : rewrite_dash(r);
	varnish::forge_response(200, "", 0, out.buf, out.len);
}

[[noreturn]] static void invalid(std::string_view what)
{
	varnish::log("Invalid manifest settings: {}", what);
	std::exit(1);
}

static long lifetime_setting(const json& settings, const char* name, long fallback)
{
	const json* value = member(settings, name);
	if (value == nullptr)
		return fallback;
	if (!value->is_number_integer() || value->get<long>() <= 0)
		invalid(std::string(name) + " must be a positive integer");
	return std::min(value->get<long>(), MAX_LIFETIME);
}

static std::string secret_setting(const json& value, std::string_view name)
{
	if (!value.is_string() || value.get_ref<const std::string&>().empty())
		invalid(std::string(name) + " must be a non-empty string");
	return value.get<std::string>();
}

static std::vector<Key> key_ring(const json& settings, const char* name)
{
	const json* ring = member(settings, name);
	if (ring == nullptr || !ring->is_object() || ring->empty())
		invalid(std::string(name) + " must map key IDs to secrets");
	std::vector<Key> result;
	for (const auto& [id, secret] : ring->items()) {
		if (!valid_id(id, 1, MAX_KEY_ID))
			invalid("key IDs must be 1 to 16 base64url characters");
		result.push_back({id, varnish::HmacSha256(secret_setting(secret, id))});
	}
	return result;
}

static void load_settings()
{
	const auto text = varnish::config_file("settings");
	if (!text)
		invalid("the tenant has no settings config file");
	const json settings = json::parse(*text, nullptr, false);
	if (!settings.is_object())
		invalid("settings must be a JSON object");

	keys = key_ring(settings, "keys");
	const json* signing_id = member(settings, "signing_key");
	if (signing_id == nullptr || !signing_id->is_string()
		|| (signing = find_key(keys, signing_id->get_ref<const std::string&>())) == nullptr)
		invalid("signing_key must name one of the keys");
	entitlement_keys = key_ring(settings, "entitlement_keys");
	const json* subscriber = member(settings, "subscriber_key");
	if (subscriber == nullptr)
		invalid("subscriber_key is required");
	subscriber_hmac.emplace(secret_setting(*subscriber, "subscriber_key"));
	if (const json* wm = member(settings, "watermark_key"))
		watermark_hmac.emplace(secret_setting(*wm, "watermark_key"));

	session_lifetime = lifetime_setting(settings, "session_lifetime", session_lifetime);
	segment_lifetime = std::min(session_lifetime,
		lifetime_setting(settings, "segment_lifetime", segment_lifetime));

	if (const json* bind = member(settings, "bind_network")) {
		if (!bind->is_object())
			invalid("bind_network must be an object");
		const auto prefix = [&] (const char* family, int max) {
			const json* bits = member(*bind, family);
			if (bits == nullptr)
				return 0;
			if (!bits->is_number_integer() || bits->get<int>() < 0 || bits->get<int>() > max)
				invalid(std::string("bind_network.") + family + " is out of range");
			return bits->get<int>();
		};
		bind_ipv4 = prefix("ipv4", 32);
		bind_ipv6 = prefix("ipv6", 128);
	}
}

static void load_revocations()
{
	const auto text = varnish::config_file("revocations");
	if (!text)
		return;
	std::string_view rest = *text;
	while (!rest.empty()) {
		const size_t nl = rest.find('\n');
		std::string_view line = rest.substr(0, nl);
		rest.remove_prefix(nl == rest.npos ? rest.size() : nl + 1);
		while (!line.empty() && (is_space(line.front())))
			line.remove_prefix(1);
		while (!line.empty() && (is_space(line.back())))
			line.remove_suffix(1);
		if (line.empty() || line[0] == '#')
			continue;
		revoked.emplace_back(line);
		revoked.push_back(pseudonym(line));
	}
	std::sort(revoked.begin(), revoked.end());
	revoked.erase(std::unique(revoked.begin(), revoked.end()), revoked.end());
}

static void on_recv(varnish::Request)
{
}

int main()
{
	load_settings();
	load_revocations();
	varnish::register_function("authorize", authorize);
	varnish::register_function("watermark", watermark);
	varnish::register_transform("personalize", personalize);
	varnish::wait_for_requests(on_recv);
}
