#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <cache/cache.h>
#include <vcl.h>
#include <vre.h>
#include <vrt_obj.h>
#include <vsa.h>
#include <vsb.h>

#include "vcl_varnish.h"

/* Longest header name we build a Varnish header spec for. The spec's
   length prefix is one byte, and the policy ABI caps names at 1024 before
   they get here, so anything longer than the prefix can say is refused. */
#define VCLV_MAX_SPEC_NAME 254

/* Varnish Enterprise still takes STRING_LIST arguments, while Varnish
   Cache 7.x takes STRANDS (with an optional prefix for the setters). */
#ifdef VARNISH_PLUS
#define VCLV_L_STRING(fn, ctx, v)	fn(ctx, v, vrt_magic_string_end)
#define VCLV_NO_VXID			0
#else
#define VCLV_L_STRING(fn, ctx, v)	fn(ctx, NULL, TOSTRAND(v))
#define VCLV_NO_VXID			NO_VXID
/* VRE_capture() passes its options straight to pcre2_match(), and vre.h
   has no name for this one. */
#define VRE_NOTEMPTY			0x00000004u	/* PCRE2_NOTEMPTY */
#endif

enum vcl_phase
vclv_phase(VRT_CTX)
{
	switch (ctx->method) {
	case VCL_MET_RECV:             return (VCL_PHASE_RECV);
	case VCL_MET_HASH:             return (VCL_PHASE_HASH);
	case VCL_MET_HIT:              return (VCL_PHASE_HIT);
	case VCL_MET_MISS:             return (VCL_PHASE_MISS);
	case VCL_MET_PASS:             return (VCL_PHASE_PASS);
	case VCL_MET_BACKEND_FETCH:    return (VCL_PHASE_BACKEND_FETCH);
	case VCL_MET_BACKEND_RESPONSE: return (VCL_PHASE_BACKEND_RESPONSE);
	case VCL_MET_BACKEND_ERROR:    return (VCL_PHASE_BACKEND_ERROR);
	case VCL_MET_DELIVER:          return (VCL_PHASE_DELIVER);
	case VCL_MET_SYNTH:            return (VCL_PHASE_SYNTH);
	default:                       return (VCL_PHASE_NONE);
	}
}

struct http *
vclv_http(VRT_CTX, enum vcl_side side)
{
	switch (vclv_phase(ctx)) {
	case VCL_PHASE_RECV:
	case VCL_PHASE_HASH:
	case VCL_PHASE_HIT:
	case VCL_PHASE_MISS:
	case VCL_PHASE_PASS:
		return (side == VCL_SIDE_REQUEST ? ctx->http_req : NULL);
	case VCL_PHASE_DELIVER:
	case VCL_PHASE_SYNTH:
		return (side == VCL_SIDE_REQUEST ? ctx->http_req : ctx->http_resp);
	case VCL_PHASE_BACKEND_FETCH:
		return (side == VCL_SIDE_REQUEST ? ctx->http_bereq : NULL);
	case VCL_PHASE_BACKEND_RESPONSE:
	case VCL_PHASE_BACKEND_ERROR:
		return (side == VCL_SIDE_REQUEST ? ctx->http_bereq : ctx->http_beresp);
	case VCL_PHASE_NONE:
		break;
	}
	return (NULL);
}

/* Varnish names a header as a length-prefixed "Name:" string. */
static int
header_spec(char *spec, const char *name, size_t nlen)
{
	if (nlen == 0 || nlen > VCLV_MAX_SPEC_NAME)
		return (-1);
	spec[0] = (char)(nlen + 1);
	memcpy(spec + 1, name, nlen);
	spec[nlen + 1] = ':';
	spec[nlen + 2] = '\0';
	return (0);
}

int
vclv_get(const struct http *hp, const char *name, size_t nlen,
    const char **value, size_t *vlen)
{
	char spec[VCLV_MAX_SPEC_NAME + 3];
	const char *v;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (header_spec(spec, name, nlen) < 0)
		return (-1);
	if (!http_GetHdr(hp, spec, &v))
		return (-1);
	*value = v;
	*vlen = strlen(v);
	return (0);
}

int
vclv_add(VRT_CTX, struct http *hp, const char *name, size_t nlen,
    const char *value, size_t vlen)
{
	const char *field;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (nlen == 0 || nlen > INT_MAX || vlen > INT_MAX)
		return (-1);
	if (hp->nhd >= hp->shd) {
		VSLb(ctx->vsl, SLT_LostHeader, "%.*s", (int)nlen, name);
		return (-1);
	}
	field = WS_Printf(hp->ws, "%.*s: %.*s",
	    (int)nlen, name, (int)vlen, value);
	if (field == NULL) {
		VSLb(ctx->vsl, SLT_LostHeader, "%.*s", (int)nlen, name);
		return (-1);
	}
	http_SetHeader(hp, field);
	return (0);
}

int
vclv_set(VRT_CTX, struct http *hp, const char *name, size_t nlen,
    const char *value, size_t vlen)
{
	vclv_unset(hp, name, nlen);
	return (vclv_add(ctx, hp, name, nlen, value, vlen));
}

void
vclv_unset(struct http *hp, const char *name, size_t nlen)
{
	char spec[VCLV_MAX_SPEC_NAME + 3];

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (header_spec(spec, name, nlen) < 0)
		return;
	http_Unset(hp, spec);
}

int
vclv_next(const struct http *hp, unsigned *cursor,
    const char **name, size_t *nlen, const char **value, size_t *vlen)
{
	unsigned u;
	const char *b, *e, *colon;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	for (u = *cursor + HTTP_HDR_FIRST; u < hp->nhd; u++) {
		b = hp->hd[u].b;
		e = hp->hd[u].e;
		if (b == NULL)
			continue;
		colon = memchr(b, ':', e - b);
		if (colon == NULL)
			continue;
		*name = b;
		*nlen = colon - b;
		colon++;
		while (colon < e && (*colon == ' ' || *colon == '\t'))
			colon++;
		*value = colon;
		*vlen = e - colon;
		*cursor = u + 1 - HTTP_HDR_FIRST;
		return (0);
	}
	*cursor = u - HTTP_HDR_FIRST;
	return (-1);
}

const char *
vclv_url(const struct http *hp, size_t *len)
{
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	*len = Tlen(hp->hd[HTTP_HDR_URL]);
	return (hp->hd[HTTP_HDR_URL].b);
}

const char *
vclv_method(const struct http *hp, size_t *len)
{
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	*len = Tlen(hp->hd[HTTP_HDR_METHOD]);
	return (hp->hd[HTTP_HDR_METHOD].b);
}

int
vclv_set_url(VRT_CTX, struct http *hp, const char *url, size_t len)
{
	char *copy;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (len > INT_MAX)
		return (-1);
	copy = WS_Copy(hp->ws, url, (int)len + 1);
	if (copy == NULL) {
		VSLb(ctx->vsl, SLT_VCL_Error, "vcl: out of workspace setting the URL");
		return (-1);
	}
	copy[len] = '\0';
	http_SetH(hp, HTTP_HDR_URL, copy);
	return (0);
}

unsigned
vclv_status(const struct http *hp)
{
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	return (hp->status);
}

double
vclv_get_duration(VRT_CTX, enum vcl_duration which)
{
	switch (which) {
	case VCL_TTL:   return (VRT_r_beresp_ttl(ctx));
	case VCL_GRACE: return (VRT_r_beresp_grace(ctx));
	case VCL_KEEP:  return (VRT_r_beresp_keep(ctx));
	}
	return (0);
}

void
vclv_set_duration(VRT_CTX, enum vcl_duration which, double seconds)
{
	switch (which) {
	case VCL_TTL:   VRT_l_beresp_ttl(ctx, seconds); break;
	case VCL_GRACE: VRT_l_beresp_grace(ctx, seconds); break;
	case VCL_KEEP:  VRT_l_beresp_keep(ctx, seconds); break;
	}
}

int
vclv_client_ip(VRT_CTX, unsigned char out[16])
{
	VCL_IP ip;
	const unsigned char *bytes;
	int family;

	ip = VRT_r_client_ip(ctx);
	if (ip == NULL)
		return (-1);
	family = VSA_GetPtr(ip, &bytes);
	if (family == PF_INET) {
		memset(out, 0, 10);
		out[10] = 0xff;
		out[11] = 0xff;
		memcpy(out + 12, bytes, 4);
		return (4);
	}
	if (family == PF_INET6) {
		memcpy(out, bytes, 16);
		return (6);
	}
	return (-1);
}

int
vclv_cache_status(VRT_CTX)
{
	if (ctx->method != VCL_MET_DELIVER)
		return (-1);
	if (VRT_r_obj_hits(ctx) <= 0)
		return (1);
	/* A hit on an object past its TTL is being served from grace. */
	return (VRT_r_obj_ttl(ctx) <= 0 ? 2 : 0);
}

/* ── Variables by number ──────────────────────────────────────────── */

#define MET_CLIENT	(VCL_MET_RECV | VCL_MET_HASH | VCL_MET_HIT | \
			 VCL_MET_MISS | VCL_MET_PASS | VCL_MET_DELIVER | \
			 VCL_MET_SYNTH)
#define MET_BACKEND	(VCL_MET_BACKEND_FETCH | VCL_MET_BACKEND_RESPONSE | \
			 VCL_MET_BACKEND_ERROR)
#define MET_BERESP	(VCL_MET_BACKEND_RESPONSE | VCL_MET_BACKEND_ERROR)
#define MET_RESP	(VCL_MET_DELIVER | VCL_MET_SYNTH)
#define MET_HIT_DELIVER	(VCL_MET_HIT | VCL_MET_DELIVER)

enum vclv_type { T_STRING, T_INT, T_BOOL, T_DURATION };

/* Where Varnish lets each variable be read and written. A VRT accessor
   asserts on the objects its subroutine has, so this table is what keeps
   a tenant from reaching one where it would panic varnishd. It mirrors
   vcl/compiler/src/vcl_vars.def, which refuses the same at compile time. */
static const struct {
	enum vclv_type	type;
	unsigned	rd;
	unsigned	wr;
} vclv_vars[] = {
	[VCLV_METHOD]		= { T_STRING, 0, MET_CLIENT | MET_BACKEND },
	[VCLV_XID]		= { T_STRING, MET_CLIENT | MET_BACKEND, 0 },
	[VCLV_RESTARTS]		= { T_INT, MET_CLIENT, 0 },
	[VCLV_ESI_LEVEL]	= { T_INT, MET_CLIENT, 0 },
	[VCLV_CAN_GZIP]		= { T_BOOL, MET_CLIENT, 0 },
	[VCLV_HASH_ALWAYS_MISS]	= { T_BOOL, MET_CLIENT, MET_CLIENT },
	[VCLV_HASH_IGNORE_BUSY]	= { T_BOOL, MET_CLIENT, MET_CLIENT },
	[VCLV_BEREQ_RETRIES]	= { T_INT, MET_BACKEND, 0 },
	[VCLV_BEREQ_UNCACHEABLE] = { T_BOOL, MET_BACKEND, 0 },
	[VCLV_BEREQ_IS_BGFETCH]	= { T_BOOL, MET_BACKEND, 0 },
	[VCLV_BERESP_STATUS]	= { T_INT, MET_BERESP, MET_BERESP },
	[VCLV_BERESP_REASON]	= { T_STRING, MET_BERESP, MET_BERESP },
	[VCLV_BERESP_DO_STREAM]	= { T_BOOL, MET_BERESP, MET_BERESP },
	[VCLV_BERESP_DO_GZIP]	= { T_BOOL, MET_BERESP, MET_BERESP },
	[VCLV_BERESP_DO_GUNZIP]	= { T_BOOL, MET_BERESP, MET_BERESP },
	[VCLV_BERESP_AGE]	= { T_DURATION, MET_BERESP, 0 },
	[VCLV_BERESP_UNCACHEABLE] = { T_BOOL, MET_BERESP, MET_BERESP },
	[VCLV_OBJ_STATUS]	= { T_INT, VCL_MET_HIT, 0 },
	[VCLV_OBJ_REASON]	= { T_STRING, VCL_MET_HIT, 0 },
	[VCLV_OBJ_HITS]		= { T_INT, MET_HIT_DELIVER, 0 },
	[VCLV_OBJ_TTL]		= { T_DURATION, MET_HIT_DELIVER, 0 },
	[VCLV_OBJ_GRACE]	= { T_DURATION, MET_HIT_DELIVER, 0 },
	[VCLV_OBJ_KEEP]		= { T_DURATION, MET_HIT_DELIVER, 0 },
	[VCLV_OBJ_AGE]		= { T_DURATION, MET_HIT_DELIVER, 0 },
	[VCLV_OBJ_UNCACHEABLE]	= { T_BOOL, VCL_MET_DELIVER, 0 },
	[VCLV_RESP_STATUS]	= { T_INT, MET_RESP, MET_RESP },
	[VCLV_RESP_REASON]	= { T_STRING, MET_RESP, MET_RESP },
	[VCLV_SERVER_HOSTNAME]	= { T_STRING, MET_CLIENT | MET_BACKEND, 0 },
	[VCLV_SERVER_IDENTITY]	= { T_STRING, MET_CLIENT | MET_BACKEND, 0 },
	[VCLV_REQUEST_PROTO]	= { T_STRING, MET_CLIENT | MET_BACKEND, 0 },
	[VCLV_RESPONSE_PROTO]	= { T_STRING, MET_RESP | MET_BERESP, 0 },
	[VCLV_OBJ_PROTO]	= { T_STRING, VCL_MET_HIT, 0 },
};

static int
vclv_known(int id)
{
	return (id > 0 && id < (int)(sizeof vclv_vars / sizeof vclv_vars[0])
	    && (vclv_vars[id].rd | vclv_vars[id].wr) != 0);
}

int
vclv_var_is_string(int id)
{
	return (vclv_known(id) && vclv_vars[id].type == T_STRING);
}

static int
vclv_backend(VRT_CTX)
{
	return ((ctx->method & MET_BACKEND) != 0);
}

/* VCL_DURATION is seconds as a double; the policy ABI is nanoseconds. */
static int64_t
vclv_nanos(VCL_DURATION d)
{
	if (d != d)
		return (0);
	if (d > 9.2e9)
		return (INT64_MAX);
	if (d < -9.2e9)
		return (INT64_MIN);
	return ((int64_t)(d * 1e9));
}

int
vclv_var_get_int(VRT_CTX, int id, int64_t *out)
{
	if (!vclv_known(id) || vclv_vars[id].type == T_STRING
	    || (vclv_vars[id].rd & ctx->method) == 0)
		return (-1);
	switch (id) {
	case VCLV_RESTARTS:	*out = VRT_r_req_restarts(ctx); break;
	case VCLV_ESI_LEVEL:	*out = VRT_r_req_esi_level(ctx); break;
	case VCLV_CAN_GZIP:	*out = VRT_r_req_can_gzip(ctx); break;
	case VCLV_HASH_ALWAYS_MISS: *out = VRT_r_req_hash_always_miss(ctx); break;
	case VCLV_HASH_IGNORE_BUSY: *out = VRT_r_req_hash_ignore_busy(ctx); break;
	case VCLV_BEREQ_RETRIES: *out = VRT_r_bereq_retries(ctx); break;
	case VCLV_BEREQ_UNCACHEABLE: *out = VRT_r_bereq_uncacheable(ctx); break;
	case VCLV_BEREQ_IS_BGFETCH: *out = VRT_r_bereq_is_bgfetch(ctx); break;
	case VCLV_BERESP_STATUS: *out = VRT_r_beresp_status(ctx); break;
	case VCLV_BERESP_DO_STREAM: *out = VRT_r_beresp_do_stream(ctx); break;
	case VCLV_BERESP_DO_GZIP: *out = VRT_r_beresp_do_gzip(ctx); break;
	case VCLV_BERESP_DO_GUNZIP: *out = VRT_r_beresp_do_gunzip(ctx); break;
	case VCLV_BERESP_AGE:	*out = vclv_nanos(VRT_r_beresp_age(ctx)); break;
	case VCLV_BERESP_UNCACHEABLE: *out = VRT_r_beresp_uncacheable(ctx); break;
	case VCLV_OBJ_STATUS:	*out = VRT_r_obj_status(ctx); break;
	case VCLV_OBJ_HITS:	*out = VRT_r_obj_hits(ctx); break;
	case VCLV_OBJ_TTL:	*out = vclv_nanos(VRT_r_obj_ttl(ctx)); break;
	case VCLV_OBJ_GRACE:	*out = vclv_nanos(VRT_r_obj_grace(ctx)); break;
	case VCLV_OBJ_KEEP:	*out = vclv_nanos(VRT_r_obj_keep(ctx)); break;
	case VCLV_OBJ_AGE:	*out = vclv_nanos(VRT_r_obj_age(ctx)); break;
	case VCLV_OBJ_UNCACHEABLE: *out = VRT_r_obj_uncacheable(ctx); break;
	case VCLV_RESP_STATUS:	*out = VRT_r_resp_status(ctx); break;
	default:
		return (-1);
	}
	return (0);
}

int
vclv_var_get_string(VRT_CTX, int id, const char **out)
{
	const char *s;

	if (!vclv_known(id) || vclv_vars[id].type != T_STRING
	    || (vclv_vars[id].rd & ctx->method) == 0)
		return (-1);
	switch (id) {
	case VCLV_XID:
#ifdef VARNISH_PLUS
		s = vclv_backend(ctx) ? VRT_r_bereq_xid(ctx) : VRT_r_req_xid(ctx);
#else
		s = WS_Printf(ctx->ws, "%jd", (intmax_t)(vclv_backend(ctx) ?
		    VRT_r_bereq_xid(ctx) : VRT_r_req_xid(ctx)));
		if (s == NULL)
			return (-1);
#endif
		break;
	case VCLV_BERESP_REASON: s = VRT_r_beresp_reason(ctx); break;
	case VCLV_OBJ_REASON:	s = VRT_r_obj_reason(ctx); break;
	case VCLV_RESP_REASON:	s = VRT_r_resp_reason(ctx); break;
	case VCLV_SERVER_HOSTNAME: s = VRT_r_server_hostname(ctx); break;
	case VCLV_SERVER_IDENTITY: s = VRT_r_server_identity(ctx); break;
	case VCLV_REQUEST_PROTO:
		s = vclv_backend(ctx) ? VRT_r_bereq_proto(ctx) : VRT_r_req_proto(ctx);
		break;
	case VCLV_RESPONSE_PROTO:
		s = vclv_backend(ctx) ? VRT_r_beresp_proto(ctx) : VRT_r_resp_proto(ctx);
		break;
	case VCLV_OBJ_PROTO:	s = VRT_r_obj_proto(ctx); break;
	default:
		return (-1);
	}
	*out = s != NULL ? s : "";
	return (0);
}

/* A status Varnish would take: three digits. Varnish itself accepts more
   (a status past 999 carries a custom reason), but the policy ABI keeps to
   what reaches the wire. */
static int
vclv_status_ok(int64_t v)
{
	return (v >= 100 && v <= 999);
}

int
vclv_var_set_int(VRT_CTX, int id, int64_t v)
{
	if (!vclv_known(id) || vclv_vars[id].type == T_STRING
	    || (vclv_vars[id].wr & ctx->method) == 0)
		return (-1);
	switch (id) {
	case VCLV_HASH_ALWAYS_MISS: VRT_l_req_hash_always_miss(ctx, v != 0); break;
	case VCLV_HASH_IGNORE_BUSY: VRT_l_req_hash_ignore_busy(ctx, v != 0); break;
	case VCLV_BERESP_STATUS:
		if (!vclv_status_ok(v))
			return (-1);
		VRT_l_beresp_status(ctx, v);
		break;
	case VCLV_BERESP_DO_STREAM: VRT_l_beresp_do_stream(ctx, v != 0); break;
	case VCLV_BERESP_DO_GZIP: VRT_l_beresp_do_gzip(ctx, v != 0); break;
	case VCLV_BERESP_DO_GUNZIP: VRT_l_beresp_do_gunzip(ctx, v != 0); break;
	case VCLV_BERESP_UNCACHEABLE: VRT_l_beresp_uncacheable(ctx, v != 0); break;
	case VCLV_RESP_STATUS:
		if (!vclv_status_ok(v))
			return (-1);
		VRT_l_resp_status(ctx, v);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
vclv_var_set_string(VRT_CTX, int id, const char *v)
{
	if (!vclv_known(id) || vclv_vars[id].type != T_STRING
	    || (vclv_vars[id].wr & ctx->method) == 0)
		return (-1);
	switch (id) {
	case VCLV_METHOD:
		if (vclv_backend(ctx))
			VCLV_L_STRING(VRT_l_bereq_method, ctx, v);
		else
			VCLV_L_STRING(VRT_l_req_method, ctx, v);
		break;
	case VCLV_BERESP_REASON:
		VCLV_L_STRING(VRT_l_beresp_reason, ctx, v);
		break;
	case VCLV_RESP_REASON:
		VCLV_L_STRING(VRT_l_resp_reason, ctx, v);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
vclv_hash_data(VRT_CTX, const char *data)
{
	if (ctx->method != VCL_MET_HASH || ctx->specific == NULL)
		return (-1);
	#ifdef VARNISH_PLUS
	VRT_hashdata(ctx, data, vrt_magic_string_end);
#else
	VRT_hashdata(ctx, TOSTRAND(data));
#endif
	return (0);
}

int
vclv_synth_body(VRT_CTX, int replace, const char *body)
{
	switch (ctx->method) {
#ifdef VARNISH_PLUS
	case VCL_MET_SYNTH:
		if (replace)
			VRT_l_resp_body(ctx, body, vrt_magic_string_end);
		else
			VRT_synth_page(ctx, body, vrt_magic_string_end);
		return (0);
	case VCL_MET_BACKEND_ERROR:
		if (replace)
			VRT_l_beresp_body(ctx, body, vrt_magic_string_end);
		else
			VRT_synth_page(ctx, body, vrt_magic_string_end);
		return (0);
#else
	case VCL_MET_SYNTH:
		VRT_l_resp_body(ctx, replace ? LBODY_SET_STRING : LBODY_ADD_STRING,
		    NULL, TOSTRAND(body));
		return (0);
	case VCL_MET_BACKEND_ERROR:
		VRT_l_beresp_body(ctx, replace ? LBODY_SET_STRING : LBODY_ADD_STRING,
		    NULL, TOSTRAND(body));
		return (0);
#endif
	default:
		return (-1);
	}
}

void
vclv_log(VRT_CTX, const char *msg, size_t len)
{
	if (ctx->vsl != NULL)
		VSLb(ctx->vsl, SLT_VCL_Log, "%.*s", (int)len, msg);
	else
		VSL(SLT_VCL_Log, VCLV_NO_VXID, "%.*s", (int)len, msg);
}

void *
vclv_regex_compile(const char *pattern, const char **error)
{
#ifdef VARNISH_PLUS
	int error_offset = 0;
	*error = "";
	return (VRE_compile(pattern, 0, error, &error_offset));
#else
	int error_code = 0, error_offset = 0;
	vre_t *re;
	re = VRE_compile(pattern, 0, &error_code, &error_offset, 0);
	*error = re == NULL ? "invalid regular expression" : "";
	return (re);
#endif
}

void
vclv_regex_free(void *re)
{
	vre_t *vre = re;
	VRE_free(&vre);
}

/* The backtracking limits of Varnish's own pcre_match_limit and
   pcre_match_limit_recursion defaults, so a pattern costs a tenant what it
   costs the VCL around it. Without them, a pattern like ^(a|aa)+$ runs PCRE
   to its built-in limit of ten million steps, outside the instruction
   budget. */
static const struct vre_limits vclv_vre_limits = {
	.match = VCLV_REGEX_MATCH_LIMIT,
#ifdef VARNISH_PLUS
	.match_recursion = VCLV_REGEX_DEPTH_LIMIT,
#else
	.depth = VCLV_REGEX_DEPTH_LIMIT,
#endif
};

const struct vre_limits *
vclv_regex_limits(void)
{
	return (&vclv_vre_limits);
}

int
vclv_regex_match(const void *re, const char *subject, size_t len)
{
	int rc;

	if (len > INT_MAX)
		return (-1);
#ifdef VARNISH_PLUS
	rc = VRE_exec(re, subject, (int)len, 0, 0, NULL, 0, &vclv_vre_limits);
#else
	rc = VRE_match(re, subject, len, 0, &vclv_vre_limits);
#endif
	if (rc >= 0)
		return (1);
	return (rc == VRE_ERROR_NOMATCH ? 0 : -1);
}

/* Append the replacement for one match: `\0`..`\9` name a capture, any
   other escaped byte stands for itself, as in VRT_regsub. */
static void
vclv_regsub_expand(struct vsb *out, const char *subject,
    const char *replacement, const int *groups, int ngroups)
{
	const char *r;
	int g;

	for (r = replacement; *r != '\0'; r++) {
		if (*r != '\\' || r[1] == '\0') {
			VSB_putc(out, *r);
			continue;
		}
		r++;
		if (*r < '0' || *r > '9') {
			VSB_putc(out, *r);
			continue;
		}
		g = *r - '0';
		if (g < ngroups && groups[2 * g] >= 0 && groups[2 * g + 1] >= groups[2 * g])
			VSB_bcat(out, subject + groups[2 * g],
			    groups[2 * g + 1] - groups[2 * g]);
	}
}

/* One match against `subject` from `start`, into groups[] as (begin, end)
   offsets into the whole subject. Returns how many groups were set (at
   least 1), 0 for no match, or -1 when PCRE gave up at its limits. */
static int
vclv_regsub_exec(const void *re, const char *subject, size_t len,
    size_t start, int notempty, int *groups, int ngroups)
{
	int rc, g;

#ifdef VARNISH_PLUS
	int ovector[VCLV_REGSUB_GROUPS * 3];

	memset(ovector, -1, sizeof ovector);
	rc = VRE_exec(re, subject, (int)len, (int)start,
	    notempty ? VRE_NOTEMPTY : 0, ovector, VCLV_REGSUB_GROUPS * 3,
	    &vclv_vre_limits);
	if (rc == VRE_ERROR_NOMATCH)
		return (0);
	if (rc < 0)
		return (-1);
	if (rc == 0 || rc > ngroups)
		rc = ngroups;
	for (g = 0; g < 2 * rc; g++)
		groups[g] = ovector[g];
#else
	txt t[VCLV_REGSUB_GROUPS];
	size_t count = VCLV_REGSUB_GROUPS;
	/* VRE_capture takes a length of 0 to mean NUL-terminated, and the
	   subject may not be, so an empty tail is matched as "". */
	const char *base = start < len ? subject + start : "";

	memset(t, 0, sizeof t);
	/* VRE_capture has no start offset, so here a `^` can match again
	   where the last replacement ended. */
	rc = VRE_capture(re, base, len - start,
	    notempty ? VRE_NOTEMPTY : 0, t, count, &vclv_vre_limits);
	if (rc == VRE_ERROR_NOMATCH)
		return (0);
	if (rc < 0)
		return (-1);
	if (rc == 0 || rc > ngroups)
		rc = ngroups;
	for (g = 0; g < rc; g++) {
		groups[2 * g] = t[g].b ? (int)(t[g].b - base + start) : -1;
		groups[2 * g + 1] = t[g].e ? (int)(t[g].e - base + start) : -1;
	}
#endif
	for (g = rc; g < ngroups; g++)
		groups[2 * g] = groups[2 * g + 1] = -1;
	return (rc);
}

int
vclv_regsub(int all, const char *subject, size_t len, const void *re,
    const char *replacement, size_t max_out, unsigned *execs, struct vsb **result)
{
	int groups[VCLV_REGSUB_GROUPS * 2];
	struct vsb *out;
	size_t at = 0;
	unsigned budget = *execs;
	int rc;

	*result = NULL;
	*execs = 0;
	if (len > INT_MAX)
		return (-1);
	out = VSB_new_auto();
	AN(out);
	do {
		/* Each exec is the unit the caller charges for. */
		if (*execs >= budget) {
			VSB_destroy(&out);
			return (-1);
		}
		(*execs)++;
		/* As VRT_regsub does: each exec starts where the last match
		   ended, in the whole subject, so a `^` matches only once, and
		   only the first match may be empty. */
		rc = vclv_regsub_exec(re, subject, len, at, *execs > 1,
		    groups, VCLV_REGSUB_GROUPS);
		if (rc < 0) {
			VSB_destroy(&out);
			return (-1);
		}
		if (rc == 0)
			break;
		VSB_bcat(out, subject + at, groups[0] - (int)at);
		vclv_regsub_expand(out, subject, replacement, groups,
		    VCLV_REGSUB_GROUPS);
		at = groups[1];
		if (VSB_len(out) > (ssize_t)max_out) {
			VSB_destroy(&out);
			return (-1);
		}
	} while (all && at <= len);
	VSB_bcat(out, subject + at, len - at);
	if (VSB_finish(out) != 0 || VSB_len(out) > (ssize_t)max_out) {
		VSB_destroy(&out);
		return (-1);
	}
	*result = out;
	return (0);
}

/* JSON string contents: a description is the author's text, so a quote, a
   backslash or a control byte in it must not end the string early. */
static void
vclv_json_escape(struct vsb *vsb, const char *s)
{
	for (; *s != '\0'; s++) {
		const unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\')
			VSB_printf(vsb, "\\%c", c);
		else if (c < 0x20)
			VSB_printf(vsb, "\\u%04x", c);
		else
			VSB_putc(vsb, c);
	}
}

#ifndef VARNISH_PLUS
/* Varnish Cache only has the va_list form of VRT_VSC_Alloc(). */
static void *
vclv_vsc_alloc(const char *category, size_t size, const unsigned char *jp,
    size_t sz_jp, const char *fmt, ...)
{
	va_list ap;
	void *p;

	va_start(ap, fmt);
	p = VRT_VSC_Alloc(NULL, NULL, category, size, jp, sz_jp, fmt, ap);
	va_end(ap);
	return (p);
}
#endif

uint64_t *
vclv_stat_alloc(const char *tenant, const char *name, const char *help,
    int gauge)
{
	struct vsb *vsb;
	uint64_t *word;

	AN(tenant);
	AN(name);
	AN(help);
	/* Varnish keeps a pointer to the descriptor and reuses its documentation
	   segment by address, so the bytes stay allocated for the life of the
	   process, like the counter itself. */
	vsb = VSB_new_auto();
	AN(vsb);
	VSB_cat(vsb, "{\"version\":\"1\",\"name\":\"riscv\",");
	VSB_cat(vsb, "\"oneliner\":\"VCL tenant statistics\",\"order\":1000,");
	VSB_cat(vsb, "\"docs\":\"Counters declared by a tenant's VCL\",");
	VSB_printf(vsb, "\"elements\":1,\"elem\":{\"%s\":{", name);
	VSB_printf(vsb, "\"type\":\"%s\",\"ctype\":\"uint64_t\",",
	    gauge ? "gauge" : "counter");
	VSB_cat(vsb, "\"level\":\"info\",\"oneliner\":\"");
	vclv_json_escape(vsb, help);
	VSB_printf(vsb, "\",\"format\":\"integer\",\"index\":0,\"name\":\"%s\",", name);
	VSB_cat(vsb, "\"docs\":\"");
	vclv_json_escape(vsb, help);
	VSB_cat(vsb, "\"}}}");
	AZ(VSB_finish(vsb));

#ifdef VARNISH_PLUS
	word = VRT_VSC_Alloc(NULL, NULL, "RISCV", sizeof *word,
	    (const unsigned char *)VSB_data(vsb), VSB_len(vsb) + 1,
	    "%s", tenant);
#else
	word = vclv_vsc_alloc("RISCV", sizeof *word,
	    (const unsigned char *)VSB_data(vsb), VSB_len(vsb) + 1,
	    "%s", tenant);
#endif
	if (word == NULL)
		VSB_destroy(&vsb);
	return (word);
}

void
vclv_fail(VRT_CTX, const char *msg)
{
	VRT_fail(ctx, "%s", msg);
}
