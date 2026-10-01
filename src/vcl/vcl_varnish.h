#pragma once
/**
 * The Varnish half of the VCL policy ABI.
 *
 * Everything here touches Varnish's own objects, so it is plain C compiled
 * against cache/cache.h: the header maps, the busy object's TTLs and the
 * delivered object's hit count are Varnish's structs, not mirrors of them.
 * The C++ side (vcl_syscalls.cpp) moves bytes in and out of guest memory
 * and calls down here with plain pointers and lengths.
 *
 * A `side` is which header map a phase means by "request" and "response":
 *
 *   method                request      response
 *   vcl_recv              req          -
 *   vcl_hash, vcl_hit,    req          -
 *   vcl_miss, vcl_pass
 *   vcl_deliver           req          resp
 *   vcl_synth             req          resp
 *   vcl_backend_fetch     bereq        -
 *   vcl_backend_response  bereq        beresp
 *   vcl_backend_error     bereq        beresp
 */
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct vrt_ctx;
struct http;

enum vcl_side { VCL_SIDE_REQUEST = 0, VCL_SIDE_RESPONSE = 1 };

/* The phase the compiled policy is running, from ctx->method. */
enum vcl_phase {
	VCL_PHASE_NONE = 0,
	VCL_PHASE_RECV,
	VCL_PHASE_BACKEND_FETCH,
	VCL_PHASE_BACKEND_RESPONSE,
	VCL_PHASE_DELIVER,
	VCL_PHASE_SYNTH,
	VCL_PHASE_HASH,
	VCL_PHASE_HIT,
	VCL_PHASE_MISS,
	VCL_PHASE_PASS,
	VCL_PHASE_BACKEND_ERROR,
};
enum vcl_phase vclv_phase(const struct vrt_ctx *);

/* The header map a side means in the current phase, or NULL. */
struct http *vclv_http(const struct vrt_ctx *, enum vcl_side);

/* First value of a header, case-insensitively. Returns 0 and sets the
   value, or -1 when the header is absent. The value is not NUL-terminated
   for the caller's purposes; *vlen is its length. */
int vclv_get(const struct http *, const char *name, size_t nlen,
    const char **value, size_t *vlen);
/* Replace every value of a header with one. 0, or -1 on workspace exhaustion. */
int vclv_set(const struct vrt_ctx *, struct http *, const char *name, size_t nlen,
    const char *value, size_t vlen);
/* Append one more value of a header. */
int vclv_add(const struct vrt_ctx *, struct http *, const char *name, size_t nlen,
    const char *value, size_t vlen);
void vclv_unset(struct http *, const char *name, size_t nlen);

/* Walk a header map: each call yields the next "Name: value" field as a name
   and a value. *cursor starts at 0. Returns 0 while there are fields. */
int vclv_next(const struct http *, unsigned *cursor,
    const char **name, size_t *nlen, const char **value, size_t *vlen);

const char *vclv_url(const struct http *, size_t *len);
const char *vclv_method(const struct http *, size_t *len);
int vclv_set_url(const struct vrt_ctx *, struct http *, const char *url, size_t len);
unsigned vclv_status(const struct http *);

/* beresp.ttl, beresp.grace, beresp.keep in whole seconds. */
enum vcl_duration { VCL_TTL = 0, VCL_GRACE = 1, VCL_KEEP = 2 };
double vclv_get_duration(const struct vrt_ctx *, enum vcl_duration);
void vclv_set_duration(const struct vrt_ctx *, enum vcl_duration, double);

/* The client address as 16 bytes, IPv4 mapped into ::ffff:0:0/96.
   Returns 4 or 6 (the original family), or -1. */
int vclv_client_ip(const struct vrt_ctx *, unsigned char out[16]);

/* How the response vcl_deliver is about to send came to be: 0 hit,
   1 miss (a pass reads as one), 2 stale (a grace hit). -1 outside
   vcl_deliver. The numbers are the policy ABI's cache status. */
int vclv_cache_status(const struct vrt_ctx *);

/* Varnish variables by number: the policy ABI's TYPED_VAR_GET/SET. The
   numbers are the compiler's `HostVar` (vcl/compiler/src/vars.rs). Each is
   gated by the subroutine running, and -1 is a refusal: a variable this
   subroutine has no access to, or a value Varnish would not take. A
   DURATION is nanoseconds, a BOOL 0 or 1. A string read is valid until the
   task's workspace is reset. */
enum vclv_var {
	VCLV_METHOD = 1,
	VCLV_XID,
	VCLV_RESTARTS,
	VCLV_ESI_LEVEL,
	VCLV_CAN_GZIP,
	VCLV_HASH_ALWAYS_MISS,
	VCLV_HASH_IGNORE_BUSY,
	VCLV_BEREQ_RETRIES,
	VCLV_BEREQ_UNCACHEABLE,
	VCLV_BEREQ_IS_BGFETCH,
	VCLV_BERESP_STATUS,
	VCLV_BERESP_REASON,
	VCLV_BERESP_DO_STREAM,
	VCLV_BERESP_DO_GZIP,
	VCLV_BERESP_DO_GUNZIP,
	VCLV_BERESP_AGE,
	VCLV_BERESP_UNCACHEABLE,
	VCLV_OBJ_STATUS,
	VCLV_OBJ_REASON,
	VCLV_OBJ_HITS,
	VCLV_OBJ_TTL,
	VCLV_OBJ_GRACE,
	VCLV_OBJ_KEEP,
	VCLV_OBJ_AGE,
	VCLV_OBJ_UNCACHEABLE,
	VCLV_RESP_STATUS,
	VCLV_RESP_REASON,
	VCLV_SERVER_HOSTNAME,
	VCLV_SERVER_IDENTITY,
	VCLV_REQUEST_PROTO,
	VCLV_RESPONSE_PROTO,
	VCLV_OBJ_PROTO,
};
int vclv_var_is_string(int id);
int vclv_var_get_int(const struct vrt_ctx *, int id, int64_t *out);
int vclv_var_get_string(const struct vrt_ctx *, int id, const char **out);
int vclv_var_set_int(const struct vrt_ctx *, int id, int64_t value);
/* value is NUL-terminated. */
int vclv_var_set_string(const struct vrt_ctx *, int id, const char *value);

/* hash_data(): feed a string to the cache key. vcl_hash only. */
int vclv_hash_data(const struct vrt_ctx *, const char *data);

/* synthetic() (replace = 0) or `set resp.body` / `set beresp.body`
   (replace = 1), in vcl_synth and vcl_backend_error. Both append to the
   synthetic body, as they do in Varnish Enterprise's own VCL. */
int vclv_synth_body(const struct vrt_ctx *, int replace, const char *body);

/* return (fail): fail the running VCL subroutine with a message. */
void vclv_fail(const struct vrt_ctx *, const char *msg);

void vclv_log(const struct vrt_ctx *, const char *msg, size_t len);

/* Regular expressions, compiled with Varnish's own engine so a pattern
   means in a compiled policy what it means in the VCL around it. */
void *vclv_regex_compile(const char *pattern, const char **error);
void vclv_regex_free(void *);
/* 1 match, 0 no match, -1 when the match could not be decided: the
   backtracking limits below were reached, or the subject is too long. A
   caller must not read -1 as "no match", or a deny rule fails open. */
#define VCLV_REGEX_MATCH_LIMIT	10000
#define VCLV_REGEX_DEPTH_LIMIT	20
int vclv_regex_match(const void *re, const char *subject, size_t len);
/* The same limits, for the VMOD API's own regex calls. */
struct vre_limits;
const struct vre_limits *vclv_regex_limits(void);
/* regsub() (all = 0) or regsuball() (all = 1), with VRT_regsub's
   semantics but under the match limits above, and counted: *execs is the
   most matches it may run on the way in, and how many it ran on the way
   out, so the caller can charge each one. 0 with the result in *result
   (the caller destroys it), or -1: a match was undecided, the budget ran
   out, or the result would be longer than max_out. */
#define VCLV_REGSUB_GROUPS	10
struct vsb;
int vclv_regsub(int all, const char *subject, size_t len, const void *re,
    const char *replacement, size_t max_out, unsigned *execs,
    struct vsb **result);

/* A Varnish counter, RISCV.<tenant>.<name>, that lives for the rest of the
   process. `gauge` picks the VSC type varnishstat shows it as. Returns the
   counter word, or NULL when Varnish refuses the descriptor. */
uint64_t *vclv_stat_alloc(const char *tenant, const char *name,
    const char *help, int gauge);

#ifdef __cplusplus
}
#endif
