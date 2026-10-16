#include "vmod_riscv.h"

#include "riscv_backend.h"
#include "vcl.h"
#include "vcc_if.h"

/*
 * Response body transformation in vcl_deliver.
 *
 * A delivery processor (VDP) cannot fail a response: by the time it sees
 * the body, the status and headers have been sent. vcl_deliver runs before
 * anything is sent, so here we map the whole object into the tenant's VM,
 * let the guest produce a new response, and swap the request's object for a
 * private transient one that delivers it, the way cnt_synth() builds its body.
 * Delivery then sees a plain, complete object: Content-Length, Range and
 * HEAD all work, and no gunzip or ESI processor gets pushed.
 * On any failure nothing has been sent, and VCL can still return (synth).
 */

extern int riscv_backend_streaming_post(struct vmod_riscv_post *, const void*, ssize_t);
extern int riscv_deliver_map_body(struct vmod_riscv_post *, const void*, ssize_t);
extern int riscv_deliver_call(VRT_CTX, const char *func, const char *arg,
	const struct vmod_riscv_post *, struct deliver_result *);
extern void *riscv_deliver_machine(VRT_CTX);
extern int riscv_deliver_iterate(void *script, uint64_t addr, size_t len,
	void *priv, objiterate_f *func);
extern void riscv_deliver_unmap(void *script, uint64_t addr, size_t len);

#ifdef VARNISH_PLUS
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Not in the installed headers (cache_objhead.h, storage.h) */
struct objcore *HSH_Private(const struct worker *wrk);
void HSH_Abandon(struct objcore *oc);
void HSH_DerefBoc(struct worker *wrk, struct objcore *);
int HSH_DerefObjCore(struct worker *, struct objcore **);
extern struct stevedore *stv_transient;
enum stv_alloc_result {
	STV_AR_OK,
	STV_AR_FALLBACK,
	STV_AR_FAIL,
};

struct deliver_obj_methods {
	void		*objgetlastlru;
	void		*objtryrefattr;
	void		*objrefattr;
	void		*objderefattr;
	void		(*objfree)(struct worker *, struct objcore *);
	int		(*objiterator)(struct worker *, struct objcore *, void *,
			    objiterate_f *, int, size_t, ssize_t);
	void		*objgetspace;
	void		*objextend;
	void		*objtrimstore;
	void		*objfinish;
	void		*objbocdone;
	void		*objslim;
	void		*objgetattr;
	void		*objsetattr;
	void		*objhasattr;
	void		*objsetauxattr;
	void		*objgetauxattr;
	void		*objrelauxattr;
	void		*objtouch;
	void		*objsetstate;
	void		*objsetlen;
	uint64_t	(*objgetlen)(struct worker *, struct objcore *);
	void		*objcheckvary;
	void		*objgetvary;
	void		*objsetvary;
	void		*objsetslicerdata;
	void		*objgetslicerdata;
	void		*objevent;
};

struct deliver_stevedore {
	unsigned	magic;
#define DELIVER_STEVEDORE_MAGIC		0x4baf43db
	const char	*name;
	void		*callbacks[24];
	const struct deliver_obj_methods *methods;
	void		*lru;
#define VRTSTVVAR(nm, vtype, ctype, dval) void *var_##nm;
#include "tbl/vrt_stv_var.h"
	void		*priv;
	void		*list[2];
	const char	*ident;
	const char	*vclname;
	void		*vgs;
};

struct deliver_view {
	struct deliver_stevedore	stv;
	unsigned			magic;
#define DELIVER_VIEW_MAGIC		0x5d1e7a11
	const struct deliver_stevedore	*real;
	void				*script;
	uint64_t			data;
	size_t				length;
	struct objcore			*orig;
	oaref_t				orig_oaref;
	uint64_t			mapped;
	size_t				mapped_len;
};

static const struct deliver_obj_methods *deliver_real_methods;
static struct deliver_obj_methods deliver_methods;
static pthread_once_t deliver_once = PTHREAD_ONCE_INIT;

static struct deliver_view *
deliver_view_of(const struct objcore *oc)
{
	struct deliver_view *dv;

	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	if (oc->stobj->stevedore == NULL)
		return (NULL);
	dv = (struct deliver_view *)(uintptr_t)oc->stobj->stevedore;
	if (dv->stv.methods != &deliver_methods)
		return (NULL);
	CHECK_OBJ(dv, DELIVER_VIEW_MAGIC);
	return (dv);
}

static int
deliver_iterator(struct worker *wrk, struct objcore *oc, void *priv,
    objiterate_f *func, int final, size_t start, ssize_t end)
{
	struct deliver_view *dv = deliver_view_of(oc);
	size_t stop;

	(void)wrk;
	(void)final;
	AN(dv);
	stop = dv->length;
	if (end >= 0 && (size_t)end < stop)
		stop = end;
	if (start >= stop)
		return (func(priv, 0, 1, NULL, 0));
	return (riscv_deliver_iterate(dv->script, dv->data + start,
	    stop - start, priv, func));
}

static uint64_t
deliver_getlen(struct worker *wrk, struct objcore *oc)
{
	struct deliver_view *dv = deliver_view_of(oc);

	(void)wrk;
	AN(dv);
	return (dv->length);
}

static void
deliver_release(struct worker *wrk, struct deliver_view *dv)
{
	if (dv->mapped_len > 0)
		riscv_deliver_unmap(dv->script, dv->mapped, dv->mapped_len);
	if (dv->orig != NULL) {
		if (dv->orig_oaref)
			ObjDerefAttr(dv->orig, &dv->orig_oaref);
		(void)HSH_DerefObjCore(wrk, &dv->orig);
	}
	dv->magic = 0;
	free(dv);
}

static void
deliver_objfree(struct worker *wrk, struct objcore *oc)
{
	struct deliver_view *dv = deliver_view_of(oc);

	AN(dv);
	oc->stobj->stevedore = (const struct stevedore *)(uintptr_t)dv->real;
	deliver_real_methods->objfree(wrk, oc);
	deliver_release(wrk, dv);
}

static void
deliver_init(void)
{
	const struct deliver_stevedore *stv = (const void *)stv_transient;

	if (stv == NULL || stv->magic != DELIVER_STEVEDORE_MAGIC ||
	    stv->ident == NULL || strcmp(stv->ident, "Transient") ||
	    stv->methods == NULL || stv->methods->objfree == NULL ||
	    stv->methods->objiterator == NULL)
		return;
	deliver_methods = *stv->methods;
	deliver_methods.objfree = deliver_objfree;
	deliver_methods.objiterator = deliver_iterator;
	deliver_methods.objgetlen = deliver_getlen;
	deliver_real_methods = stv->methods;
}

static int
deliver_map_to_vm(void *priv, int flush, int last, const void *ptr, ssize_t len)
{
	(void)flush;
	(void)last;
	if (len != 0)
		return (riscv_deliver_map_body(priv, ptr, len));
	return (0);
}

static int
deliver_copy_to_vm(void *priv, int flush, int last, const void *ptr, ssize_t len)
{
	(void)flush;
	(void)last;
	if (len != 0)
		return (riscv_backend_streaming_post(priv, ptr, len));
	return (0);
}

/* Build a private transient object for the guest's response body.
   Returns NULL with nothing left behind on failure. */
static struct objcore *
deliver_new_object(VRT_CTX, oaref_t *oaref)
{
	struct req *req = ctx->req;
	struct worker *wrk = req->wrk;
	struct stv_hints hints[1];
	STV_STAT_STACKALLOC(stvstat, 64);
	int ok = 1;

	struct objcore *oc = HSH_Private(wrk);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	memset(hints, 0, sizeof *hints);
	hints->vrt_privs = req->privs;
	hints->vrt_privs_id = (uintptr_t)req;
	hints->vcl = req->vcl;
	hints->is_synth_client = 1;

	*oaref = 0;
	if (STV_NewObject(wrk, oc, stv_transient, hints, stvstat) == STV_AR_OK) {
		*oaref = ObjRefAttr(wrk, oc);
		AN(*oaref);
	} else
		ok = 0;
	if (ok && ((const struct deliver_stevedore *)
	    (const void *)oc->stobj->stevedore)->methods != deliver_real_methods)
		ok = 0;

	HSH_DerefBoc(wrk, oc);
	if (stvstat != NULL)
		STV_Stat_log(stv_transient, req->vsl, stvstat);

	if (!ok) {
		VSLb(req->vsl, SLT_Error,
			"deliver_transform: could not store the response");
		if (*oaref)
			ObjDerefAttr(oc, oaref);
		AZ(*oaref);
		(void)HSH_DerefObjCore(wrk, &oc);
		return (NULL);
	}
	return (oc);
}

VCL_BOOL
vmod_deliver_transform(VRT_CTX, VCL_STRING func, VCL_STRING arg, VCL_BYTES max_size)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	if (ctx->method != VCL_MET_DELIVER) {
		VRT_fail(ctx, "riscv.deliver_transform() is only allowed in vcl_deliver");
		return (0);
	}
	if (func == NULL || *func == 0) {
		VRT_fail(ctx, "riscv.deliver_transform(): no function given");
		return (0);
	}
	struct req *req = ctx->req;
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	CHECK_OBJ_NOTNULL(req->objcore, OBJCORE_MAGIC);
	AN(req->oc_oaref);
	struct worker *wrk = req->wrk;

	if (req->esi_level > 0) {
		VSLb(ctx->vsl, SLT_Error, "deliver_transform: not supported in ESI includes");
		return (0);
	}
	AZ(pthread_once(&deliver_once, deliver_init));
	if (deliver_real_methods == NULL) {
		VSLb(ctx->vsl, SLT_Error,
			"deliver_transform: unsupported Transient storage");
		return (0);
	}
	/* The guest gets the stored bytes, so they must be the body itself */
	if (http_GetHdr(req->resp, H_Content_Encoding, NULL) ||
	    ObjCheckFlag(wrk, req->objcore, req->oc_oaref, OF_GZIPED) ||
	    ObjCheckFlag(wrk, req->objcore, req->oc_oaref, OF_BROTLIED) ||
	    ObjCheckFlag(wrk, req->objcore, req->oc_oaref, OF_ESIPROC) ||
	    ObjCheckFlag(wrk, req->objcore, req->oc_oaref, OF_VESPROC) ||
	    ObjCheckFlag(wrk, req->objcore, req->oc_oaref, OF_JSONPROC)) {
		VSLb(ctx->vsl, SLT_Error,
			"deliver_transform: encoded or processed bodies are not supported");
		return (0);
	}
	void *script = riscv_deliver_machine(ctx);
	if (script == NULL) {
		VSLb(ctx->vsl, SLT_Error, "deliver_transform: no active tenant");
		return (0);
	}
	struct deliver_view *prev = deliver_view_of(req->objcore);

	/* Read the whole body into the VM. This waits for a streaming
	   fetch to finish, and fails if the fetch fails. */
	struct vmod_riscv_post post = {
		.address = 0,
		.length = 0,
		.capacity = max_size,
		.ctx = ctx,
	};
	struct deliver_result result;
	memset(&result, 0, sizeof result);
	oaref_t oaref;
	struct objcore *oc = NULL;
	struct deliver_view *dv = NULL;

	if (ObjIterate(wrk, req->objcore, &post,
	    prev ? deliver_copy_to_vm : deliver_map_to_vm, 0, 0, -1) < 0) {
		VSLb(ctx->vsl, SLT_Error, "deliver_transform: could not read the body");
		goto fail;
	}
	if (riscv_deliver_call(ctx, func, arg ? arg : "", &post, &result) < 0)
		goto fail;
	if (result.length > (size_t)max_size) {
		VSLb(ctx->vsl, SLT_Error,
			"deliver_transform: response of %zu bytes is over the %jd byte limit",
			result.length, (intmax_t)max_size);
		goto fail;
	}
	dv = calloc(1, sizeof *dv);
	if (dv == NULL) {
		VSLb(ctx->vsl, SLT_Error, "deliver_transform: out of memory");
		goto fail;
	}
	oc = deliver_new_object(ctx, &oaref);
	if (oc == NULL)
		goto fail;

	dv->magic = DELIVER_VIEW_MAGIC;
	dv->real = (const void *)oc->stobj->stevedore;
	dv->stv = *dv->real;
	dv->stv.methods = &deliver_methods;
	dv->script = script;
	dv->data = result.data;
	dv->length = result.length;
	if (prev != NULL) {
		dv->orig = prev->orig;
		dv->orig_oaref = prev->orig_oaref;
		dv->mapped = prev->mapped;
		dv->mapped_len = prev->mapped_len;
		prev->orig = NULL;
		prev->orig_oaref = 0;
		prev->mapped_len = 0;
		ObjDerefAttr(req->objcore, &req->oc_oaref);
		(void)HSH_DerefObjCore(wrk, &req->objcore);
	} else {
		dv->orig = req->objcore;
		dv->orig_oaref = req->oc_oaref;
		dv->mapped = post.address;
		dv->mapped_len = post.length;
		if (dv->orig->flags & OC_F_TRANSIENT)
			HSH_Abandon(dv->orig);
		req->objcore = NULL;
		req->oc_oaref = 0;
	}
	oc->stobj->stevedore = (const void *)&dv->stv;
	AZ(req->oc_oaref);
	AZ(req->objcore);
	req->objcore = oc;
	req->oc_oaref = oaref;

	http_PutResponse(req->resp, "HTTP/1.1", (uint16_t)result.status, NULL);
	/* Delivery recomputes it from the object, but not for HEAD */
	http_Unset(req->resp, H_Content_Length);
	http_PrintfHeader(req->resp, "Content-Length: %zu", result.length);
	/* The validators were for the original body, and a 304 must not
	   let a client keep an earlier (per-client) response. Without a
	   Last-Modified, cnt_deliver() would compare If-Modified-Since with
	   the new object's, so the conditional headers are ignored. */
	http_Unset(req->resp, H_ETag);
	http_Unset(req->resp, H_Last_Modified);
	req->http->conds = 0;
	if (result.tsize > 0) {
		http_Unset(req->resp, H_Content_Type);
		http_PrintfHeader(req->resp, "Content-Type: %.*s",
			(int)result.tsize, result.type);
	}
	return (1);

fail:
	free(dv);
	if (prev == NULL && post.length > 0)
		riscv_deliver_unmap(script, post.address, post.length);
	return (0);
}
#else
VCL_BOOL
vmod_deliver_transform(VRT_CTX, VCL_STRING func, VCL_STRING arg, VCL_BYTES max_size)
{
	(void)func;
	(void)arg;
	(void)max_size;
	VRT_fail(ctx, "riscv.deliver_transform() is only supported on Varnish Enterprise");
	return (0);
}
#endif
