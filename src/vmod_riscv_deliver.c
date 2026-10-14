#include "vmod_riscv.h"

#include "riscv_backend.h"
#include "vcl.h"
#include "vcc_if.h"

/*
 * Response body transformation in vcl_deliver.
 *
 * A delivery processor (VDP) cannot fail a response: by the time it sees
 * the body, the status and headers have been sent. vcl_deliver runs before
 * anything is sent, so here we read the whole object into the tenant's VM,
 * let the guest produce a new response, and swap the request's object for a
 * private transient one holding it, the way cnt_synth() builds its body.
 * Delivery then sees a plain, complete object: Content-Length, Range and
 * HEAD all work, and no gunzip or ESI processor gets pushed.
 * On any failure nothing has been sent, and VCL can still return (synth).
 */

extern int riscv_backend_streaming_post(struct vmod_riscv_post *, const void*, ssize_t);
extern int riscv_deliver_call(VRT_CTX, const char *func, const char *arg,
	const struct vmod_riscv_post *, struct deliver_result *);
extern int riscv_deliver_copy_out(VRT_CTX, void *dst, uint64_t src, size_t len);

#ifdef VARNISH_PLUS
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

static int
deliver_body_to_vm(void *priv, int flush, int last, const void *ptr, ssize_t len)
{
	(void)flush;
	(void)last;
	if (len != 0)
		return (riscv_backend_streaming_post(priv, ptr, len));
	return (0);
}

/* Build a private transient object from the guest's response body.
   Returns NULL with nothing left behind on failure. */
static struct objcore *
deliver_new_object(VRT_CTX, const struct deliver_result *result, oaref_t *oaref)
{
	struct req *req = ctx->req;
	struct worker *wrk = req->wrk;
	struct stv_hints hints[1];
	STV_STAT_STACKALLOC(stvstat, 64);
	uint64_t src = result->data;
	ssize_t sz = result->length;
	ssize_t l2;
	uint8_t *dest;
	int ok = 1;

	struct objcore *oc = HSH_Private(wrk);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	memset(hints, 0, sizeof *hints);
	hints->size_body = sz;
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

	while (ok && sz > 0) {
		l2 = sz;
		if (!ObjGetSpace(wrk, oc, &l2, &dest, stvstat)) {
			ok = 0;
			break;
		}
		AN(dest);
		if (l2 > sz)
			l2 = sz;
		if (riscv_deliver_copy_out(ctx, dest, src, l2) < 0) {
			ok = 0;
			break;
		}
		ObjExtend(wrk, oc, l2, stvstat);
		src += l2;
		sz -= l2;
	}
	if (ok)
		ObjSetLen(wrk, oc, *oaref, result->length);

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

	/* Read the whole body into the VM. This waits for a streaming
	   fetch to finish, and fails if the fetch fails. */
	struct vmod_riscv_post post = {
		.address = 0,
		.length = 0,
		.capacity = max_size,
		.ctx = ctx,
	};
	if (ObjIterate(wrk, req->objcore, &post, deliver_body_to_vm, 0, 0, -1) < 0) {
		VSLb(ctx->vsl, SLT_Error, "deliver_transform: could not read the body");
		return (0);
	}

	struct deliver_result result;
	memset(&result, 0, sizeof result);
	if (riscv_deliver_call(ctx, func, arg ? arg : "", &post, &result) < 0)
		return (0);
	if (result.length > (size_t)max_size) {
		VSLb(ctx->vsl, SLT_Error,
			"deliver_transform: response of %zu bytes is over the %jd byte limit",
			result.length, (intmax_t)max_size);
		return (0);
	}

	oaref_t oaref;
	struct objcore *oc = deliver_new_object(ctx, &result, &oaref);
	if (oc == NULL)
		return (0);

	/* Let go of the original, the way cnt_deliver() does when VCL
	   does not deliver it */
	ObjDerefAttr(req->objcore, &req->oc_oaref);
	AZ(req->oc_oaref);
	if (req->objcore->flags & OC_F_TRANSIENT)
		HSH_Abandon(req->objcore);
	(void)HSH_DerefObjCore(wrk, &req->objcore);
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
