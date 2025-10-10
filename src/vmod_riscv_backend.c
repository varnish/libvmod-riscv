#include "vmod_riscv.h"
#include "riscv_backend.h"

#include <malloc.h>
#include <stdlib.h>
#include <vtim.h>
#include "vcl.h"
#include "vcc_if.h"

extern struct vmod_riscv_machine* riscv_current_machine(VRT_CTX);
extern const char* riscv_current_name(VRT_CTX);
extern const char* riscv_name_from_tenant(const void* tenant);
extern void riscv_backend_call(VRT_CTX, const void*, struct vmod_riscv_arguments *, struct backend_result *);
extern int riscv_get_body(struct vmod_riscv_post *post, struct busyobj *bo);

static void v_matchproto_(vdi_panic_f)
riscvbe_panic(const struct director *dir, struct vsb *vsb)
{
	(void)dir;
	(void)vsb;
}

#ifdef VARNISH_PLUS
static void v_matchproto_(vdi_finish_f)
riscvbe_finish(const struct director *dir, struct worker *wrk, struct busyobj *bo)
{
	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	struct vmod_riscv_updater *rvu = (struct vmod_riscv_updater *) dir->priv;
	CHECK_OBJ_NOTNULL(rvu, RISCV_BACKEND_MAGIC);
	//FREE_OBJ(dir);
	//FREE_OBJ(rvu);
	(void) wrk;
	/* */
	bo->htc = NULL;
}
#else
static void v_matchproto_(vdi_finish_f)
riscvbe_finish(VRT_CTX, const struct director *dir)
{
	(void)dir;

	CHECK_OBJ_NOTNULL(ctx->bo, BUSYOBJ_MAGIC);
	struct busyobj *bo = ctx->bo;

	CHECK_OBJ_NOTNULL(bo->htc, HTTP_CONN_MAGIC);
	bo->htc->priv = NULL;
	bo->htc->magic = 0;
	bo->htc = NULL;
}
#endif

static enum vfp_status v_matchproto_(vfp_pull_f)
pull(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p, ssize_t *lp)
{
	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
	AN(p);
	AN(lp);

	struct backend_result *result = (struct backend_result *)vfe->priv1;
	if (result->content_length == 0) {
		*lp = 0;
		return (VFP_END);
	}

	struct VMBuffer *current = &result->buffers[vfe->priv2];
	ssize_t max = *lp;
	ssize_t written = 0;

	while (1) {
		ssize_t len = (current->size > max) ? max : current->size;
		memcpy(p, current->data, len);
		p = (void *) ((char *)p + len);
		current->data += len;
		current->size -= len;
		written += len;

		/* Go to next buffer, or end if no more */
		if (current->size == 0) {
			/* Go to next buffer */
			vfe->priv2 ++;
			/* Reaching bufcount means end of fetch */
			if (vfe->priv2 == (ssize_t)result->bufcount) {
				assert(current->size == 0);
				*lp = written;
				return (VFP_END);
			}
			current = &result->buffers[vfe->priv2];
		}
		/* Return later if there's more, and we can't send more */
		max -= len;
		if (max == 0) {
			assert(vfe->priv2 < (ssize_t)result->bufcount);
			*lp = written;
			return (VFP_OK);
		}
	}
}

static const struct vfp riscv_fetch_processor = {
	.name = "riscv_backend",
	.pull = pull,
};

static int
vfp_init(struct busyobj *bo, const char *name)
{
	CHECK_OBJ_NOTNULL(bo->vfc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(bo->htc, HTTP_CONN_MAGIC);

	struct vfp *vfp = WS_Alloc(bo->ws, sizeof *vfp);
	if (vfp == NULL)
		return (-1);
	vfp->name = name;
	vfp->pull = &pull;

	struct vfp_entry *vfe =
		VFP_Push(bo->vfc, &riscv_fetch_processor);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);

	vfe->priv1 = bo->htc->priv;
	vfe->priv2 = 0;
	return (0);
}

#ifdef VARNISH_PLUS
static int v_matchproto_(vdi_gethdrs_f)
riscvbe_gethdrs(const struct director *dir,
	struct worker *wrk, struct busyobj *bo)
{
	(void)wrk;
	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
	CHECK_OBJ_NOTNULL(bo->bereq, HTTP_MAGIC);
	CHECK_OBJ_NOTNULL(bo->beresp, HTTP_MAGIC);
	AZ(bo->htc);
#else
static int v_matchproto_(vdi_gethdrs_f)
riscvbe_gethdrs(const struct vrt_ctx *other_ctx, const struct director *dir)
{
	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	struct busyobj *bo = other_ctx->bo;

	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
	CHECK_OBJ_NOTNULL(bo->bereq, HTTP_MAGIC);
	CHECK_OBJ_NOTNULL(bo->beresp, HTTP_MAGIC);
	AZ(bo->htc);
#endif

	/* Produce backend response */
	struct vmod_riscv_response *rvr;
	CAST_OBJ_NOTNULL(rvr, dir->priv, RISCV_BACKEND_MAGIC);

	const struct vrt_ctx ctx = {
		.magic = VRT_CTX_MAGIC,
		.vcl = bo->vcl,
#ifndef VARNISH_PLUS
		.vpi = bo->wrk->vpi,
#endif
		.ws  = bo->ws,
		.vsl = bo->vsl,
		.req = NULL,
		.bo  = bo,
		.http_bereq  = bo->bereq,
		.http_beresp = bo->beresp,
	};

	/* Request body first, then VM result */
#ifdef VARNISH_PLUS
	const int is_post =
		(bo->initial_req_body_status != REQ_BODY_NONE || bo->bereq_body != NULL);
#else
	/// XXX: Is this correct?
	const int is_post = (bo->bereq_body != NULL
		|| (bo->req != NULL && bo->req->req_body_status != NULL && bo->req->req_body_status->avail));
#endif
	if (is_post)
	{
		/* Retrieve body by copying directly into VM. */
		struct vmod_riscv_post *post = &rvr->arguments.post;
		post->ctx = &ctx;
		post->address = 0;
		post->capacity = POST_BUFFER;
		post->length  = 0;

		const int ret = riscv_get_body(post, bo);
		if (ret < 0) {
			VSLb(ctx.vsl, SLT_Error,
				"riscv: Unable to aggregate request body data for program %s",
				riscv_name_from_tenant(rvr->machine));
			return (-1);
		}
	}

	struct backend_result *result =
		(struct backend_result *)WS_Alloc(bo->ws, VMBE_RESULT_SIZE);
	if (result == NULL) {
		VSLb(ctx.vsl, SLT_Error, "Backend VM: Out of workspace for result");
		return (-1);
	}
	result->bufcount = VMBE_NUM_BUFFERS;

	riscv_backend_call(&ctx, rvr->priv_key, &rvr->arguments, result);

	/* Status code is sanitized in the backend call */
	http_PutResponse(bo->beresp, "HTTP/1.1", result->status, NULL);
	/* Allow missing content-type when no content present */
	if (result->content_length > 0)
	{
		http_PrintfHeader(bo->beresp, "Content-Type: %.*s",
			(int) result->tsize, result->type);
		http_PrintfHeader(bo->beresp,
			"Content-Length: %zu", result->content_length);
	}

	char timestamp[VTIM_FORMAT_SIZE];
	VTIM_format(VTIM_real(), timestamp);
	http_PrintfHeader(bo->beresp, "Last-Modified: %s", timestamp);

	bo->htc = WS_Alloc(bo->ws, sizeof *bo->htc);
	if (bo->htc == NULL)
		return (-1);
	INIT_OBJ(bo->htc, HTTP_CONN_MAGIC);

	/* store the output in workspace and free result */
	bo->htc->content_length = result->content_length;
	bo->htc->priv = (void *)result;
	bo->htc->body_status = BS_LENGTH;
#ifndef VARNISH_PLUS
	bo->htc->doclose = SC_REM_CLOSE;
#endif

	return vfp_init(bo, riscv_name_from_tenant(rvr->machine));
}

#ifndef VARNISH_PLUS
static const struct vdi_methods riscv_director_methods[1] = {{
	.magic = VDI_METHODS_MAGIC,
	.type  = "riscv_director_methods",
	.gethdrs = riscvbe_gethdrs,
	.finish  = riscvbe_finish,
	.panic   = riscvbe_panic,
}};
#endif
static void setup_backend_director(const struct vrt_ctx *ctx,
	struct director *dir, struct vmod_riscv_response *rvr)
{
	INIT_OBJ(dir, DIRECTOR_MAGIC);
	dir->priv = rvr;
	dir->vcl_name = "vmod_riscv";
#ifdef VARNISH_PLUS
	dir->name = "VM backend director";
	dir->gethdrs = riscvbe_gethdrs;
	dir->finish  = riscvbe_finish;
	dir->panic   = riscvbe_panic;
#else
	struct vcldir *vdir =
		WS_Alloc(ctx->ws, sizeof(struct vcldir));
	if (vdir == NULL) {
		VRT_fail(ctx, "RISC-V: Out of workspace for director");
		return;
	}
	memset(vdir, 0, sizeof(*vdir));
	vdir->magic = VCLDIR_MAGIC;
	vdir->dir = dir;
	vdir->vcl = ctx->vcl;
	vdir->flags |= VDIR_FLG_NOREFCNT;
	vdir->methods = riscv_director_methods;

	dir->vdir = vdir;
#endif
	if (rvr->machine != NULL) {
		dir->vcl_name = riscv_name_from_tenant(rvr->machine);
	}
}

VCL_BACKEND vmod_vm_backend(VRT_CTX, VCL_STRING func, VCL_STRING farg)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	struct vmod_riscv_response *rvr;
	rvr = WS_Alloc(ctx->ws, sizeof(struct vmod_riscv_response));
	if (rvr == NULL) {
		VRT_fail(ctx, "Out of workspace");
		return NULL;
	}

	INIT_OBJ(rvr, RISCV_BACKEND_MAGIC);
	rvr->priv_key = ctx->bo;
	rvr->machine = riscv_current_machine(ctx);
	if (rvr->machine == NULL) {
		VRT_fail(ctx, "VM backend: No active tenant");
		return NULL;
	}

	if (func) {
		rvr->arguments.funcaddr = atoi(func);
		rvr->arguments.funcarg  = atoi(farg);
		/* TODO: If it's null, should we abandon? */
		if (rvr->arguments.funcaddr == 0x0) {
			return (NULL);
		}
	}
	rvr->arguments.max_response_size = 0;

	setup_backend_director(ctx, &rvr->dir, rvr);

	return &rvr->dir;
}
