#include "vmod_riscv.h"

#include "riscv_backend.h"
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include "vcl.h"
#include "vcc_if.h"

extern int riscv_backend_streaming_post(struct vmod_riscv_post *, const void*, ssize_t);

#ifdef VARNISH_PLUS
static int
riscv_get_aggregate_body(void *priv, int flush, int last, const void *ptr, ssize_t len)
{
	struct vmod_riscv_post *post = (struct vmod_riscv_post *)priv;
	(void)flush;
	(void)last;

	/* We will want to call backend stream once per segment, and not
	   finally with len=0 and last=1. Instead we can use the on_post
	   callback to trigger any finishing logic. The on_post callback
	   will get called right after returning from here. */
	if (len != 0)
		return (riscv_backend_streaming_post(post, ptr, len));
	else
		return (0);
}
#else // open-source
static int
riscv_get_aggregate_body(void *priv, unsigned flush, const void *ptr, ssize_t len)
{
	struct vmod_riscv_post *post = (struct vmod_riscv_post *)priv;
	(void)flush;

	/* We will want to call backend stream once per segment, and not
	   finally with len=0 and last=1. Instead we can use the on_post
	   callback to trigger any finishing logic. The on_post callback
	   will get called right after returning from here. */
	if (len != 0)
		return (riscv_backend_streaming_post(post, ptr, len));
	else
		return (0);
}
#endif

int riscv_get_body(struct vmod_riscv_post *post, struct busyobj *bo)
{
	post->length = 0;
#ifdef VARNISH_PLUS
	if (bo->req)
		return (VRB_Iterate(bo->req, riscv_get_aggregate_body, post));
	else if (bo->bereq_body)
		return (ObjIterate(bo->wrk, bo->bereq_body, post,
			riscv_get_aggregate_body, 0, 0, -1));
#else
	if (bo->req)
		return (VRB_Iterate(bo->wrk, bo->vsl, bo->req, riscv_get_aggregate_body, post));
	else if (bo->bereq_body)
		return (ObjIterate(bo->wrk, bo->bereq_body, post,
			riscv_get_aggregate_body, 0));
#endif
	fprintf(stderr, "riscv_get_body: no body to read\n");
	return (-1);
}
