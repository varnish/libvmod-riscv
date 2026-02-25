#include "vmod_riscv_sandbox.h"

#include <string.h>
#include <cache/cache.h>
#include <vsha256.h>
#include <vcl.h>

#include "vcc_if.h"
#include "vmod_util.h"
#include "update_result.h" // vcall_info

extern void init_tenants_str(VRT_CTX, const char*);
extern void init_tenants_file(VRT_CTX, const char*);
extern void finalize_tenants_impl(VRT_CTX);
extern void tenant_append_main_argument(VRT_CTX, const char*, const char*);

extern void* riscv_fork(VRT_CTX, const char* ten, size_t tenlen, int dbg);
// Functions operating on a machine already forked, which
// is accessible through a priv_task.
extern const char* riscv_current_call(VRT_CTX, const char*, const char*);
extern long riscv_current_call_idx(VRT_CTX, vcall_info, const char*);
extern long riscv_current_resume(VRT_CTX);
extern const char* riscv_current_name(VRT_CTX);
extern const char* riscv_current_group(VRT_CTX);
extern const char* riscv_current_result(VRT_CTX);
extern long riscv_current_result_value(VRT_CTX, size_t);
extern const char* riscv_current_result_string(VRT_CTX, size_t);
extern int  riscv_current_is_paused(VRT_CTX);
extern int  riscv_current_apply_hash(VRT_CTX);

#define HDR_INVALID   UINT32_MAX
static inline vcall_info enum_to_idx(VCL_ENUM e)
{
#ifdef VARNISH_PLUS
#define VENUM(x) vmod_enum_##x
#endif
	if (e == VENUM(ON_REQUEST)) return (vcall_info){1, HDR_REQ, HDR_INVALID};
	if (e == VENUM(ON_HASH))    return (vcall_info){2, HDR_INVALID, HDR_INVALID};
	if (e == VENUM(ON_SYNTH))   return (vcall_info){3, HDR_REQ, HDR_RESP};
	if (e == VENUM(ON_BACKEND_FETCH)) return (vcall_info){4, HDR_BEREQ, HDR_BERESP};
	if (e == VENUM(ON_BACKEND_RESPONSE)) return (vcall_info){5, HDR_BEREQ, HDR_BERESP};
	if (e == VENUM(ON_BACKEND_ERROR)) return (vcall_info){6, HDR_BEREQ, HDR_BERESP};
	if (e == VENUM(ON_DELIVER)) return (vcall_info){7, HDR_REQ, HDR_RESP};
	if (e == VENUM(ON_HIT))    return (vcall_info){8, HDR_REQ, HDR_OBJ};
	if (e == VENUM(ON_MISS))   return (vcall_info){9, HDR_REQ, HDR_BEREQ};

	if (e == VENUM(ON_LIVE_UPDATE)) return (vcall_info){10, HDR_INVALID, HDR_INVALID};
	if (e == VENUM(ON_RESUME_UPDATE)) return (vcall_info){11, HDR_INVALID, HDR_INVALID};
	return (vcall_info){-1, HDR_INVALID, HDR_INVALID};
}

/* Load tenant information from a JSON string */
VCL_VOID vmod_embed_tenants(VRT_CTX, VCL_STRING str)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	init_tenants_str(ctx, str);
}
/* Finalize tenant loading: actually instantiate all VM programs.
   Call after embed_tenants/load_tenants and any add_main_argument calls. */
VCL_VOID vmod_finalize_tenants(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	finalize_tenants_impl(ctx);
}
/* Load tenant information from a JSON file */
VCL_VOID vmod_load_tenants(VRT_CTX, VCL_STRING filename)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	init_tenants_file(ctx, filename);
}
/* Append to a tenants main function arguments. */
VCL_VOID vmod_add_main_argument(VRT_CTX, VCL_STRING tenant, VCL_STRING arg)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	tenant_append_main_argument(ctx, tenant, arg);
}

/* Fork into a new VM. The VM is freed when the
   request (priv_task) ends. */
VCL_BOOL vmod_fork(VRT_CTX, VCL_STRING tenant, VCL_STRING debug)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_fork(ctx, tenant, strlen(tenant), debug != NULL) != NULL;
}

/* Check if there is a VM currently for this request. */
VCL_BOOL vmod_active(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_name(ctx) != NULL;
}
VCL_INT vmod_vcall(VRT_CTX, VCL_ENUM e)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_call_idx(ctx, enum_to_idx(e), NULL);
}
VCL_INT vmod_run(VRT_CTX, VCL_STRING arg)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	VCL_ENUM e = VENUM(ON_REQUEST);
	switch (ctx->method) {
	case VCL_MET_RECV:
		e = VENUM(ON_REQUEST); break;
	case VCL_MET_HASH:
		e = VENUM(ON_HASH); break;
	case VCL_MET_SYNTH:
		e = VENUM(ON_SYNTH); break;
	case VCL_MET_BACKEND_FETCH:
		e = VENUM(ON_BACKEND_FETCH); break;
	case VCL_MET_BACKEND_RESPONSE:
		e = VENUM(ON_BACKEND_RESPONSE); break;
	case VCL_MET_BACKEND_ERROR:
		e = VENUM(ON_BACKEND_ERROR); break;
	case VCL_MET_HIT:
		e = VENUM(ON_HIT); break;
	case VCL_MET_MISS:
		e = VENUM(ON_MISS); break;
	case VCL_MET_DELIVER:
		e = VENUM(ON_DELIVER); break;
	default:
		/* Unsupported method */
		if (ctx && ctx->vsl) {
			VSLb(ctx->vsl, SLT_Error, 0,
				"riscv.run() called from unsupported VCL method %d", ctx->method);
		}
		return -1;
	}

	return riscv_current_call_idx(ctx, enum_to_idx(e), arg);
}
VCL_STRING vmod_call(VRT_CTX, VCL_STRING function, VCL_STRING arg)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return (riscv_current_call(ctx, function, arg));
}
VCL_INT vmod_resume(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_resume(ctx);
}
VCL_STRING vmod_current_name(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_name(ctx);
}

/* Returns a string that represents what the VM wants to happen next.
   Such as: "lookup", "synth", ... */
VCL_STRING vmod_want_result(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_result(ctx);
}
/* Returns the status code the VM wants to return, when relevant.
   Such as when calling synth(). */
VCL_INT vmod_want_status(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_result_value(ctx, 0);
}
VCL_INT vmod_result_value(VRT_CTX, VCL_INT idx)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_result_value(ctx, idx);
}
VCL_STRING vmod_result_as_string(VRT_CTX, VCL_INT idx)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_result_string(ctx, idx);
}
VCL_BOOL vmod_want_resume(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_is_paused(ctx);
}
VCL_BOOL vmod_apply_hash(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	return riscv_current_apply_hash(ctx);
}
