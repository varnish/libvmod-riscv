#include "sandbox_tenant.hpp"
#include "varnish.hpp"
extern "C" {
#include "update_result.h"
}
extern "C" long riscv_call_idx(rvs::Script*, VRT_CTX, vcall_info);

//#define ENABLE_TIMING
#ifdef ENABLE_TIMING
#include "timing.hpp"
#endif

namespace rvs {
#ifdef ENABLE_TIMING
static Timing timing_vmcall {"vmcall"};
#endif

inline Script* get_machine(VRT_CTX, const void* key)
{
	auto* priv_task = VRT_priv_task(ctx, key);
	//printf("priv_task: ctx=%p bo=%p key=%p task=%p\n", ctx, ctx->bo, key, priv_task);
	if (priv_task->priv && (unsigned)priv_task->len == SCRIPT_MAGIC)
		return (Script*) priv_task->priv;
	return nullptr;
}
inline Script* get_machine(VRT_CTX)
{
	if (ctx->req)
		return get_machine(ctx, ctx->req);
	return get_machine(ctx, ctx->bo);
}

} // rvs

extern "C"
const rvs::SandboxTenant* riscv_current_machine(VRT_CTX)
{
	auto* script = rvs::get_machine(ctx);
	if (script) {
		return script->vrm();
	}
	return nullptr;
}

extern "C"
long riscv_current_call_idx(VRT_CTX, vcall_info info)
{
	using namespace rvs;

	auto* script = get_machine(ctx);
	if (script) {
		return riscv_call_idx(script, ctx, info);
	}
	VRT_fail(ctx, "current_call_idx() failed (no running machine)");
	return -1;
}
extern "C"
long riscv_current_resume(VRT_CTX)
{
	auto* script = rvs::get_machine(ctx);
	if (script) {
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t1);
	#endif
		long ret = script->resume(script->max_instructions());
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t2);
		printf("Time spent in resume(): %ld ns\n", nanodiff(t1, t2));
	#endif
		return ret;
	}
	return -1;
}

extern "C"
const char* riscv_current_name(VRT_CTX)
{
	auto* script = rvs::get_machine(ctx);
	if (script)
		return script->name().c_str();
	return nullptr;
}
extern "C"
const char* riscv_name_from_tenant(const rvs::SandboxTenant* tenant)
{
	if (tenant) {
		return tenant->config.name.c_str();
	}
	return nullptr;
}
extern "C"
const char* riscv_current_result(VRT_CTX)
{
	auto* script = rvs::get_machine(ctx);
	if (script)
		return script->want_result();
	return nullptr;
}
extern "C"
long riscv_current_result_value(VRT_CTX, size_t idx)
{
	auto* script = rvs::get_machine(ctx);
	if (script && idx < rvs::Script::RESULTS_MAX)
		return script->want_values().at(idx);
	return 503;
}
extern "C"
const char* riscv_current_result_string(VRT_CTX, size_t idx)
{
	auto* script = rvs::get_machine(ctx);
	if (script && idx < rvs::Script::RESULTS_MAX)
		return script->want_workspace_string(idx);
	return nullptr;
}
extern "C"
int  riscv_current_is_paused(VRT_CTX)
{
	auto* script = rvs::get_machine(ctx);
	if (script)
		return script->is_paused();
	return 0;
}
extern "C"
int  riscv_current_apply_hash(VRT_CTX)
{
	auto* script = rvs::get_machine(ctx);
	if (script)
		return script->apply_hash();
	return 0;
}
extern "C"
int  riscv_current_copy_to_machine(VRT_CTX, const void* data, size_t size, rvs::Script::gaddr_t addr)
{
	auto* script = rvs::get_machine(ctx);
	if (script) {
		script->machine().copy_to_guest(addr, data, size);
		return 1;
	}
	return 0;
}
extern "C"
uint64_t  riscv_current_mmap_allocate(VRT_CTX, size_t size)
{
	auto* script = rvs::get_machine(ctx);
	if (script) {
		return script->machine().memory.mmap_allocate(size);
	}
	return 0;
}
