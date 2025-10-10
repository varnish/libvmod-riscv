#include "sandbox_tenant.hpp"
#include "varnish.hpp"
extern "C" {
#include "update_result.h"
}
struct CallResults {
	long results[3];
};

namespace rvs
{
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
}

extern "C"
rvs::Script* riscv_fork(VRT_CTX, const char* tenant, size_t tenantlen, int debug)
{
	using namespace rvs;

	extern SandboxTenant* tenant_find(VRT_CTX, const char* name, size_t namelen);
	auto* tenptr = tenant_find(ctx, tenant, tenantlen);
	if (UNLIKELY(tenptr == nullptr))
		return nullptr;

	return tenptr->vmfork(ctx, debug);
}

extern "C"
int riscv_delete(VRT_CTX)
{
	using namespace rvs;

	auto* script = rvs::get_machine(ctx);
	if (script)
	{
		script->~Script();
		return 0;
	}
	return -1;
}

extern "C"
int  riscv_apply_hash(rvs::Script* script)
{
	return script->apply_hash();
}

extern "C"
long riscv_call_idx(rvs::Script* script, VRT_CTX, vcall_info info)
{
	using namespace rvs;

	const auto& callbacks = script->program().callback_entries;
	if (info.idx < callbacks.size())
	{
		auto addr = callbacks[info.idx];
		if (addr == 0x0) {
			VSLb(ctx->vsl, SLT_Error,
				"VM call '%s' skipped: The function at index %d is not available",
				callback_names.at(info.idx), info.idx);
			return -1;
		}
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t1);
	#endif
		// VRT ctx can easily change even on the same request due to waitlist
		script->set_ctx(ctx);
		int ret = script->call(addr, (int) info.arg1, (int) info.arg2);
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t2);
		timing_vmcall.add(t1, t2);
	#endif
		return ret;
	}
	VRT_fail(ctx, "VM call failed (invalid index given: %d)", info.idx);
	return -1;
}
extern "C"
const char* riscv_current_call(VRT_CTX,
	const char* func, const char* arg)
{
	if (func == nullptr) {
		VRT_fail(ctx, "VM call failed: no function name given");
		return nullptr;
	}
	using namespace rvs;

	auto* script = rvs::get_machine(ctx);
	if (script == nullptr) {
		VRT_fail(ctx, "No active RISC-V VM for this request");
		return nullptr;
	}

	try {
		const auto it = script->program().function_map.find(func);
		if (it == script->program().function_map.end()) {
			VRT_fail(ctx, "VM call failed: function '%s' not registered", func);
			return nullptr;
		}
		const auto addr = it->second;
		if (addr == 0) {
			VRT_fail(ctx, "VM call failed: function '%s' not found", func);
			return nullptr;
		}
		// VRT ctx can easily change even on the same request due to waitlist
		script->set_ctx(ctx);
		arg = arg ? arg : "";
		const size_t arglen = arg ? strlen(arg) : 0;
		long result = script->call(addr, arg, arglen);
		if (result == 0) {
			return nullptr;
		}
		// Read the string from guest memory
		const std::string str =
			script->machine().memory.memstring(result);
		// Allocate it on the workspace to return
		char* ws_ptr = (char*)WS_Alloc(ctx->ws, str.size() + 1);
		if (ws_ptr == nullptr) {
			VRT_fail(ctx, "VM call failed: out of workspace");
			return nullptr;
		}
		memcpy(ws_ptr, str.data(), str.size() + 1);
		return ws_ptr;
	} catch (const std::exception& e) {
		VRT_fail(ctx, "VM call failed: exception: %s", e.what());
		return nullptr;
	}
}

extern "C"
long riscv_result_values(rvs::Script* script, struct CallResults *cr)
{
	cr->results[0] = script->want_values().at(0);
	cr->results[1] = script->want_values().at(1);
	cr->results[2] = script->want_values().at(2);
	return 0;
}
