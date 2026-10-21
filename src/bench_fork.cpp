/* PROTOTYPE: measure what a tenant VM costs a request, per phase.
   Runs acquire -> vcall(ON_REQUEST) -> release N times inside the
   calling task, rolling back the workspace and the request headers
   after each round, so every round sees the same request. */
#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#include <algorithm>
#include <chrono>
#include <x86intrin.h>
extern "C" {
#include "update_result.h"
}
extern "C" long riscv_call_idx(rvs::Script*, VRT_CTX, vcall_info, const char*);
extern "C" rvs::SandboxTenant* tenant_find(struct vmod_priv*, const char* name, size_t namelen);

namespace {
using namespace rvs;

struct Phase {
	const char* name;
	std::vector<uint64_t> ticks;
};

struct HttpSnapshot {
	explicit HttpSnapshot(struct http* hp)
		: hp(hp), nhd(hp->nhd), hd(hp->hd, hp->hd + hp->nhd), hdf(hp->hdf, hp->hdf + hp->nhd) {}
	void restore() {
		std::copy(hd.begin(), hd.end(), hp->hd);
		std::copy(hdf.begin(), hdf.end(), hp->hdf);
		hp->nhd = nhd;
	}
	struct http* hp;
	uint16_t nhd;
	std::vector<txt> hd;
	std::vector<unsigned char> hdf;
};

std::string summarize(std::vector<Phase>& phases, double ns_per_tick)
{
	std::string out;
	char buf[256];
	for (auto& p : phases) {
		auto& v = p.ticks;
		std::sort(v.begin(), v.end());
		const auto pct = [&] (double q) { return v[size_t(q * (v.size() - 1))] * ns_per_tick; };
		double sum = 0;
		for (auto t : v) sum += t;
		snprintf(buf, sizeof(buf), "%s: p50=%.0f p90=%.0f p99=%.0f mean=%.0f max=%.0f; ",
			p.name, pct(0.5), pct(0.9), pct(0.99), sum / v.size() * ns_per_tick, v.back() * ns_per_tick);
		out += buf;
	}
	return out;
}
} // namespace

extern "C"
const char* riscv_bench_fork(VRT_CTX, struct vmod_priv* priv,
	const char* tenant_name, long iterations, const char* mode)
{
	auto* tenant = tenant_find(priv, tenant_name, strlen(tenant_name));
	if (tenant == nullptr || ctx->req == nullptr || iterations <= 0)
		return "bench_fork: no such tenant, or not in a client task";
	auto prog = rvs::atomic_load(&tenant->program);
	if (prog == nullptr)
		return "bench_fork: no program";

	const bool m_fork    = strcmp(mode, "FORK") == 0;
	const bool m_clear   = strcmp(mode, "CLEAR") == 0;
	const bool m_restore = strcmp(mode, "RESTORE") == 0;
	const bool m_warm    = strcmp(mode, "WARM") == 0;
	const vcall_info on_request {1, GUEST_HDR_REQ, int(UINT32_MAX)};

	std::vector<Phase> phases {{"acquire", {}}, {"call", {}}, {"release", {}}, {"total", {}}, {"rollback", {}}};
	for (auto& p : phases) p.ticks.reserve(iterations);

	HttpSnapshot http_snap(ctx->http_req);
	Script* warm = nullptr;
	if (m_warm)
		warm = tenant->pool_acquire(ctx, prog);

	size_t pages_total = 0, pages_written = 0;

	const auto wall0 = std::chrono::steady_clock::now();
	const uint64_t tsc0 = __rdtsc();
	try {
	for (long i = 0; i < iterations; i++)
	{
		const auto ws_snap = WS_Snapshot(ctx->ws);
		const uint64_t t0 = __rdtsc();
		Script* script;
		if (m_fork) {
			uintptr_t saddr = (uintptr_t)WS_Alloc(ctx->ws, sizeof(Script) + 0x20);
			saddr = (saddr + 0x1F) & ~(uintptr_t)0x1F;
			script = (Script*) saddr;
			new (script) Script{prog->script, ctx, tenant, *prog};
			auto ref = prog;
			script->assign_instance(ref);
		} else if (m_warm) {
			script = warm;
			script->set_ctx(ctx);
		} else {
			script = tenant->pool_acquire(ctx, prog);
		}
		const uint64_t t1 = __rdtsc();
		riscv_call_idx(script, ctx, on_request, nullptr);
		const uint64_t t2 = __rdtsc();
		if (i == iterations - 1) {
			for (auto& [pageno, page] : script->machine().memory.pages()) {
				pages_total++;
				if (page.attr.write) pages_written++;
			}
		}
		if (m_fork)
			script->~Script();
		else if (!m_warm)
			SandboxTenant::pool_release(script, m_restore);
		const uint64_t t3 = __rdtsc();

		http_snap.restore();
		WS_Reset(ctx->ws, ws_snap);
		const uint64_t t4 = __rdtsc();
		phases[4].ticks.push_back(t4 - t3);
		phases[0].ticks.push_back(t1 - t0);
		phases[1].ticks.push_back(t2 - t1);
		phases[2].ticks.push_back(t3 - t2);
		phases[3].ticks.push_back(t3 - t0);
	}
	} catch (const std::exception& e) {
		VRT_fail(ctx, "bench_fork: %s", e.what());
		return nullptr;
	}
	const uint64_t tsc1 = __rdtsc();
	const auto wall1 = std::chrono::steady_clock::now();
	if (warm)
		SandboxTenant::pool_release(warm);
	(void)m_clear;

	const double ns = std::chrono::duration<double, std::nano>(wall1 - wall0).count();
	const double ns_per_tick = ns / double(tsc1 - tsc0);
	std::string result = std::string(mode) + " x" + std::to_string(iterations) + ": "
		+ summarize(phases, ns_per_tick);
	char buf[128];
	snprintf(buf, sizeof(buf), "avg=%.0fns/iter pages=%zu written=%zu sizeof(Script)=%zu",
		ns / iterations, pages_total, pages_written, sizeof(Script));
	result += buf;
	printf("[bench_fork] %s\n", result.c_str());
	fflush(stdout);
	if (const char* path = getenv("RISCV_BENCH_OUT"); path != nullptr) {
		if (FILE* f = fopen(path, "a"); f != nullptr) {
			fprintf(f, "%s %s\n", tenant_name, result.c_str());
			fclose(f);
		}
	}
	VSLb(ctx->vsl, SLT_VCL_Log, "bench_fork %s", result.c_str());
	return (const char*) WS_Copy(ctx->ws, result.c_str(), int(result.size() + 1));
}

extern "C" long riscv_pooled_vms()
{
	return rvs::SandboxTenant::pooled_count();
}
