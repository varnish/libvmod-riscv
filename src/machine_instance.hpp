#pragma once
#include "script.hpp"
#include "vcl/vcl_program.hpp"
#include <mutex>
namespace riscv {
	template <int W> struct RSPClient;
}

namespace rvs {

[[maybe_unused]]
static inline std::array<const char*, 13> callback_names = {
	"Invalid callback",
	"on_recv",
	"on_hash",
	"on_synth",         // 3
	"on_backend_fetch",
	"on_backend_response",
	"on_backend_error",
	"on_deliver",
	"on_hit",
	"on_miss",
	"on_live_update",   // 10
	"on_resume_update", // 11
	"on_pass",          // 12
};

struct MachineInstance
{
	MachineInstance(std::vector<uint8_t>,
		const vrt_ctx*, SandboxTenant*, bool debug = false, bool vcl = false);
	~MachineInstance();

	const std::vector<uint8_t> binary;
	/* A program compiled from VCL (vcl/compiler.hpp) rather than a tenant
	   program that registers its own callbacks. */
	const bool is_vcl;
	Script   script;
	std::array<Script::gaddr_t, 13> callback_entries;
	std::unordered_map<std::string, Script::gaddr_t> function_map;

	Script   storage;
	std::mutex storage_mtx;

	/* Set for a VCL program once its main() has run. */
	std::unique_ptr<vcl::Program> vcl_program;

	std::unique_ptr<riscv::RSPClient<Script::MARCH>> rspclient;
	Script* rsp_script = nullptr;
	std::mutex rsp_mtx;
};

} // rvs
