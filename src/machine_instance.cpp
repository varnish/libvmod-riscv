#include "machine_instance.hpp"
#include <libriscv/rsp_server.hpp>

namespace rvs {

MachineInstance::MachineInstance(
	std::vector<uint8_t> elf,
	const vrt_ctx* ctx, SandboxTenant* ten,
	bool debug, bool vcl)
	: binary{std::move(elf)},
	  is_vcl{vcl},
	  script{binary, ctx, ten, *this, false, debug},
	  storage{binary, ctx, ten, *this, true, debug},
	  rspclient{nullptr},
	  callback_entries {}
{
	// sym_vector is now initialized, so we can run
	// through the main function of the tenants VM
	// for both the storage and main VM.
	storage.machine_initialize();
	script.machine_initialize();
	if (is_vcl)
		this->vcl_program = vcl::Program::install(script, *this);
}
MachineInstance::~MachineInstance()
{
}

} // rvs
