#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rvs::vcl {

struct Compiled
{
	std::vector<uint8_t> elf;
	/* Rendered compiler warnings, one per entry, for the log. */
	std::vector<std::string> warnings;
};

/**
 * Compile a tenant's `.vcl` file into a tenant program, inside the sandbox.
 *
 * The compiler is vcl/compiler built as a RISC-V guest (vcl/vclc.elf,
 * embedded in this VMOD), so a tenant's VCL source is compiled in the same
 * kind of VM its compiled policy runs in: an instruction budget, a memory
 * ceiling, no filesystem and no sockets. Each compile gets a fresh machine,
 * so nothing crosses from one tenant's source to the next.
 *
 * `include "x.vcl";` is answered by the host, confined to the directory of
 * `path`. Throws std::runtime_error carrying the rendered diagnostics when
 * the policy does not compile, or naming the limit a compile ran into.
 */
Compiled compile(const std::string& path);

} // rvs::vcl
