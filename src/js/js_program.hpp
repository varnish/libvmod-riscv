#pragma once
#include <memory>
#include <string>
#include <string_view>

struct vrt_ctx;
namespace rvs {
struct MachineInstance;
struct SandboxTenant;
}

namespace rvs::js {

/* Load a `.js` file as a tenant program: the embedded QuickJS guest
   (program/js.elf), with the file as its last argument, which it evaluates
   once in main(). Throws if the file cannot be read or main() fails. */
std::shared_ptr<MachineInstance> load(const std::string& path,
	const struct vrt_ctx*, struct SandboxTenant*);

/* Whether a tenant filename names JavaScript source rather than a program. */
bool is_js_source(std::string_view filename);

} // rvs::js
