#include "js_program.hpp"
#include "../machine_instance.hpp"
#include "../sandbox_tenant.hpp"

/* js_blob.c */
extern "C" const uint8_t js_elf[];
extern "C" const uint8_t js_elf_end[];

namespace rvs {
extern std::vector<uint8_t> file_loader(const std::string& filename);
}

namespace rvs::js {

bool is_js_source(std::string_view filename)
{
	return filename.size() > 3 && filename.substr(filename.size() - 3) == ".js";
}

std::shared_ptr<MachineInstance> load(const std::string& path,
	const vrt_ctx* ctx, SandboxTenant* tenant)
{
	const auto source = file_loader(path);

	/* Only a new machine reads argv, in its main(), so the source is
	   appended for as long as this one is constructed. The caller makes
	   sure that nothing else constructs one meanwhile: the tenant is not
	   published yet, or its update_mtx is held. */
	const auto argv = rvs::atomic_load(&tenant->config.group.argv);
	auto with_source = std::make_shared<std::vector<std::string>>(*argv);
	with_source->emplace_back(source.begin(), source.end());
	rvs::atomic_store(&tenant->config.group.argv, std::move(with_source));
	struct Restore {
		SandboxTenant* tenant;
		const std::shared_ptr<std::vector<std::string>>& argv;
		~Restore() { rvs::atomic_store(&tenant->config.group.argv, argv); }
	} restore{tenant, argv};

	return std::make_shared<MachineInstance>(
		std::vector<uint8_t>(js_elf, js_elf_end), ctx, tenant);
}

} // rvs::js
