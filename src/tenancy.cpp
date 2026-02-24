#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#include <nlohmann/json.hpp>
#include <libriscv/util/crc32.hpp>
using json = nlohmann::json;

namespace rvs {
extern std::vector<uint8_t> file_loader(const std::string& filename);
using MapType = std::unordered_map<uint32_t, struct SandboxTenant*>;

inline MapType& tenants(VRT_CTX)
{
	(void) ctx;
	static MapType t;
	return t;
}

inline void load_tenant(VRT_CTX, TenantConfig&& config)
{
	try {
		const auto hash = riscv::crc32c(config.name.c_str(), config.name.size());
		auto res = tenants(ctx).try_emplace(
			hash,
			new SandboxTenant(ctx, config));
		if (res.second == false)
			throw std::runtime_error("Tenant " + config.name + " already existed!");
	} catch (const std::exception& e) {
		VRT_fail(ctx, "Exception when creating machine '%s': %s",
			config.name.c_str(), e.what());
	}
}

template <typename T>
static void configure_tenant(TenantGroup& group, const T& obj)
{
	if (obj.contains("max_memory")) {
		group.max_memory_mb = obj["max_memory"];
	}
	if (obj.contains("max_heap")) {
		group.max_heap_mb = obj["max_heap"];
	}
	if (obj.contains("max_instructions")) {
		group.max_instructions = obj["max_instructions"];
	}
	if (obj.contains("arguments")) {
		group.argv = obj["arguments"].template get<std::vector<std::string>>();
	}
}

static void init_tenants(VRT_CTX,
	const std::vector<uint8_t>& vec, const char* source)
{
	SandboxTenant::init();
	try {
		const json j = json::parse(vec.begin(), vec.end());

		std::map<std::string, TenantGroup> groups {
			{"test", TenantGroup{}}
		};

		for (const auto& it : j.items())
		{
			const auto& obj = it.value();
			if (obj.contains("filename"))
			{
				std::string grname;
				if (obj.contains("group"))
					grname = obj["group"];
				else
					grname = "test";

				/* Validate the group name */
				auto grit = groups.find(grname);
				if (grit == groups.end()) {
					VSL(SLT_Error, 0,
						"Group '%s' missing for tenant: %s",
						grname.c_str(), it.key().c_str());
					continue;
				}
				// Make a copy of the group
				TenantGroup group = grit->second;
				// Apply any overrides
				configure_tenant(group, obj);
				/* Use the group data except filename */
				load_tenant(ctx, TenantConfig{
					it.key(), obj["filename"], group,
				});
			} else {
				// Existing tenant, reconfigure
				auto tit = tenants(ctx).find(
					riscv::crc32c(it.key().c_str(), it.key().size())
				);
				if (tit != tenants(ctx).end()) {
					auto& tenant = tit->second;
					auto& group  = tenant->config.group;
					configure_tenant(group, obj);
					continue;
				}
				/* Find or create group */
				auto git = groups.find(it.key());
				if (git == groups.end()) {
					/* New group */
					groups.emplace(it.key(), TenantGroup{});
					git = groups.find(it.key());
				}
				auto& group = git->second;
				configure_tenant(group, obj);
			}
		}
	} catch (const std::exception& e) {
		VSL(SLT_Error, 0,
			"Exception '%s' when loading tenants from: %s",
			e.what(), source);
		/* TODO: VRT_fail here? */
		VRT_fail(ctx, "Exception '%s' when loading tenants from: %s",
			e.what(), source);
	}
}

} // rvs

extern "C"
rvs::SandboxTenant* tenant_find(VRT_CTX, const char* name, size_t namelen)
{
	if (UNLIKELY(name == nullptr))
		return nullptr;
	auto& map = rvs::tenants(ctx);
	const auto hash = riscv::crc32c(name, namelen);
	// regular tenants
	auto it = map.find(hash);
	if (it != map.end())
		return it->second;
	return nullptr;
}

extern "C"
void init_tenants_str(VRT_CTX, const char* str)
{
	std::vector<uint8_t> json { str, str + strlen(str) };
	rvs::init_tenants(ctx, json, "string");
}

extern "C"
void init_tenants_file(VRT_CTX, const char* filename)
{
	const auto json = rvs::file_loader(filename);
	rvs::init_tenants(ctx, json, filename);
}

extern "C"
void finalize_tenants_impl(VRT_CTX)
{
	for (auto& [hash, tenant] : rvs::tenants(ctx)) {
		if (tenant->no_program_loaded()) {
			tenant->load(ctx);
		}
	}
}

extern "C"
void tenant_append_main_argument(VRT_CTX, const char* tenant, const char* arg)
{
	auto t = tenant_find(ctx, tenant, strlen(tenant));
	if (t) {
		t->config.group.argv.push_back(arg);
	} else {
		VSL(SLT_Error, 0,
			"Attempted to add main argument to non-existent tenant '%s'",
			tenant);
	}
}
