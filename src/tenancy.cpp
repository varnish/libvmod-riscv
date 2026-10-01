#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#include <nlohmann/json.hpp>
#include <string_view>
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

/* The map is keyed by a CRC of the name, which anyone can collide, so a
   lookup is only a hit when the name itself matches too. */
inline SandboxTenant* find_tenant(VRT_CTX, std::string_view name)
{
	auto& map = tenants(ctx);
	auto it = map.find(riscv::crc32c(name.data(), name.size()));
	if (it != map.end() && it->second->config.name == name)
		return it->second;
	return nullptr;
}

inline void load_tenant(VRT_CTX, TenantConfig&& config)
{
	try {
		const auto hash = riscv::crc32c(config.name.c_str(), config.name.size());
		auto existing = tenants(ctx).find(hash);
		if (existing != tenants(ctx).end()) {
			if (existing->second->config.name == config.name)
				throw std::runtime_error("Tenant " + config.name + " already existed!");
			throw std::runtime_error("Tenant " + config.name + " has the same hash as tenant "
				+ existing->second->config.name + "; rename one of them");
		}
		tenants(ctx).emplace(hash, new SandboxTenant(ctx, config));
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
		group.argv = std::make_shared<std::vector<std::string>>(
			obj["arguments"].template get<std::vector<std::string>>());
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
				if (auto* tenant = find_tenant(ctx, it.key())) {
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
	return rvs::find_tenant(ctx, {name, namelen});
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
		/* vcl_init is single-threaded, but use copy-and-swap for consistency */
		auto new_argv = std::make_shared<std::vector<std::string>>(*t->config.group.argv);
		new_argv->push_back(arg);
		rvs::atomic_store(&t->config.group.argv, std::move(new_argv));
	} else {
		VSL(SLT_Error, 0,
			"Attempted to add main argument to non-existent tenant '%s'",
			tenant);
	}
}
