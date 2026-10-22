#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#include <nlohmann/json.hpp>
#include <string_view>
#include <unordered_set>
#include <libriscv/util/crc32.hpp>
using json = nlohmann::json;

namespace rvs {
extern std::vector<uint8_t> file_loader(const std::string& filename);
using MapType = std::unordered_map<uint32_t, std::shared_ptr<SandboxTenant>>;

/* The tenants of one VCL, kept in its PRIV_VCL. Every VCL has its own, so
   a reload builds a new set beside the running one, and a VCL that fails
   to load leaves the running one untouched.

   It is only written in vcl_init, which is single-threaded, and requests
   do not reach a VCL before its vcl_init has finished, so the request
   path reads it without a lock. */
struct TenantRegistry
{
	static constexpr uint64_t MAGIC = 0x4b1d7e3a90c25f61;
	const uint64_t magic = MAGIC;
	MapType map;
	/* Tenants finalize_tenants() has not yet loaded. Only these are still
	   private to this VCL, so only these may be reconfigured. */
	std::unordered_set<const SandboxTenant*> pending;
};

static void registry_free(void* priv)
{
	delete static_cast<TenantRegistry*>(priv);
}
#ifndef VARNISH_PLUS
static void registry_fini(const struct vrt_ctx* ctx, void* priv)
{
	(void)ctx;
	registry_free(priv);
}
static const struct vmod_priv_methods registry_methods[1] = {{
	.magic = VMOD_PRIV_METHODS_MAGIC,
	.type = "vmod_riscv_tenants",
	.fini = registry_fini
}};
#endif

static inline TenantRegistry* registry(struct vmod_priv* priv)
{
	if (priv == nullptr || priv->priv == nullptr)
		return nullptr;
	auto* reg = static_cast<TenantRegistry*>(priv->priv);
	assert(reg->magic == TenantRegistry::MAGIC);
	return reg;
}
static TenantRegistry& registry_create(struct vmod_priv* priv)
{
	if (auto* reg = registry(priv))
		return *reg;
	auto* reg = new TenantRegistry;
	priv->priv = reg;
#ifdef VARNISH_PLUS
	priv->free = registry_free;
#else
	priv->methods = registry_methods;
#endif
	return *reg;
}

/* Changing the tenants of a VCL while it serves requests would race them. */
static bool in_vcl_init(VRT_CTX, const char* func)
{
	if (ctx->method == VCL_MET_INIT)
		return true;
	VRT_fail(ctx, "riscv.%s() can only be used in vcl_init", func);
	return false;
}

/* Every published tenant by name, across all loaded VCLs, newest last, so
   that a reload can keep running a tenant whose configuration and program
   file did not change. Entries expire with the last VCL holding them. */
static std::mutex& index_mtx()
{
	static std::mutex mtx;
	return mtx;
}
static auto& tenant_index()
{
	static std::unordered_map<std::string,
		std::vector<std::weak_ptr<SandboxTenant>>> index;
	return index;
}

/* Drop what discarded VCLs left behind, including tenants that are no
   longer configured anywhere, whose entries a lookup would never reach. */
static void prune_index()
{
	std::scoped_lock lock(index_mtx());
	auto& index = tenant_index();
	for (auto it = index.begin(); it != index.end(); ) {
		std::erase_if(it->second, [] (const auto& weak) { return weak.expired(); });
		if (it->second.empty())
			it = index.erase(it);
		else
			++it;
	}
}

static std::shared_ptr<SandboxTenant>
find_reusable(const SandboxTenant& fresh, const FileStamp& stamp)
{
	if (!fresh.reusable_source())
		return nullptr;
	std::scoped_lock lock(index_mtx());
	auto it = tenant_index().find(fresh.config.name);
	if (it == tenant_index().end())
		return nullptr;
	auto& list = it->second;
	std::shared_ptr<SandboxTenant> found;
	for (auto rit = list.rbegin(); rit != list.rend() && !found; ++rit)
	{
		auto candidate = rit->lock();
		if (candidate == nullptr)
			continue;
		/* A live update may be swapping its program, argv and stamp */
		std::scoped_lock ulock(candidate->update_mtx);
		if (candidate->file_stamp == stamp
			&& candidate->config.same_as(fresh.config)
			&& rvs::atomic_load(&candidate->program) != nullptr)
			found = std::move(candidate);
	}
	return found;
}

static void publish(const std::shared_ptr<SandboxTenant>& tenant)
{
	std::scoped_lock lock(index_mtx());
	tenant_index()[tenant->config.name].push_back(tenant);
}

/* The map is keyed by a CRC of the name, which anyone can collide, so a
   lookup is only a hit when the name itself matches too. */
inline SandboxTenant* find_tenant(TenantRegistry* reg, std::string_view name)
{
	if (reg == nullptr)
		return nullptr;
	auto it = reg->map.find(riscv::crc32c(name.data(), name.size()));
	if (it != reg->map.end() && it->second->config.name == name)
		return it->second.get();
	return nullptr;
}

inline void load_tenant(VRT_CTX, TenantRegistry& reg, TenantConfig&& config)
{
	try {
		const auto hash = riscv::crc32c(config.name.c_str(), config.name.size());
		auto existing = reg.map.find(hash);
		if (existing != reg.map.end()) {
			if (existing->second->config.name == config.name)
				throw std::runtime_error("Tenant " + config.name + " already existed!");
			throw std::runtime_error("Tenant " + config.name + " has the same hash as tenant "
				+ existing->second->config.name + "; rename one of them");
		}
		auto tenant = std::make_shared<SandboxTenant>(ctx, config);
		reg.pending.insert(tenant.get());
		reg.map.emplace(hash, std::move(tenant));
	} catch (const std::exception& e) {
		VRT_fail(ctx, "Exception when creating machine '%s': %s",
			config.name.c_str(), e.what());
	}
}

template <typename T>
static std::string allow_string(const T& value, const std::string& key)
{
	if (!value.is_string())
		throw std::runtime_error("fetch: \"" + key + "\" of an allow entry must be a string");
	return value.template get<std::string>();
}

/* An allow entry is a URL, or an object with the URL and the TLS files
   for it. Unknown keys are refused: a misspelt "ca_file" would otherwise
   leave the system CAs in place. */
template <typename T>
static FetchAllow parse_fetch_allow(const T& e)
{
	FetchAllow entry;
	if (e.is_string()) {
		entry.url = e.template get<std::string>();
		return entry;
	}
	if (!e.is_object() || !e.contains("url"))
		throw std::runtime_error("fetch: an allow entry is a URL, or an object with \"url\"");
	for (const auto& kv : e.items()) {
		const auto& key = kv.key();
		if (key == "url")
			entry.url = allow_string(kv.value(), key);
		else if (key == "ca_file")
			entry.tls.ca_file = allow_string(kv.value(), key);
		else if (key == "client_cert")
			entry.tls.client_cert = allow_string(kv.value(), key);
		else if (key == "client_key")
			entry.tls.client_key = allow_string(kv.value(), key);
		else
			throw std::runtime_error("fetch: unknown key in allow entry: " + key);
	}
	return entry;
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
	if (obj.contains("fetch")) {
		const auto& f = obj["fetch"];
		FetchConfig fetch;
		std::vector<FetchAllow> allow;
		if (f.contains("allow")) {
			if (!f["allow"].is_array())
				throw std::runtime_error("fetch: \"allow\" must be an array");
			for (const auto& e : f["allow"]) {
				allow.push_back(parse_fetch_allow(e));
			}
		}
		fetch.max_requests = f.value("max_requests", fetch.max_requests);
		fetch.timeout_ms = f.value("timeout_ms", fetch.timeout_ms);
		fetch.connect_timeout_ms = f.value("connect_timeout_ms", fetch.connect_timeout_ms);
		fetch.max_request_body = f.value("max_request_body", fetch.max_request_body);
		fetch.max_response_body = f.value("max_response_body", fetch.max_response_body);
		fetch.max_redirects = f.value("max_redirects", fetch.max_redirects);
		fetch.allow_insecure = f.value("allow_insecure", fetch.allow_insecure);
		fetch.compile(allow);
		group.fetch = std::make_shared<const FetchConfig>(std::move(fetch));
	}
	if (obj.contains("arguments")) {
		group.argv = std::make_shared<std::vector<std::string>>(
			obj["arguments"].template get<std::vector<std::string>>());
	}
}

static void init_tenants(VRT_CTX, struct vmod_priv* priv,
	const std::vector<uint8_t>& vec, const char* source)
{
	SandboxTenant::init();
	auto& reg = registry_create(priv);
	try {
		const json j = json::parse(vec.begin(), vec.end());

		std::map<std::string, TenantGroup> groups {
			{"test", TenantGroup{}}
		};

		/* Groups first: JSON objects are ordered by key, and a tenant
		   may name a group that sorts after it. */
		for (const auto& it : j.items())
		{
			const auto& obj = it.value();
			if (obj.contains("filename"))
				continue;
			// Existing tenant, reconfigure
			if (auto* tenant = find_tenant(&reg, it.key())) {
				if (!reg.pending.contains(tenant)) {
					VRT_fail(ctx, "Tenant '%s' is already finalized and "
						"can not be reconfigured", it.key().c_str());
					continue;
				}
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
		for (const auto& it : j.items())
		{
			const auto& obj = it.value();
			if (!obj.contains("filename"))
				continue;
			std::string grname;
			if (obj.contains("group"))
				grname = obj["group"];
			else
				grname = "test";

			/* Validate the group name */
			auto grit = groups.find(grname);
			if (grit == groups.end()) {
				VSL(SLT_Error, RISCV_NO_VXID,
					"Group '%s' missing for tenant: %s",
					grname.c_str(), it.key().c_str());
				VRT_fail(ctx, "Group '%s' missing for tenant: %s",
					grname.c_str(), it.key().c_str());
				continue;
			}
			// Make a copy of the group
			TenantGroup group = grit->second;
			// Apply any overrides
			configure_tenant(group, obj);
			/* Use the group data except filename */
			load_tenant(ctx, reg, TenantConfig{
				it.key(), obj["filename"], group,
			});
		}
	} catch (const std::exception& e) {
		VSL(SLT_Error, RISCV_NO_VXID,
			"Exception '%s' when loading tenants from: %s",
			e.what(), source);
		/* TODO: VRT_fail here? */
		VRT_fail(ctx, "Exception '%s' when loading tenants from: %s",
			e.what(), source);
	}
}

} // rvs

extern "C"
rvs::SandboxTenant* tenant_find(struct vmod_priv* priv, const char* name, size_t namelen)
{
	if (UNLIKELY(name == nullptr))
		return nullptr;
	return rvs::find_tenant(rvs::registry(priv), {name, namelen});
}

extern "C"
void init_tenants_str(VRT_CTX, struct vmod_priv* priv, const char* str)
{
	if (!rvs::in_vcl_init(ctx, "embed_tenants"))
		return;
	std::vector<uint8_t> json { str, str + strlen(str) };
	rvs::init_tenants(ctx, priv, json, "string");
}

extern "C"
void init_tenants_file(VRT_CTX, struct vmod_priv* priv, const char* filename)
{
	if (!rvs::in_vcl_init(ctx, "load_tenants"))
		return;
	/* Nothing may throw into C */
	std::vector<uint8_t> json;
	try {
		json = rvs::file_loader(filename);
	} catch (const std::exception& e) {
		VRT_fail(ctx, "load_tenants: %s", e.what());
		return;
	}
	rvs::init_tenants(ctx, priv, json, filename);
}

/* Load the program of every pending tenant, unless a VCL that is already
   loaded runs the same tenant with the same configuration from the same
   program file: then this VCL shares that tenant, with its program as live
   updates have left it, instead of loading the file again. */
extern "C"
void finalize_tenants_impl(VRT_CTX, struct vmod_priv* priv)
{
	using namespace rvs;
	if (!in_vcl_init(ctx, "finalize_tenants"))
		return;
	auto* reg = registry(priv);
	if (reg == nullptr)
		return;
	prune_index();
	try {
		for (auto& [hash, tenant] : reg->map) {
			if (!reg->pending.erase(tenant.get()))
				continue;
			/* Stamped before reading, so that a file replaced while it
			   loads is loaded again on the next reload. */
			const auto stamp = FileStamp::of(tenant->program_path());
			if (auto shared = find_reusable(*tenant, stamp)) {
				VSL(SLT_Debug, RISCV_NO_VXID, "Tenant '%s' is unchanged, keeping its program",
					tenant->config.name.c_str());
				tenant = std::move(shared);
				continue;
			}
			/* Not yet published, so nothing else can see it */
			tenant->file_stamp = stamp;
			tenant->load(ctx);
			publish(tenant);
		}
	} catch (const std::exception& e) {
		VRT_fail(ctx, "finalize_tenants: %s", e.what());
	}
}

extern "C"
void tenant_append_main_argument(VRT_CTX, struct vmod_priv* priv,
	const char* tenant, const char* arg)
{
	if (!rvs::in_vcl_init(ctx, "add_main_argument"))
		return;
	auto* reg = rvs::registry(priv);
	auto* t = rvs::find_tenant(reg, tenant);
	if (t == nullptr) {
		VSL(SLT_Error, RISCV_NO_VXID,
			"Attempted to add main argument to non-existent tenant '%s'",
			tenant);
		return;
	}
	/* A finalized tenant may be running in another VCL */
	if (!reg->pending.contains(t)) {
		VRT_fail(ctx, "add_main_argument: tenant '%s' is already finalized",
			tenant);
		return;
	}
	auto new_argv = std::make_shared<std::vector<std::string>>(*t->config.group.argv);
	new_argv->push_back(arg);
	rvs::atomic_store(&t->config.group.argv, std::move(new_argv));
}
