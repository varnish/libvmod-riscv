#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace rvs {
/* C++20 deprecates the std::atomic_* free functions for shared_ptr in favor
   of std::atomic<std::shared_ptr<T>>, which GCC 11 (EL9, AL2023) lacks. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
template <typename T>
inline std::shared_ptr<T> atomic_load(const std::shared_ptr<T>* p) {
	return std::atomic_load(p);
}
template <typename T>
inline void atomic_store(std::shared_ptr<T>* p, std::type_identity_t<std::shared_ptr<T>> v) {
	std::atomic_store(p, std::move(v));
}
template <typename T>
inline std::shared_ptr<T> atomic_exchange(std::shared_ptr<T>* p, std::type_identity_t<std::shared_ptr<T>> v) {
	return std::atomic_exchange(p, std::move(v));
}
#pragma GCC diagnostic pop

/* TLS files for the requests to an origin, as absolute paths. They are
   the host's: the guest never sees them, and can not pick others. */
struct FetchTLS {
	std::string ca_file;     // verify the server with these CAs only
	std::string client_cert; // present this certificate (mutual TLS)
	std::string client_key;  // its private key, unless in client_cert
	bool operator==(const FetchTLS&) const = default;
	bool empty() const noexcept {
		return ca_file.empty() && client_cert.empty() && client_key.empty();
	}
};

/* An entry of the "allow" list, as written. Only its rule is kept. */
struct FetchAllow {
	std::string url;
	FetchTLS    tls;
};

/* An origin a tenant may send requests to, with ECALL_FETCH. Parsed by
   curl, as the URLs the guest gives are, so that both are read the same. */
struct FetchRule {
	std::string scheme;
	std::string host;
	unsigned    port = 0;
	std::string path; // a prefix
	FetchTLS    tls;
	bool operator==(const FetchRule&) const = default;
};

/* Outgoing HTTP access ("fetch" in the tenant JSON). Disabled when the
   allow list is empty. */
struct FetchConfig {
	std::vector<FetchRule> rules; // parsed from the allow list
	uint32_t max_requests       = 8;      // per task
	uint32_t timeout_ms         = 5000;   // the whole transfer
	uint32_t connect_timeout_ms = 2000;
	uint32_t max_request_body   = 1u << 20;
	uint32_t max_response_body  = 16u << 20;
	bool     allow_insecure     = false;  // FETCH_FLAG_INSECURE
	bool operator==(const FetchConfig&) const = default;

	/* Parse the allow list into rules, or throw */
	void compile(const std::vector<FetchAllow>& allow);
};

struct TenantGroup {
	uint64_t max_instructions  = 20'000'000ull;
	uint32_t max_memory_mb     = 32; // 32MB
	uint32_t max_heap_mb       = 512; // 512MB
	size_t   max_backends = 8;
	size_t   max_regex    = 32;
	bool	 verbose      = false;
	std::shared_ptr<const FetchConfig> fetch;

	/* Atomically swappable: readers snapshot this shared_ptr, writers
	   create a new vector and exchange the pointer. */
	std::shared_ptr<std::vector<std::string>> argv =
		std::make_shared<std::vector<std::string>>();
};

/* Identifies the program file a tenant was loaded from, so that a VCL
   reload can tell whether it has been replaced on disk since. */
struct FileStamp {
	uint64_t dev = 0;
	uint64_t ino = 0;
	int64_t  size = -1;
	int64_t  mtime_ns = 0;

	static FileStamp of(const std::string& path);
	bool operator==(const FileStamp&) const = default;
};

struct TenantConfig
{
	std::string    name;
	std::string    filename;
	TenantGroup    group;

	uint64_t max_instructions() const noexcept { return group.max_instructions; }
	uint64_t max_memory() const noexcept { return uint64_t(group.max_memory_mb) << 20; }
	uint64_t max_heap() const noexcept { return uint64_t(group.max_heap_mb) << 20; }
	size_t   max_regex() const noexcept { return group.max_regex; }
	size_t   max_backends() const noexcept { return group.max_backends; }
	bool     elf_execute_only() const noexcept { return false; }

	TenantConfig(std::string n, std::string f, TenantGroup g)
		: name(n), filename(f), group{std::move(g)} {}

	/* Whether two tenants would load the same program the same way.
	   The argv of a running tenant must be read under its update_mtx. */
	bool same_as(const TenantConfig& other) const;
};

} // rvs
