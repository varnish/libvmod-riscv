#include <cstdint>
#include <string>
#include <vector>

namespace rvs {
struct TenantGroup {
	uint64_t max_instructions  = 20'000'000ull;
	uint32_t max_memory_mb     = 32; // 32MB
	uint32_t max_heap_mb       = 512; // 512MB
	size_t   max_backends = 8;
	size_t   max_regex    = 32;
	bool	 verbose      = false;

	std::vector<std::string> argv;
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
};

} // rvs
