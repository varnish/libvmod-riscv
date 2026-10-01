#include "vcl_stats.hpp"
#include "vcl_program.hpp"
#include "vcl_varnish.h"
#include "../machine_instance.hpp"
#include "../sandbox_tenant.hpp"
#include "../varnish.hpp"
#include <cstring>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>

namespace rvs::vcl {

/* Bytes of one `.carapace.stats` row: word address, kind, reserved flags,
   name address, help address. */
static constexpr size_t ROW = 32;
/* The compiler's caps (MAX_STAT_NAME, MAX_STAT_HELP in types.rs). */
static constexpr size_t MAX_NAME = 64;
static constexpr size_t MAX_HELP = 200;
/* The most statistics a tenant has, per program and across every program
   it has loaded since varnishd started (MAX_STATS in types.rs). A counter
   is never freed, and they share VSM with every tenant, so without the
   lifetime cap a tenant could reload with fresh names until the shared
   memory runs out. */
static constexpr size_t MAX_STATS = 64;

static const char* kind_word(StatKind kind)
{
	switch (kind) {
	case StatKind::Counter: return "counter";
	case StatKind::Gauge:   return "gauge";
	case StatKind::Max:     return "max";
	case StatKind::Min:     return "min";
	}
	return "?";
}

/* `[a-z][a-z0-9_]*`, not ending in '_' and without "__". The compiler
   checks the same, but the ELF is input like any other. */
static bool name_ok(const std::string& name)
{
	if (name.empty() || name.size() > MAX_NAME || name[0] < 'a' || name[0] > 'z'
		|| name.back() == '_' || name.find("__") != std::string::npos)
		return false;
	for (char c : name)
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
			return false;
	return true;
}

/* One tenant counter. The registry outlives every program and every VCL:
   a counter keeps its value for as long as varnishd runs. */
struct Counter
{
	StatKind kind;
	std::string help;
	uint64_t* word;
};
static std::mutex registry_mtx;
static std::map<std::pair<std::string, std::string>, Counter> registry;

/* Signed, like every comparison of an extreme. */
static void raise(uint64_t* word, uint64_t value)
{
	uint64_t current = __atomic_load_n(word, __ATOMIC_RELAXED);
	while (int64_t(value) > int64_t(current)
		&& !__atomic_compare_exchange_n(word, &current, value, true,
			__ATOMIC_RELAXED, __ATOMIC_RELAXED));
}
static void lower(uint64_t* word, uint64_t value)
{
	uint64_t current = __atomic_load_n(word, __ATOMIC_RELAXED);
	while (int64_t(value) < int64_t(current)
		&& !__atomic_compare_exchange_n(word, &current, value, true,
			__ATOMIC_RELAXED, __ATOMIC_RELAXED));
}

/* Bind every row to its tenant counter. Every row is checked against the
   registry before any counter is allocated, so a refused program leaves
   nothing behind. */
static void bind_counters(const std::string& tenant, std::vector<Stat>& stats,
	const std::vector<std::string>& names, const std::vector<std::string>& helps)
{
	std::lock_guard lock(registry_mtx);
	size_t owned = 0, fresh = 0;
	for (auto it = registry.lower_bound({tenant, std::string()});
		it != registry.end() && it->first.first == tenant; ++it)
		owned++;
	for (size_t i = 0; i < stats.size(); i++)
		if (registry.find({tenant, names[i]}) == registry.end())
			fresh++;
	if (owned + fresh > MAX_STATS)
		throw std::runtime_error("VCL program: tenant " + tenant + " would have "
			+ std::to_string(owned + fresh) + " statistics, past the limit of "
			+ std::to_string(MAX_STATS) + " (a statistic lives until varnishd restarts)");
	for (size_t i = 0; i < stats.size(); i++) {
		auto it = registry.find({tenant, names[i]});
		/* Two programs that disagree about what a name counts would fold
		   into one counter with two meanings. */
		if (it != registry.end() && it->second.kind != stats[i].kind)
			throw std::runtime_error("VCL program: statistic " + names[i] + " is a "
				+ kind_word(stats[i].kind) + ", but tenant " + tenant + " already counts it as a "
				+ kind_word(it->second.kind) + " (a statistic cannot change kind without a restart)");
	}
	for (size_t i = 0; i < stats.size(); i++) {
		auto& stat = stats[i];
		auto it = registry.find({tenant, names[i]});
		if (it != registry.end()) {
			auto& counter = it->second;
			if (counter.help != helps[i]) {
				/* The description is fixed when Varnish publishes the counter. */
				VSL(SLT_VCL_Log, 0, "[%s] VCL warning: statistic %s keeps its first description '%s'",
					tenant.c_str(), names[i].c_str(), counter.help.c_str());
			}
			stat.counter = counter.word;
		} else {
			auto* word = vclv_stat_alloc(tenant.c_str(), names[i].c_str(), helps[i].c_str(),
				stat.kind != StatKind::Counter);
			if (word == nullptr)
				throw std::runtime_error("VCL program: Varnish refused the counter for statistic " + names[i]);
			/* An extreme starts at the first value its word holds, the
			   master's. Until a request moves it, a min shows INT64_MAX,
			   and a negative max shows as a huge unsigned number. */
			if (stat.kind == StatKind::Max || stat.kind == StatKind::Min)
				__atomic_store_n(word, stat.initial, __ATOMIC_RELAXED);
			registry.emplace(std::make_pair(tenant, names[i]), Counter{stat.kind, helps[i], word});
			stat.counter = word;
		}
		/* Every fork starts from the master's value, and fold_stats skips
		   a word that is unchanged, so the extreme has to include it now. */
		if (stat.kind == StatKind::Max)
			raise(stat.counter, stat.initial);
		else if (stat.kind == StatKind::Min)
			lower(stat.counter, stat.initial);
	}
}

std::vector<Stat> install_stats(Script& master, const uint8_t* section,
	size_t size, uint64_t bss_start, uint64_t bss_size)
{
	if (size % ROW != 0)
		throw std::runtime_error("VCL program: .carapace.stats is not a whole number of rows");
	if (size / ROW > MAX_STATS)
		throw std::runtime_error("VCL program: .carapace.stats declares " + std::to_string(size / ROW)
			+ " statistics; the limit is " + std::to_string(MAX_STATS));
	auto& machine = master.machine();
	const std::string& tenant = master.tenant().config.name;
	if (bss_size > UINT64_MAX - bss_start)
		throw std::runtime_error("VCL program: .bss wraps the address space");
	const uint64_t bss_end = bss_start + bss_size;
	std::vector<Stat> stats;
	std::vector<std::string> names, helps;
	for (size_t at = 0; at < size; at += ROW) {
		uint64_t address, name_addr, help_addr;
		uint32_t kind;
		memcpy(&address, section + at, 8);
		memcpy(&kind, section + at + 8, 4);
		memcpy(&name_addr, section + at + 16, 8);
		memcpy(&help_addr, section + at + 24, 8);
		if (kind > uint32_t(StatKind::Min))
			throw std::runtime_error("VCL program: .carapace.stats names statistic kind "
				+ std::to_string(kind) + "; the kinds are 0..3");
		/* Eight bytes, wholly inside .bss: the host reads the word after
		   every hook and primes a min once, and neither may touch anything
		   else the guest owns. */
		if (address % 8 != 0 || address < bss_start || address > bss_end
			|| bss_end - address < 8)
			throw std::runtime_error("VCL program: .carapace.stats points outside .bss");

		std::string name, help;
		try {
			name = machine.memory.memstring(name_addr, MAX_NAME + 1);
			help = machine.memory.memstring(help_addr, MAX_HELP + 1);
		} catch (const std::exception&) {
			throw std::runtime_error("VCL program: .carapace.stats has an unreadable name or description");
		}
		if (!name_ok(name))
			throw std::runtime_error("VCL program: .carapace.stats names statistic '" + name
				+ "', which is not [a-z][a-z0-9_]* of at most 64 bytes");
		if (help.size() > MAX_HELP)
			throw std::runtime_error("VCL program: the description of statistic " + name
				+ " is over 200 bytes");
		for (auto& seen : names)
			if (seen == name)
				throw std::runtime_error("VCL program: statistic " + name + " is declared twice");
		names.push_back(std::move(name));
		helps.push_back(std::move(help));

		const auto stat_kind = StatKind(kind);
		/* The compiler refuses an initializer on a min, so its word is still
		   zero here: give it the sentinel every fork then starts from. */
		const uint64_t initial = stat_kind == StatKind::Min
			? uint64_t(INT64_MAX) : machine.memory.template read<uint64_t>(address);
		/* Written even when unchanged: a fork can only use a page the
		   master has, and a zero-initialized static's page may never have
		   been touched by main(). */
		machine.memory.template write<uint64_t>(address, initial);
		stats.push_back(Stat{
			.address = address,
			.kind = stat_kind,
			.initial = initial,
			.counter = nullptr,
		});
	}
	/* Bound only once every row is valid. */
	bind_counters(tenant, stats, names, helps);
	return stats;
}

void fold_stats(Script& script)
{
	const auto* program = script.program().vcl_program.get();
	if (program == nullptr || program->stats.empty())
		return;
	const auto& stats = program->stats;
	/* The last value the host read, per word. A fork starts where the
	   master left off, so the first hook folds against the initial values. */
	auto& seen = script.vcl_task().stat_seen;
	if (seen.empty()) {
		seen.reserve(stats.size());
		for (auto& stat : stats)
			seen.push_back(stat.initial);
	}
	auto& memory = script.machine().memory;
	for (size_t i = 0; i < stats.size(); i++) {
		const auto& stat = stats[i];
		const uint64_t now = memory.template read<uint64_t>(stat.address);
		if (now == seen[i])
			continue;
		switch (stat.kind) {
		case StatKind::Counter:
		case StatKind::Gauge:
			/* Wrapping: a gauge that goes down adds a negative difference. */
			__atomic_fetch_add(stat.counter, now - seen[i], __ATOMIC_RELAXED);
			break;
		case StatKind::Max:
			raise(stat.counter, now);
			break;
		case StatKind::Min:
			lower(stat.counter, now);
			break;
		}
		seen[i] = now;
	}
}

} // rvs::vcl
