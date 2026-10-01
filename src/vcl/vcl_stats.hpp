#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace rvs {
class Script;
}

namespace rvs::vcl {

/**
 * Statistics a policy declares for itself: `static var NAME: INT stat
 * [KIND] ["help"];`, published by the compiler as `.carapace.stats` rows.
 *
 * Each one is a Varnish counter named RISCV.<tenant>.<name>, shared by
 * every program the tenant loads, so it keeps counting across a live update
 * and a VCL reload. The guest's static is an ordinary 8-byte word that each
 * request's fork starts from the master's value. The host never writes it:
 * after every hook it reads the word again and folds the change into the
 * counter. A counter or a gauge adds the difference, a max or a min keeps
 * the extreme of what the word has held.
 */
enum class StatKind : uint32_t {
	Counter = 0,
	Gauge   = 1,
	Max     = 2,
	Min     = 3,
};

struct Stat
{
	uint64_t address;
	StatKind kind;
	/* What every fork's word starts at: the master's after main(). */
	uint64_t initial;
	/* The Varnish counter. Never freed. */
	uint64_t* counter;
};

/* Parse `.carapace.stats`, resolve each row's name and description in the
   master VM, and bind each row to its tenant counter, allocating the ones
   the tenant has not declared before. A `min` word is primed in the master.
   `bss` is the .bss address range, where every word has to live. Throws
   with a message naming what is wrong. */
std::vector<Stat> install_stats(Script& master, const uint8_t* section,
	size_t size, uint64_t bss_start, uint64_t bss_size);

/* Fold what the hook that just returned did to the statistics into their
   counters. Call after every hook of a fork. */
void fold_stats(Script&);

} // rvs::vcl
