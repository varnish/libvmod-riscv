#include "vcl_program.hpp"
#include "compiler.hpp"
#include "vcl_varnish.h"
#include "../machine_instance.hpp"
#include "../sandbox_tenant.hpp"
#include "../varnish.hpp"
#include <cstring>
#include <libriscv/elf.hpp>
#include <stdexcept>

namespace rvs::vcl {

/* The hooks a compiled policy exports, and the VMOD callback each one
   answers (callback_names in machine_instance.hpp), which is the one
   riscv.run() picks for the Varnish subroutine it is called from. */
static constexpr std::pair<const char*, size_t> HOOKS[] = {
	{"on_recv", 1},              // ON_REQUEST
	{"on_hash", 2},              // ON_HASH
	{"on_synth", 3},             // ON_SYNTH
	{"on_backend_fetch", 4},     // ON_BACKEND_FETCH
	{"on_backend_response", 5},  // ON_BACKEND_RESPONSE
	{"on_backend_error", 6},     // ON_BACKEND_ERROR
	{"on_deliver", 7},           // ON_DELIVER
	{"on_hit", 8},               // ON_HIT
	{"on_miss", 9},              // ON_MISS
	{"on_pass", 12},             // ON_PASS
};
/* Carapace's ceiling on the region, kept: a request global is at most 264
   bytes, and the region is copied into every fork. */
static constexpr uint64_t MAX_GLOBALS = 8192;

Program::~Program()
{
	for (auto& [pattern, re] : patterns)
		vclv_regex_free(re);
}

const void* Program::pattern(std::string_view pattern) const
{
	auto it = patterns.find(std::string(pattern));
	return it != patterns.end() ? it->second : nullptr;
}

std::unique_ptr<Program> Program::install(Script& master, MachineInstance& inst)
{
	auto program = std::make_unique<Program>();
	auto& machine = master.machine();
	const auto& binary = inst.binary;
	/* A section's header, or false when it is absent. Every offset is
	   checked: the loader has accepted the ELF, but these sections are not
	   loaded, so nothing else has looked at them. */
	using Elf = riscv::Elf<8>;
	auto find = [&] (const char* name, Elf::SectionHeader& found) -> bool {
		auto fits = [&] (uint64_t off, uint64_t len) {
			return off <= binary.size() && len <= binary.size() - off;
		};
		Elf::Header hdr;
		if (!fits(0, sizeof(hdr)))
			return false;
		memcpy(&hdr, binary.data(), sizeof(hdr));
		if (hdr.e_shentsize != sizeof(Elf::SectionHeader) || hdr.e_shstrndx >= hdr.e_shnum
			|| !fits(hdr.e_shoff, uint64_t(hdr.e_shnum) * sizeof(Elf::SectionHeader)))
			return false;
		auto header = [&] (unsigned i) {
			Elf::SectionHeader sh;
			memcpy(&sh, binary.data() + hdr.e_shoff + i * sizeof(sh), sizeof(sh));
			return sh;
		};
		const auto strtab = header(hdr.e_shstrndx);
		if (!fits(strtab.sh_offset, strtab.sh_size))
			return false;
		const size_t name_len = strlen(name) + 1;
		for (unsigned i = 0; i < hdr.e_shnum; i++) {
			const auto sh = header(i);
			if (sh.sh_name >= strtab.sh_size || strtab.sh_size - sh.sh_name < name_len
				|| memcmp(binary.data() + strtab.sh_offset + sh.sh_name, name, name_len) != 0)
				continue;
			found = sh;
			return true;
		}
		return false;
	};
	/* A section's bytes, or null when it is absent. */
	auto section = [&] (const char* name, size_t& size) -> const uint8_t* {
		Elf::SectionHeader sh;
		if (!find(name, sh))
			return nullptr;
		if (sh.sh_offset > binary.size() || sh.sh_size > binary.size() - sh.sh_offset)
			throw std::runtime_error(std::string("VCL program: ") + name + " lies outside the ELF");
		size = sh.sh_size;
		return binary.data() + sh.sh_offset;
	};

	/* NUL-separated pattern literals. */
	size_t size = 0;
	if (const auto* bytes = section(".carapace.regex", size)) {
		const char* p = reinterpret_cast<const char*>(bytes);
		const char* end = p + size;
		while (p < end) {
			const char* nul = static_cast<const char*>(memchr(p, '\0', end - p));
			if (nul == nullptr)
				throw std::runtime_error("VCL program: unterminated pattern in .carapace.regex");
			std::string pattern(p, nul);
			p = nul + 1;
			if (program->patterns.count(pattern))
				continue;
			const char* error = "";
			void* re = vclv_regex_compile(pattern.c_str(), &error);
			if (re == nullptr)
				throw std::runtime_error("VCL program: regex '" + pattern + "' does not compile: " + error);
			program->patterns.emplace(std::move(pattern), re);
		}
	}

	/* address, size, then the initial image. */
	if (const auto* p = section(".carapace.globals", size)) {
		const size_t section_size = size;
		if (section_size < 16)
			throw std::runtime_error("VCL program: .carapace.globals is truncated");
		uint64_t address;
		memcpy(&address, p, 8);
		memcpy(&size, p + 8, 8);
		if (size == 0 || size > MAX_GLOBALS || section_size != 16 + size)
			throw std::runtime_error("VCL program: .carapace.globals has a bad size");
		program->globals_address = address;
		program->globals_image.assign(p + 16, p + 16 + size);
		/* Every fork starts from the master, so seeding it once is what
		   gives each request its own copy of the initial values. */
		machine.copy_to_guest(address, program->globals_image.data(), size);
	}

	if (const auto* rows = section(".carapace.stats", size)) {
		Elf::SectionHeader bss;
		if (!find(".bss", bss))
			throw std::runtime_error("VCL program: .carapace.stats without a .bss");
		program->stats = install_stats(master, rows, size, bss.sh_addr, bss.sh_size);
	}

	for (auto& [symbol, index] : HOOKS)
		inst.callback_entries.at(index) = machine.address_of(symbol);
	return program;
}

bool is_vcl_source(std::string_view filename)
{
	return filename.size() > 4 && filename.substr(filename.size() - 4) == ".vcl";
}

std::shared_ptr<MachineInstance> load(const std::string& path,
	const vrt_ctx* ctx, SandboxTenant* tenant)
{
	auto compiled = compile(path);
	for (auto& warning : compiled.warnings) {
		VSL(SLT_VCL_Log, 0, "[%s] VCL warning: %s",
			tenant->config.name.c_str(), warning.c_str());
		printf("[%s] VCL warning: %s\n", tenant->config.name.c_str(), warning.c_str());
	}
	return std::make_shared<MachineInstance>(std::move(compiled.elf), ctx, tenant, false, true);
}

} // rvs::vcl
