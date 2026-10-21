#include "script.hpp"

#include <libriscv/native_heap.hpp>
#include <libriscv/threads.hpp>
#include "machine/include_api.hpp"
#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#if defined(RISCV_BINARY_TRANSLATION) && defined(RISCV_LIBTCC)
#include <functional>
#include <future>
#include <thread>
#endif
extern "C" void riscv_SetHash(struct req*, VSHA256_CTX*);

namespace rvs {
namespace vcl { void install_syscalls(); }
	inline timespec time_now();
	inline long nanodiff(timespec start_time, timespec end_time);
	static constexpr uint64_t SIGHANDLER_INSN = 60'000;
	/* Workspace that fork pages leave for Varnish itself */
	static constexpr unsigned WS_PAGE_SPARE = 16384;
	static constexpr unsigned NATIVE_SYSCALLS_BASE = 580;
	/* The native heap takes base+0..4 and the native memory helpers
	   base+5..base+19 (their n+14 is "print backtrace"). EBREAK is system
	   call RISCV_SYSCALLS_MAX-1: if it lands in that range, a guest's
	   ebreak runs a helper and carries on instead of trapping, and every
	   trap a compiled VCL policy relies on fails open. */
	static_assert(riscv::SYSCALL_EBREAK >= NATIVE_SYSCALLS_BASE + 5 + 15,
		"EBREAK collides with the native helpers: RISCV_SYSCALLS_MAX must be at least 601");
	static constexpr bool VERBOSE_ERRORS = true;

//#define ENABLE_TIMING
#define TIMING_LOCATION(x) \
	asm("" ::: "memory"); \
	auto x = time_now();  \
	asm("" ::: "memory");

void Script::init()
{
	setup_syscall_interface();
	vcl::install_syscalls();
	// Show current emulator features enabled
	printf("[RISC-V features] Architecture: %s  Vectors (RVV): %s  Compressed (RVC): %s\n",
		MARCH == riscv::RISCV64 ? "64-bit" : "32-bit",
		riscv::vector_extension ? "enabled" : "disabled",
		riscv::compressed_enabled ? "enabled" : "disabled");
	printf("[RISC-V features] Binary translation: %s  asmjit: %s  Memory traps: %s Flat Arena: %s\n",
		riscv::binary_translation_enabled ? (riscv::libtcc_enabled ? "jit" : "full") : "disabled",
		riscv::asmjit_enabled ? "enabled" : "disabled",
		riscv::memory_traps_enabled ? "enabled" : "disabled",
		riscv::flat_readwrite_arena ? "enabled" : "disabled");
}

Script::Script(
	const Script& source, const vrt_ctx* ctx,
	const SandboxTenant* ten, MachineInstance& inst, bool persistent)
	: m_machine(source.machine(), {
		.memory_max = 0,
		.minimal_fork = true,
		.use_memory_arena = false,
	  }),
	  m_parent(&source.machine()),
	  m_ctx(ctx), m_tenant(ten), m_inst(inst),
	  m_is_debug(source.is_debug()),
	  m_persistent(persistent),
	  m_sighandler{source.m_sighandler},
	  m_regex     {ten->config.max_regex()},
	  m_directors {ten->config.max_backends()}
{
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t0);
#endif
	/* No initialization */
	this->machine_setup(machine(), false);

	/* Most requests never allocate, so the fork's native heap is only
	   created when the guest first uses it: see on_missing_arena. */
	/* Load the compiled regexes of the source */
	m_regex.loan_from(source.m_regex);
	/* Load the directors of the source */
	m_directors.loan_from(source.m_directors);
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t1);
	printf("Total time in Script constr body: %ldns\n", nanodiff(t0, t1));
#endif
}

/* Set up a fresh arena starting at the master's high-water mark.
 * This is O(1): no chunk-list copy, no pointer fixups.
 * The fork's allocator covers only [watermark, heap_end), i.e. the region
 * beyond everything the master has ever allocated.  Master-owned addresses
 * are "unknown" to this arena; the callbacks below handle the two cases
 * that would otherwise fail:
 *   free()    – silently succeed; the space is recovered when the fork is
 *               destroyed, or reset to its master.
 *   realloc() – allocate fresh memory in the fork's range, return the old
 *               size so the ecall layer can memcpy the contents. */
void Script::setup_fork_arena()
{
	const Script& source = m_inst.script;
	const auto watermark = source.m_arena_watermark;
	machine().setup_native_heap(NATIVE_SYSCALLS_BASE, watermark, source.m_arena_end - watermark);

	machine().arena().on_unknown_free(
		[](auto /*ptr*/, auto* /*ch*/) -> int { return 0; });

	const riscv::Arena* src_arena = &source.machine().arena();
	machine().arena().on_unknown_realloc(
		[src_arena, this](auto ptr, auto newsize) -> riscv::Arena::ReallocResult {
			const size_t old_len = src_arena->size(ptr);
			const auto   new_ptr = machine().arena().malloc(newsize);
			return {new_ptr, old_len};
		});
}

bool Script::reset_to_master(bool restore)
{
	const Script& source = m_inst.script;
	const machine_t& master = *m_parent;
	auto& mem = machine().memory;
	/* State a new fork does not have, or has a copy of the master's,
	   and that is not worth undoing: the fork is not reused. */
	if (UNLIKELY(machine().has_signals() || machine().has_file_descriptors()
		|| mem.execute_segments_count() != master.memory.execute_segments_count()
		|| machine().has_threads() != master.has_threads()))
		return false;
	if (machine().has_threads()) {
		const auto& mt = machine().threads();
		const auto& master_mt = master.threads();
		if (UNLIKELY(mt.m_thread_counter != master_mt.m_thread_counter
			|| mt.m_threads.size() != master_mt.m_threads.size()
			|| mt.get_tid() != master_mt.get_tid()))
			return false;
	}

	auto& pages = mem.pages();
	if (restore) {
		/* Pages written during the task are owned, writable copies.
		   Give them the master's data back (or zeroes, when the master
		   has no such page), and make them copy-on-write again, so that
		   the next task's first write is noticed and only pages written
		   since are restored. A write to such a page costs a write fault,
		   but no allocation and no copy. */
		const auto& master_pages = master.memory.pages();
		size_t retained = 0;
		for (auto it = pages.begin(); it != pages.end(); ) {
			auto& page = it->second;
			/* A page that was not installed by our own page handlers,
			   or had its attributes changed since (mmap(), mprotect(),
			   zero-copy bodies, ...): drop it, and let the next task
			   fault it in from the master like a new fork would. */
			if (UNLIKELY(page.attr.user_defined != FORK_PAGE)) {
				it = pages.erase(it);
				continue;
			}
			if (!page.attr.non_owning) {
				if (page.attr.write) {
					auto mit = master_pages.find(it->first);
					if (mit != master_pages.end() && mit->second.m_page != nullptr)
						std::memcpy(page.data(), mit->second.data(), riscv::Page::size());
					else
						std::memset(page.data(), 0, riscv::Page::size());
					page.attr.write = false;
					page.attr.is_cow = true;
				}
				retained++;
			}
			++it;
		}
		/* Bound what an idle fork holds on to */
		if (UNLIKELY(retained > RETAINED_PAGES_MAX))
			pages.clear();
	} else {
		/* Drop every page. Owned pages are freed, and loaned pages
		   are loaned again on use. */
		pages.clear();
	}
	mem.invalidate_reset_cache();
	mem.mmap_address() = master.memory.mmap_address();
	mem.set_brk_address(master.memory.brk_address());
	mem.mmap_cache() = master.memory.mmap_cache();
	machine().cpu.registers().copy_from(
		riscv::Registers<MARCH>::Options::NoVectors, master.cpu.registers());
	/* An arena is only there if the task allocated */
	if (machine().has_arena())
		machine().arena().reset();
	m_task_pages = 0;

	m_regex.foreach_owned([] (auto& entry) { VRE_free(&entry.item); });
	m_regex.reset();
	m_regex.loan_from(source.m_regex);
	m_directors.reset();
	m_directors.loan_from(source.m_directors);

	m_vcl_task.reason.clear();
	m_vcl_task.stat_seen.clear();
	m_want_result.clear();
	m_want_values = {};
	m_is_paused = false;
	m_sighandler = source.m_sighandler;
	m_sha_ctx = nullptr;
	fetch_reset();
	m_post_data = 0;
	m_last_newline = true;
	m_ctx = nullptr;
	return true;
}

Script::Script(
	const std::vector<uint8_t>& binary, const vrt_ctx* ctx,
	const SandboxTenant* ten, MachineInstance& inst,
	bool storage, bool debug)
	: m_machine(binary, {
		.memory_max = ten->config.max_memory(),
		.stack_size = STACK_SIZE,
		.enforce_exec_only = ten->config.elf_execute_only(),
		.default_exit_function = "fast_exit",
		/* Run the guest's own memcpy, memchr, strlen, etc. natively.
		   Like the native memory system calls, these are not charged
		   per byte, only bounded in length. */
		.libc_fastpath = true,
#ifdef RISCV_BINARY_TRANSLATION
		.translate_enabled = true,
		.translation_use_arena = false,
		//.translate_ignore_instruction_limit = true,
#  ifdef RISCV_LIBTCC
		.translate_background_callback = [this](std::function<void()>& callback) {
			std::thread([this, callback = std::move(callback)]() {
				try {
					if (callback)
						callback();
					if (getenv("VERBOSE") != nullptr) {
						printf("[%s] Binary translation completed in background.\n",
							name().c_str());
					}
				} catch (const std::exception &e) {
					fprintf(stderr, "[%s] Binary translation exception: %s\n",
						name().c_str(), e.what());
				}
			}).detach();
		},
#  endif // RISCV_LIBTCC
#endif
	  }),
	  m_parent(nullptr),
	  m_ctx(ctx), m_tenant(ten), m_inst(inst),
	  m_is_storage(storage), m_is_debug(debug),
	  m_regex     {ten->config.max_regex()},
	  m_directors {ten->config.max_backends()}
{
}

Script::~Script()
{
	fetch_reset();
	// free any owned regex pointers
	m_regex.foreach_owned(
		[] (auto& entry) {
			VRE_free(&entry.item);
		});
	if (this->is_debug()) {
		this->stop_debugger();
	}
}

void Script::setup_virtual_memory(bool /*init*/)
{
}

void Script::machine_initialize()
{
	// setup system calls and traps
	this->machine_setup(machine(), true);
	// run through the initialization
	try {
		machine().simulate<true>(max_instructions());
		// A VCL program's main() just exits: its hooks are exported by
		// name, not registered by waiting for requests.
		if (!this->is_paused() && !m_inst.is_vcl) {
			throw std::runtime_error("The machine was not waiting for requests. "
			"Did you forget to call wait_for_requests()?");
		}
	} catch (const riscv::MachineTimeoutException& e) {
		handle_timeout(machine().cpu.pc());
		throw;
	} catch (const std::exception& e) {
		handle_exception(machine().cpu.pc());
		throw;
	}
	// Cache the high-water mark of the master arena once, after initialization.
	// Fork constructors use this to create a fresh arena starting here — O(1)
	// instead of copying the full chunk list.
	if (machine().has_arena())
		m_arena_watermark = machine().arena().high_watermark();
}
void Script::machine_setup(machine_t& machine, bool init)
{
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t0);
#endif
	machine.set_userdata<Script>(this);
	machine.set_printer(
		[] (const machine_t& m, auto* data, size_t len) {
			auto* script = m.get_userdata<Script> ();
			/* TODO: Use VSLb here or disable this completely */
			script->print({data, len});
		});
	machine.set_stdin([] (const auto&, auto*, size_t) -> long { return 0; });

	if (init == false)
	{
		/* Loan a page of the master to this fork: read-only, and
		   copy-on-write when the master can write to it */
		static constexpr auto loan_page =
		[] (riscv::Memory<MARCH>& mem, gaddr_t pageno, const riscv::Page& foreign_page) -> riscv::Page& {
			riscv::PageAttributes attr = foreign_page.attr;
			attr.non_owning = true;
			attr.is_cow = foreign_page.attr.write || foreign_page.attr.is_cow;
			attr.write = false;
			attr.user_defined = FORK_PAGE;
			riscv::PageData* data = const_cast<riscv::PageData*>(foreign_page.m_page.get());
			return mem.allocate_page(pageno, attr, data);
		};
		/* Give this fork its own copy of a loaned page */
		auto copy_page = [this] (auto& mem, gaddr_t pageno, riscv::Page& page) -> void {
			assert(page.attr.is_cow);
			/* A page restored by reset_to_master(): it has the master's
			   data already, and only needs to become writable again */
			if (!page.attr.non_owning && page.m_page != nullptr) {
				this->own_page(mem, pageno);
				page.attr.write = true;
				page.attr.is_cow = false;
				return;
			}
			/* Pages are allocated from workspace */
			auto* data = m_persistent ? nullptr : (riscv::PageData*) riscv_ws_alloc_spare(
				m_ctx->ws, riscv::Page::size(), WS_PAGE_SPARE);
			if (LIKELY(data != nullptr)) {
				std::memcpy(data, page.data(), page.size());
				/* Replace old data with new non-owned data */
				page.new_data(data, false);
				page.attr.write = true;
				page.attr.is_cow = false;
				return;
			}
			// With heap as fallback, to allow bigger VMs
			this->own_page(mem, pageno);
			page.make_writable();
		};
		machine.memory.set_page_fault_handler(
		[this, copy_page] (auto& mem, size_t pageno, bool init) -> riscv::Page& {
			/* A write to a page this fork has not read yet. If the master
			   has the page, a fresh page would replace the master's data
			   with zeroes (or workspace garbage), so the fork copies it
			   like any other copy-on-write page. A read-only page stays
			   read-only, and the write that got us here faults. */
			const auto& master_pages = m_parent->memory.pages();
			if (auto it = master_pages.find(pageno); it != master_pages.end()) {
				auto& page = loan_page(mem, pageno, it->second);
				if (page.attr.is_cow)
					copy_page(mem, pageno, page);
				return page;
			}
			/* Pages are allocated from workspace, while it has room */
			auto* data = m_persistent ? nullptr : (riscv::PageData*) riscv_ws_alloc_spare(
				m_ctx->ws, riscv::Page::size(), WS_PAGE_SPARE);
			if (LIKELY(data != nullptr)) {
				if (init) {
					new (data) riscv::PageData();
				}
				return mem.allocate_page(pageno,
					riscv::PageAttributes{
						.non_owning = true, // don't delete!
						.user_defined = FORK_PAGE },
					data);
			}
			// With heap as fallback, to allow bigger VMs
			this->own_page(mem, pageno);
			using namespace riscv;
			auto& page = mem.allocate_page(pageno, init ? PageData::INITIALIZED : PageData::UNINITIALIZED);
			page.attr.user_defined = FORK_PAGE;
			return page;
		});
		// Copy-on-write handling
		machine.memory.set_page_write_handler(copy_page);
		machine.memory.set_page_readf_handler(
		[] (const riscv::Memory<MARCH>& mem, gaddr_t pageno) -> const riscv::Page& {
			//printf("Reading page %zu @ 0x%lX\n", pageno, long(pageno * 4096u));
			Script& script = *mem.machine().template get_userdata<Script>();
			const riscv::Page& foreign_page = script.m_parent->memory.get_pageno(pageno);
			// Install the page as a non-owning, COW page
			return loan_page(const_cast<riscv::Memory<MARCH>&>(mem), pageno, foreign_page);
		});
	}
	else {
		machine.memory.set_page_fault_handler(
		[this] (auto& mem, size_t pageno, bool) -> riscv::Page& {
			bool dont_fork = false;
			const auto stack_pbase = stack_base() / riscv::Page::size();
			const auto stack_pend  = stack_begin() / riscv::Page::size();
			if (pageno >= stack_pbase && pageno < stack_pend) {
				dont_fork = true;
			}
			auto* data = new riscv::PageData {};
			return mem.allocate_page(pageno,
				riscv::PageAttributes{
					.dont_fork  = dont_fork,
					.user_defined = 1 },
				data);
		});
	}

#ifdef ENABLE_TIMING
	TIMING_LOCATION(t1);
#endif
	if (init)
	{
		// page protections and "hidden" stacks
		this->setup_virtual_memory(init);

	#ifdef RISCV_DEBUG
		machine.verbose_instructions = true;
		//machine.verbose_registers = true;
	#endif

		// Full Linux-compatible stack
		machine.cpu.reset_stack_pointer(); // DONT TOUCH (YES YOU)
		std::vector<std::string> args;
		args.push_back(name());
		auto argv_snap = rvs::atomic_load(&tenant().config.group.argv);
		for (const auto& a : *argv_snap) {
			args.push_back(a);
		}
		std::vector<std::string> envs;
		envs.push_back("LC_CTYPE=C");
		envs.push_back("LC_ALL=C");
		envs.push_back("USER=groot");
		if (is_storage())
			envs.push_back("RISCV_MODE=storage");
		else
			envs.push_back("RISCV_MODE=request");
		if (is_debug())
			envs.push_back("RISCV_DEBUG=1");
		machine.setup_linux(args, envs);

	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t2);
	#endif
		// Add system call interfaces
		machine.on_unhandled_syscall = [] (auto& m, size_t num) {
			// The handler is shared by every machine of this type, and
			// the VCL compiler's machine (vcl/compiler.cpp) has no Script.
			auto* script = m.template get_userdata<Script>();
			if (script == nullptr)
				return;
			const std::string text =
				"Unhandled system call: " + std::to_string(num);
			script->print(text);
		};
		// Most requests never allocate, so a fork's native heap is only
		// created when the guest first uses it. See setup_fork_arena().
		machine.on_missing_arena = [] (machine_t& m) {
			auto* script = m.get_userdata<Script>();
			if (script != nullptr && script->m_parent != nullptr
				&& script->m_parent->has_arena())
				script->setup_fork_arena();
		};
		machine.setup_linux_syscalls(false, false);
		machine.setup_posix_threads();
		// Custom system call API >= 500
		// Forked VMs call setup_native_heap themselves (in the fork ctor)
		// starting at the master's high-water mark, so we only set it up here.
		const uint64_t arena_base = machine.memory.mmap_allocate(vrm()->config.max_heap());
		machine.setup_native_heap(NATIVE_SYSCALLS_BASE,
			arena_base, vrm()->config.max_heap());
		this->m_arena_end = arena_base + vrm()->config.max_heap();
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t3);
	#endif
		machine.setup_native_memory(NATIVE_SYSCALLS_BASE+5);
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t4);
	#endif

#ifdef ENABLE_TIMING
	TIMING_LOCATION(t5);
	printf("[Constr] pagetbl: %ldns, vmem: %ldns, arena: %ldns, nat.mem: %ldns, syscalls: %ldns\n",
		nanodiff(t0, t1), nanodiff(t1, t2), nanodiff(t2, t3), nanodiff(t3, t4), nanodiff(t4, t5));
#endif
	} // init
} // machine_setup()

/* Account for a page the task makes its own, against max_memory.
   A persistent fork counts the pages this task wrote to, as the pages
   it keeps between tasks are not allocated again. */
void Script::own_page(const riscv::Memory<MARCH>& mem, gaddr_t pageno)
{
	const bool below = m_persistent
		? m_task_pages < tenant().config.max_memory() / riscv::Page::size()
		: mem.owned_pages_active() * riscv::Page::size() < tenant().config.max_memory();
	if (UNLIKELY(!below))
		throw riscv::MachineException(
			riscv::OUT_OF_MEMORY, "Out of memory (max_memory limit reached)",
				pageno * riscv::Page::size());
	m_task_pages++;
}

void Script::handle_exception(gaddr_t address)
{
	try {
		throw;
	}
	catch (const riscv::MachineException& e) {
		if constexpr (VERBOSE_ERRORS) {
		fprintf(stderr, "Script exception: %s (data: 0x%lX)\n",
			e.what(), e.data());
		fprintf(stderr, ">>> [%08lu] %s\n",
			machine().instruction_counter(),
			machine().cpu.current_instruction_to_string().c_str());
		fprintf(stderr, ">>> Machine registers:\n[PC\t%08lX] %s\n",
			(long)machine().cpu.pc(),
			machine().cpu.registers().to_string().c_str());
		}
		VRT_fail(m_ctx, "Script exception: %s", e.what());
	}
	catch (const std::exception& e) {
		if constexpr (VERBOSE_ERRORS) {
			fprintf(stderr, "Script exception: %s\n", e.what());
		}
		VRT_fail(m_ctx, "Script exception: %s", e.what());
	}
	if constexpr (VERBOSE_ERRORS) {
		printf("Program page: %s\n", machine().memory.get_page_info(machine().cpu.pc()).c_str());
		printf("Stack page: %s\n", machine().memory.get_page_info(machine().cpu.reg(2)).c_str());

		auto callsite = machine().memory.lookup(address);
		fprintf(stderr, "Function call: %s\n", callsite.name.c_str());
		this->print_backtrace(address);
	}
	if (this->m_sighandler != 0) {
		auto handler = this->m_sighandler;
		//machine().stack_push(machine().cpu.pc());
		machine().stack_push(machine().cpu.reg(riscv::REG_RA));
		machine().cpu.reg(riscv::REG_RA) = machine().cpu.pc();
		machine().cpu.reg(riscv::REG_ARG0) = 11; /* SIGSEGV */
		machine().cpu.jump(handler);
		this->m_sighandler = 0;
		this->resume(SIGHANDLER_INSN);
		this->m_sighandler = handler;
	}
}
void Script::handle_timeout(gaddr_t address)
{
	if constexpr (VERBOSE_ERRORS) {
		auto callsite = machine().memory.lookup(address);
		fprintf(stderr, "Script hit max instructions (%zu) for: %s\n",
			max_instructions(), callsite.name.c_str());
	}
	VRT_fail(m_ctx, "Script for '%s' timed out", name().c_str());
}
void Script::print(std::string_view text)
{
	if (text.empty())
		return;
	if (this->m_last_newline) {
		printf(">>> [%s] %.*s", name().c_str(), (int)text.size(), text.begin());
	} else {
		printf("%.*s", (int)text.size(), text.begin());
	}
	this->m_last_newline = (text.back() == '\n');
}
void Script::print_backtrace(const gaddr_t addr)
{
	machine().memory.print_backtrace(
		[] (std::string_view line) {
			printf("-> %.*s\n", (int)line.size(), line.begin());
		});
	auto origin = machine().memory.lookup(addr);
	printf("-> [-] 0x%08lx + 0x%.3x: %s\n",
			(long) origin.address,
			origin.offset, origin.name.c_str());
}
void Script::set_sigaction(int, gaddr_t handler)
{
	this->m_sighandler = handler;
}

uint64_t Script::max_instructions() const noexcept {
	return vrm()->config.max_instructions();
}
const std::string& Script::name() const noexcept {
	return vrm()->config.name;
}
Script::gaddr_t Script::max_memory() const noexcept {
	return vrm()->config.max_memory();
}
Script::gaddr_t Script::stack_begin() const noexcept {
	return machine().memory.stack_initial();
}
Script::gaddr_t Script::stack_base() const noexcept {
	return stack_begin() - stack_size();
}
size_t  Script::stack_size() const noexcept {
	return STACK_SIZE;
}
size_t Script::heap_size() const noexcept {
	return vrm()->config.max_heap();
}
bool Script::within_heap(gaddr_t addr) const noexcept
{
	return addr >= machine().memory.heap_address() &&
		addr < machine().memory.mmap_address();
}

Script::gaddr_t Script::guest_alloc(size_t len)
{
	return machine().arena().malloc(len);
}
bool Script::guest_free(gaddr_t addr)
{
	return machine().arena().free(addr) == 0;
}

Script::gaddr_t Script::allocate_post_data(size_t size)
{
	this->m_post_data = machine().memory.mmap_allocate(size);
	return m_post_data;
}

const char* Script::want_workspace_string(size_t idx)
{
	const auto addr = m_want_values.at(idx);
	const size_t len = machine().memory.strlen(addr);
	char* str = (char *)WS_Alloc(m_ctx->ws, len + 1);
	if (str != nullptr) {
		machine().memory.memcpy_out(str, addr, len + 1);
		return str;
	}
	return nullptr;
}

inline void Script::init_sha256()
{
	if (ctx()->req == nullptr) {
		throw std::runtime_error("SHA256 not available during initialization");
	}
	this->m_sha_ctx =
		(VSHA256_CTX*) WS_Alloc(ctx()->ws, sizeof(VSHA256_CTX));
	if (!this->m_sha_ctx)
		throw std::runtime_error("SHA256: Out of workspace");
	VSHA256_Init(this->m_sha_ctx);
}
void Script::hash_buffer(const char* buffer, int len)
{
	if (ctx() == nullptr) return;
	if (m_sha_ctx == nullptr) init_sha256();

	VSHA256_Update(this->m_sha_ctx, buffer, len);
	VSLb(ctx()->vsl, SLT_Hash, "%.*s", len, buffer);
}
bool Script::apply_hash(const vrt_ctx* ctx)
{
	if (m_sha_ctx && ctx->req) {
		riscv_SetHash(ctx->req, m_sha_ctx);
		return true;
	}
	return false;
}

Script::gaddr_t Script::resolve_address(const char* name) const {
	return machine().address_of(name);
}
std::string Script::symbol_name(gaddr_t address) const
{
	auto callsite = machine().memory.lookup(address);
	return callsite.name;
}

const TenantConfig& Script::config() const noexcept
{
	return m_tenant->config;
}

#ifdef ENABLE_TIMING
timespec time_now()
{
	timespec t;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
	return t;
}
long nanodiff(timespec start_time, timespec end_time)
{
	assert(end_time.tv_sec == 0); /* We should never use seconds */
	return end_time.tv_nsec - start_time.tv_nsec;
}
#endif

} // rvs
