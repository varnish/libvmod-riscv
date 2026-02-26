#pragma once
#include <cassert>
#include <functional>
#include <libriscv/machine.hpp>
#include "script_cache.hpp"

struct vrt_ctx;
struct VSHA256Context;
struct director;
struct vre;

namespace rvs {
struct SandboxTenant;
struct MachineInstance;
struct TenantConfig;

class Script {
public:
#ifdef RISCV_64I
	static constexpr int MARCH = riscv::RISCV64;
#else
	static constexpr int MARCH = riscv::RISCV32;
#endif
	using gaddr_t = riscv::address_type<MARCH>;
	using machine_t = riscv::Machine<MARCH>;
	static constexpr gaddr_t SHEAP_BASE   = 0x80000000;
	static constexpr gaddr_t STACK_SIZE   = 0x100000ul;
	static constexpr size_t  REGEX_MAX    = 64;
	static constexpr size_t  DIRECTOR_MAX = 32;
	static constexpr size_t  RESULTS_MAX  = 3;

	// call any script function, with any parameters
	template <typename... Args>
	inline long call(gaddr_t addr, Args&&...);
	template <typename... Args>
	inline long debugcall(gaddr_t addr, Args&&...);

	template <typename... Args>
	inline long preempt(gaddr_t addr, Args&&...);

	inline long resume(uint64_t cycles);

	auto& regex() { return m_regex; }
	auto& directors() { return m_directors; }

	auto& machine() { return m_machine; }
	const auto& machine() const { return m_machine; }

	const auto* ctx() const noexcept { return m_ctx; }
	const auto* vrm() const noexcept { return m_tenant; }
	const auto& tenant() const noexcept { return *m_tenant; }
	auto& program() { return m_inst; }
	const auto& program() const { return m_inst; }
	void set_ctx(const vrt_ctx* ctx) { m_ctx = ctx; }
	void assign_instance(std::shared_ptr<MachineInstance>& ref) { m_inst_ref = std::move(ref); }

	uint64_t max_instructions() const noexcept;
	const std::string& name() const noexcept;
	auto* want_result() const noexcept { return m_want_result.c_str(); }
	const char* want_workspace_string(size_t idx);
	const auto& want_values() const noexcept { return m_want_values; }
	void set_result(const std::string& res, gaddr_t value, bool p) {
		m_want_result = res; m_want_values[0] = value; m_is_paused = p;
	}
	void set_results(const std::string& res, std::array<gaddr_t, RESULTS_MAX> values, bool p) {
		m_want_result = res; m_want_values = values; m_is_paused = p;
	}
	void pause() noexcept { m_is_paused = true; }
	bool is_paused() const noexcept { return m_is_paused; }
	bool is_storage() const noexcept { return m_is_storage; }
	bool is_debug() const noexcept { return m_is_debug; }

	void print(std::string_view text);

	gaddr_t max_memory() const noexcept;
	gaddr_t stack_begin() const noexcept;
	gaddr_t stack_base() const noexcept;
	size_t  stack_size() const noexcept;
	size_t  heap_size() const noexcept;
	bool    within_stack(gaddr_t addr) const noexcept { return addr >= stack_base() && addr < stack_begin(); }
	bool    within_heap(gaddr_t addr) const noexcept;
	gaddr_t guest_alloc(size_t len);
	bool    guest_free(gaddr_t addr);

	gaddr_t allocate_post_data(size_t size);

	void init_sha256();
	void hash_buffer(const char* buffer, int len);
	bool apply_hash();

	std::string symbol_name(gaddr_t address) const;
	gaddr_t resolve_address(const char* name) const;
	auto    callsite(gaddr_t addr) const { return machine().memory.lookup(addr); }

	void set_sigaction(int sig, gaddr_t handler);
	void print_backtrace(const gaddr_t addr);
	void open_debugger(uint16_t);

	const TenantConfig& config() const noexcept;

	static void init();
	Script(const std::vector<uint8_t>&, const vrt_ctx*, const SandboxTenant*, MachineInstance&, bool sto, bool dbg);
	Script(const Script& source, const vrt_ctx*, const SandboxTenant*, MachineInstance&);
	~Script();
	void machine_initialize();
	bool reset(); // true if the reset was successful

private:
	void handle_exception(gaddr_t);
	void handle_timeout(gaddr_t);
	bool install_binary(const std::string& file, bool shared = true);
	void machine_setup(machine_t&, bool init);
	void setup_virtual_memory(bool init);
	static void setup_syscall_interface();

	machine_t m_machine;
	const machine_t* m_parent = nullptr;
	const vrt_ctx* m_ctx;
	const struct SandboxTenant* m_tenant = nullptr;
	MachineInstance& m_inst;
	gaddr_t     m_post_data = 0;
	gaddr_t     m_arena_watermark = 0; // cached after machine_initialize(); used by fork ctor

	std::string m_want_result;
	std::array<gaddr_t, RESULTS_MAX> m_want_values = {};
	bool        m_is_paused = false;
	bool        m_is_storage = false;
	bool        m_is_debug = false;
	bool        m_last_newline = true;
	gaddr_t     m_sighandler = 0;
	struct VSHA256Context* m_sha_ctx = nullptr;

	Cache<struct vre> m_regex;
	Cache<const struct director> m_directors;

	/* GDB RSP client */
	long resume_debugger();
	long finish_debugger();
	void stop_debugger();
	void run_debugger_loop();

	/* Delete this last */
	std::shared_ptr<MachineInstance> m_inst_ref = nullptr;
};

template <typename... Args>
inline long Script::call(gaddr_t address, Args&&... args)
{
	try {
		// setup calling convention
		machine().setup_call(std::forward<Args>(args)...);
		// GDB debugger attachment
		if (UNLIKELY(is_debug()))
			return resume_debugger();
		// execute function
		machine().simulate_with<true>(max_instructions(), 0u, address);
		// address-sized integer return value
		return machine().cpu.reg(riscv::REG_ARG0);
	}
	catch (const riscv::MachineTimeoutException& e) {
		this->handle_timeout(address);
	}
	catch (const std::exception& e) {
		this->handle_exception(address);
	}
	return -1;
}

template <typename... Args>
inline long Script::preempt(gaddr_t address, Args&&... args)
{
	const auto regs = machine().cpu.registers();
	try {
		const long ret = machine().preempt<true, false>(50'000,
			address, std::forward<Args>(args)...);
		machine().cpu.registers() = regs;
		return ret;
	}
	catch (const riscv::MachineTimeoutException& e) {
		this->handle_timeout(address);
	}
	catch (const std::exception& e) {
		this->handle_exception(address);
	}
	machine().cpu.registers() = regs;
	return -1;
}

inline long Script::resume(uint64_t cycles)
{
	try {
		// GDB debugger attachment
		if (UNLIKELY(is_debug()))
			return resume_debugger();
		machine().simulate<false>(cycles);
		return machine().cpu.reg(riscv::REG_RETVAL);
	}
	catch (const std::exception& e) {
		this->handle_exception(machine().cpu.pc());
	}
	return -1;
}

} // rvs
