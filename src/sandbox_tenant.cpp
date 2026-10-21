#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#include <libriscv/util/crc32.hpp>
#include "builder/builder.hpp"
#include "js/js_program.hpp"
#include <atomic>
#include <climits>
#include <dlfcn.h>
#include <pthread.h>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>
using riscv::crc32;
typedef void mi_output_fun(const char*, void*);
extern "C" void mi_stats_print_out (mi_output_fun* out, void* arg);

//#define ENABLE_TIMING
#ifdef ENABLE_TIMING
#include "timing.hpp"
#endif

namespace rvs {
#ifdef ENABLE_TIMING
static Timing timing_constr {"constructor"};
static Timing timing_destr {"destructor"};
#endif

std::vector<uint8_t> file_loader(const std::string& file);

std::string apply_dollar_vars(std::string str)
{
	// Replace $HOME with the home directory
	auto find_home = str.find("$HOME");
	if (find_home != std::string::npos) {
		const char* home = getenv("HOME");
		if (home != nullptr) {
			str.replace(find_home, 5, std::string(home));
		}
	}
	// Replace $PWD with the current working directory
	auto find_pwd = str.find("$PWD");
	if (find_pwd != std::string::npos) {
		char cwd[PATH_MAX];
		if (getcwd(cwd, sizeof(cwd)) != nullptr) {
			str.replace(find_pwd, 4, std::string(cwd));
		}
	}
	return str;
}

FileStamp FileStamp::of(const std::string& path)
{
	struct stat st;
	if (stat(path.c_str(), &st) != 0)
		return {};
	return {
		.dev  = uint64_t(st.st_dev),
		.ino  = uint64_t(st.st_ino),
		.size = int64_t(st.st_size),
		.mtime_ns = int64_t(st.st_mtim.tv_sec) * 1'000'000'000 + st.st_mtim.tv_nsec,
	};
}

bool TenantConfig::same_as(const TenantConfig& other) const
{
	const auto& a = this->group;
	const auto& b = other.group;
	return name == other.name && filename == other.filename
		&& a.max_instructions == b.max_instructions
		&& a.max_memory_mb == b.max_memory_mb
		&& a.max_heap_mb == b.max_heap_mb
		&& a.max_backends == b.max_backends
		&& a.max_regex == b.max_regex
		&& a.verbose == b.verbose
		&& (a.fetch == b.fetch || (a.fetch && b.fetch && *a.fetch == *b.fetch))
		&& *rvs::atomic_load(&a.argv) == *rvs::atomic_load(&b.argv);
}

std::string SandboxTenant::program_path() const
{
	if (config.filename.starts_with("rust:"))
		return apply_dollar_vars(config.filename.substr(5));
	return apply_dollar_vars(config.filename);
}

bool SandboxTenant::reusable_source() const
{
	return !config.filename.starts_with("rust:");
}

SandboxTenant::SandboxTenant(VRT_CTX, const TenantConfig& conf)
	: config{conf}
{
	(void) ctx;
}
SandboxTenant::~SandboxTenant()
{
	MachineInstance::retire(this->program);
	MachineInstance::retire(this->debug_program);
}

void SandboxTenant::load(VRT_CTX)
{
	try {
		std::string filename = config.filename;
		// Replace $vars in filename
		filename = apply_dollar_vars(filename);
		// If the filename ends with .cpp, build it first
		if (config.filename.size() > 4 &&
		    config.filename.substr(config.filename.size() - 4) == ".cpp") {
			auto code = file_loader(config.filename);
			auto bin = build_and_load(std::string(code.begin(), code.end()));
			this->program =
				std::make_shared<MachineInstance> (std::move(bin), ctx, this);
			return;
		}
		// A .vcl file is compiled to a tenant program, inside the sandbox
		if (vcl::is_vcl_source(filename)) {
			this->program = vcl::load(filename, ctx, this);
			return;
		}
		// A .js file is run by the embedded QuickJS program
		if (js::is_js_source(filename)) {
			this->program = js::load(filename, ctx, this);
			return;
		}
		// If the filename begins with "rust:", build it as a Rust project
		if (config.filename.size() > 5 &&
		    config.filename.substr(0, 5) == "rust:") {
			std::string path = config.filename.substr(5);
			auto bin = build_and_load_rust(path);
			this->program =
				std::make_shared<MachineInstance> (std::move(bin), ctx, this);
			return;
		}
		// Otherwise, load the file directly
		auto elf = file_loader(filename);
		this->program =
			std::make_shared<MachineInstance> (std::move(elf), ctx, this);
	} catch (const std::exception& e) {
		VSL(SLT_Error, RISCV_NO_VXID,
			"Exception when loading machine '%s': %s",
			config.name.c_str(), e.what());
		printf("Machine '%s' failed: %s\n",
			config.name.c_str(), e.what());
		this->program = nullptr;
	}
}
void SandboxTenant::init()
{
	/* This installs the process-wide system call handlers, which the
	   requests of an already running VCL use while another one loads. */
	static std::once_flag once;
	std::call_once(once, Script::init);
}

static inline void* get_priv_key(VRT_CTX) {
	if (ctx->req) return ctx->req;
	return ctx->bo;
}

static void SandboxFreeFunction(void* script) {
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t2);
#endif
	((Script*) script)->~Script(); /* call destructor */
#  if 0
	// Print mimalloc stats, if enabled
	mi_stats_print_out([](const char* str, void*) -> void {
		printf("[mimalloc] %s", str);
	}, nullptr);
#  endif
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t3);
	timing_destr.add(t2, t3);
#endif
}
#ifndef VARNISH_PLUS
static void SandboxPrivFreeFunction(const struct vrt_ctx* ctx, void *priv)
{
	(void)ctx;
	SandboxFreeFunction(priv);
}
static const struct vmod_priv_methods riscv_priv_methods[1] = {{
	.magic = VMOD_PRIV_METHODS_MAGIC,
	.type = "vmod_riscv",
	.fini = SandboxPrivFreeFunction
}};
#endif

namespace {
/* Permanent VMs that exist, idle or in use by a task */
std::atomic<long> pooled_vms {0};

void destroy_pooled(Script* script)
{
	delete script;
	pooled_vms--;
}

struct ForkPool {
	static constexpr size_t MAX_IDLE = 4;
	/* Least recently used first */
	std::vector<Script*> idle;
	~ForkPool() { for (auto* script : idle) destroy_pooled(script); }

	/* Drop the idle VMs of programs that are no longer in use */
	void drop_retired() {
		std::erase_if(idle, [] (Script* script) {
			if (LIKELY(!script->program().retired.load(std::memory_order_relaxed)))
				return false;
			destroy_pooled(script);
			return true;
		});
	}
};

/* Each worker thread has its own pool, which is freed when the thread
   exits. A task can move to another thread (waiting list), so a pooled
   fork is taken out of the pool while in use, and put back into the
   pool of the thread that ends the task. */
pthread_key_t pool_key;

void pool_key_create()
{
	AZ(pthread_key_create(&pool_key,
		[] (void* pool) { delete (ForkPool*) pool; }));
	/* The key's destructor is in this VMOD, and runs whenever a worker
	   thread exits */
	SandboxTenant::pin_vmod();
}

ForkPool& fork_pool()
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	AZ(pthread_once(&once, pool_key_create));
	auto* pool = (ForkPool*) pthread_getspecific(pool_key);
	if (UNLIKELY(pool == nullptr)) {
		pool = new ForkPool;
		AZ(pthread_setspecific(pool_key, pool));
	}
	return *pool;
}
}

long SandboxTenant::pooled_count() { return pooled_vms.load(); }

void SandboxTenant::pin_vmod()
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	AZ(pthread_once(&once, [] {
		Dl_info info;
		if (dladdr((void*) &SandboxTenant::pin_vmod, &info) && info.dli_fname != nullptr)
			(void) dlopen(info.dli_fname, RTLD_NOW | RTLD_NODELETE);
	}));
}

Script* SandboxTenant::pool_acquire(VRT_CTX, std::shared_ptr<MachineInstance> prog)
{
	auto& pool = fork_pool();
	pool.drop_retired();
	auto& idle = pool.idle;
	/* The most recently used VM has the warmest caches */
	for (size_t i = idle.size(); i-- > 0; ) {
		Script* script = idle[i];
		if (&script->program() == prog.get()) {
			idle.erase(idle.begin() + i);
			script->set_ctx(ctx);
			return script;
		}
	}
	auto* script = new Script{prog->script, ctx, this, *prog, true};
	pooled_vms++;
	script->assign_instance(prog);
	return script;
}

void SandboxTenant::pool_release(Script* script, bool restore)
{
	/* A VM of a replaced program is not kept, nor one whose task left
	   state behind that a reset does not undo */
	bool reusable = !script->program().retired.load(std::memory_order_relaxed);
	try {
		reusable = reusable && script->reset_to_master(restore);
	} catch (...) {
		reusable = false;
	}
	if (!reusable) {
		destroy_pooled(script);
		return;
	}
	auto& idle = fork_pool().idle;
	/* Evict the least recently used fork */
	if (idle.size() >= ForkPool::MAX_IDLE) {
		destroy_pooled(idle.front());
		idle.erase(idle.begin());
	}
	idle.push_back(script);
}

static void PoolFreeFunction(void* priv) {
	SandboxTenant::pool_release((Script*) priv);
}
#ifndef VARNISH_PLUS
static void PoolPrivFreeFunction(const struct vrt_ctx*, void *priv)
{
	PoolFreeFunction(priv);
}
static const struct vmod_priv_methods riscv_pool_priv_methods[1] = {{
	.magic = VMOD_PRIV_METHODS_MAGIC,
	.type = "vmod_riscv_pool",
	.fini = PoolPrivFreeFunction
}};
#endif

Script* SandboxTenant::vmfork(VRT_CTX, bool debug, bool permanent)
{
	auto* priv_task = VRT_priv_task(ctx, get_priv_key(ctx));
	if (!priv_task->priv)
	{
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t0);
	#endif
		std::shared_ptr<MachineInstance> prog;
		if (LIKELY(!debug))
			prog = rvs::atomic_load(&this->program);
		else
			prog = rvs::atomic_load(&this->debug_program);
		/* First-time tenants could have no program loaded */
		if (UNLIKELY(prog == nullptr)) {
			VSLb(ctx->vsl, SLT_VCL_Error,
			    "No program loaded: %s", this->config.name.c_str());
			return nullptr;
		}
		if (permanent && !debug) {
			Script* script;
			try {
				script = pool_acquire(ctx, std::move(prog));
			} catch (std::exception& e) {
				VRT_fail(ctx, "VM '%s' exception: %s", config.name.c_str(), e.what());
				return nullptr;
			}
			priv_task->priv = script;
			priv_task->len  = SCRIPT_MAGIC;
#ifdef VARNISH_PLUS
			priv_task->free = PoolFreeFunction;
#else
			priv_task->methods = riscv_pool_priv_methods;
#endif
			return script;
		}
		/* Allocate Script on workspace, and construct it in-place */
		uintptr_t saddr = (uintptr_t)WS_Alloc(ctx->ws, sizeof(Script) + 0x20);
		if (UNLIKELY(saddr == 0x0)) {
			VRT_fail(ctx, "Out of workspace");
			return nullptr;
		}
		// IMPORTANT: Make sure Script* is 32-byte aligned
		saddr = (saddr + 0x1F) & ~(uintptr_t)0x1F;
		auto* script = (Script*) saddr;

		try {
			new (script) Script{prog->script, ctx, this, *prog};
			/* This creates a self-reference, which ensures that open
			   Script instances will keep the machine instance alive. */
			script->assign_instance(prog);

		} catch (std::exception& e) {
			VRT_fail(ctx,
				"VM '%s' exception: %s", script->name().c_str(), e.what());
			return nullptr;
		}
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t1);
		timing_constr.add(t0, t1);
	#endif

		priv_task->priv = script;
		priv_task->len  = SCRIPT_MAGIC;
#ifdef VARNISH_PLUS
		priv_task->free = SandboxFreeFunction;
#else
		priv_task->methods = riscv_priv_methods;
#endif
	}
	else if (UNLIKELY(((Script*) priv_task->priv)->vrm() != this)) {
		VSLb(ctx->vsl, SLT_VCL_Error,
		    "riscv.fork: '%s' already forked, can't fork '%s'",
		    ((Script*) priv_task->priv)->name().c_str(),
		    this->config.name.c_str());
		return nullptr;
	}
	return (Script*) priv_task->priv;
}

#include <unistd.h>
std::vector<uint8_t> file_loader(const std::string& filename)
{
    size_t size = 0;
    FILE* f = fopen(filename.c_str(), "rb");
    if (f == NULL) throw std::runtime_error("Could not open file: " + filename);

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> result(size);
    if (size != fread(result.data(), 1, size, f))
    {
        fclose(f);
        throw std::runtime_error("Error when reading from file: " + filename);
    }
    fclose(f);
    return result;
}

} // rvs
