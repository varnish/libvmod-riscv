#include "sandbox_tenant.hpp"
#include "varnish.hpp"
#include <dlfcn.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <map>
#include <mutex>
#include <set>
#include <thread>
extern "C" {
#ifdef VARNISH_PLUS
	void VSL_Setup(struct vsl_log*, void*, size_t);
#else
	void VSL_Alloc(struct vsl_log*);
	void VSL_Free(struct vsl_log*);
#endif
	void VSL_Flush(struct vsl_log*, int);
}
#ifndef VARNISH_PLUS
struct wrk_vpi {
	unsigned magic;
	unsigned handling;
	unsigned trace;
	unsigned ref;
};
#endif

namespace rvs {
extern std::string apply_dollar_vars(std::string str);

namespace {

constexpr uint32_t WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF;
constexpr int SETTLE_MS = 100;
constexpr size_t RELOAD_WS_SIZE = 64 * 1024;

struct BackgroundCtx {
	BackgroundCtx()
	{
		INIT_OBJ(&ctx, VRT_CTX_MAGIC);
		memset(&vsl, 0, sizeof(vsl));
#ifdef VARNISH_PLUS
		VSL_Setup(&vsl, nullptr, 0);
#else
		VSL_Alloc(&vsl);
		vpi.magic = 0xaa3d3df3;
		ctx.vpi = &vpi;
#endif
		WS_Init(&ws, "rvr", wsbuf.get(), RELOAD_WS_SIZE);
		ctx.vsl = &vsl;
		ctx.ws = &ws;
		ctx.msg = VSB_new_auto();
		AN(ctx.msg);
	}
	~BackgroundCtx()
	{
		AZ(VSB_finish(ctx.msg));
		if (VSB_len(ctx.msg) > 0)
			VSL(SLT_Error, RISCV_NO_VXID, "%s", VSB_data(ctx.msg));
		VSB_destroy(&ctx.msg);
		VSL_Flush(&vsl, 0);
#ifdef VARNISH_PLUS
		free(vsl.wlb);
#else
		VSL_Free(&vsl);
#endif
	}
	struct vrt_ctx ctx;
	struct vsl_log vsl;
	struct ws ws;
#ifndef VARNISH_PLUS
	struct wrk_vpi vpi {};
#endif
	std::unique_ptr<char[]> wsbuf {new char[RELOAD_WS_SIZE]};
};

struct Watched {
	std::weak_ptr<SandboxTenant> tenant;
	const SandboxTenant* key;
	std::set<std::string> dirs;
};

struct ConfigWatcher {
	std::mutex mtx;
	int fd = -1;
	int wake = -1;
	std::map<std::string, int> dirs;
	std::vector<Watched> watched;
};

ConfigWatcher& watcher()
{
	static auto* w = new ConfigWatcher;
	return *w;
}

std::string dirname_of(const std::string& path)
{
	const size_t slash = path.rfind('/');
	if (slash == path.npos)
		return ".";
	if (slash == 0)
		return "/";
	return path.substr(0, slash);
}

void reload(SandboxTenant& tenant)
{
	std::scoped_lock lock(tenant.update_mtx);
	auto old = rvs::atomic_load(&tenant.program);
	if (old == nullptr || old->is_vcl || config_files_current(*old))
		return;
	BackgroundCtx bg;
	try {
		auto inst = std::make_shared<MachineInstance>(
			std::vector<uint8_t>(old->binary), &bg.ctx, &tenant, false);
		rvs::atomic_store(&tenant.program, inst);
		transfer_state(*old, *inst, &bg.ctx);
		VSL(SLT_VCL_Log, RISCV_NO_VXID,
			"riscv: tenant '%s' reloaded after a config file changed",
			tenant.config.name.c_str());
	} catch (const std::exception& e) {
		VSL(SLT_Error, RISCV_NO_VXID,
			"riscv: tenant '%s' reload failed; keeping the current program: %s",
			tenant.config.name.c_str(), e.what());
	}
}

void check(ConfigWatcher& w)
{
	std::vector<std::shared_ptr<SandboxTenant>> live;
	{
		std::scoped_lock lock(w.mtx);
		std::erase_if(w.watched, [] (const Watched& e) { return e.tenant.expired(); });
		std::set<std::string> needed;
		for (const auto& e : w.watched) {
			if (auto t = e.tenant.lock())
				live.push_back(std::move(t));
			needed.insert(e.dirs.begin(), e.dirs.end());
		}
		for (auto it = w.dirs.begin(); it != w.dirs.end(); ) {
			if (needed.contains(it->first)) {
				++it;
				continue;
			}
			inotify_rm_watch(w.fd, it->second);
			it = w.dirs.erase(it);
		}
	}
	for (auto& tenant : live) {
		const auto program = rvs::atomic_load(&tenant->program);
		if (program != nullptr && !config_files_current(*program))
			reload(*tenant);
	}
}

void drain(int fd)
{
	alignas(struct inotify_event) char buffer[4096];
	while (read(fd, buffer, sizeof(buffer)) > 0) {}
}

void run(ConfigWatcher& w)
{
	struct pollfd fds[2] = {{w.fd, POLLIN, 0}, {w.wake, POLLIN, 0}};
	while (true) {
		if (poll(fds, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			VSL(SLT_Error, RISCV_NO_VXID, "riscv: config file watcher stopped: %s",
				strerror(errno));
			return;
		}
		do {
			drain(w.fd);
			drain(w.wake);
		} while (poll(fds, 2, SETTLE_MS) > 0);
		check(w);
	}
}

bool start(ConfigWatcher& w)
{
	if (w.fd >= 0)
		return true;
	/* The thread outlives the VCL that started it, so the VMOD must
	   remain loaded even after all VCLs using it have been discarded. */
	Dl_info info;
	if (dladdr((void*) &watch_config_files, &info) == 0 || info.dli_fname == nullptr
		|| dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE) == nullptr)
		return false;
	w.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	w.wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (w.fd < 0 || w.wake < 0) {
		if (w.fd >= 0)
			close(w.fd);
		if (w.wake >= 0)
			close(w.wake);
		w.fd = w.wake = -1;
		return false;
	}
	std::thread([&w] { run(w); }).detach();
	return true;
}

} // namespace

void watch_config_files(const std::shared_ptr<SandboxTenant>& tenant)
{
	if (tenant->config.group.config_files.empty())
		return;
	auto& w = watcher();
	std::scoped_lock lock(w.mtx);
	for (const auto& e : w.watched)
		if (e.key == tenant.get() && !e.tenant.expired())
			return;
	if (!start(w)) {
		VSL(SLT_Error, RISCV_NO_VXID,
			"riscv: unable to watch config files for tenant '%s': %s",
			tenant->config.name.c_str(), strerror(errno));
		return;
	}
	Watched entry {tenant, tenant.get(), {}};
	for (const auto& [name, path] : tenant->config.group.config_files) {
		const std::string dir = dirname_of(apply_dollar_vars(path));
		if (!w.dirs.contains(dir)) {
			const int wd = inotify_add_watch(w.fd, dir.c_str(), WATCH_MASK);
			if (wd < 0) {
				VSL(SLT_Error, RISCV_NO_VXID,
					"riscv: unable to watch '%s' for tenant '%s': %s",
					dir.c_str(), tenant->config.name.c_str(), strerror(errno));
				continue;
			}
			w.dirs.emplace(dir, wd);
		}
		entry.dirs.insert(dir);
	}
	w.watched.push_back(std::move(entry));
	const uint64_t one = 1;
	[[maybe_unused]] auto n = write(w.wake, &one, sizeof(one));
}

} // rvs
