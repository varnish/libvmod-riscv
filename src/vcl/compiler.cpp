#include "compiler.hpp"
#include "abi.hpp"
#include "../script.hpp"
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

/* vclc_blob.S */
extern "C" const uint8_t vclc_elf[];
extern "C" const uint8_t vclc_elf_end[];

namespace rvs::vcl {
using machine_t = Script::machine_t;
using gaddr_t = Script::gaddr_t;

/* Limits of one compile. Constants, not configuration: a legitimate policy
   that hits one has found a compiler performance bug, not a knob. */
static constexpr uint64_t MAX_INSTRUCTIONS = 16'000'000'000ull;
static constexpr uint64_t MAX_MEMORY = 512ull << 20;
static constexpr uint64_t ARENA_SIZE = 256ull << 20;
/* NATIVE_SYSCALLS_BASE in script.cpp, and HEAP_SYSCALLS_BASE in
   vcl/vclc/src/env.rs. */
static constexpr unsigned HEAP_SYSCALLS_BASE = 580;

/* Mirrors of vcl/compiler: MAX_SOURCE_BYTES, MAX_INCLUDE_FILES, and the
   caps in wire.rs the host decodes the answer under. */
static constexpr size_t MAX_SOURCE_BYTES = 1024 * 1024;
static constexpr size_t MAX_INCLUDE_FILES = 64;
static constexpr size_t MAX_ELF = 8 * 1024 * 1024;
static constexpr size_t MAX_LINE_ENTRIES = 1024 * 1024;
static constexpr size_t MAX_RENDERED = 1024 * 1024;
static constexpr size_t MAX_NAME = 4096;
static constexpr size_t MAX_RESPONSE = MAX_ELF + 16 * MAX_LINE_ENTRIES
	+ (MAX_INCLUDE_FILES + 1) * (MAX_NAME + MAX_RENDERED) + 64;
static constexpr uint32_t WIRE_VERSION = 2;

/* ── Include session ────────────────────────────────────────────────── */

/* The syscall table is per machine type, so the include read is reachable
   from every tenant VM in the process. What makes it answer only the
   compiler is this thread-local, which exists only while compile() runs
   the guest on this thread. */
struct IncludeSession
{
	std::string root;       // realpath of the policy's directory
	size_t files = 0;
	size_t bytes = 0;
	/* The guest measures, then fills: the last answer is kept so the
	   second call neither reads the file again nor sees it change. */
	std::string last_name;
	std::string last_answer;
	bool last_ok = false;
};
static thread_local IncludeSession* session = nullptr;

static bool read_beneath(IncludeSession& s, const std::string& name, std::string& out)
{
	/* The compiler has already normalised the name and confined it to a
	   relative path; the host confines it again, against the filesystem. */
	if (name.empty() || name[0] == '/' || name.find('\0') != std::string::npos) {
		out = "include '" + name + "' is not a relative path";
		return false;
	}
	const std::string joined = s.root + "/" + name;
	char resolved[PATH_MAX];
	if (realpath(joined.c_str(), resolved) == nullptr) {
		out = "include '" + name + "' was not found";
		return false;
	}
	if (strncmp(resolved, s.root.c_str(), s.root.size()) != 0 || resolved[s.root.size()] != '/') {
		out = "include '" + name + "' resolves outside the policy directory";
		return false;
	}
	const int fd = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		if (fd >= 0) close(fd);
		out = "include '" + name + "' is not a regular file";
		return false;
	}
	if (s.files >= MAX_INCLUDE_FILES || size_t(st.st_size) > MAX_SOURCE_BYTES - s.bytes) {
		close(fd);
		out = "include '" + name + "' is past the limit of " + std::to_string(MAX_INCLUDE_FILES)
			+ " files and " + std::to_string(MAX_SOURCE_BYTES) + " bytes per policy";
		return false;
	}
	out.resize(st.st_size);
	size_t got = 0;
	while (got < out.size()) {
		const ssize_t n = read(fd, out.data() + got, out.size() - got);
		if (n <= 0) break;
		got += n;
	}
	close(fd);
	out.resize(got);
	s.files++;
	s.bytes += got;
	return true;
}

/* TYPED_INCLUDE_READ(name, name_len, out, cap): >= 0 the source's length,
   < 0 a refusal whose reason is -(n + 1) bytes. Either is copied into
   `out` when it fits. */
void include_read(machine_t& m)
{
	const auto nptr = m.sysarg<gaddr_t>(1);
	const auto nlen = m.sysarg<gaddr_t>(2);
	const auto out  = m.sysarg<gaddr_t>(3);
	const auto cap  = m.sysarg<gaddr_t>(4);

	std::string answer;
	bool ok = false;
	if (session == nullptr) {
		/* A tenant policy calling it: no log line, since a policy could
		   otherwise drive the log at whatever rate its budget allows. */
		answer = "this host call is not available to tenant programs";
	} else if (nlen > MAX_NAME) {
		answer = "include name is too long";
	} else {
		std::string name(nlen, '\0');
		m.memory.memcpy_out(name.data(), nptr, nlen);
		if (name == session->last_name) {
			answer = session->last_answer;
			ok = session->last_ok;
		} else {
			ok = read_beneath(*session, name, answer);
			session->last_name = std::move(name);
			session->last_answer = answer;
			session->last_ok = ok;
		}
	}
	if (out != 0 && cap >= answer.size() && !answer.empty())
		m.copy_to_guest(out, answer.data(), answer.size());
	m.set_result(ok ? int64_t(answer.size()) : -int64_t(answer.size()) - 1);
}

/* ── Wire format (vcl/compiler/src/wire.rs) ─────────────────────────── */

static void put_u8(std::string& o, uint8_t v) { o.push_back(char(v)); }
static void put_u32(std::string& o, uint32_t v) { o.append(reinterpret_cast<const char*>(&v), 4); }
static void put_str(std::string& o, const std::string& s) { put_u32(o, uint32_t(s.size())); o.append(s); }

static std::string encode_request(const std::string& filename, const std::string& root,
	const std::string& source)
{
	std::string o;
	o.append("VCLQ");
	put_u32(o, WIRE_VERSION);
	put_str(o, filename);
	put_str(o, root);
	put_str(o, source);
	put_u8(o, 1);  // verify_ir
	put_u8(o, 1);  // optimization: basic
	put_u32(o, 0); // variant_headers: a Carapace routing concept, none here
	put_u8(o, 0);  // stale_caps: none
	return o;
}

/* A cursor that never reads past its buffer, and checks every length
   against what is left before it trusts it. The guest is our compiler,
   but it has just run over untrusted source. */
struct Reader
{
	const uint8_t* p;
	size_t left;
	void need(size_t n, const char* what) {
		if (n > left)
			throw std::runtime_error(std::string("VCL compiler answer is truncated at ") + what);
	}
	uint8_t u8(const char* what) { need(1, what); left--; return *p++; }
	uint32_t u32(const char* what) { need(4, what); uint32_t v; memcpy(&v, p, 4); p += 4; left -= 4; return v; }
	std::string bytes(const char* what, size_t max) {
		const uint32_t n = u32(what);
		if (n > max)
			throw std::runtime_error(std::string("VCL compiler answer has an oversized ") + what);
		need(n, what);
		std::string s(reinterpret_cast<const char*>(p), n);
		p += n; left -= n;
		return s;
	}
	void skip(size_t n, const char* what) { need(n, what); p += n; left -= n; }
	uint32_t count(const char* what, size_t max, size_t min_each) {
		const uint32_t n = u32(what);
		if (n > max || size_t(n) * min_each > left)
			throw std::runtime_error(std::string("VCL compiler answer has a bad ") + what + " count");
		return n;
	}
};

static Compiled decode_response(const std::string& buffer)
{
	Reader r{reinterpret_cast<const uint8_t*>(buffer.data()), buffer.size()};
	r.need(4, "magic");
	if (memcmp(r.p, "VCLR", 4) != 0)
		throw std::runtime_error("VCL compiler answer has a bad magic");
	r.skip(4, "magic");
	if (r.u32("version") != WIRE_VERSION)
		throw std::runtime_error("VCL compiler answer is from another wire version");
	const uint8_t tag = r.u8("outcome");
	if (tag == 1)
		throw std::runtime_error(r.bytes("diagnostics", MAX_RENDERED));
	if (tag != 0)
		throw std::runtime_error("VCL compiler answer has an unknown outcome");

	Compiled result;
	const std::string elf = r.bytes("elf", MAX_ELF);
	result.elf.assign(elf.begin(), elf.end());
	/* The line table and the file list are for a debugger; the VMOD has no
	   use for them yet, so they are validated and skipped. */
	const uint32_t lines = r.count("line table", MAX_LINE_ENTRIES, 16);
	r.skip(size_t(lines) * 16, "line table");
	const uint32_t files = r.count("file list", MAX_INCLUDE_FILES, 4);
	for (uint32_t i = 0; i < files; i++)
		r.bytes("file name", MAX_NAME);
	r.u32("exports");
	const uint32_t warnings = r.count("warnings", MAX_INCLUDE_FILES, 4);
	for (uint32_t i = 0; i < warnings; i++)
		result.warnings.push_back(r.bytes("warning", MAX_RENDERED));
	if (r.left != 0)
		throw std::runtime_error("VCL compiler answer has trailing bytes");
	return result;
}

/* ── The compile ────────────────────────────────────────────────────── */

static std::string read_source(const std::string& path)
{
	const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		if (fd >= 0) close(fd);
		throw std::runtime_error("Could not open VCL file: " + path);
	}
	if (size_t(st.st_size) > MAX_SOURCE_BYTES) {
		close(fd);
		throw std::runtime_error("VCL file is larger than " + std::to_string(MAX_SOURCE_BYTES)
			+ " bytes: " + path);
	}
	std::string source(st.st_size, '\0');
	size_t got = 0;
	while (got < source.size()) {
		const ssize_t n = read(fd, source.data() + got, source.size() - got);
		if (n <= 0) break;
		got += n;
	}
	close(fd);
	source.resize(got);
	return source;
}

Compiled compile(const std::string& path)
{
	const std::string source = read_source(path);
	char dir[PATH_MAX];
	{
		std::string parent = path.substr(0, path.find_last_of('/') + 1);
		if (parent.empty()) parent = ".";
		if (realpath(parent.c_str(), dir) == nullptr)
			throw std::runtime_error("Could not resolve the directory of " + path);
	}

	const std::string_view elf{reinterpret_cast<const char*>(vclc_elf), size_t(vclc_elf_end - vclc_elf)};
	machine_t machine{elf, riscv::MachineOptions<Script::MARCH>{
		.memory_max = MAX_MEMORY,
		.default_exit_function = "fast_exit",
#ifdef RISCV_BINARY_TRANSLATION
		/* One run per machine: translating 1.8 MB of compiler costs more
		   than interpreting the ~10 ms a compile takes. */
		.translate_enabled = false,
#endif
	}};
	machine.set_userdata<void>(nullptr);
	machine.set_printer([] (const machine_t&, const char*, size_t) {});
	machine.set_stdin([] (const machine_t&, char*, size_t) -> long { return 0; });
	machine.setup_linux({"vclc"}, {"LC_ALL=C"});
	machine.setup_linux_syscalls(false, false);
	const auto arena = machine.memory.mmap_allocate(ARENA_SIZE);
	machine.setup_native_heap(HEAP_SYSCALLS_BASE, arena, ARENA_SIZE);
	machine.setup_native_memory(HEAP_SYSCALLS_BASE + 5);

	IncludeSession include{.root = dir};
	session = &include;
	struct Reset { ~Reset() { session = nullptr; } } reset;

	gaddr_t answer = 0;
	try {
		machine.simulate(MAX_INSTRUCTIONS);
		const std::string request = encode_request(path, dir, source);
		const gaddr_t input = machine.arena().malloc(request.size());
		if (input == 0)
			throw std::runtime_error("out of memory for the request");
		machine.copy_to_guest(input, request.data(), request.size());
		answer = machine.vmcall<MAX_INSTRUCTIONS>("vclc_compile", input, gaddr_t(request.size()));
	} catch (const riscv::MachineTimeoutException&) {
		throw std::runtime_error("VCL compile of " + path + " ran past its instruction budget");
	} catch (const riscv::MachineException& e) {
		/* A compiler panic is an abort, which is a machine fault here: the
		   containment the sandbox exists for. */
		throw std::runtime_error("VCL compiler failed on " + path + ": " + e.what());
	}
	if (answer == 0)
		throw std::runtime_error("VCL compiler returned no answer for " + path);

	uint32_t len;
	machine.memory.memcpy_out(&len, answer, 4);
	if (len > MAX_RESPONSE)
		throw std::runtime_error("VCL compiler answer is oversized");
	std::string buffer(len, '\0');
	machine.memory.memcpy_out(buffer.data(), answer + 4, len);
	return decode_response(buffer);
}

} // rvs::vcl
