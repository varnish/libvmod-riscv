#include "builder.hpp"

#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#include <libriscv/common.hpp>
#include "builder.sh.h"
static constexpr bool VERBOSE_COMPILER = false;
/* Where program/ (the guest API and toolchain files) is: the source tree
   this VMOD was built from, unless RISCV_PROGRAM_PATH says otherwise. */
#ifndef RISCV_PROGRAM_PATH
#define RISCV_PROGRAM_PATH "."
#endif
static const std::string PROGRAM_PATH = RISCV_PROGRAM_PATH;

std::string env_with_default(const char* var, const std::string& defval) {
	std::string value = defval;
	if (const char* envval = getenv(var); envval) value = std::string(envval);
	return value;
}

TemporaryDirectory::TemporaryDirectory()
{
	char templ[] = "/tmp/builder-XXXXXX";
	if (mkdtemp(templ) == nullptr)
		throw std::runtime_error("Unable to create temporary directory");
	this->path = templ;
}
TemporaryDirectory::~TemporaryDirectory()
{
	std::error_code ec;
	std::filesystem::remove_all(this->path, ec);
}
std::string TemporaryDirectory::write(const std::string& name,
	const std::string& contents, mode_t mode)
{
	const std::string filename = this->path + "/" + name;
	const int fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_EXCL, mode);
	if (fd < 0)
		throw std::runtime_error("Unable to create temporary file: " + filename);
	const ssize_t len = ::write(fd, contents.data(), contents.size());
	close(fd);
	if (len < (ssize_t)contents.size())
		throw std::runtime_error("Unable to write to temporary file: " + filename);
	return filename;
}

std::vector<uint8_t> load_file(const std::string& filename)
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

std::vector<uint8_t>
	build_and_load(const std::string& code, const std::string& args)
{
	/* micro.cmake picks the compiler flags */
	(void) args;
	// The builder script, the code and the binary, all removed afterwards
	TemporaryDirectory tmpdir;
	const std::string builder_script =
		tmpdir.write("builder.sh", std::string((const char*)builder_sh, builder_sh_len), 0700);
	const std::string code_file = tmpdir.write("program.cpp", code, 0600);
	const std::string bin_filename = tmpdir.path + "/program";
	const std::string gcc_triple = env_with_default("RISCV_GCC_TRIPLE",
#if defined(RISCV_64I) && defined(RISCV_EXT_C)
		"riscv64-linux-gnu"
#elif defined(RISCV_64I)
		"riscv64-unknown-elf"
#else
		"riscv32-unknown-elf"
#endif
	);
	const std::string program_path = env_with_default("RISCV_PROGRAM_PATH", PROGRAM_PATH);

	char command[8192];
	snprintf(command, sizeof(command),
		"exec \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"",
		builder_script.c_str(),
		gcc_triple.c_str(),
		program_path.c_str(),
		code_file.c_str(),
		bin_filename.c_str());

	if constexpr (VERBOSE_COMPILER) {
		printf("Command: %s\n", command);
	}
	// Compile program
	FILE* f = popen(command, "r");
	if (f == nullptr) {
		throw std::runtime_error("Unable to compile code");
	}
	ssize_t r = 0;
	size_t len = 0;
	do {
		r = fread(command, 1, sizeof(command), f);
		if (r > 0) {
			len = r;
		}
	} while (r > 0);
	pclose(f);

	try {
		return load_file(bin_filename);
	} catch (const std::exception& e) {
		if (len > 0) {
			printf("Compilation:\n%.*s\n", (int)len, command);
		}
		fprintf(stderr, "Error: %s\n", e.what());
		throw;
	}
}
