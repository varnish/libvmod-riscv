#include "builder.hpp"

#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <libriscv/common.hpp>
#include <libriscv/util/crc32.hpp>
#include "builder.sh.h"
static constexpr bool VERBOSE_COMPILER = false;
static const std::string PROGRAM_PATH = "/home/gonzo/github/libvmod-riscv";

std::string env_with_default(const char* var, const std::string& defval) {
	std::string value = defval;
	if (const char* envval = getenv(var); envval) value = std::string(envval);
	return value;
}

struct TemporaryFile
{
	TemporaryFile(std::string contents)
	{
		// Create temporary filenames for code and binary
		this->filename = "/tmp/builder-XXXXXX";
		// Open temporary code file with owner privs
		this->fd = mkstemp(&filename[0]);
		if (this->fd < 0)
		{
			throw std::runtime_error(
				"Unable to create temporary file: " + this->filename);
		}

		// Write code to temp code file
		const ssize_t len = write(this->fd, contents.data(), contents.size());
		close(this->fd);
		if (len < (ssize_t)contents.size())
		{
			throw std::runtime_error("Unable to write to temporary file");
		}
	}
	~TemporaryFile()
	{
		//if (fd > 0)
		//	unlink(this->filename.c_str());
	}

	int fd;
	std::string filename;
};

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
	// Create temporary file for builder script
	TemporaryFile builder_script_tmpfile { std::string((const char*)builder_sh, builder_sh_len) };
	chmod(builder_script_tmpfile.filename.c_str(), 0755);

	// Create temporary filenames for code and binary
	TemporaryFile code_tmpfile { code };
	// Compile code to binary file
	char bin_filename[256];
	const uint32_t code_checksum = riscv::crc32((const uint8_t *)code.c_str(), code.size());
	const uint32_t final_checksum = riscv::crc32(code_checksum, (const uint8_t *)args.c_str(), args.size());
	(void)snprintf(bin_filename, sizeof(bin_filename),
		"/tmp/binary-%08X", final_checksum);
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
		"exec %s \"%s\" %s %s %s",
		builder_script_tmpfile.filename.c_str(),
		gcc_triple.c_str(),
		program_path.c_str(),
		code_tmpfile.filename.c_str(),
		bin_filename);

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
		std::vector<uint8_t> vec = load_file(bin_filename);
		unlink(bin_filename);
		return vec;
	} catch (const std::exception& e) {
		if (len > 0) {
			printf("Compilation:\n%.*s\n", (int)len, command);
		}
		fprintf(stderr, "Error: %s\n", e.what());
		throw;
	}
}
