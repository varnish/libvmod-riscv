#include "builder.hpp"

#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <libriscv/util/crc32.hpp>
static constexpr bool VERBOSE_COMPILER = false;
extern std::vector<uint8_t> load_file(const std::string& filename);
extern std::string env_with_default(const char* var, const std::string& defval);

std::vector<uint8_t>
	build_and_load_rust(const std::string& path)
{
	/* Prints the path of the executable it built, from cargo's JSON */
	const char *script_file =
		R"SH(#!/bin/bash
set -e
set -o pipefail
export RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static -C link-args=-Wl,--wrap=memcpy,--wrap=memset,--wrap=memmove,--wrap=memcmp,--wrap=strlen,--wrap=__memcmpeq"
cd "$1"
cargo build --release --target "$2" --message-format=json-render-diagnostics |
	sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1
)SH";
	const std::string target = env_with_default("RISCV_RUST_TARGET",
		"riscv64gc-unknown-linux-gnu");
	// The build script, removed afterwards
	TemporaryDirectory tmpdir;
	const std::string script = tmpdir.write("build.sh", script_file, 0700);

	char command[8192];
	snprintf(command, sizeof(command),
		"exec \"%s\" \"%s\" \"%s\"",
		script.c_str(),
		path.c_str(),
		target.c_str());

	if constexpr (VERBOSE_COMPILER) {
		printf("Command: %s\n", command);
	}
	// Compile program
	FILE* f = popen(command, "r");
	if (f == nullptr) {
		throw std::runtime_error("Unable to compile Rust code");
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

	/* The last line of output is the executable */
	std::string bin_filename(command, len);
	while (!bin_filename.empty() && bin_filename.back() == '\n')
		bin_filename.pop_back();
	bin_filename = bin_filename.substr(bin_filename.find_last_of('\n') + 1);
	if (bin_filename.empty())
		throw std::runtime_error("Rust build of " + path + " produced no executable");
	// Load compiled binary
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
