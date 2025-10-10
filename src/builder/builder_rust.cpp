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
	const char *script_file =
		R"(#!/bin/bash
set -e
set -o pipefail
export RUSTFLAGS="-C target-feature=+crt-static -C link-args=-Wl,--wrap=memcpy,--wrap=memset,--wrap=memmove,--wrap=memcmp,--wrap=strlen,--wrap=__memcmpeq"
pushd "$1"
cargo build --release --target riscv64gc-unknown-linux-gnu
)";
	char filebuffer[256];
	const char* filename = tmpnam_r(filebuffer);
	if (filename == nullptr) {
		throw std::runtime_error("Unable to create temporary build script");
	}
	FILE* f = fopen(filename, "w");
	if (f == nullptr) {
		throw std::runtime_error("Unable to open temporary build script");
	}
	size_t written = fwrite(script_file, 1, strlen(script_file), f);
	fclose(f);
	if (written != strlen(script_file)) {
		throw std::runtime_error("Unable to write temporary build script");
	}
	chmod(filename, 0755);

	char command[8192];
	snprintf(command, sizeof(command),
		"exec %s \"%s\"",
		filename,
		path.c_str());

	if constexpr (VERBOSE_COMPILER) {
		printf("Command: %s\n", command);
	}
	// Compile program
	f = popen(command, "r");
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

	const std::string bin_filename = path + "/target/riscv64gc-unknown-linux-gnu/release/rusty";
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
