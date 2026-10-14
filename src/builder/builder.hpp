#pragma once
#include <cstdint>
#include <sys/types.h>
#include <memory>
#include <string>
#include <vector>

extern std::vector<uint8_t> build_and_load(
    const std::string& code,
    const std::string& args = "-O2 -static");

extern std::vector<uint8_t> build_and_load_rust(
	const std::string& path);

/* A private directory under /tmp, removed with everything in it */
struct TemporaryDirectory
{
	TemporaryDirectory();
	~TemporaryDirectory();
	/* Creates name in the directory, and returns its path */
	std::string write(const std::string& name, const std::string& contents, mode_t mode);

	std::string path;
};
