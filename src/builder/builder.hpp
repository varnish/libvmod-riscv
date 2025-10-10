#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

extern std::vector<uint8_t> build_and_load(
    const std::string& code,
    const std::string& args = "-O2 -static");

extern std::vector<uint8_t> build_and_load_rust(
	const std::string& path);
