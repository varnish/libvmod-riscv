#include "script_functions.hpp"
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/sha.h>
#include <array>
#include <cstring>

namespace rvs {

void sha256(machine_t& machine)
{
	auto [buffer, dst, dstlen] =
		machine.sysargs<riscv::Buffer, gaddr_t, unsigned> ();
	if (UNLIKELY(dstlen != 32)) {
		machine.set_result(0);
		return;
	}

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	buffer.foreach(
		[&ctx] (const char* data, size_t len) {
			SHA256_Update(&ctx, data, len);
		});
	unsigned char result[SHA256_DIGEST_LENGTH];
	SHA256_Final(result, &ctx);

	machine.copy_to_guest(dst, result, sizeof(result));
	machine.set_result(SHA256_DIGEST_LENGTH);
}

using hmac_state_t = std::array<SHA_LONG, 16>;

static SHA256_CTX resume(const SHA_LONG* h)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	std::memcpy(ctx.h, h, sizeof(ctx.h));
	ctx.Nl = SHA256_CBLOCK * 8;
	return ctx;
}

void hmac_sha256_key(machine_t& machine)
{
	auto [key, dst, dstlen] =
		machine.sysargs<riscv::Buffer, gaddr_t, unsigned> ();
	hmac_state_t state;
	if (UNLIKELY(dstlen != sizeof(state))) {
		machine.set_result(0);
		return;
	}
	std::array<unsigned char, SHA256_CBLOCK> k {};
	if (key.size() > k.size()) {
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		key.foreach(
			[&ctx] (const char* data, size_t len) {
				SHA256_Update(&ctx, data, len);
			});
		SHA256_Final(k.data(), &ctx);
	} else {
		size_t off = 0;
		key.foreach(
			[&k, &off] (const char* data, size_t len) {
				std::memcpy(k.data() + off, data, len);
				off += len;
			});
	}
	machine.penalize(key.size());

	const unsigned char pad[2] = {0x36, 0x5c};
	for (unsigned i = 0; i < 2; i++) {
		std::array<unsigned char, SHA256_CBLOCK> block;
		for (size_t j = 0; j < block.size(); j++)
			block[j] = k[j] ^ pad[i];
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, block.data(), block.size());
		std::memcpy(state.data() + 8 * i, ctx.h, sizeof(ctx.h));
	}
	machine.copy_to_guest(dst, state.data(), sizeof(state));
	machine.set_result(sizeof(state));
}

void hmac_sha256(machine_t& machine)
{
	static constexpr unsigned MAX_PARTS = 8;
	auto [state_addr, parts_addr, nparts, dst, dstlen] =
		machine.sysargs<gaddr_t, gaddr_t, unsigned, gaddr_t, unsigned> ();
	if (UNLIKELY(dstlen != SHA256_DIGEST_LENGTH || nparts > MAX_PARTS)) {
		machine.set_result(0);
		return;
	}
	hmac_state_t state;
	machine.memory.memcpy_out(state.data(), state_addr, sizeof(state));
	std::array<gaddr_t, 2 * MAX_PARTS> parts;
	machine.memory.memcpy_out(parts.data(), parts_addr, 2 * nparts * sizeof(gaddr_t));

	SHA256_CTX ctx = resume(state.data());
	size_t total = 0;
	for (unsigned i = 0; i < nparts; i++) {
		auto buffer = machine.memory.membuffer(parts[2 * i], parts[2 * i + 1]);
		buffer.foreach(
			[&ctx] (const char* data, size_t len) {
				SHA256_Update(&ctx, data, len);
			});
		total += buffer.size();
	}
	machine.penalize(total);
	std::array<unsigned char, SHA256_DIGEST_LENGTH> digest;
	SHA256_Final(digest.data(), &ctx);

	ctx = resume(state.data() + 8);
	SHA256_Update(&ctx, digest.data(), digest.size());
	SHA256_Final(digest.data(), &ctx);

	machine.copy_to_guest(dst, digest.data(), digest.size());
	machine.set_result(SHA256_DIGEST_LENGTH);
}

} // rvs
