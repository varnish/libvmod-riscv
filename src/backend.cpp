#include "sandbox_tenant.hpp"
#include "varnish.hpp"

extern "C" {
#  include "riscv_backend.h"
}

namespace rvs {

inline Script* get_machine(VRT_CTX, const void* key)
{
	auto* priv_task = VRT_priv_task(ctx, key);
	//printf("priv_task: ctx=%p bo=%p key=%p task=%p\n", ctx, ctx->bo, key, priv_task);
	if (priv_task->priv && (unsigned)priv_task->len == SCRIPT_MAGIC)
		return (Script*) priv_task->priv;
	return nullptr;
}

/* The guest's Content-Type, which goes into a header line as is */
inline const char* content_type_copy(VRT_CTX, const riscv::Buffer& buffer)
{
	if (buffer.to_string().find_first_of(std::string_view("\r\n\0", 3)) != std::string::npos)
		throw std::runtime_error("Invalid Content-Type");
	if (buffer.is_sequential())
		return buffer.data();

	char* data = (char*) WS_Alloc(ctx->ws, buffer.size());
	// TODO: move to heap
	if (data == nullptr)
		throw std::runtime_error("Out of workspace");
	buffer.copy_to(data, buffer.size());
	return data;
}

} // rvs

extern "C"
void riscv_backend_call(VRT_CTX, const void* key, struct vmod_riscv_arguments *args,
	struct backend_result *result)
{
	using namespace rvs;
	auto* script = get_machine(ctx, ctx->bo);
	(void) key;
	if (script) {
		auto* old_ctx = script->ctx();
		try {
		#ifdef ENABLE_TIMING
			TIMING_LOCATION(t1);
		#endif
			/* Use backend ctx which can write to beresp */
			script->set_ctx(ctx);
			/* Call the backend response function */
			auto& machine = script->machine();
			/* What vmcall() does, but within the tenant's instruction
			   limit: vmcall() without one does not count instructions,
			   and a guest that never returns would keep the thread. */
			machine.cpu.reset_stack_pointer();
			/* Cast all arguments to gaddr_t to avoid double-register 64-bit ABI */
			machine.setup_call((Script::gaddr_t)args->funcarg, (Script::gaddr_t)args->post.address, (Script::gaddr_t)args->post.length);
			machine.simulate_with<true>(script->max_instructions(), 0u, args->funcaddr);
			/* Restore old ctx for backend_response */
			script->set_ctx(old_ctx);

			/* Get content-type, data and status */
			const auto [status, type, data, datalen] =
				machine.sysargs<int, riscv::Buffer, Script::gaddr_t, Script::gaddr_t> ();
			/* http_PutResponse() asserts on a status that is not three digits */
			if (UNLIKELY(status < 100 || status > 999))
				throw std::runtime_error("Invalid backend response status: " + std::to_string(status));
			/* Return content-type, status, and iovecs containing data */
			using vBuffer = riscv::vBuffer;
			result->type = content_type_copy(ctx, type);
			result->tsize = type.size();
			result->status = status;
			result->content_length = datalen;
			result->bufcount = machine.memory.gather_buffers_from_range(
				result->bufcount, (vBuffer *)result->buffers, data, datalen);

		#ifdef ENABLE_TIMING
			TIMING_LOCATION(t2);
			printf("Time spent in backend_call(): %ld ns\n", nanodiff(t1, t2));
		#endif
			return;
		} catch (const riscv::MachineException& e) {
			fprintf(stderr, "Backend VM exception: %s (data: 0x%lX)\n",
				e.what(), e.data());
			VSLb(ctx->vsl, SLT_Error,
				"Backend VM exception: %s (data: 0x%lX)\n",
				e.what(), e.data());
		} catch (const std::exception& e) {
			fprintf(stderr, "Backend VM exception: %s\n", e.what());
			VSLb(ctx->vsl, SLT_Error, "VM call exception: %s", e.what());
		}
		script->set_ctx(old_ctx);
	}
	/* An error result */
	new (result) backend_result {nullptr, 0,
		500, /* Internal server error */
		0,
		0, {}
	};
}
extern "C"
int riscv_backend_streaming_post(struct vmod_riscv_post *post,
	const void *data_ptr, ssize_t data_len)
{
	using namespace rvs;
	/* A backend VM is keyed on the busyobj, a deliver VM on the req */
	const void* key = post->ctx->req ? (const void *)post->ctx->req : post->ctx->bo;
	auto* script = get_machine(post->ctx, key);
	if (script) {
		auto* old_ctx = script->ctx();
		try {
			script->set_ctx(post->ctx);

			/* Regular POST, first payload: Allocate payload in VM. */
			if (post->length == 0)
			{
				assert(post->address == 0);
				post->address = script->allocate_post_data(post->capacity);
			}

			/* The body must fit what was allocated for it, or it
			   would be written over whatever the guest has after it. */
			if (UNLIKELY(data_len < 0 || size_t(data_len) > post->capacity - post->length))
				throw std::runtime_error("POST body is larger than " + std::to_string(post->capacity) + " bytes");

			/* Copy the data segment into VM at the right offset,
			   building a sequential, complete buffer. */
			script->machine().copy_to_guest(post->address + post->length, data_ptr, data_len);

			/* Increment POST length, no VM call. */
			post->length += data_len;
			return 0;
		} catch (const riscv::MachineException& e) {
			fprintf(stderr, "Streaming post VM exception: %s (data: 0x%lX)\n",
				e.what(), e.data());
			VSLb(post->ctx->vsl, SLT_Error,
				"Streaming post VM exception: %s (data: 0x%lX)\n",
				e.what(), e.data());
		} catch (const std::exception& e) {
			fprintf(stderr, "Streaming post VM exception: %s\n", e.what());
			VSLb(post->ctx->vsl, SLT_Error, "Streaming post VM exception: %s", e.what());
		}
		script->set_ctx(old_ctx);
	} else {
		fprintf(stderr, "Streaming post error: no VM instance\n");
		VSLb(post->ctx->vsl, SLT_Error, "Streaming post error: no VM instance");
	}
	return -1;
}
extern "C"
int riscv_deliver_call(VRT_CTX, const char* func, const char* arg,
	const struct vmod_riscv_post *post, struct deliver_result *result)
{
	using namespace rvs;
	auto* script = get_machine(ctx, ctx->req);
	if (script == nullptr) {
		VSLb(ctx->vsl, SLT_Error, "deliver_transform: no active tenant");
		return -1;
	}
	auto* old_ctx = script->ctx();
	try {
		Script::gaddr_t addr = 0;
		const auto it = script->program().function_map.find(func);
		if (it != script->program().function_map.end())
			addr = it->second;
		else
			addr = script->resolve_address(func);
		if (addr == 0)
			throw std::runtime_error("function '" + std::string(func) + "' not found");

		/* The guest may read and change resp while it runs */
		script->set_ctx(ctx);
		auto& machine = script->machine();
		machine.cpu.reset_stack_pointer();
		machine.setup_call(std::string(arg), (Script::gaddr_t)post->address, (Script::gaddr_t)post->length);
		machine.simulate_with<true>(script->max_instructions(), 0u, addr);
		script->set_ctx(old_ctx);

		/* A function that returns instead of responding has no answer */
		const auto exit_pc = machine.memory.exit_address();
		if (machine.cpu.pc() == exit_pc || machine.cpu.pc() == exit_pc + 4)
			throw std::runtime_error("function '" + std::string(func) + "' returned without a response");

		const auto [status, type, data, datalen] =
			machine.sysargs<int, riscv::Buffer, Script::gaddr_t, Script::gaddr_t> ();
		/* http_PutResponse() asserts on a status that is not three digits */
		if (UNLIKELY(status < 100 || status > 999))
			throw std::runtime_error("Invalid deliver response status: " + std::to_string(status));
		result->type = content_type_copy(ctx, type);
		result->tsize = type.size();
		result->status = status;
		result->data = data;
		result->length = datalen;
		return 0;
	} catch (const riscv::MachineException& e) {
		VSLb(ctx->vsl, SLT_Error,
			"deliver_transform VM exception: %s (data: 0x%lX)",
			e.what(), e.data());
	} catch (const std::exception& e) {
		VSLb(ctx->vsl, SLT_Error, "deliver_transform VM exception: %s", e.what());
	}
	script->set_ctx(old_ctx);
	return -1;
}

extern "C"
int riscv_deliver_map_body(struct vmod_riscv_post *post,
	const void *data_ptr, ssize_t data_len)
{
	using namespace rvs;
	auto* script = get_machine(post->ctx, post->ctx->req);
	if (script == nullptr) {
		VSLb(post->ctx->vsl, SLT_Error, "deliver_transform: no active tenant");
		return -1;
	}
	auto* old_ctx = script->ctx();
	try {
		script->set_ctx(post->ctx);
		if (post->length == 0)
		{
			assert(post->address == 0);
			post->address = script->allocate_post_data(post->capacity);
		}
		if (UNLIKELY(data_len < 0 || size_t(data_len) > post->capacity - post->length))
			throw std::runtime_error("Body is larger than " + std::to_string(post->capacity) + " bytes");

		auto& machine = script->machine();
		constexpr size_t PSIZE = riscv::Page::size();
		auto* src = (const uint8_t *)data_ptr;
		size_t len = data_len;
		Script::gaddr_t dst = post->address + post->length;

		const size_t head = std::min(len, (PSIZE - (dst & (PSIZE - 1))) & (PSIZE - 1));
		if (head > 0) {
			machine.copy_to_guest(dst, src, head);
			dst += head; src += head; len -= head;
		}
		const size_t whole = len & ~(PSIZE - 1);
		if (whole > 0) {
			machine.memory.free_pages(dst, whole);
			machine.memory.insert_non_owned_memory(dst, (void *)src, whole,
				riscv::PageAttributes{
					.read = true,
					.write = false,
					.exec = false,
					.is_cow = true });
			dst += whole; src += whole; len -= whole;
		}
		if (len > 0)
			machine.copy_to_guest(dst, src, len);

		post->length += data_len;
		script->set_ctx(old_ctx);
		return 0;
	} catch (const std::exception& e) {
		VSLb(post->ctx->vsl, SLT_Error, "deliver_transform: could not map the body: %s", e.what());
	}
	script->set_ctx(old_ctx);
	return -1;
}

extern "C"
void* riscv_deliver_machine(VRT_CTX)
{
	return rvs::get_machine(ctx, ctx->req);
}

extern "C"
int riscv_deliver_iterate(void *vscript, uint64_t addr, size_t len, void *priv,
	int (*func)(void *, int, int, const void *, ssize_t))
{
	auto* script = (rvs::Script*) vscript;
	const auto& memory = script->machine().memory;
	constexpr size_t MAX_BUFFERS = 64;
	riscv::vBuffer buffers[MAX_BUFFERS];
	try {
		while (len > 0)
		{
			const size_t chunk = std::min(len, (MAX_BUFFERS - 1) * riscv::Page::size());
			const size_t cnt = memory.gather_buffers_from_range(MAX_BUFFERS, buffers, addr, chunk);
			addr += chunk;
			len -= chunk;
			for (size_t i = 0; i < cnt; i++) {
				const int last = (len == 0 && i == cnt - 1);
				const int ret = func(priv, 1, last, buffers[i].ptr, buffers[i].len);
				if (ret != 0)
					return ret;
			}
		}
		return 0;
	} catch (const std::exception& e) {
		fprintf(stderr, "deliver_transform: could not read the response: %s\n", e.what());
	}
	return -1;
}

extern "C"
void riscv_deliver_unmap(void *vscript, uint64_t addr, size_t len)
{
	auto* script = (rvs::Script*) vscript;
	script->machine().memory.free_pages(addr, len);
}
