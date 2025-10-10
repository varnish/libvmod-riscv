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

inline const char* optional_copy(VRT_CTX, const riscv::Buffer& buffer)
{
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
			/* Cast all arguments to gaddr_t to avoid double-register 64-bit ABI */
			machine.vmcall(args->funcaddr, (Script::gaddr_t)args->funcarg, (Script::gaddr_t)args->post.address, (Script::gaddr_t)args->post.length);
			/* Restore old ctx for backend_response */
			script->set_ctx(old_ctx);

			/* Get content-type, data and status */
			const auto [status, type, data, datalen] =
				machine.sysargs<int, riscv::Buffer, Script::gaddr_t, Script::gaddr_t> ();
			/* Return content-type, status, and iovecs containing data */
			using vBuffer = riscv::vBuffer;
			result->type = optional_copy(ctx, type);
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
	auto* script = get_machine(post->ctx, post->ctx->bo);
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