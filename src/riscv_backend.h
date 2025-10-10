#pragma once
#include <stddef.h>
#include <stdint.h>

struct VMBuffer {
	const char *data;
	ssize_t size;
};

struct vmod_riscv_post {
	uint64_t address;
	size_t   length;
	size_t   capacity;
	const struct vrt_ctx *ctx;
};
#define POST_BUFFER (128ull * 1024 * 1024)

struct vmod_riscv_arguments {
	uint64_t funcaddr;
	uint64_t funcarg;
	uint64_t max_response_size;
	struct vmod_riscv_post post;
};

struct backend_result {
	const char *type;
	uint16_t tsize; /* Max 64KB Content-Type */
	int16_t  status;
	size_t  content_length;
	size_t  bufcount;
	struct VMBuffer buffers[0];
};

#define VMBE_NUM_BUFFERS  1024
#define VMBE_RESULT_SIZE  (sizeof(struct backend_result) + VMBE_NUM_BUFFERS * sizeof(struct VMBuffer))
