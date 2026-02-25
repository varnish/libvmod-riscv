#pragma once

struct http {
	unsigned       magic;
	uint16_t       fields_max;
	txt*           field_array;
	unsigned char* field_flags;
	uint16_t       field_count;
	enum VSL_tag_e logtag;
	struct vsl_log*vsl;
	struct ws*     ws;
	uint16_t       status;
	uint8_t        protover;
	uint8_t        conds;
};

#ifdef VARNISH_PLUS
void http_SetStatus(struct http *hp, uint16_t status);
#else
void http_SetStatus(struct http *to, uint16_t status, const char *reason);
const char *http_Status2Reason(uint16_t status, const char **pdefault);
#endif
void http_SetH(struct http *to, unsigned n, const char *fm);
void http_UnsetIdx(struct http *hp, unsigned idx);
unsigned HTTP_FindHdr(const struct http *hp, unsigned l, const char *hdr);
void http_PrintfHeader(struct http *to, const char *fmt, ...);
void riscv_SetCacheable(VRT_CTX, bool a);
bool riscv_GetCacheable(VRT_CTX);
void riscv_SetTTL(VRT_CTX, float ttl);
float riscv_GetTTL(VRT_CTX);
long riscv_SetBackend(VRT_CTX, VCL_BACKEND);

#define HDR_FIRST     6
#define HDR_INVALID   UINT32_MAX
