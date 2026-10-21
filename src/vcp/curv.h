/*
 * libcurv's header from Varnish Enterprise (include/curv.h, as of
 * 6.0.18r6), which varnish-plus-dev does not install. libcurv itself is
 * linked into varnishd, and started by it, since 6.0.16r10. Keep this
 * in sync with the struct curv_req layout of the Varnish it runs in.
 */
/*
 * Copyright (c) 2022 Varnish Software AS
 * All rights reserved.
 *
 * Author: Reza Naghibi <reza@varnish-software.com>
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
 *
 */

#include <curl/curl.h>

#define CURV_MAX_OBJECTS		100
#define CURV_LABEL_OBJECT		(CURV_MAX_OBJECTS + 1)

#define COK(s)				((s) == CURLE_OK)

#define ACOK(s)						\
	do {						\
		if ((s) != CURLE_OK)			\
			WRONG(curl_easy_strerror(s));	\
	} while (0)

#define ACMOK(s)					\
	do {						\
		if ((s) != CURLM_OK)			\
			WRONG(curl_multi_strerror(s));	\
	} while (0)

extern struct VSC_vmod_http *curv_vsc;

struct curv_task;

enum curv_param_type {
	CURV_PARAM_NONE = 0,
	CURV_PARAM_STRINGPOINT,
	CURV_PARAM_LONG
};

enum curv_log_level {
	CURV_LOG_NONE = 0,
	CURV_LOG_LOW,
	CURV_LOG_MEDIUM,
	CURV_LOG_HIGH,
	CURV_LOG_DEBUG
};

struct curv_param {
	unsigned			magic;
#define CURV_PARAM_MAGIC		0xA85346EE

	VRB_ENTRY(curv_param)		entry;

	const char			*param;
	int				value;
	enum curv_param_type		type;
};

struct curv_alloc {
	unsigned			magic;
#define CURV_ALLOC_MAGIC		0xbbbd9d25
	VSLIST_ENTRY(curv_alloc)	list;
	char				data[];
};

struct curv_header {
	unsigned			magic;
#define CURV_HEADER_MAGIC		0x80f33c34
	const char			*name;
	union {
		const char		*resp_value;
		const char		*req_hdrline;
	};
	VTAILQ_ENTRY(curv_header)	list;
};
VTAILQ_HEAD(curv_header_head, curv_header);

struct curv_debugline {
	VSTAILQ_ENTRY(curv_debugline)	list;
	char				data[];
};

struct curv_req {
	unsigned			magic;
#define CURV_REQ_MAGIC			0x53ecf9b6

	int				id;
	const char			*label;

	VSLIST_HEAD(, curv_alloc)	allocs;

	CURL				*easy;

	vtim_dur			elapsed;

	CURLcode			cc;

	unsigned			resp_skip:1;
	unsigned			resp_skip_body:1;
	unsigned			has_req_url:1;

	struct curv_header_head		req_headers;
	struct vsb			*req_body;

	const char			*resp_reason;
	struct curv_header_head		resp_headers;
	struct vsb			*resp_body;
	VSTAILQ_HEAD(, curv_debugline)	debuglog;
};

#define CURL_EASYSET(REQ, PARAM, VALUE)					\
	do {								\
		if ((REQ)->cc == CURLE_OK)				\
			(REQ)->cc = curl_easy_setopt((REQ)->easy,	\
			    PARAM, VALUE);				\
	} while (0)

#define CURL_EASYSET_RET(REQ, PARAM, VALUE)				\
	do {								\
		if ((REQ)->cc == CURLE_OK)				\
			(REQ)->cc = curl_easy_setopt((REQ)->easy,	\
			    PARAM, VALUE);				\
		if ((REQ)->cc != CURLE_OK)				\
			return;						\
	} while (0)

/* libcurv.c */
const char * curv_init(void);
void curv_fini(void);

/* libcurv_engine.c */
const char *curv_engine_init(void);
void curv_engine_fini(void);
const char *curv_engine_exec(struct curv_req **preq, struct curv_task **ptask,
	int do_debuglog, int resp_skip_body);
struct curv_req *curv_engine_wait(struct curv_task **ptask, int timeout_ms);
void curv_engine_mark_async(struct curv_task *task);
void curv_engine_detach(struct curv_task **ptask);
int curv_engine_task_count(int id, unsigned async_only);

/* libcurv_req.c */
struct curv_req *curv_req_new(int id, const char *name);
void curv_req_destroy(struct curv_req **preq);
const char *curv_req_get_reqheader(struct curv_req *req, const char *name);
struct curv_header * curv_req_header_from_txt(struct curv_req *req,
    const txt t);
int curv_req_set_reqheader(struct curv_req *req, const char *name,
    const char *value, int validate);
void curv_req_replace_reqheaders(struct curv_req *req,
    struct curv_header_head *headers);
const char *curv_req_get_respheader(struct curv_req *req, const char *name);
size_t curv_req_respheader_data(struct curv_req *req, const char *ptr,
    size_t len);
size_t curv_req_respbody_data(struct curv_req *req, const char *ptr,
    size_t len);
void curv_req_respfinish(struct curv_req *req);
void *curv_req_alloc(struct curv_req *req, size_t size);
void curv_req_add_debuglog(struct curv_req *req, const char *fmt, ...)
	v_printflike_(2, 3);

/* libcurv_params.c */
void curv_params_init(void);
const struct curv_param* curv_params_get(const char *param);
void curv_params_free(void);
