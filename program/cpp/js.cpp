/**
 * QuickJS bridge for the Varnish RISC-V API
 *
 * Isolation model
 * ---------------
 * libriscv uses per-request snapshot/restore: the VM state captured after
 * main() returns is replayed from scratch for every incoming request.
 * This means:
 *   - g_ctx, g_global, g_hooks, and g_objects are set once at init-time and
 *     are part of the saved snapshot; they remain permanently valid across
 *     requests.
 *   - JS mutable state changed during a request (global vars, closure state)
 *     is automatically reverted for the next request — no bleed-through.
 *   - JS_FreeValue inside callbacks is GC hygiene within a single request;
 *     it is not required for cross-request correctness.
 *
 * The last argument is the JavaScript program string evaluated once at startup.
 * The program may define any of the following hooks as global functions:
 *
 *   function on_recv(req)                       { ... }  // vcl_recv
 *   function on_hash(req)                       { ... }  // vcl_hash
 *   function on_synth(req, resp)                { ... }  // vcl_synth
 *   function on_hit(req, obj)                   { ... }  // vcl_hit
 *   function on_miss(req, bereq)                { ... }  // vcl_miss
 *   function on_deliver(req, resp)              { ... }  // vcl_deliver
 *   function on_backend_fetch(bereq)            { ... }  // vcl_backend_fetch
 *   function on_backend_response(bereq, beresp) { ... }  // vcl_backend_response
 *   function on_backend_error(bereq, beresp)    { ... }  // vcl_backend_error
 *
 * req / bereq properties and methods:
 *   req.url            -> string  (lazy: fetched on access)
 *   req.method         -> string  (lazy: fetched on access)
 *   req.get(name)      -> string | null
 *   req.set(line)      -> void    // full "Name: Value" line
 *   req.unset(name)    -> void
 *
 * resp / beresp / obj properties and methods:
 *   resp.status           -> number  (lazy: fetched on access)
 *   resp.get(name)        -> string | null
 *   resp.set(line)        -> void
 *   resp.unset(name)      -> void
 *   resp.setStatus(code)  -> void
 *
 * The varnish namespace (global object "varnish") exposes:
 *
 *   Caching:
 *     varnish.setCacheable(bool)  -> void
 *     varnish.setTTL(secs)        -> void
 *
 *   Decisions / misc:
 *     varnish.decision(name [, status]) -> void
 *     varnish.hashData(str)             -> void
 *     varnish.print(str)  -> void  // Varnish stdout
 *     varnish.log(str)    -> void  // Varnish VSL log
 */

#include <api.h>
#include <quickjs.h>
#include <string.h>

namespace varnish = api;

// ---------------------------------------------------------------------------
// Global QuickJS state (lives for the entire process lifetime)
// ---------------------------------------------------------------------------

static JSContext* g_ctx    = nullptr;
static JSValue    g_global = JS_UNDEFINED;

// JS function references cached once after eval — avoids per-call property lookup
static struct {
	JSValue on_recv;
	JSValue on_hash;
	JSValue on_synth;
	JSValue on_hit;
	JSValue on_miss;
	JSValue on_deliver;
	JSValue on_backend_fetch;
	JSValue on_backend_response;
	JSValue on_backend_error;
} g_hooks;

// Pre-built HTTP objects — created once in main(), reused every request.
// The snapshot/restore model guarantees a pristine copy at each request entry.
static struct {
	JSValue req;    // HDR_REQ
	JSValue resp;   // HDR_RESP
	JSValue obj;    // HDR_OBJ  (cached object, vcl_hit)
	JSValue bereq;  // HDR_BEREQ
	JSValue beresp; // HDR_BERESP
} g_objects;

// ---------------------------------------------------------------------------
// Error reporting (mirrors js_std_dump_error without the libc dependency)
// ---------------------------------------------------------------------------

static void js_dump_exception(JSContext* ctx)
{
	JSValue exc = JS_GetException(ctx);

	const char* msg = JS_ToCString(ctx, exc);
	if (msg) {
		varnish::print("JS exception: {}\n", msg);
		JS_FreeCString(ctx, msg);
	}

	JSValue stack = JS_GetPropertyStr(ctx, exc, "stack");
	if (!JS_IsUndefined(stack) && !JS_IsNull(stack)) {
		const char* s = JS_ToCString(ctx, stack);
		if (s) {
			varnish::print("{}\n", s);
			JS_FreeCString(ctx, s);
		}
	}
	JS_FreeValue(ctx, stack);
	JS_FreeValue(ctx, exc);
}

// ---------------------------------------------------------------------------
// Header helpers: construct the API type inline and dispatch the syscall.
// gethdr_e is just an enum — no heap allocation needed.
// ---------------------------------------------------------------------------

static JSValue hdr_get(JSContext* ctx, api::gethdr_e where,
					   int argc, JSValueConst* argv)
{
	if (argc < 1)
		return JS_NULL;
	const char* name = JS_ToCString(ctx, argv[0]);
	if (!name)
		return JS_EXCEPTION;
	api::HTTP http{where};
	const auto hf = http.find(name);
	JS_FreeCString(ctx, name);
	if (!hf)
		return JS_NULL;
	const auto val = hf.value();
	return JS_NewStringLen(ctx, val.c_str(), val.size());
}

static JSValue hdr_set(JSContext* ctx, api::gethdr_e where,
					   int argc, JSValueConst* argv)
{
	if (argc < 1)
		return JS_UNDEFINED;
	size_t len;
	const char* line = JS_ToCStringLen(ctx, &len, argv[0]);
	if (!line)
		return JS_EXCEPTION;
	api::HTTP{where}.append({line, len});
	JS_FreeCString(ctx, line);
	return JS_UNDEFINED;
}

static JSValue hdr_unset(JSContext* ctx, api::gethdr_e where,
						 int argc, JSValueConst* argv)
{
	if (argc < 1)
		return JS_UNDEFINED;
	const char* name = JS_ToCString(ctx, argv[0]);
	if (!name)
		return JS_EXCEPTION;
	api::HTTP http{where};
	auto hf = http.find(name);
	JS_FreeCString(ctx, name);
	if (hf)
		hf.unset();
	return JS_UNDEFINED;
}

// ---------------------------------------------------------------------------
// JSCFunctionData wrappers: 'magic' carries the gethdr_e value so each
// method object on req/resp/bereq/beresp can dispatch to the right headers
// without heap allocation or JS closures.
// ---------------------------------------------------------------------------

static JSValue js_hdr_get_fn(JSContext* ctx, JSValueConst,
							  int argc, JSValueConst* argv, int magic, JSValue*)
	{ return hdr_get(ctx, (api::gethdr_e)magic, argc, argv); }

static JSValue js_hdr_set_fn(JSContext* ctx, JSValueConst,
							  int argc, JSValueConst* argv, int magic, JSValue*)
	{ return hdr_set(ctx, (api::gethdr_e)magic, argc, argv); }

static JSValue js_hdr_unset_fn(JSContext* ctx, JSValueConst,
								int argc, JSValueConst* argv, int magic, JSValue*)
	{ return hdr_unset(ctx, (api::gethdr_e)magic, argc, argv); }

static JSValue js_resp_setstatus_fn(JSContext* ctx, JSValueConst,
									int argc, JSValueConst* argv, int magic, JSValue*)
{
	if (argc < 1)
		return JS_UNDEFINED;
	int32_t code = 200;
	if (JS_ToInt32(ctx, &code, argv[0]))
		return JS_EXCEPTION;
	varnish::Response resp{(api::gethdr_e)magic};
	resp.set_status((uint16_t)code);
	return JS_UNDEFINED;
}

// ---------------------------------------------------------------------------
// Lazy property getters: called on first access instead of at object creation.
// 'magic' carries the gethdr_e value — same pattern as the method wrappers.
// ---------------------------------------------------------------------------

static JSValue js_url_getter(JSContext* ctx, JSValueConst,
							  int, JSValueConst*, int magic, JSValue*)
{
	const api::HTTP http{(api::gethdr_e)magic};
	const auto s = http.url();
	return JS_NewStringLen(ctx, s.c_str(), s.size());
}

static JSValue js_method_getter(JSContext* ctx, JSValueConst,
								 int, JSValueConst*, int magic, JSValue*)
{
	const api::Request req{(api::gethdr_e)magic};
	const auto s = req.method();
	return JS_NewStringLen(ctx, s.c_str(), s.size());
}

static JSValue js_status_getter(JSContext* ctx, JSValueConst,
								 int, JSValueConst*, int magic, JSValue*)
{
	const api::Response resp{(api::gethdr_e)magic};
	return JS_NewInt32(ctx, (int32_t)resp.status());
}

// Helper: define a read-only accessor property with a JSCFunctionData getter.
// JS_DefinePropertyGetSet consumes (frees) the getter JSValue internally.
static void define_lazy_getter(JSContext* ctx, JSValue obj, const char* name,
                                JSCFunctionData* fn, int magic)
{
	JSAtom atom = JS_NewAtom(ctx, name);
	JSValue getter = JS_NewCFunctionData(ctx, fn, 0, magic, 0, nullptr);
	JS_DefinePropertyGetSet(ctx, obj, atom, getter, JS_UNDEFINED,
	                        JS_PROP_ENUMERABLE | JS_PROP_CONFIGURABLE);
	JS_FreeAtom(ctx, atom);
}

// ---------------------------------------------------------------------------
// HTTP object factories
// ---------------------------------------------------------------------------

// Request-side object: req or bereq
static JSValue make_req_obj(JSContext* ctx, api::gethdr_e where)
{
	JSValue obj = JS_NewObject(ctx);

	// Lazy getters for url and method (fetched from the API on access)
	define_lazy_getter(ctx, obj, "url",    js_url_getter,    (int)where);
	define_lazy_getter(ctx, obj, "method", js_method_getter, (int)where);

	// Header manipulation methods (magic = gethdr_e)
	JS_SetPropertyStr(ctx, obj, "get",
		JS_NewCFunctionData(ctx, js_hdr_get_fn,   1, (int)where, 0, nullptr));
	JS_SetPropertyStr(ctx, obj, "set",
		JS_NewCFunctionData(ctx, js_hdr_set_fn,   1, (int)where, 0, nullptr));
	JS_SetPropertyStr(ctx, obj, "unset",
		JS_NewCFunctionData(ctx, js_hdr_unset_fn, 1, (int)where, 0, nullptr));

	return obj;
}

// Response-side object: resp, beresp, or obj (cached)
static JSValue make_resp_obj(JSContext* ctx, api::gethdr_e where)
{
	JSValue obj = JS_NewObject(ctx);

	// Lazy getter for status (fetched from the API on access)
	define_lazy_getter(ctx, obj, "status", js_status_getter, (int)where);

	// Header manipulation methods (magic = gethdr_e)
	JS_SetPropertyStr(ctx, obj, "get",
		JS_NewCFunctionData(ctx, js_hdr_get_fn,        1, (int)where, 0, nullptr));
	JS_SetPropertyStr(ctx, obj, "set",
		JS_NewCFunctionData(ctx, js_hdr_set_fn,        1, (int)where, 0, nullptr));
	JS_SetPropertyStr(ctx, obj, "unset",
		JS_NewCFunctionData(ctx, js_hdr_unset_fn,      1, (int)where, 0, nullptr));
	JS_SetPropertyStr(ctx, obj, "setStatus",
		JS_NewCFunctionData(ctx, js_resp_setstatus_fn, 1, (int)where, 0, nullptr));

	return obj;
}

// ---------------------------------------------------------------------------
// varnish.* — caching, decisions, misc
// ---------------------------------------------------------------------------

static JSValue js_set_cacheable(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
	if (argc < 1)
		return JS_UNDEFINED;
	varnish::Response::set_cacheable(JS_ToBool(ctx, argv[0]) != 0);
	return JS_UNDEFINED;
}

static JSValue js_set_ttl(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
	if (argc < 1)
		return JS_UNDEFINED;
	double secs = 0.0;
	if (JS_ToFloat64(ctx, &secs, argv[0]))
		return JS_EXCEPTION;
	varnish::Response::set_ttl((float)secs);
	return JS_UNDEFINED;
}

static JSValue js_decision(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
	if (argc < 1)
		return JS_UNDEFINED;
	size_t len;
	const char* dec = JS_ToCStringLen(ctx, &len, argv[0]);
	if (!dec)
		return JS_EXCEPTION;
	int32_t status = 403;
	if (argc >= 2)
		JS_ToInt32(ctx, &status, argv[1]);
	varnish::decision({dec, len}, status);
	JS_FreeCString(ctx, dec);
	return JS_UNDEFINED;
}

static JSValue js_hash_data(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
	if (argc < 1)
		return JS_UNDEFINED;
	size_t len;
	const char* s = JS_ToCStringLen(ctx, &len, argv[0]);
	if (!s)
		return JS_EXCEPTION;
	varnish::hash_data({s, len});
	JS_FreeCString(ctx, s);
	return JS_UNDEFINED;
}

static JSValue js_print(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
	for (int i = 0; i < argc; i++) {
		const char* s = JS_ToCString(ctx, argv[i]);
		if (!s)
			return JS_EXCEPTION;
		varnish::print("{}", s);
		JS_FreeCString(ctx, s);
	}
	return JS_UNDEFINED;
}

static JSValue js_log(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
	for (int i = 0; i < argc; i++) {
		const char* s = JS_ToCString(ctx, argv[i]);
		if (!s)
			return JS_EXCEPTION;
		varnish::log("{}", s);
		JS_FreeCString(ctx, s);
	}
	return JS_UNDEFINED;
}

// ---------------------------------------------------------------------------
// main: build the varnish namespace, eval the user script, cache hooks
// ---------------------------------------------------------------------------

static void setup_quickjs(const char* js_code, bool verbose)
{
	JSRuntime* rt = JS_NewRuntime();
	g_ctx = JS_NewContext(rt);

	g_global = JS_GetGlobalObject(g_ctx);

	JSValue vns = JS_NewObject(g_ctx);
	JS_SetPropertyStr(g_ctx, g_global, "varnish", JS_DupValue(g_ctx, vns));

#define BIND(name, func, nargs) \
	JS_SetPropertyStr(g_ctx, vns, name, JS_NewCFunction(g_ctx, func, name, nargs))

	BIND("setCacheable", js_set_cacheable, 1);
	BIND("setTTL",       js_set_ttl,       1);
	BIND("decision",     js_decision,      1);
	BIND("hashData",     js_hash_data,     1);
	BIND("print",        js_print,         1);
	BIND("log",          js_log,           1);

#undef BIND

	JS_FreeValue(g_ctx, vns);

	/* Evaluate the user-supplied JS program */
	if (verbose) {
		varnish::print("Evaluating JS program:\n{}\n", js_code);
	}
	JSValue result = JS_Eval(g_ctx, js_code, strlen(js_code),
							 "<script>", JS_EVAL_TYPE_GLOBAL);
	if (JS_IsException(result)) {
		varnish::print("JS eval error:\n");
		js_dump_exception(g_ctx);
	}
	JS_FreeValue(g_ctx, result);

	/* Build HTTP objects once — they are reused on every request via
	   snapshot/restore so we never pay for JS object allocation per request. */
	g_objects.req    = make_req_obj(g_ctx, api::HDR_REQ);
	g_objects.resp   = make_resp_obj(g_ctx, api::HDR_RESP);
	g_objects.obj    = make_resp_obj(g_ctx, api::HDR_OBJ);
	g_objects.bereq  = make_req_obj(g_ctx, api::HDR_BEREQ);
	g_objects.beresp = make_resp_obj(g_ctx, api::HDR_BERESP);

	/* Cache hook function references; missing hooks are silently ignored */
	g_hooks.on_recv             = JS_GetPropertyStr(g_ctx, g_global, "on_recv");
	g_hooks.on_hash             = JS_GetPropertyStr(g_ctx, g_global, "on_hash");
	g_hooks.on_synth            = JS_GetPropertyStr(g_ctx, g_global, "on_synth");
	g_hooks.on_hit              = JS_GetPropertyStr(g_ctx, g_global, "on_hit");
	g_hooks.on_miss             = JS_GetPropertyStr(g_ctx, g_global, "on_miss");
	g_hooks.on_deliver          = JS_GetPropertyStr(g_ctx, g_global, "on_deliver");
	g_hooks.on_backend_fetch    = JS_GetPropertyStr(g_ctx, g_global, "on_backend_fetch");
	g_hooks.on_backend_response = JS_GetPropertyStr(g_ctx, g_global, "on_backend_response");
	g_hooks.on_backend_error    = JS_GetPropertyStr(g_ctx, g_global, "on_backend_error");
}

// ---------------------------------------------------------------------------
// Return-value → VCL decision mapping
//
//   return "pass"         → decision("pass")
//   return ["synth", 200] → decision("synth", 200)
//   return null/undefined → no-op (explicit varnish.decision() already called)
// ---------------------------------------------------------------------------

static void apply_return_decision(JSContext* ctx, JSValue ret)
{
	if (JS_IsString(ret)) {
		size_t len;
		const char* s = JS_ToCStringLen(ctx, &len, ret);
		if (s) {
			varnish::decision({s, len});
			JS_FreeCString(ctx, s);
		}
	} else if (JS_IsArray(ret)) {
		JSValue v0 = JS_GetPropertyUint32(ctx, ret, 0);
		JSValue v1 = JS_GetPropertyUint32(ctx, ret, 1);
		size_t len;
		const char* s = JS_ToCStringLen(ctx, &len, v0);
		int32_t status = 200;
		JS_ToInt32(ctx, &status, v1);
		if (s) {
			varnish::decision({s, len}, status);
			JS_FreeCString(ctx, s);
		}
		JS_FreeValue(ctx, v0);
		JS_FreeValue(ctx, v1);
	}
	// null / undefined / other → no-op
}

// ---------------------------------------------------------------------------
// C++ callbacks: pass pre-built g_objects directly to JS hooks
// ---------------------------------------------------------------------------

static void on_recv(varnish::Request, varnish::Response, const char*)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_recv))
		return;

	JSValue ret = JS_Call(g_ctx, g_hooks.on_recv, JS_UNDEFINED, 1, &g_objects.req);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_hash(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_hash))
		return;

	// req headers are available in vcl_hash even though vcall passes HDR_INVALID
	JSValue ret = JS_Call(g_ctx, g_hooks.on_hash, JS_UNDEFINED, 1, &g_objects.req);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_synth(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_synth))
		return;

	JSValue args[2] = { g_objects.req, g_objects.resp };
	JSValue ret = JS_Call(g_ctx, g_hooks.on_synth, JS_UNDEFINED, 2, args);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_hit(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_hit))
		return;

	JSValue args[2] = { g_objects.req, g_objects.obj };
	JSValue ret = JS_Call(g_ctx, g_hooks.on_hit, JS_UNDEFINED, 2, args);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_miss(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_miss))
		return;

	// bereq (HDR_BEREQ) is the newly-created backend request, presented as req-like
	JSValue args[2] = { g_objects.req, g_objects.bereq };
	JSValue ret = JS_Call(g_ctx, g_hooks.on_miss, JS_UNDEFINED, 2, args);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_deliver(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_deliver))
		return;

	JSValue args[2] = { g_objects.req, g_objects.resp };
	JSValue ret = JS_Call(g_ctx, g_hooks.on_deliver, JS_UNDEFINED, 2, args);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_backend_fetch(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_backend_fetch))
		return;

	JSValue ret = JS_Call(g_ctx, g_hooks.on_backend_fetch, JS_UNDEFINED, 1, &g_objects.bereq);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_backend_response(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_backend_response))
		return;

	JSValue args[2] = { g_objects.bereq, g_objects.beresp };
	JSValue ret = JS_Call(g_ctx, g_hooks.on_backend_response, JS_UNDEFINED, 2, args);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

static void on_backend_error(varnish::Request, varnish::Response)
{
	if (!JS_IsFunction(g_ctx, g_hooks.on_backend_error))
		return;

	JSValue args[2] = { g_objects.bereq, g_objects.beresp };
	JSValue ret = JS_Call(g_ctx, g_hooks.on_backend_error, JS_UNDEFINED, 2, args);
	if (JS_IsException(ret))
		js_dump_exception(g_ctx);
	else
		apply_return_decision(g_ctx, ret);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
	varnish::print("{} main entered{}\n",
		varnish::is_storage() ? "Storage" : "Request",
		varnish::is_debug()   ? " (debug)" : "");

	// JavaScript code is in the last argument
	setup_quickjs(argv[argc - 1], !varnish::is_storage());

	varnish::sys_register_callback(varnish::CALLBACK_ON_RECV,
		(void(*)())on_recv);
	varnish::sys_register_callback(varnish::CALLBACK_ON_HASH,
		(void(*)())on_hash);
	varnish::sys_register_callback(varnish::CALLBACK_ON_SYNTH,
		(void(*)())on_synth);
	varnish::sys_register_callback(varnish::CALLBACK_ON_HIT,
		(void(*)())on_hit);
	varnish::sys_register_callback(varnish::CALLBACK_ON_MISS,
		(void(*)())on_miss);
	varnish::sys_register_callback(varnish::CALLBACK_ON_BACKEND_FETCH,
		(void(*)())on_backend_fetch);
	varnish::sys_register_callback(varnish::CALLBACK_ON_BACKEND_RESPONSE,
		(void(*)())on_backend_response);
	varnish::sys_register_callback(varnish::CALLBACK_ON_BACKEND_ERROR,
		(void(*)())on_backend_error);

	varnish::set_on_deliver(on_deliver);
	varnish::wait_for_requests(on_recv);
}
