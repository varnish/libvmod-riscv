/**
 * QuickJS bridge for the Varnish RISC-V API
 *
 * Isolation model
 * ---------------
 * libriscv uses per-request snapshot/restore: the VM state captured after
 * main() returns is replayed from scratch for every incoming request.
 * This means:
 *   - g_ctx, g_global, and g_hooks are set once at init-time and are part
 *     of the saved snapshot; they remain permanently valid across requests.
 *   - JS mutable state changed during a request (global vars, closure state)
 *     is automatically reverted for the next request — no bleed-through.
 *   - JS_FreeValue inside callbacks is GC hygiene within a single request;
 *     it is not required for cross-request correctness.
 *
 * argv[1] is the JavaScript program string evaluated once at startup.
 * The program may define any of the following hooks as global functions:
 *
 *   function on_recv(url, method)    { ... }  // vcl_recv
 *   function on_deliver(url, status) { ... }  // vcl_deliver
 *
 * The varnish namespace (global object "varnish") exposes:
 *
 *   Header access — request (HDR_REQ):
 *     varnish.reqGet(name)    -> string | null
 *     varnish.reqSet(line)    -> void   // full "Name: Value" line
 *     varnish.reqUnset(name)  -> void
 *     varnish.reqUrl()        -> string
 *     varnish.reqMethod()     -> string
 *
 *   Header access — response (HDR_RESP):
 *     varnish.respGet(name)      -> string | null
 *     varnish.respSet(line)      -> void
 *     varnish.respUnset(name)    -> void
 *     varnish.respStatus()       -> number
 *     varnish.respSetStatus(code)-> void
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

#define COUNTOF(a) (sizeof(a) / sizeof(*(a)))

// ---------------------------------------------------------------------------
// Global QuickJS state (lives for the entire process lifetime)
// ---------------------------------------------------------------------------

static JSContext* g_ctx      = nullptr;
static JSValue    g_global   = JS_UNDEFINED;

// JS function references cached once after eval — avoids per-call property lookup
static struct {
    JSValue on_recv;
    JSValue on_deliver;
} g_hooks;

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
    const char* line = JS_ToCString(ctx, argv[0]);
    if (!line)
        return JS_EXCEPTION;
    api::HTTP http{where};
    http.append(line);
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
// varnish.req* — request headers (HDR_REQ)
// ---------------------------------------------------------------------------

static JSValue js_req_get(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    { return hdr_get(ctx, api::HDR_REQ, argc, argv); }

static JSValue js_req_set(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    { return hdr_set(ctx, api::HDR_REQ, argc, argv); }

static JSValue js_req_unset(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    { return hdr_unset(ctx, api::HDR_REQ, argc, argv); }

static JSValue js_req_url(JSContext* ctx, JSValueConst, int, JSValueConst*)
{
    varnish::Request req{api::HDR_REQ};
    const auto s = req.url();
    return JS_NewStringLen(ctx, s.c_str(), s.size());
}

static JSValue js_req_method(JSContext* ctx, JSValueConst, int, JSValueConst*)
{
    varnish::Request req{api::HDR_REQ};
    const auto s = req.method();
    return JS_NewStringLen(ctx, s.c_str(), s.size());
}

// ---------------------------------------------------------------------------
// varnish.resp* — response headers (HDR_RESP)
// ---------------------------------------------------------------------------

static JSValue js_resp_get(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    { return hdr_get(ctx, api::HDR_RESP, argc, argv); }

static JSValue js_resp_set(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    { return hdr_set(ctx, api::HDR_RESP, argc, argv); }

static JSValue js_resp_unset(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    { return hdr_unset(ctx, api::HDR_RESP, argc, argv); }

static JSValue js_resp_status(JSContext* ctx, JSValueConst, int, JSValueConst*)
{
    varnish::Response resp{api::HDR_RESP};
    return JS_NewInt32(ctx, (int32_t)resp.status());
}

static JSValue js_resp_set_status(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
    if (argc < 1)
        return JS_UNDEFINED;
    int32_t code = 200;
    if (JS_ToInt32(ctx, &code, argv[0]))
        return JS_EXCEPTION;
    varnish::Response resp{api::HDR_RESP};
    resp.set_status((uint16_t)code);
    return JS_UNDEFINED;
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
    const char* dec = JS_ToCString(ctx, argv[0]);
    if (!dec)
        return JS_EXCEPTION;
    int32_t status = 403;
    if (argc >= 2)
        JS_ToInt32(ctx, &status, argv[1]);
    varnish::decision(std::string(dec), status);
    JS_FreeCString(ctx, dec);
    return JS_UNDEFINED;
}

static JSValue js_hash_data(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
{
    if (argc < 1)
        return JS_UNDEFINED;
    const char* s = JS_ToCString(ctx, argv[0]);
    if (!s)
        return JS_EXCEPTION;
    varnish::hash_data(std::string(s));
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

static void setup_quickjs(const char* js_code)
{
    JSRuntime* rt = JS_NewRuntime();
    g_ctx = JS_NewContext(rt);

    g_global = JS_GetGlobalObject(g_ctx);

    /* Build the varnish namespace object in main(), matching the reference style */
    JSValue vns = JS_NewObject(g_ctx);
    JS_SetPropertyStr(g_ctx, g_global, "varnish", JS_DupValue(g_ctx, vns));

#define BIND(name, func, nargs) \
    JS_SetPropertyStr(g_ctx, vns, name, JS_NewCFunction(g_ctx, func, name, nargs))

    /* Request */
    BIND("reqGet",    js_req_get,    1);
    BIND("reqSet",    js_req_set,    1);
    BIND("reqUnset",  js_req_unset,  1);
    BIND("reqUrl",    js_req_url,    0);
    BIND("reqMethod", js_req_method, 0);

    /* Response */
    BIND("respGet",       js_resp_get,        1);
    BIND("respSet",       js_resp_set,        1);
    BIND("respUnset",     js_resp_unset,      1);
    BIND("respStatus",    js_resp_status,     0);
    BIND("respSetStatus", js_resp_set_status, 1);

    /* Caching */
    BIND("setCacheable", js_set_cacheable, 1);
    BIND("setTTL",       js_set_ttl,       1);

    /* Decisions / misc */
    BIND("decision", js_decision, 1);
    BIND("hashData", js_hash_data, 1);
    BIND("print",    js_print,    1);
    BIND("log",      js_log,      1);

#undef BIND

    JS_FreeValue(g_ctx, vns);

    /* Evaluate the user-supplied JS program */
    JSValue result = JS_Eval(g_ctx, js_code, strlen(js_code),
                             "<script>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(result)) {
        varnish::print("JS eval error:\n");
        js_dump_exception(g_ctx);
    }
    JS_FreeValue(g_ctx, result);

    /* Cache hook function references; missing hooks are silently ignored */
    g_hooks.on_recv    = JS_GetPropertyStr(g_ctx, g_global, "on_recv");
    g_hooks.on_deliver = JS_GetPropertyStr(g_ctx, g_global, "on_deliver");
}

// ---------------------------------------------------------------------------
// C++ callbacks: extract primitive args and call into JS
// ---------------------------------------------------------------------------

static void on_recv(varnish::Request req)
{
    if (!JS_IsFunction(g_ctx, g_hooks.on_recv))
        return;

    const auto url    = req.url();
    const auto method = req.method();

    JSValue args[2];
    args[0] = JS_NewStringLen(g_ctx, url.c_str(),    url.size());
    args[1] = JS_NewStringLen(g_ctx, method.c_str(), method.size());

    JSValue ret = JS_Call(g_ctx, g_hooks.on_recv, JS_UNDEFINED, 2, args);
    if (JS_IsException(ret))
        js_dump_exception(g_ctx);

    JS_FreeValue(g_ctx, ret);
    JS_FreeValue(g_ctx, args[0]);
    JS_FreeValue(g_ctx, args[1]);
}

static void on_deliver(varnish::Request req, varnish::Response resp)
{
    if (!JS_IsFunction(g_ctx, g_hooks.on_deliver))
        return;

    const auto url    = req.url();
    const int  status = (int)resp.status();

    JSValue args[2];
    args[0] = JS_NewStringLen(g_ctx, url.c_str(), url.size());
    args[1] = JS_NewInt32(g_ctx, status);

    JSValue ret = JS_Call(g_ctx, g_hooks.on_deliver, JS_UNDEFINED, 2, args);
    if (JS_IsException(ret))
        js_dump_exception(g_ctx);

    JS_FreeValue(g_ctx, ret);
    JS_FreeValue(g_ctx, args[0]);
    JS_FreeValue(g_ctx, args[1]);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main(int, char** argv)
{
    varnish::print("{} main entered{}\n",
        varnish::is_storage() ? "Storage" : "Request",
        varnish::is_debug()   ? " (debug)" : "");

    setup_quickjs(argv[1]);

    varnish::set_on_deliver(on_deliver);
    varnish::wait_for_requests(on_recv);
}
