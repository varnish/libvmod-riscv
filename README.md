# RISC-V Multi-Tenancy in Varnish

A Varnish Module (VMOD) that enables **ultra-fast multi-tenancy** using ephemeral RISC-V virtual machines. Each tenant can execute custom logic to configure HTTP requests and responses with VCL-like capabilities, with VM creation/destruction overhead of less than **1 microsecond**.

## Key Features

- **Blazing Fast**: ~1μs overhead per request compared to native VCL
- **Sandboxed Execution**: Isolated RISC-V VMs for each tenant
- **Developer-Friendly**: Write tenant logic in C++ or Rust with a VCL-like API
- **Ephemeral VMs**: VMs are created and destroyed per-request for zero state leakage
- **VCL Integration**: Seamlessly integrates with existing Varnish configurations
- **JSON/XML Support**: Built-in JSON and XML parsing, validation

## Use Cases

- **Multi-tenant CDNs**: Give each customer programmable edge logic
- **Request customization**: Per-tenant header manipulation, URL rewriting, and routing
- **Dynamic backends**: Programmatically select backends based on custom logic
- **Edge computing**: Run lightweight computations at the edge with microsecond latency

## Quick Start

Check out the [demo VCL](demo/demo.vcl) and [example tenant program](program/cpp/basic.cpp) to see it in action.

### Example: Tenant Program

Here's a minimal example of what tenant code looks like:

```cpp
#include <api.h>
namespace varnish = api;

static void on_recv(varnish::Request req) {
    // Manipulate request headers
    req.append("X-Hello: url=" + req.url());

    // Return a JSON response
    forge(varnish::Cached, [] (auto bereq, auto beresp) {
        nlohmann::json json;
        json["message"] = "Hello from RISC-V!";
        return varnish::response{200, "application/json", json.dump()};
    });
}

int main() {
    varnish::wait_for_requests(on_recv);
}
```

### Example: VCL Configuration

```vcl
sub vcl_init {
    riscv.embed_tenants("""{
        "customer1.com": {
            "filename": "/path/to/tenant_program"
        }
    }""");
}

sub vcl_recv {
    riscv.fork("customer1.com");
    riscv.run();
}
```
Note: If you have a RISC-V compiler installed, you can use source files directly as the filename for a tenant, and it will be compiled, cached and loaded automatically: `"filename": "/my/source.cpp"`. The compiler will be detected from [the compiler detection script](/program/detect_compiler.sh).

The same is true for Rust projects. Point `"filename"` to your Rust project and make sure you have a 64-bit RISC-V compiler installed. It will build and load the rust program automatically.

## Rust example program

Have a look at [the Rust main.rs](/program/rust/src/main.rs). You will need a full Linux-compatible RISC-V cross compiler, which is usually provided by your distro package repositories. For example, on Ubuntu the package is called `gcc-14-riscv64-linux-gnu` and the correct `linker` value for [the Rust cargo config](/program/rust/.cargo/config) is `riscv64-linux-gnu-gcc-14`.

In order to be able to boot the Rust program you should build the VMOD with 64-bit and C-extension support:
```sh
./build.sh --64 --C
```
Once this is done, point your VCL config to the path containing your project, and it will build and run it:
```sh
Info: Child (...) said >>> [rusty.com] RISC-V Rust example program started
```

An example program in Rust:
```rs
fn on_client_request(_a: u32, _b: u32) {
	add_req_header("X-Hello", &get_url());

	forge(CachingDecision::Uncached, |_a: u32, _b: u32| {
		BackendResponse {
			status: 200,
			content_type: "text/plain",
			body: "<p>hello from Rust 2</p>".as_bytes().to_vec(),
		}
	});
}

pub fn main() {
	wait_for_requests(on_client_request);
}
```

## JavaScript example program

Tenant logic can also be written in plain JavaScript, powered by the embedded [QuickJS-ng](https://github.com/nicowillis/quickjs-ng) engine. No compiler or external toolchain is required — the JavaScript source is passed as a string directly in your VCL via `add_main_argument`.

Point the tenant `filename` at the `js` binary built with the VMOD:

```vcl
sub vcl_init {
    riscv.embed_tenants("""{
        "customer1.com": {
            "filename": "/path/to/js"
        }
    }""");
    riscv.add_main_argument("customer1.com", """
function on_recv(req) {
    req.set("X-Tenant: customer1");
    if (req.url == "/health") return ["synth", 200];
    return ["pass"];
}
""");
    riscv.finalize_tenants();
}

sub vcl_recv {
    if (!riscv.fork(req.http.Host)) {
        return (synth(403));
    }
    riscv.run();
    if (riscv.want_result() == "synth") {
        return (synth(riscv.want_status()));
    }
}
```

The available hooks mirror the VCL stages: `on_recv`, `on_hash`, `on_synth`, `on_deliver`, `on_backend_fetch`, `on_backend_response`. Each hook receives request/response objects with `get`, `set`, and `unset` methods for header manipulation. Return an array like `["synth", 200]` or a string like `"pass"` to drive the VCL decision.

## VCL tenants

A tenant can also be plain VCL. Point `"filename"` at a `.vcl` file and the VMOD compiles it to a tenant program at `vcl_init`. It uses the same compiler that [Carapace](https://github.com/varnish/carapace) uses for its policies, built as a RISC-V program and embedded in the VMOD. So the tenant's source is compiled *inside the sandbox*: a fresh VM per compile, an instruction budget, no filesystem and no sockets. A compile takes about 10 ms. No toolchain is needed.

```vcl
vcl 4.1;

sub vcl_recv {
    if (req.url ~ "^/admin") {
        return (synth(403, "denied"));
    }
    set req.http.X-Tenant = "customer1";
    return (hash);
}

sub vcl_hash {
    hash_data(req.url);
    return (lookup);
}

sub vcl_synth {
    set resp.http.Content-Type = "text/plain";
    synthetic("no");
    return (deliver);
}

sub vcl_backend_response {
    set beresp.ttl = 1m;
}
```

The surrounding VCL forks the tenant in each subroutine and dispatches the return action. `riscv.run()` executes the tenant's hook for the current subroutine. `riscv.want_result()` returns the action string: `"hash"`, `"lookup"`, `"pass"`, `"miss"`, `"fetch"`, `"deliver"`, `"synth"`, `"error"` or `"abandon"`. It returns `""` when the tenant has no hook for the subroutine or the hook did not return an action, in which case the surrounding VCL falls through to Varnish's built-in behavior. `riscv.want_status()` and `riscv.want_reason()` return the arguments of `synth(...)` and `error(...)`. `return (fail)` calls `VRT_fail` on the subroutine.

[`tests/vcl_router.vcl`](tests/vcl_router.vcl) is a complete surrounding VCL covering every subroutine. In short:

```vcl
sub vcl_init {
    riscv.embed_tenants("""{
        "customer1.com": { "filename": "/etc/varnish/tenants/customer1.vcl" }
    }""");
    riscv.finalize_tenants();
}

sub vcl_recv {
    if (!riscv.fork(req.http.Host)) {
        return (synth(404));
    }
    riscv.run();
    if (riscv.want_result() == "synth") {
        return (synth(riscv.want_status(), riscv.want_reason()));
    } else if (riscv.want_result() == "pass") {
        return (pass);
    } else if (riscv.want_result() == "hash") {
        return (hash);
    }
}

sub vcl_hash {
    riscv.run();
    if (riscv.want_result() == "lookup") {
        return (lookup);
    }
}

# vcl_hit, vcl_miss, vcl_pass and vcl_deliver: the same, for their actions.

sub vcl_synth {
    if (riscv.active()) {
        riscv.run();
        if (riscv.want_result() == "deliver") {
            return (deliver);
        }
    }
}

sub vcl_backend_fetch {
    if (!riscv.fork(bereq.http.Host)) {
        return (error(503));
    }
    riscv.run();
    if (riscv.want_result() == "error") {
        return (error(riscv.want_status(), riscv.want_reason()));
    } else if (riscv.want_result() == "abandon") {
        return (abandon);
    }
}

# vcl_backend_response and vcl_backend_error: the same, for their actions.
```

Tenant VCL follows Varnish Enterprise VCL, with the same subroutines, variables, return actions and scope rules:
- Subroutines: `vcl_recv`, `vcl_hash`, `vcl_hit`, `vcl_miss`, `vcl_pass`, `vcl_deliver`, `vcl_synth`, `vcl_backend_fetch`, `vcl_backend_response` and `vcl_backend_error`.
- Return actions: `hash`, `lookup`, `miss`, `fetch`, `pass`, `deliver`, `abandon`, `synth(status, "reason")`, `error(status, "reason")` and `fail`. Custom-status `synth` works as usual, e.g. `return (synth(750, "/elsewhere"))` handled by a redirect in `vcl_synth`.
- `hash_data()` in `vcl_hash`. `synthetic()`, `set resp.body` and `set beresp.body` in `vcl_synth` and `vcl_backend_error`.
- Headers on `req`, `bereq`, `beresp` and `resp`. Writable: `req.url`, `req.method`, `bereq.url`, `bereq.method`, `resp.status`, `resp.reason`, `beresp.status`, `beresp.reason`. `beresp.ttl`, `grace`, `keep`, `uncacheable`, `do_stream`, `do_gzip` and `do_gunzip`. Read-only `obj` fields: `obj.hits`, `obj.ttl`, `obj.status`, etc. `req.xid`, `req.restarts`, `req.esi_level`, `req.can_gzip`, `req.hash_always_miss`, `req.hash_ignore_busy`, `bereq.retries`, `bereq.uncacheable`, the `proto` fields, `server.hostname`, `server.identity`, `client.ip`, `now`. `req.cache_hit` (non-standard) indicates whether `vcl_deliver` is serving a cache hit.
- Regular expressions, compiled by Varnish's regex engine, under Varnish's default `pcre_match_limit` (10000) and `pcre_match_limit_recursion` (20). A match that reaches a limit fails the subroutine instead of reading as "no match", so a deny rule cannot fail open. Each match is charged to the tenant's instruction budget. ACLs, user subroutines and `include` (confined to the tenant's directory).
- VMODs: `std`, `str`, `digest`, `headerplus`, `cookieplus`, `urlplus`. Lexical locals (`var` inside a sub).
- Request globals (`var` at the top level). The client side (`vcl_recv` through `vcl_deliver` and `vcl_synth`) shares one copy. The backend fetch starts from the initializers, not from the client-side values, because it runs in a separate fork. Pass values to the backend on `bereq` headers, as in Varnish.
- Statistics: `static var NAME: INT stat [counter|gauge|max|min] ["description"];` declares a Varnish counter named `RISCV.<tenant>.<name>`, visible in `varnishstat`. See below.

The following are denied by the compiler and enforced again at runtime by the VMOD:
- `req.http.Host` is read-only. The surrounding VCL uses it to select the tenant on both client and backend sides; allowing writes would route the request to another tenant. To set the origin Host header, use `bereq.http.Host` in `vcl_backend_fetch`.
- Cache key isolation: the VMOD prepends the tenant name to every cache key before `vcl_hash` runs, preventing cross-tenant cache reads or poisoning.
- Restarts, retries, `pipe`, `purge`, `vcl_purge`, `vcl_pipe`, `vcl_init`, `vcl_fini`, bans, backends, directors, storage selection, timeouts and `beresp.do_esi` (whose includes could reference another tenant's origin). These are reserved for the surrounding VCL.
- Plain `static var` (non-stat), because each request runs in a fresh fork with no state carried between requests.
- Writes to framing headers (`Content-Length`, `Transfer-Encoding`, etc.).
- Variables used outside their allowed subroutine scope. `req.*` belongs to the client side and `bereq.*` to the backend side, as in Varnish.

### Statistics

```vcl
import std;

static var blocked: INT stat "Requests the tenant refused";
static var inflight: INT stat gauge;
static var largest_body: INT stat max "Largest Content-Length seen";

sub vcl_recv {
    set var.inflight += 1;
    if (req.url ~ "^/admin") {
        set var.blocked += 1;
        return (synth(403, "denied"));
    }
}

sub vcl_deliver {
    set var.inflight -= 1;
}

sub vcl_backend_response {
    set var.largest_body = std.integer(beresp.http.Content-Length, 0);
}
```

```sh
$ varnishstat -1 -f 'RISCV.*'
RISCV.customer1.com.blocked                     17         0.00 Requests the tenant refused
RISCV.customer1.com.inflight                     0          .   VCL-declared gauge inflight
RISCV.customer1.com.largest_body            524288          .   Largest Content-Length seen
```

Each fork initializes the static variable to its declared value. After each subroutine, the VMOD reads the variable and applies the delta to the tenant's counter. `counter` (the default) and `gauge` add the difference. `max` and `min` retain the highest or lowest value seen. A subroutine observes only its own request's delta, not the running total. `min` has no initializer and reads `INT64_MAX` until a request sets a lower value. A gauge that decrements below zero wraps, because Varnish counters are unsigned.

A tenant may have at most 64 statistics. The cap counts every name a tenant has published since varnishd started, because a counter is never freed and all tenants share the same shared memory. A reload that would add a name past the cap is refused, and the running program stays. Counters belong to the tenant, not to the program binary. They persist across `riscv.live_update_file()` and VCL reloads, and live until varnishd exits. Redeclaring a name with a different kind is refused. A changed description is logged; the original description is kept.

A `.vcl` file that fails to compile leaves the tenant without a program: `riscv.fork()` returns false and the compiler diagnostics are logged as `Error` records. `riscv.live_update_file()` also accepts `.vcl` files; a failed compile leaves the running program unchanged.

Forks take their dirtied pages from the task workspace, so give tenants some room, e.g. `-p workspace_client=128k`. `vcl/README.md` has the compiler's layout and how to rebuild it.

## Benchmarks

Performance comparison showing the minimal overhead of RISC-V VMs:

**RISC-V ephemeral VMs** configuring the request:
```sh
$ ./wrk -c1 -t1 -L http://127.0.0.1:8000/riscv
Running 10s test @ http://127.0.0.1:8000/riscv
  1 threads and 1 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.62us    2.53us 266.00us   98.65%
    Req/Sec    84.51k     0.94k   86.88k    72.73%
  Latency Distribution
     50%   11.00us
     75%   12.00us
     90%   12.00us
     99%   15.00us
  184992 requests in 2.20s, 63.98MB read
Requests/sec:  84083.68
Transfer/sec:     29.08MB
```

A regular Varnish cache hit, with equivalent work to RISC-V above:
```sh
$ ./wrk -c1 -t1 -L http://127.0.0.1:8000/varnish
Running 10s test @ http://127.0.0.1:8000/varnish
  1 threads and 1 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    10.70us    7.30us 703.00us   99.75%
    Req/Sec    92.33k     2.12k   94.84k    88.46%
  Latency Distribution
     50%   10.00us
     75%   11.00us
     90%   11.00us
     99%   14.00us
  238839 requests in 2.60s, 215.02MB read
Requests/sec:  91862.25
Transfer/sec:     82.70MB
```

We can see that the single-threaded overhead from ephemeral VMs configuring the request is only ~1 microsecond.

Ubuntu Linux 6.14.0-33-generic, AMD Ryzen 9 7950X

## Building the VMOD

Requirements:
```sh
sudo apt install build-essential cmake g++
```

Open-source Varnish:
```sh
./build.sh
```

Enterprise Varnish:
```sh
./build.sh --enterprise
```

## Custom RISC-V compiler

For Rust (and some other languages) you will need a full 64-bit Linux cross-compiler, in which case you should ignore this step and install one from your distro packaging. Yes, you do have a RISC-V compiler, and no I don't know the incantation to install it for you.

A custom compiler is needed to make the most efficient _C++ guest programs_. Clone the [RISC-V GNU toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain), and build it like so:

```sh
./configure --prefix=$HOME/riscv --with-arch=rv32g_zba_zbb_zbc_zbs --with-abi=ilp32d
make
```

After completion, expose the compiler by adding `~/riscv/bin` to PATH. Verify with:

```sh
$ riscv32-unknown-elf-g++ 
riscv32-unknown-elf-g++: fatal error: no input files
```

Again, _this step is not necessary_. Do not do this unless you want to flex.

## Running

```sh
cd demo
./run.sh
```

It will automatically build a basic program, however the filepath might be wrong on your system. Please edit the [Demo VCL](demo/demo.vcl) with your path to the example program.
