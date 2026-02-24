# libvmod-riscv Project Notes

## QuickJS VTC Tests
- Always add `-arg "-p workspace_client=128k"` to the varnish instance in JS tests.
  The QuickJS tenant consumes more workspace than Varnish's default, causing 500 errors.
- JS binary is pre-compiled: use `"filename": "${testdir}/js"` (symlink in tests/ dir).
- Pass JavaScript code via `riscv.add_main_argument("tenant", """...JS...""")`.
- JS hooks: `on_recv(req)`, `on_deliver(req, resp)`, `on_backend_fetch(bereq)`, `on_backend_response(bereq, beresp)`.
- Return values from hooks: `["synth", 200]` or `"pass"` or call `varnish.decision()` explicitly.
- VTC synth pattern for JS (no on_synth in JS bridge):
  ```
  sub vcl_synth { if (riscv.active()) { return (deliver); } }
  ```
- Build folder: `/home/gonzo/github/libvmod-riscv/.build/`
- Tests folder: `/home/gonzo/github/libvmod-riscv/tests/` (also accessible as `src/tests` symlink)

## riscv.run() — Preferred Over vcall

- `riscv.run()` is the newer, preferred API. It automatically selects the right hook
  based on current VCL state (e.g. `vcl_recv` → calls `on_recv`, `vcl_deliver` → calls `on_deliver`).
- `riscv.vcall(ON_REQUEST)` is the older explicit form — avoid in new tests.
- `riscv.fork(req.http.Host)` is still required before `riscv.run()`.
- Pattern for `vcl_recv` with `riscv.run()`:
  ```vcl
  sub vcl_recv {
      if (!riscv.fork(req.http.Host)) { return (synth(403)); }
      riscv.run();
      if (riscv.want_result() == "synth") { return (synth(riscv.want_status())); }
      return (synth(500));
  }
  ```
- Pattern for `vcl_deliver` with `riscv.run()`:
  ```vcl
  sub vcl_deliver {
      if (riscv.active()) { riscv.run(); }
  }
  ```
- Use `return (synth(500))` as the fallback in vcl_recv (not 400) to signal unexpected code path.

## VCL Header Pitfall

- In `vcl_synth`, doing `set resp.http.X-Foo = req.http.X-Foo` when `req.http.X-Foo` is
  undefined sets the response header to an **empty string**, not `<undef>`.
- Always guard with `if (req.http.X-Foo) { set resp.http.X-Foo = req.http.X-Foo; }`
  to avoid spurious empty headers in tests.

## IDE Diagnostics (False Positives)

- The IDE language server does not understand VTC/VCL syntax and flags valid calls like
  `riscv.add_main_argument`, `riscv.finalize_tenants`, `riscv.run()` as errors.
- These diagnostics are always false positives — ignore them. Trust `ctest .` instead.

## Running Tests

- Run: `cd .build && ctest .`
- Verbose (shows varnishtest output): `ctest --verbose .`
- Rerun failed only: `ctest --rerun-failed --output-on-failure .`
