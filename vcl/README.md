# VCL compiler

The VCL-to-RISC-V compiler behind `.vcl` tenants, ported from Carapace's
`carapace-vcl` and `carapace-vcl-rt`. The top-level README describes what a
tenant's VCL can do. This file describes how the pieces fit together.

| Path | What it is |
|---|---|
| `compiler/` | The compiler: preprocessor → parser → type checker → IR → RV64 codegen → ELF. Plain Rust with no dependencies but the runtime blob, and nothing in it opens a file. |
| `runtime/` | Allocation-free routines the generated code calls (cookie, URL and header lists, time and duration parsing, …), and `runtime/runtime.elf`, their pre-linked image that the compiler copies into every policy. |
| `vclc/` | The compiler built as a RISC-V guest program. It exports `vclc_compile` and makes one host call, to read an `include`. |
| `vclc.elf` | That guest, embedded in the VMOD by `src/vcl/vclc_blob.c`. |

The host side lives in `src/vcl/`:

| File | What it does |
|---|---|
| `compiler.cpp` | Runs `vclc.elf` in a fresh machine per compile, answers its includes (confined to the policy's directory), and decodes the answer under hard caps. |
| `vcl_program.cpp` | Loads a compiled policy: compiles its regex literals (`.carapace.regex`), seeds its request globals (`.carapace.globals`) into the master VM, binds its statistics (`.carapace.stats`), and maps its hooks to the VMOD callbacks. |
| `vcl_stats.cpp` | Statistics: the tenant counter registry, and the fold of each statistic word into its Varnish counter after every hook. |
| `vcl_syscalls.cpp` | The policy ABI the generated code calls, at syscalls 540..=560 (`abi.hpp`), and the gates on each call. |
| `vcl_varnish.c` | Everything that touches Varnish's own objects, in C against `cache/cache.h`. |

## The ABI

A compiled policy calls the host with Carapace's scripting ABI, shifted from
490..=510 to 540..=560 so that it sits between the VMOD's own API (500..=539)
and the native heap helpers (580..). `define_syscalls!` in
`compiler/src/ir.rs` and `src/vcl/abi.hpp` are the two halves; change both
together.

Differences from Carapace:

- The language is Varnish Enterprise's rather than Carapace's subset. Every
  Varnish subroutine a tenant can reach is a hook of its own: `on_recv`,
  `on_hash`, `on_hit`, `on_miss`, `on_pass`, `on_deliver`, `on_synth`,
  `on_backend_fetch`, `on_backend_response` and `on_backend_error`.
  `vcl_synth` is no longer folded into the hooks that return `synth(...)`.
  The variables and return actions follow Varnish's tables
  (`compiler/src/vcl_vars.def`, `check_return_action` in
  `compiler/src/typecheck.rs`), less what a tenant is denied. `req.*` is the
  client side and `bereq.*` the backend side, as in Varnish, where Carapace
  let the backend phases read the client request.
- Header edits go straight to Varnish's header maps, instead of being
  recorded and replayed after the phase.
- Most variables go through one pair of calls, `TYPED_VAR_GET_*` and
  `TYPED_VAR_SET_*`, by a number: the compiler's `HostVar`, and `vclv_var` in
  `src/vcl/vcl_varnish.h`. The host gates each number by `ctx->method` with a
  table that mirrors `vcl_vars.def`. That gate is what stops a hand-written
  ELF from calling a `VRT_r_obj_*` accessor where it would assert.
- `return (...)` codes are the compiler's `ActionCode` and the host's
  `ACTION_*`. The host checks each against Varnish's return table and
  reports it as `riscv.want_result()`.
- The client's `Host` is read-only. It picked the tenant, so the host refuses
  a write to it even from an ELF the compiler did not make. In `vcl_hash` the
  VMOD feeds the tenant's name into the key before the hook runs.
- Regular expressions are Varnish's (PCRE). The compiler still validates
  patterns against its own, stricter rules, but those were written for a
  linear-time engine and do not stop a pattern that backtracks. The host
  matches under Varnish's default match limits (`vclv_vre_limits` in
  `vcl_varnish.c`), charges each match that limit in instructions, and
  reports a match the limits stopped as undecided, which traps. regsub and
  regsuball are the host's own (`vclv_regsub`), with VRT_regsub's meaning,
  so each match a regsuball runs is counted and charged.
- A tenant's `std.log()` lines start with `[tenant]`, as the VMOD's own lines
  do, so one tenant cannot write lines that read as another's.
- A plain `static var` is refused, because each request runs in a fresh fork
  and has nothing to accumulate into. A `stat`-annotated static is allowed.
  The host folds each fork's changes to it into a Varnish counter,
  `RISCV.<tenant>.<name>`, instead of a Prometheus family. A tenant has at
  most 64 (`MAX_STATS`, in `types.rs` and `vcl_stats.cpp`), counted across
  every program it has loaded, since a counter is never freed. Dynamic
  statistics (`stat NAME: KIND {KEYS} ttl ...`) are not ported.

## Rebuilding the blobs

Both blobs are committed, so building the VMOD needs no Rust or RISC-V
toolchain. Rebuild them after changing the compiler or the runtime:

```sh
make -C vcl/runtime/guest blob   # after changing vcl/runtime/src
make -C vcl/vclc blob            # after changing vcl/compiler or vcl/runtime
```

Both builds are pinned to Rust 1.91.0 and are reproducible, so an unchanged
source gives an unchanged blob. They need the `riscv64gc-unknown-none-elf` and
`riscv64gc-unknown-linux-gnu` targets and `riscv64-linux-gnu-gcc-14`.

The compiler's own tests run natively:

```sh
cd vcl/compiler && cargo test
```
