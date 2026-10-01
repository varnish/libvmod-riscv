//! A byte fuzzer for the whole compiler.
//!
//! [`crate::differential`] fuzzes *well-formed* programs and compares the two
//! engines; nothing fuzzed the bytes themselves. The parser's own
//! `corrupted_token_streams_never_panic` comes closest, and it stops at
//! `parse`: everything below — the resolver, the type checker, the desugarer,
//! the IR builder and verifier, the optimizer, the register allocator, codegen
//! and the ELF writer — has its own internal invariants, and an `expect` in
//! one of those is what [`crate::on_owned_stack`] now turns into a rejection
//! rather than an abort. This is what proves the rejection is all there ever
//! is.
//!
//! The claim is deliberately narrow, and it is the only one a compiler owes a
//! hostile input: **a diagnostic or an ELF, never a panic, and never
//! unbounded time.** Nothing here asserts what the diagnostic says.
//!
//! Seeded and reproducible: `CARAPACE_VCL_BYTES_SEED` and
//! `CARAPACE_VCL_BYTES_ITERS` pick up where a failure left off. The PR path
//! runs a few hundred cases; `nightly.yml` runs the long one.

use std::time::{Duration, Instant};

use crate::{compile, CompileOptions, MAX_SOURCE_BYTES};

/// Cases the PR path runs. The nightly job raises it.
const DEFAULT_ITERS: usize = 400;
const DEFAULT_SEED: u64 = 0x5eed_1cef_a11b_9d03;

/// How long one case may take. Generous by three orders of magnitude for the
/// shapes below — the point is to catch an accidental superlinearity, not to
/// measure anything.
const CASE_BUDGET: Duration = Duration::from_secs(5);

/// The tokens a soup case is built from: every VCL punctuation mark, the
/// keywords that open a construct, and a few literals. Token soup finds the
/// recovery loops that arbitrary bytes never reach, because arbitrary bytes
/// mostly fail in the lexer.
const WORDS: &[&str] = &[
    "vcl",
    "4.1",
    "4.0",
    ";",
    "sub",
    "vcl_recv",
    "vcl_backend_response",
    "vcl_deliver",
    "vcl_synth",
    "{",
    "}",
    "(",
    ")",
    "[",
    "]",
    ",",
    ".",
    "=",
    "==",
    "!=",
    "~",
    "!~",
    "<",
    ">",
    "+",
    "-",
    "*",
    "/",
    "%",
    "&&",
    "||",
    "!",
    "if",
    "else",
    "elsif",
    "return",
    "set",
    "unset",
    "call",
    "include",
    "import",
    "static",
    "acl",
    "new",
    "var",
    "req.url",
    "req.http.X",
    "beresp.ttl",
    "beresp.status",
    "resp.http.Y",
    "client.ip",
    "now",
    "std.log",
    "std.toupper",
    "regsub",
    "hash_data",
    "synthetic",
    "\"a\"",
    "\"^/x\"",
    "1",
    "0",
    "1s",
    "1.5",
    "-1",
    "true",
    "false",
    "pass",
    "hash",
    "deliver",
    "abandon",
    "fetch",
    "synth",
    "#",
    "\n",
    " ",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64, same as the differential generator's.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        (self.next() % upper as u64) as usize
    }
}

/// Arbitrary bytes, biased toward the printable range so the lexer gets past
/// its first character often enough to be interesting.
fn arbitrary(rng: &mut Rng, length: usize) -> String {
    let mut out = String::with_capacity(length);
    for _ in 0..length {
        let byte = match rng.below(4) {
            0 => rng.below(256) as u8,
            _ => 0x20 + rng.below(0x5f) as u8,
        };
        out.push(byte as char);
    }
    out
}

/// A sequence of real tokens with no grammar between them.
fn soup(rng: &mut Rng, tokens: usize) -> String {
    let mut out = String::new();
    for _ in 0..tokens {
        out.push_str(WORDS[rng.below(WORDS.len())]);
        out.push(' ');
    }
    out
}

/// Token soup after a well-formed prologue, so the parser is inside a
/// subroutine body rather than refusing the version marker.
fn prefixed_soup(rng: &mut Rng, tokens: usize) -> String {
    format!("vcl 4.1;\nsub vcl_recv {{ {} }}\n", soup(rng, tokens))
}

/// One long run of one token. This is the shape that used to abort the
/// process: `1+1+…` at a few thousand terms overflowed the stack in the type
/// checker, and `spawn_blocking` does not contain a stack overflow.
fn repetition(rng: &mut Rng) -> String {
    let token = WORDS[rng.below(WORDS.len())];
    let count = 1 + rng.below(20_000);
    format!(
        "vcl 4.1;\nsub vcl_recv {{ set req.http.X = 1 {}; }}\n",
        format!("{token} ").repeat(count)
    )
}

/// A policy that compiles, exercising most of the surface. The mutation
/// shape starts from this so a case has a chance of reaching the stages below
/// the parser — arbitrary bytes and token soup almost never do.
const SEED_POLICY: &str = r#"vcl 4.1;
import std;
acl trusted { "127.0.0.1"; "10.0.0.0"/8; }
var counter: INT;
sub helper {
    set req.http.X-Helper = "1";
}
sub vcl_recv {
    var n: INT = 3;
    set var.counter = var.counter + var.n;
    call helper;
    if (client.ip ~ trusted && req.url ~ "^/api/") {
        set req.http.X-Api = std.toupper(req.url) + "/" + var.counter;
        return (pass);
    }
    if (std.strstr(req.url, "/x") != "") { return (synth(403, "no")); }
    return (hash);
}
sub vcl_backend_response {
    set beresp.ttl = 30s;
    set beresp.grace = 10s;
    if (beresp.status >= 500) { return (abandon); }
    return (deliver);
}
sub vcl_deliver {
    set resp.http.X-Cache = regsub(req.url, "^/", "");
    return (deliver);
}
sub vcl_synth {
    synthetic("denied");
    return (deliver);
}
"#;

/// [`SEED_POLICY`] with a handful of bytes changed. Most edits break it, but
/// the ones that do not land somewhere below the parser, which is the half of
/// the compiler nothing else fuzzes.
fn mutated(rng: &mut Rng, edits: usize) -> String {
    let mut bytes = SEED_POLICY.as_bytes().to_vec();
    for _ in 0..edits {
        let at = rng.below(bytes.len());
        match rng.below(3) {
            0 => bytes[at] = 0x20 + rng.below(0x5f) as u8,
            1 => bytes.insert(at, 0x20 + rng.below(0x5f) as u8),
            _ => {
                bytes.remove(at);
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn case(rng: &mut Rng) -> String {
    let shape = rng.below(10);
    let length = 1 + rng.below(4096);
    let tokens = 1 + rng.below(400);
    let edits = 1 + rng.below(6);
    let source = match shape {
        0..=1 => arbitrary(rng, length),
        2..=3 => prefixed_soup(rng, tokens),
        4 => soup(rng, tokens),
        5 => repetition(rng),
        _ => mutated(rng, edits),
    };
    // The host reads at most this much, so neither does the fuzzer.
    match source.char_indices().nth(MAX_SOURCE_BYTES) {
        Some((at, _)) => source[..at].to_string(),
        None => source,
    }
}

/// Arbitrary bytes are a diagnostic or an ELF, never a panic and never
/// unbounded time.
#[test]
fn arbitrary_bytes_are_a_diagnostic_or_an_elf() {
    let seed = env_parse("VCL_BYTES_SEED").unwrap_or(DEFAULT_SEED);
    let iterations = env_parse("VCL_BYTES_ITERS").unwrap_or(DEFAULT_ITERS);
    assert!(iterations > 0, "VCL_BYTES_ITERS must be positive");

    // The mutation shape is only worth anything if what it mutates compiles.
    compile(SEED_POLICY, CompileOptions::default())
        .unwrap_or_else(|error| panic!("the fuzzer's seed policy must compile:\n{error}"));

    let mut rng = Rng(seed);
    let mut compiled = 0usize;
    let mut slowest = Duration::ZERO;
    for iteration in 0..iterations {
        let source = case(&mut rng);
        let started = Instant::now();
        // A panic below here would already have been turned into a
        // diagnostic by the owned compiler thread, so this asserts the whole
        // contract: `compile` returns, whatever it was handed.
        let outcome = compile(&source, CompileOptions::default());
        let elapsed = started.elapsed();
        slowest = slowest.max(elapsed);
        if let Ok(ref built) = outcome {
            compiled += 1;
            assert!(
                built.elf.starts_with(&[0x7f, b'E', b'L', b'F']),
                "case {iteration} (seed {seed:#x}) produced something that is not an ELF"
            );
        }
        assert!(
            elapsed < CASE_BUDGET,
            "case {iteration} (seed {seed:#x}) took {elapsed:?}, over the {CASE_BUDGET:?} budget; \
             re-run with CARAPACE_VCL_BYTES_SEED={seed:#x}"
        );
    }
    eprintln!(
        "byte fuzz: {iterations} cases from seed {seed:#x} — {compiled} compiled, \
         slowest {slowest:?}"
    );
}

fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok()?.parse().ok()
}
