//! A small, in-process VCL compiler for Carapace.
//!
//! VCL is a frontend only: the output is a deterministic RV64 ELF which uses
//! the existing carapace-scripting ABI. The pipeline is deliberately explicit:
//! preprocessor → lexer → parser → resolver → type checker → desugarer →
//! virtual-register IR → verifier → pass manager → register allocator → RV64
//! codegen → ELF writer. Extending the language therefore does not couple
//! parsing to the sandbox.

#![deny(clippy::wildcard_enum_match_arm)]

mod ast;
mod backend;
mod codegen;
mod desugar;
mod diagnostic;
mod dump;
mod elf;
mod ir;
mod lexer;
mod optimizer;
mod parser;
mod preprocess;
mod regalloc;
mod regex_check;
mod resolver;
mod riscv;
mod runtime;
mod typecheck;
mod types;
mod vars;
mod vmod;
pub mod wire;

#[cfg(test)]
mod bytefuzz;

pub use diagnostic::{Diagnostic, Diagnostics, Severity, MAX_DIAGNOSTICS};
/// The host regex limits the compiler mirrors rather than imports.
///
/// `vcl-compiler` has no runtime dependency on `carapace-scripting` and the
/// sandbox plan keeps it that way, so these are copies. They are public for
/// one reason: `tests/regex_parity.rs` pins each to its
/// `carapace_scripting::abi::Limits` original, which makes a drift a failing
/// test rather than a silently wrong compile-time check.
pub mod limits {
    pub use crate::regex_check::{MAX_PATTERN, REGEX_SIZE_LIMIT};
    pub use crate::types::{MAX_GLOBAL_STRING, MAX_REQUEST_GLOBALS};
}
pub use ir::LineTable;
pub use types::{PhaseSet, Span};

/// Maximum bytes accepted across one VCL policy and all of its libraries.
///
/// The host applies the same limit while reading standalone files, before it
/// allocates an unbounded buffer. Keeping the compiler-side check as well
/// protects callers that provide source text from another configuration
/// source.
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;

/// Maximum number of libraries one policy may import. The byte ceiling bounds
/// non-empty libraries; this separately bounds a large set of empty ones.
pub const MAX_INCLUDE_FILES: usize = 64;

/// Stack the compiler is given, whoever calls it.
///
/// The type checker, the desugarer and the IR builder all walk the expression
/// tree recursively, so the depth the parser admits has to fit somewhere. On
/// the reload path that somewhere is a `spawn_blocking` worker; at boot and
/// under `--test` it is whatever thread `main` happens to be on. Owning the
/// stack makes the parser's `MAX_NESTING` mean the same thing on all three,
/// rather than "whatever the caller had left". The sandbox is the fourth
/// caller and the exception: it compiles on the guest machine's own stack,
/// for the reason `on_owned_stack`'s `riscv64` half gives.
#[cfg(not(target_arch = "riscv64"))]
const COMPILER_STACK_BYTES: usize = 16 * 1024 * 1024;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Reads one included library, named by the *relative* path the compiler has
/// already normalized and confined.
///
/// Relative and not resolved: the name is the only thing that can cross the
/// sandbox boundary as a syscall argument, so the compiler hands its provider
/// exactly what a sandboxed compile can hand the host. Whoever supplies the
/// callback owns the confinement of that name against a real filesystem —
/// `carapace::vcl_source` on both paths.
type IncludeRead = dyn Fn(&Path) -> Result<String, String> + Send + Sync;

type IncludeObserver = dyn Fn(&str, &str) + Send + Sync;

/// Where a policy's `include` statements are read from.
///
/// The compiler holds no file descriptor and opens nothing: it normalizes the
/// include name, confines it to a relative path, and asks its provider. That
/// is what lets the same compiler run natively and inside the script sandbox
/// (`docs/plans/vcl-compiler-sandbox.md`, S3).
#[derive(Clone)]
pub struct IncludeResolver {
    root: PathBuf,
    read: Arc<IncludeRead>,
    /// Called with the name and text of every library actually read.
    ///
    /// The reload path uses it to hash the exact bytes a compile consumed,
    /// which is what lets an unchanged policy skip the next compile. An
    /// observer that re-read the tree afterwards would hash whatever the tree
    /// held *then*, and would keep serving a stale ELF for a library rewritten
    /// in between.
    observer: Option<Arc<IncludeObserver>>,
}

impl std::fmt::Debug for IncludeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncludeResolver")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl IncludeResolver {
    /// Create a resolver backed by a source provider.
    ///
    /// The provider owns source lookup after the compiler has normalized and
    /// confined the relative include name. `root` is display only: it prefixes
    /// the path a diagnostic tells the operator to open, and never reaches the
    /// generated ELF, so two copies of one policy tree still compile to the
    /// same bytes.
    pub fn new<F>(root: impl Into<PathBuf>, read: F) -> Self
    where
        F: Fn(&Path) -> Result<String, String> + Send + Sync + 'static,
    {
        Self {
            root: root.into(),
            read: Arc::new(read),
            observer: None,
        }
    }

    /// The directory include names are relative to, for diagnostics.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Report the name and text of every library this resolver reads.
    ///
    /// Names are as the `include` statement spells them, in first-read order,
    /// deduplicated the same way the preprocessor deduplicates them — so the
    /// sequence lines up with [`Compiled::files`].
    #[must_use]
    pub fn observing(mut self, observe: impl Fn(&str, &str) + Send + Sync + 'static) -> Self {
        self.observer = Some(Arc::new(observe));
        self
    }

    pub(crate) fn observe(&self, name: &str, text: &str) {
        if let Some(observe) = self.observer.as_ref() {
            observe(name, text);
        }
    }

    /// Read one library by the name an `include` spells, without compiling.
    ///
    /// Same confinement as a compile: the name is normalized and refused if it
    /// escapes the root. The reload path uses it to re-hash a policy's
    /// libraries and find out whether anything changed.
    pub fn read_include(&self, name: &str) -> Result<String, String> {
        let include = self.resolve(name)?;
        self.read(&include)
    }
}

/// Compiler controls plus the declarative route context needed to reject
/// cache-key-changing request policy. Route context affects validation only,
/// never generated bytes.
#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub verify_ir: bool,
    pub optimization: OptimizationLevel,
    forbidden_recv_headers: BTreeSet<String>,
    include_resolver: Option<IncludeResolver>,
    /// The route's `grace` and `keep`, in seconds, if it names them.
    ///
    /// Validation context only: the compiler does not clamp, because the host
    /// already does and a script may not raise a cap. Knowing the numbers is
    /// what lets it *say* that `set beresp.grace = 1h;` on a route capped at
    /// 30s will be 30s. Nothing here changes a byte of the ELF, which is what
    /// keeps two routes with the same variance sharing one compile.
    stale_caps: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OptimizationLevel {
    None,
    #[default]
    Basic,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            verify_ir: true,
            optimization: OptimizationLevel::Basic,
            forbidden_recv_headers: BTreeSet::new(),
            include_resolver: None,
            stale_caps: None,
        }
    }
}

impl CompileOptions {
    pub fn with_include_resolver(mut self, resolver: IncludeResolver) -> Self {
        self.include_resolver = Some(resolver);
        self
    }

    /// Add the route's `variant_headers`, the request headers an object may
    /// vary on. `vcl_recv` runs before variance is derived, so it must not
    /// mutate any of these headers.
    pub fn with_variant_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.forbidden_recv_headers.extend(
            headers
                .into_iter()
                .map(|header| header.as_ref().trim().to_ascii_lowercase()),
        );
        self
    }

    /// The route's `grace`/`keep` caps in seconds, for the note a write over
    /// one gets. A route that names neither caps at zero, which is what
    /// "stale serving is off unless a route asks for it" means.
    #[must_use]
    pub fn with_stale_caps(mut self, grace: u32, keep: u32) -> Self {
        self.stale_caps = Some((grace, keep));
        self
    }

    pub(crate) fn stale_cap(&self, lowering: vars::Lowering) -> Option<u32> {
        let (grace, keep) = self.stale_caps?;
        match lowering {
            vars::Lowering::StaleWhileRevalidate => Some(grace),
            vars::Lowering::StaleIfError => Some(keep),
            vars::Lowering::RequestHeader
            | vars::Lowering::ResponseHeader
            | vars::Lowering::RequestUrl
            | vars::Lowering::RequestMethod
            | vars::Lowering::Body
            | vars::Lowering::Host(_)
            | vars::Lowering::Now
            | vars::Lowering::ClientIp
            | vars::Lowering::Ttl
            | vars::Lowering::Uncacheable
            | vars::Lowering::CacheHit => None,
        }
    }

    pub(crate) fn forbids_recv_header(&self, header: &str) -> bool {
        self.forbidden_recv_headers
            .contains(&header.to_ascii_lowercase())
    }
}

/// Result of compiling one VCL source string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub elf: Vec<u8>,
    pub lines: LineTable,
    /// Included libraries, in the order the line table's file indexes number
    /// them: index 1 is the first entry here. Index 0 is the compiled unit's
    /// own source, which the caller already has a path for.
    pub files: Vec<String>,
    pub exports: PhaseSet,
    /// Things the policy does that compile, but not to what a Varnish author
    /// would expect: a fractional cache duration the ABI truncates, a stale
    /// window the route's cap will lower, a `vcl_synth` nothing dispatches to.
    /// Never fatal — the caller renders them into its log.
    pub warnings: Diagnostics,
}

/// The text every span in a lowered program points into: the compiled unit's
/// own source first, then each included library appended after it.
///
/// Codegen needs the whole of it. A line table built from the main source
/// alone maps every instruction an include contributed to the main file's last
/// line, which is worse than no location at all.
pub(crate) use preprocess::SourceUnit;

/// Reusable, stateless compiler configuration.
///
/// A `Compiler` owns only options. Every stage remains a pure function of one
/// source file, so callers may share a compiler across parallel reload work.
#[derive(Debug, Clone)]
pub struct Compiler {
    options: CompileOptions,
}

impl Compiler {
    pub fn new(options: CompileOptions) -> Self {
        Self { options }
    }

    pub fn compile(&self, source: &str) -> Result<Compiled, Diagnostics> {
        on_owned_stack(source, || {
            #[cfg(test)]
            if source.contains(PANIC_PROBE) {
                unreachable!("panic probe");
            }
            let (program, unit, warnings) = lower_to_ir(source, &self.options)?;
            let mut compiled = emit_program(&unit, &program)?;
            compiled.warnings =
                Diagnostics::new(&unit.text, warnings).with_files(unit.files.clone());
            Ok(compiled)
        })
    }
}

/// Compile VCL source directly to a static RV64 ELF.
pub fn compile(source: &str, options: CompileOptions) -> Result<Compiled, Diagnostics> {
    Compiler::new(options).compile(source)
}

/// The marker a test uses to make the compiler panic where an internal
/// invariant would.
#[cfg(test)]
const PANIC_PROBE: &str = "vcl-compiler-panic-probe";

/// Run `work` on a thread whose stack size the compiler owns, turning a panic
/// in it into a diagnostic.
///
/// Every stage below the parser recurses, and an internal-invariant `expect`
/// in one of them would otherwise be a startup abort at boot and under
/// `--test` — a node that will not come up, with no line to look at. The
/// reload path already survives one by accident, because `spawn_blocking`
/// catches it; this makes all three entry points behave the same way on
/// purpose. A stack *overflow* is still an abort, which is why the parser's
/// depth bound is not optional.
///
/// The sandbox is the exception; the `riscv64` half below says why.
#[cfg(not(target_arch = "riscv64"))]
fn on_owned_stack<T: Send>(
    source: &str,
    work: impl FnOnce() -> Result<T, Diagnostics> + Send,
) -> Result<T, Diagnostics> {
    std::thread::scope(|scope| {
        let started = std::thread::Builder::new()
            .name("vcl-compile".to_string())
            .stack_size(COMPILER_STACK_BYTES)
            .spawn_scoped(scope, work);
        let handle = match started {
            Ok(handle) => handle,
            Err(error) => {
                return Err(Diagnostics::single(
                    source,
                    Diagnostic::error(
                        Span::default(),
                        format!("could not start the VCL compiler thread: {error}"),
                    ),
                ))
            }
        };
        handle.join().unwrap_or_else(|payload| {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "no message".to_string());
            Err(Diagnostics::single(
                source,
                Diagnostic::error(
                    Span::default(),
                    format!("internal compiler error: {detail}"),
                )
                .with_help("this is a bug in the VCL compiler; the policy was not applied"),
            ))
        })
    })
}

/// Inside the sandbox, run `work` where it already is.
///
/// A guest thread would buy nothing here and costs correctness. Nothing:
/// `vcl-compiler/guest` builds `panic = "abort"`, so a broken invariant is a
/// machine fault whatever thread it happens on, and the host already reports
/// that as a failed compile and a rejected candidate — the containment this
/// guest exists for. Correctness: libriscv keeps one syscall-handler table
/// per `Machine<W>` *type*, which is process-wide, and every VM construction
/// rewrites entry 93 twice — `setup_linux_syscalls` first, with the plain
/// "stop this machine" exit, then `setup_posix_threads` with the thread-aware
/// one. A VM being built on one host thread therefore leaves a window in
/// which another machine's *guest* thread exiting stops that machine
/// outright: `vclc_compile` never returns, and the host reads a null buffer
/// where the answer should be. Concurrent compiles are the reload path's
/// ordinary shape, so that window is reached in practice — it is what made
/// `carapace`'s own suite flake, at about 1.5% of compiles under 16 threads.
///
/// So the compile runs on the machine's own stack, and libriscv's 1 MiB
/// default is what has to hold the parser's `MAX_NESTING`.
/// `vcl-compiler/tests/sandbox_parity.rs` compiles a maximally nested policy
/// both ways and is what says it does.
///
/// `target_arch` rather than a feature: a feature can be left off, and a
/// sandboxed compiler that quietly regained the thread would be this bug
/// again. riscv64 is the guest and nothing else — carapace itself is built
/// for amd64 and arm64.
#[cfg(target_arch = "riscv64")]
fn on_owned_stack<T: Send>(
    _source: &str,
    work: impl FnOnce() -> Result<T, Diagnostics> + Send,
) -> Result<T, Diagnostics> {
    work()
}

/// Run the source-language frontend and produce verified IR.
///
/// Keeping this boundary separate from machine emission is what lets the test
/// suite execute the exact IR handed to codegen and compare the two results.
/// It also prevents a differential test from accidentally rebuilding a
/// slightly different frontend pipeline for its reference side.
fn lower_to_ir(
    source: &str,
    options: &CompileOptions,
) -> Result<(ir::Program, SourceUnit, Vec<Diagnostic>), Diagnostics> {
    let (mut program, unit, warnings) = lower_unoptimized(source, options)?;
    if options.optimization == OptimizationLevel::Basic {
        optimizer::PassManager::basic(options.verify_ir)
            .run(&mut program)
            .map_err(|error| backend_diagnostics(&unit, error))?;
    }
    Ok((program, unit, warnings))
}

fn lower_unoptimized(
    source: &str,
    options: &CompileOptions,
) -> Result<(ir::Program, SourceUnit, Vec<Diagnostic>), Diagnostics> {
    let (typed, unit) = lower_typed(source, options)?;
    let warnings = typed.warnings.clone();
    let program = ir::lower(&typed);
    if options.verify_ir {
        ir::verify(&program).map_err(|error| backend_diagnostics(&unit, error))?;
    }
    Ok((program, unit, warnings))
}

fn lower_typed(
    source: &str,
    options: &CompileOptions,
) -> Result<(typecheck::TypedProgram, SourceUnit), Diagnostics> {
    let (checked, unit) = check_typed(source, options)?;
    let typed = desugar_checked(&unit, checked)?;
    Ok((typed, unit))
}

/// Type-check without desugaring. Only `dump_ir` needs the two trees apart;
/// the compile path desugars in place rather than cloning the checked tree.
fn check_typed(
    source: &str,
    options: &CompileOptions,
) -> Result<(typecheck::TypedProgram, SourceUnit), Diagnostics> {
    let unit = preprocess::preprocess(source, options)?;
    let resolved = resolver::resolve(&unit.text, unit.program.clone())
        .map_err(|diagnostics| diagnostics.with_files(unit.files.clone()))?;
    let typed = typecheck::check(&unit.text, resolved, options)
        .map_err(|diagnostics| diagnostics.with_files(unit.files.clone()))?;
    Ok((typed, unit))
}

fn desugar_checked(
    unit: &SourceUnit,
    checked: typecheck::TypedProgram,
) -> Result<typecheck::TypedProgram, Diagnostics> {
    desugar::desugar(&unit.text, checked)
        .map_err(|diagnostics| diagnostics.with_files(unit.files.clone()))
}

/// Render verbose virtual-register IR, including each enabled optimizer stage.
pub fn dump_ir(source: &str, options: CompileOptions) -> Result<String, Diagnostics> {
    on_owned_stack(source, || dump_ir_on_this_stack(source, &options))
}

fn dump_ir_on_this_stack(source: &str, options: &CompileOptions) -> Result<String, Diagnostics> {
    let options = options.clone();
    let mut output = String::new();
    let (checked, unit) = check_typed(source, &options)?;
    let desugared = desugar_checked(&unit, checked.clone())?;
    dump::write_typed_stage(&mut output, "typed", &checked);
    dump::write_typed_stage(&mut output, "desugared", &desugared);
    let unoptimized = ir::lower(&desugared);
    if options.verify_ir {
        ir::verify(&unoptimized).map_err(|error| backend_diagnostics(&unit, error))?;
    }
    dump::write_ir_stage(&mut output, "lowered (O0)", &unoptimized);
    if options.optimization == OptimizationLevel::Basic {
        for (index, name) in optimizer::PassManager::basic_pass_names()
            .into_iter()
            .enumerate()
        {
            let mut prefix = unoptimized.clone();
            optimizer::PassManager::basic_prefix(options.verify_ir, index + 1)
                .run(&mut prefix)
                .map_err(|error| Diagnostics::single(source, error.into_diagnostic()))?;
            dump::write_ir_stage(&mut output, &format!("after {name}"), &prefix);
        }
    }
    Ok(output)
}

/// Emit machine code and its ELF container from already-verified IR.
fn emit_program(unit: &SourceUnit, program: &ir::Program) -> Result<Compiled, Diagnostics> {
    let allocated =
        regalloc::allocate(program).map_err(|error| backend_diagnostics(unit, error))?;
    let image =
        codegen::generate(&allocated, unit).map_err(|error| backend_diagnostics(unit, error))?;
    let lines = image.lines.clone();
    let elf = elf::build(&image).map_err(|error| backend_diagnostics(unit, error))?;
    let exports = image.exports.clone();
    Ok(Compiled {
        elf,
        lines,
        files: unit.include_names(),
        exports,
        warnings: Diagnostics::new(&unit.text, Vec::new()),
    })
}

fn backend_diagnostics(unit: &SourceUnit, error: backend::BackendError) -> Diagnostics {
    Diagnostics::single(&unit.text, error.into_diagnostic()).with_files(unit.files.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC: &str = r#"
vcl 4.1;
sub vcl_recv {
    set req.http.X-VCL = "compiled";
    std.log("VCL recv");
    return (pass);
}
"#;

    #[test]
    fn compilation_is_deterministic() {
        let a = compile(BASIC, CompileOptions::default()).unwrap();
        let b = compile(BASIC, CompileOptions::default()).unwrap();
        assert_eq!(a, b);
        assert!(a.exports.contains("on_recv"));
    }

    #[test]
    fn include_library_shape_and_refusals_are_explicit() {
        let root = "vcl 4.1; include \"lib.vcl\"; sub vcl_recv { call helper; return (hash); }";
        let remote = compile(root, CompileOptions::default())
            .unwrap_err()
            .to_string();
        assert!(
            remote.contains("not supported from remote configuration yet"),
            "{remote}"
        );

        let compile_library = |source: &str, body: &'static str| {
            let options = CompileOptions::default()
                .with_include_resolver(IncludeResolver::new("/bundle", move |_| {
                    Ok(body.to_string())
                }));
            compile(source, options)
        };
        for (body, expected) in [
            ("include \"nested.vcl\";", "nested include is not supported"),
            (
                "vcl 4.1; sub helper { return; }",
                "must not contain a vcl version marker",
            ),
            (
                "sub vcl_recv { return (hash); }",
                "included library may not define hook",
            ),
        ] {
            let error = compile_library(root, body).unwrap_err().to_string();
            assert!(error.contains(expected), "expected {expected:?} in {error}");
        }

        let duplicate = "vcl 4.1; include \"lib.vcl\"; include \"lib.vcl\"; sub vcl_recv { call helper; return (hash); }";
        let error = compile_library(duplicate, "sub helper { return; }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate include 'lib.vcl'"), "{error}");

        let collision = "vcl 4.1; include \"lib.vcl\"; sub helper { return; } sub vcl_recv { call helper; return (hash); }";
        let error = compile_library(collision, "sub helper { return; }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate declaration of helper"), "{error}");

        let semantic = compile_library(root, "sub helper { set resp.http.X-Wrong-Phase = \"x\"; }")
            .unwrap_err()
            .to_string();
        assert!(semantic.contains("lib.vcl:1:"), "{semantic}");
        assert!(semantic.contains("not writable in vcl_recv"), "{semantic}");

        let missing = CompileOptions::default()
            .with_include_resolver(IncludeResolver::new("/bundle", |_| {
                Err("not found".to_string())
            }));
        let error = compile(root, missing).unwrap_err().to_string();
        assert!(
            error.contains("failed to include 'lib.vcl': not found"),
            "{error}"
        );
    }

    #[test]
    fn source_and_include_aggregate_are_bounded() {
        let oversized = " ".repeat(MAX_SOURCE_BYTES + 1);
        let error = compile(&oversized, CompileOptions::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("over the 1048576-byte limit"), "{error}");

        let source = "vcl 4.1; include \"lib.vcl\"; sub vcl_recv { return (hash); }";
        let library = " ".repeat(MAX_SOURCE_BYTES);
        let options =
            CompileOptions::default()
                .with_include_resolver(IncludeResolver::new("/bundle", move |_| {
                    Ok(library.clone())
                }));
        let error = compile(source, options).unwrap_err().to_string();
        assert!(error.contains("aggregate limit"), "{error}");

        let mut too_many = "vcl 4.1;".to_string();
        for index in 0..=MAX_INCLUDE_FILES {
            too_many.push_str(&format!(" include \"lib-{index}.vcl\";"));
        }
        too_many.push_str(" sub vcl_recv { return (hash); }");
        let error = compile(&too_many, CompileOptions::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("64-file limit"), "{error}");
    }


    #[test]
    fn storage_and_subroutine_rules_have_source_diagnostics() {
        let cases = [
            (
                "vcl 4.1; sub vcl_recv { set var.missing = 1; }",
                "var.missing is not declared",
            ),
            (
                "vcl 4.1; static var n: INT = 1; sub vcl_recv {}",
                "static variables are not supported",
            ),
            (
                "vcl 4.1; sub unused { return; } sub vcl_recv {}",
                "sub unused is never called",
            ),
            (
                "vcl 4.1; sub loop { call loop; } sub vcl_recv { call loop; }",
                "recursive VCL subroutine cycle",
            ),
            (
                "vcl 4.1; sub gate { return (hash); } sub vcl_recv { call gate; }",
                "call of deciding sub gate",
            ),
            (
                "vcl 4.1; sub helper { return; } sub vcl_recv { return (helper); }",
                "plain sub helper does not return an action",
            ),
        ];
        for (source, expected) in cases {
            let error = compile(source, CompileOptions::default())
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "expected {expected:?} in {error}");
        }
    }

    #[test]
    fn static_declarations_are_refused_at_the_declaration() {
        let declaration = "static var requests: INT = 1;";
        let source = format!(
            "vcl 4.1; {declaration} sub vcl_recv {{ set var.requests = var.requests + 1; return (hash); }}"
        );
        let error = compile(&source, CompileOptions::default()).unwrap_err();
        // One diagnostic: the uses of the refused name are not also reported.
        let [diagnostic] = error.diagnostics.as_slice() else {
            panic!("expected one diagnostic, got {error}");
        };
        assert_eq!(
            diagnostic.message,
            "static variables are not supported: every request runs in a fresh VM fork, so \
             nothing persists between requests"
        );
        assert_eq!(
            diagnostic.help.as_deref(),
            Some(
                "use a request global ('var NAME: TYPE;' at the top level) instead, or annotate \
                 it with 'stat' to count into a Varnish counter"
            )
        );
        assert_eq!(
            &source[diagnostic.span.start..diagnostic.span.end],
            declaration
        );

        // Every type is refused the same way, before any other complaint.
        for source in [
            "vcl 4.1; static var s: STRING; sub vcl_recv {}",
            "vcl 4.1; static var n: INT = 1 + 2; sub vcl_recv {}",
        ] {
            let error = compile(source, CompileOptions::default()).unwrap_err();
            assert_eq!(error.diagnostics.len(), 1, "{error}");
            assert!(
                error.to_string().contains("static variables are not supported"),
                "{error}"
            );
        }
    }

    #[test]
    fn dynamic_statistics_are_not_part_of_the_language() {
        for source in [
            "vcl 4.1; stat hits: counter {path} ttl 1h \"help\"; sub vcl_recv {}",
            "vcl 4.1; sub vcl_recv { set stat.hits{path = req.url} += 1; }",
            "vcl 4.1; sub vcl_recv { var h: STAT; }",
        ] {
            assert!(
                compile(source, CompileOptions::default()).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn stat_writes_are_observable_and_survive_optimization() {
        let source = "vcl 4.1; static var requests: INT stat; sub vcl_recv { set var.requests = var.requests + 1; return (hash); }";
        let ir = dump_ir(source, CompileOptions::default()).unwrap();
        assert!(ir.contains("store.static requests"), "{ir}");
        let compiled = compile(source, CompileOptions::default()).unwrap();
        assert!(section(&compiled.elf, ".carapace.statics").is_some());
    }

    /// One `.carapace.stats` row, with its guest strings resolved out of the
    /// image — the test-side mirror of what the host does when the program
    /// loads.
    #[derive(Debug, PartialEq, Eq)]
    struct StatRow {
        addr: u64,
        kind: u32,
        flags: u32,
        name: String,
        help: String,
    }

    /// Bytes of a named section, by walking the section headers the writer
    /// emitted.
    fn section<'a>(elf: &'a [u8], want: &str) -> Option<&'a [u8]> {
        let u16at = |at: usize| u16::from_le_bytes(elf[at..at + 2].try_into().unwrap()) as usize;
        let u32at = |at: usize| u32::from_le_bytes(elf[at..at + 4].try_into().unwrap()) as usize;
        let u64at = |at: usize| u64::from_le_bytes(elf[at..at + 8].try_into().unwrap()) as usize;
        let table = u64at(0x28);
        let entry = u16at(0x3a);
        let count = u16at(0x3c);
        let names = u16at(0x3e);
        let names_at = u64at(table + names * entry + 24);
        for index in 0..count {
            let at = table + index * entry;
            let spelled = elf[names_at + u32at(at)..]
                .split(|byte| *byte == 0)
                .next()
                .unwrap();
            if spelled == want.as_bytes() {
                let offset = u64at(at + 24);
                return Some(&elf[offset..offset + u64at(at + 32)]);
            }
        }
        None
    }

    /// Read `.carapace.stats`, resolving name and help against `.rodata`.
    fn stat_rows(elf: &[u8]) -> Vec<StatRow> {
        let Some(rows) = section(elf, ".carapace.stats") else {
            return Vec::new();
        };
        assert_eq!(rows.len() % 32, 0, "a stats row is 32 bytes");
        let text = section(elf, ".text").expect(".text");
        let rodata = section(elf, ".rodata").expect(".rodata");
        let rodata_base = codegen::BASE_ADDRESS + text.len() as u64;
        let string_at = |address: u64| {
            let offset = (address - rodata_base) as usize;
            let bytes = rodata[offset..].split(|byte| *byte == 0).next().unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        };
        rows.chunks_exact(32)
            .map(|row| {
                let u32at = |at: usize| u32::from_le_bytes(row[at..at + 4].try_into().unwrap());
                let u64at = |at: usize| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
                StatRow {
                    addr: u64at(0),
                    kind: u32at(8),
                    flags: u32at(12),
                    name: string_at(u64at(16)),
                    help: string_at(u64at(24)),
                }
            })
            .collect()
    }

    #[test]
    fn stat_annotations_publish_one_row_per_kind() {
        let source = r#"vcl 4.1;
static var blocked: INT stat;
static var token_failures: INT stat counter "Requests whose signed token did not verify";
static var inflight: INT stat gauge "Requests the policy has admitted";
static var peak_header_bytes: INT stat max "Largest header block seen";
static var fastest_decision_us: INT stat min "Fastest recv decision";
sub vcl_recv {
    set var.blocked = var.blocked + 1;
    set var.token_failures = var.token_failures + 1;
    set var.inflight = var.inflight + 1;
    set var.peak_header_bytes = 8192;
    set var.fastest_decision_us = 12;
    return (hash);
}"#;
        let compiled = compile(source, CompileOptions::default()).unwrap();
        let rows = stat_rows(&compiled.elf);
        let named: Vec<(&str, u32, &str)> = rows
            .iter()
            .map(|row| (row.name.as_str(), row.kind, row.help.as_str()))
            .collect();
        assert_eq!(
            named,
            [
                ("blocked", 0, "VCL-declared counter blocked"),
                (
                    "token_failures",
                    0,
                    "Requests whose signed token did not verify"
                ),
                ("inflight", 1, "Requests the policy has admitted"),
                ("peak_header_bytes", 2, "Largest header block seen"),
                ("fastest_decision_us", 3, "Fastest recv decision"),
            ]
        );
        // Rows are in declaration order, and every row's address is the
        // word `.carapace.statics` gives it.
        let statics = section(&compiled.elf, ".carapace.statics").expect("statics section");
        let mut at = 0;
        let mut addresses = Vec::new();
        while at < statics.len() {
            let address = u64::from_le_bytes(statics[at..at + 8].try_into().unwrap());
            let name_len =
                u32::from_le_bytes(statics[at + 12..at + 16].try_into().unwrap()) as usize;
            let name = String::from_utf8(statics[at + 16..at + 16 + name_len].to_vec()).unwrap();
            addresses.push((name, address));
            at += 16 + name_len;
        }
        for row in &rows {
            assert_eq!(row.flags, 0, "flags are reserved");
            assert_eq!(row.addr % 8, 0, "a stat word is 8-byte aligned");
            let expected = addresses
                .iter()
                .find(|(name, _)| *name == row.name)
                .expect("declared static");
            assert_eq!(row.addr, expected.1, "{} address", row.name);
        }
        assert_eq!(addresses.len(), 5, "every static is published");
    }

    #[test]
    fn a_policy_with_no_stat_publishes_no_section() {
        let compiled = compile(BASIC, CompileOptions::default()).unwrap();
        assert!(section(&compiled.elf, ".carapace.stats").is_none());
        assert!(!compiled
            .elf
            .windows(b".carapace.stats\0".len())
            .any(|bytes| bytes == b".carapace.stats\0"));
    }

    #[test]
    fn a_stat_annotation_does_not_move_the_generated_code() {
        // The kind and the description are metadata: they change rodata and
        // a section row, and must not change an instruction.
        let plain =
            "vcl 4.1; static var n: INT stat; sub vcl_recv { set var.n = var.n + 1; return (hash); }";
        let described = "vcl 4.1; static var n: INT stat gauge \"a longer description\"; \
                         sub vcl_recv { set var.n = var.n + 1; return (hash); }";
        let plain = compile(plain, CompileOptions::default()).unwrap();
        let described = compile(described, CompileOptions::default()).unwrap();
        assert_eq!(
            section(&plain.elf, ".text").unwrap(),
            section(&described.elf, ".text").unwrap()
        );
    }

    #[test]
    fn compiling_a_stat_policy_is_deterministic() {
        let source = r#"vcl 4.1;
static var blocked: INT stat "help";
sub vcl_recv { set var.blocked = var.blocked + 1; return (hash); }"#;
        let first = compile(source, CompileOptions::default()).unwrap();
        let second = compile(source, CompileOptions::default()).unwrap();
        assert_eq!(first.elf, second.elf);
    }

    #[test]
    fn statistics_are_capped_per_policy() {
        let policy = |count: usize| {
            let mut source = String::from("vcl 4.1;");
            for i in 0..count {
                source.push_str(&format!(" static var s{i}: INT stat;"));
            }
            source.push_str(" sub vcl_recv {}");
            source
        };
        compile(&policy(types::MAX_STATS), CompileOptions::default())
            .expect("a policy at the cap compiles");
        let error = compile(&policy(types::MAX_STATS + 1), CompileOptions::default()).unwrap_err();
        let [diagnostic] = error.diagnostics.as_slice() else {
            panic!("expected one diagnostic, got {error}");
        };
        assert_eq!(
            diagnostic.message,
            format!("a policy declares at most {} statistics", types::MAX_STATS)
        );
    }

    #[test]
    fn stat_annotation_diagnostics() {
        let cases = [
            (
                "vcl 4.1; static var b: BOOL stat; sub vcl_recv {}",
                "a BOOL static cannot be a statistic",
            ),
            (
                "vcl 4.1; static var t: TIME stat; sub vcl_recv {}",
                "a TIME static cannot be a statistic",
            ),
            (
                "vcl 4.1; static var d: DURATION stat; sub vcl_recv {}",
                "a DURATION static cannot be a statistic yet",
            ),
            (
                "vcl 4.1; static var f: INT = 1 stat min; sub vcl_recv {}",
                "a 'min' statistic cannot have an initializer",
            ),
            (
                "vcl 4.1; static var Blocked: INT stat; sub vcl_recv {}",
                "a statistic name must match [a-z][a-z0-9_]*, not ending in '_'",
            ),
            (
                "vcl 4.1; static var acme_: INT stat; sub vcl_recv {}",
                "a statistic name must match [a-z][a-z0-9_]*, not ending in '_'",
            ),
            (
                "vcl 4.1; static var a__b: INT stat; sub vcl_recv {}",
                "a statistic name may not contain '__'",
            ),
            (
                "vcl 4.1; static var s: STRING stat; sub vcl_recv {}",
                "static cannot have type STRING",
            ),
            (
                "vcl 4.1; static var n: INT stat median; sub vcl_recv {}",
                "'median' is not a statistic kind",
            ),
            (
                "vcl 4.1; static var n: INT = 1 + 2 stat; sub vcl_recv {}",
                "runs before any request exists",
            ),
        ];
        for (source, expected) in cases {
            let error = compile(source, CompileOptions::default())
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "expected {expected:?} in {error}");
        }

        // A refused STRING static is still declared, so its uses are not
        // also reported as undeclared.
        let error = compile(
            "vcl 4.1; static var s: STRING stat; sub vcl_recv { set var.s = \"x\"; }",
            CompileOptions::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("static cannot have type STRING"), "{error}");
        assert!(!error.contains("is not declared"), "{error}");

        let long_name = format!(
            "vcl 4.1; static var {}: INT stat; sub vcl_recv {{}}",
            "a".repeat(65)
        );
        assert!(compile(&long_name, CompileOptions::default())
            .unwrap_err()
            .to_string()
            .contains("a statistic name is at most 64 bytes"));

        let long_help = format!(
            "vcl 4.1; static var n: INT stat \"{}\"; sub vcl_recv {{}}",
            "x".repeat(201)
        );
        assert!(compile(&long_help, CompileOptions::default())
            .unwrap_err()
            .to_string()
            .contains("a statistic description is at most 200 bytes"));
    }

    #[test]
    fn stat_is_a_contextual_keyword() {
        // Nothing about `stat` is reserved: it still names a sub, a local
        // and the statistic itself.
        let source = "vcl 4.1; static var stat: INT stat; \
                      sub vcl_recv { set var.stat = var.stat + 1; return (hash); }";
        let compiled = compile(source, CompileOptions::default()).unwrap();
        assert_eq!(stat_rows(&compiled.elf).len(), 1);
        compile(
            "vcl 4.1; sub stat { set req.http.x-stat = \"1\"; } \
             sub vcl_recv { var stat: INT = 1; set var.stat = var.stat + 1; call stat; return (hash); }",
            CompileOptions::default(),
        )
        .unwrap();
    }

    #[test]
    fn the_typed_dump_shows_the_annotation() {
        let dump = dump_ir(
            "vcl 4.1; static var blocked: INT stat gauge \"why\"; sub vcl_recv { set var.blocked = 1; return (hash); }",
            CompileOptions::default(),
        )
        .unwrap();
        assert!(dump.contains("Gauge"), "{dump}");
        assert!(dump.contains("why"), "{dump}");
    }

    #[test]
    fn route_validation_context_does_not_change_generated_bytes() {
        let plain = compile(BASIC, CompileOptions::default()).unwrap();
        let contextual = compile(
            BASIC,
            CompileOptions::default().with_variant_headers(["x-unrelated"]),
        )
        .unwrap();
        assert_eq!(plain, contextual);
    }




    #[test]
    fn regex_operators_require_strings_and_a_literal_pattern() {
        let wrong_subject = compile(
            "vcl 4.1; sub vcl_backend_response { if (beresp.status ~ \"5..\") {} }",
            CompileOptions::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            wrong_subject.contains("'~' and '!~' require STRING operands"),
            "{wrong_subject}"
        );

        let dynamic_pattern = compile(
            "vcl 4.1; sub vcl_recv { if (req.url ~ req.http.X-Pattern) {} }",
            CompileOptions::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            dynamic_pattern.contains("must be a literal pattern"),
            "{dynamic_pattern}"
        );
    }

    #[test]
    fn every_rejected_surface_names_its_replacement_or_invariant() {
        let ordinary = CompileOptions::default();
        let variant_header = CompileOptions::default().with_variant_headers(["x-variant"]);
        let cases = [
            (
                "vcl 4.1; backend origin {} sub vcl_recv {}",
                &ordinary,
                "backends and directors belong to the Varnish VCL",
            ),
            (
                "vcl 4.1; director pool {} sub vcl_recv {}",
                &ordinary,
                "backends and directors belong to the Varnish VCL",
            ),
            ("vcl 4.1; sub vcl_init {}", &ordinary, "backends and directors belong"),
            (
                "vcl 4.1; sub vcl_recv { set req.backend_hint = \"origin\"; }",
                &ordinary,
                "backends and directors belong to the Varnish VCL",
            ),
            (
                "vcl 4.1; sub vcl_backend_fetch { set bereq.backend = \"origin\"; }",
                &ordinary,
                "backends and directors belong to the Varnish VCL",
            ),
            (
                "vcl 4.1; sub vcl_recv { hash_data(req.url); }",
                &ordinary,
                "hash_data() is only valid in vcl_hash",
            ),
            (
                "vcl 4.1; sub vcl_recv { set req.http.Host = \"other\"; }",
                &ordinary,
                "req.http.Host picked this tenant",
            ),
            (
                "vcl 4.1; sub vcl_hit { unset req.http.host; }",
                &ordinary,
                "req.http.Host picked this tenant",
            ),
            (
                "vcl 4.1; sub vcl_recv { set req.http.X-Variant = \"a\"; }",
                &variant_header,
                "the header is part of the cache key",
            ),
            (
                "vcl 4.1; sub vcl_recv { set req.url = \"has space\"; }",
                &ordinary,
                "cannot be empty or contain spaces",
            ),
            (
                "vcl 4.1; sub vcl_backend_response { set req.url = \"/x\"; }",
                &ordinary,
                "the backend side writes its own copy of the request, bereq",
            ),
            (
                "vcl 4.1; sub vcl_recv { return (restart); }",
                &ordinary,
                "host-controlled",
            ),
            (
                "vcl 4.1; sub vcl_backend_response { return (retry); }",
                &ordinary,
                "host-controlled",
            ),
            (
                "vcl 4.1; sub vcl_recv { return (pipe); }",
                &ordinary,
                "host-controlled",
            ),
            (
                "vcl 4.1; sub vcl_recv { return (purge); }",
                &ordinary,
                "purging belongs to the Varnish VCL",
            ),
            (
                "vcl 4.1; sub vcl_purge {}",
                &ordinary,
                "not a hook a tenant policy can define",
            ),
            (
                "vcl 4.1; sub vcl_backend_response { set beresp.do_esi = true; }",
                &ordinary,
                "an include may name another tenant's site",
            ),
            (
                "vcl 4.1; sub vcl_recv { synthetic(\"body\"); }",
                &ordinary,
                "only valid in vcl_synth and vcl_backend_error",
            ),
            (
                "vcl 4.1; import cookie; sub vcl_recv {}",
                &ordinary,
                "Rust guest",
            ),
            (
                "vcl 4.1; sub vcl_recv { set req.http.X = 1.5; }",
                &ordinary,
                "integer or duration arithmetic",
            ),
            (
                "vcl 4.1; sub vcl_hit { set req.storage = \"s0\"; }",
                &ordinary,
                "storage selection belongs to the Varnish VCL",
            ),
        ];

        for (source, options, expected) in cases {
            let error = compile(source, options.clone()).unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "expected {expected:?} in:\n{error}"
            );
        }
    }

    /// The compiler runs on a thread it owns, so a broken internal invariant
    /// is a rejected candidate rather than a dead process. Before this, boot
    /// and `--test` ran the compiler on the caller's thread with nothing
    /// between a stage's `expect` and the node.
    #[test]
    fn an_internal_compiler_panic_is_a_diagnostic_rather_than_an_abort() {
        let source = format!("vcl 4.1;\n// {PANIC_PROBE}\nsub vcl_recv {{ return (hash); }}\n");
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let error = compile(&source, CompileOptions::default()).unwrap_err();
        std::panic::set_hook(hook);
        let rendered = error.to_string();
        assert!(rendered.contains("internal compiler error"), "{rendered}");
        assert!(rendered.contains("panic probe"), "{rendered}");
    }

    /// The host compiles `.carapace.regex` when the program loads and looks
    /// patterns up by the exact string the code passes. A `headerplus` name
    /// pattern is passed with the `(?i)` its vmod implies, so that spelling
    /// is the one the section has to carry.
    #[test]
    fn regex_section_carries_the_spelling_the_code_passes() {
        let source = r#"
            vcl 4.1;
            import headerplus;
            sub vcl_recv {
                headerplus.init_req();
                headerplus.delete_regex("^X-Drop-");
                headerplus.write();
                if (req.url ~ "^/api/") { return (pass); }
                return (hash);
            }
        "#;
        let compiled = compile(source, CompileOptions::default()).unwrap();
        let contains = |needle: &[u8]| compiled.elf.windows(needle.len()).any(|w| w == needle);
        assert!(contains(b"(?i)^X-Drop-\0"));
        assert!(contains(b"^/api/\0"));
        assert!(!contains(b"\0^X-Drop-\0"), "the unprefixed spelling is never passed");
    }
}
