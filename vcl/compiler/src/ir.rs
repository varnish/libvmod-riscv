//! Typed, virtual-register intermediate representation.
//!
//! The IR is independent of scripting ABI registers and RV64 encodings. All
//! constants are materialised into virtual values before use, so verification,
//! optimisation, interpretation, and allocation see the exact same program.
//!
//! Control flow is a linear operation list with unique labels. Every jump is
//! forward-only, and a terminator ends the emitted region until the next
//! label. Linear-scan allocation relies on this contract: introducing a
//! backward edge requires a different liveness model, not merely a new op.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::BinaryOp;
use crate::backend::BackendError;
use crate::typecheck::GlobalInit;
use crate::typecheck::{
    DigestFunction, TypedExpr, TypedExprKind, TypedProgram, TypedReturnAction, TypedStatement,
    VmodAction,
};
use crate::types::{
    AclId, GlobalId, LocalId, Phase, StatSpec, StaticId, StringConversion, ValueType,
};
use crate::vars::{HostVar, Lowering};
use crate::vmod::{Commit, Module, RegexSelect, Source};
use crate::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ValueId(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LabelId(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueClass {
    Scalar,
    String,
}

#[derive(Debug, Clone, Copy)]
struct SyscallSpec {
    number: u32,
    name: &'static str,
    typed_subcommand: Option<i64>,
    signature: Option<&'static [ValueClass]>,
    result: Option<ValueClass>,
}

macro_rules! define_syscalls {
    ($( $variant:ident => {
        number: $number:literal,
        name: $name:literal,
        command: $command:expr,
        args: $args:expr,
        result: $result:expr
    } ),+ $(,)?) => {
        /// Host calls reachable from lowered VCL. Each ABI fact has one row.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum Syscall { $( $variant ),+ }

        impl Syscall {
            fn spec(self) -> SyscallSpec {
                match self {
                    $( Self::$variant => SyscallSpec {
                        number: $number,
                        name: $name,
                        typed_subcommand: $command,
                        signature: $args,
                        result: $result,
                    } ),+
                }
            }

            pub(crate) fn number(self) -> u32 { self.spec().number }
            pub(crate) fn name(self) -> &'static str { self.spec().name }
            pub(crate) fn typed_subcommand(self) -> Option<i64> { self.spec().typed_subcommand }
            pub(crate) fn signature(self) -> Option<&'static [ValueClass]> { self.spec().signature }
            pub(crate) fn result(self) -> Option<ValueClass> { self.spec().result }
        }
    };
}

/// `TYPED_CACHE_DURATION` selectors. Must agree with the host's
/// `CACHE_DURATION_*` in `carapace-scripting/src/syscalls.rs`.
const CACHE_DURATION_TTL: i64 = 0;
const CACHE_DURATION_GRACE: i64 = 1;
const CACHE_DURATION_KEEP: i64 = 2;

/// The two `TYPED_CACHE_STATUS` answers `req.cache_hit` is true for. Must
/// agree with the host's `CacheStatus` in `carapace-scripting/src/syscalls.rs`,
/// with `CARAPACE_CACHE_*` in `carapace.h` and with `carapace_guest::cache`.
pub(crate) const CACHE_STATUS_HIT: i64 = 0;
pub(crate) const CACHE_STATUS_STALE: i64 = 2;

/// Nanoseconds in a second: every VCL `DURATION` is nanoseconds, and the
/// cache ABI is whole seconds, so one scale factor sits on each side of the
/// three cache-metadata calls.
const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// The syscall and selector one cache-metadata variable reads through.
fn cache_metadata_read(lowering: Lowering) -> (Syscall, i64) {
    match lowering {
        Lowering::Ttl => (Syscall::GetTtl, CACHE_DURATION_TTL),
        Lowering::StaleWhileRevalidate => (Syscall::GetStaleWhileRevalidate, CACHE_DURATION_GRACE),
        Lowering::StaleIfError => (Syscall::GetStaleIfError, CACHE_DURATION_KEEP),
        Lowering::RequestHeader
        | Lowering::ResponseHeader
        | Lowering::RequestUrl
        | Lowering::RequestMethod
        | Lowering::Now
        | Lowering::ClientIp
        | Lowering::Uncacheable
        | Lowering::CacheHit
        | Lowering::Body
        | Lowering::Host(_) => unreachable!("not a cache-metadata variable"),
    }
}

// libvmod-riscv places the policy ABI at 540..=560: carapace's 490..=510
// block shifted by 50, clear of the VMOD's own API at 500..=539 and of the
// native heap and memory helpers at 580.. (`NATIVE_SYSCALLS_BASE`). The
// host's `src/vcl/abi.hpp` mirrors these numbers.

define_syscalls! {
    RequestGetMethod => { number: 540, name: "req_get_method", command: None, args: Some(&[]), result: Some(ValueClass::String) },
    RequestGetUrl => { number: 541, name: "req_get_url", command: None, args: Some(&[]), result: Some(ValueClass::String) },
    RequestGetHeader => { number: 542, name: "req_get_header", command: None, args: Some(&[ValueClass::String]), result: Some(ValueClass::String) },
    RequestHasHeader => { number: 542, name: "req_has_header", command: None, args: Some(&[ValueClass::String]), result: Some(ValueClass::Scalar) },
    RequestSetHeader => { number: 543, name: "req_set_header", command: None, args: Some(&[ValueClass::String, ValueClass::String]), result: None },
    RequestSetUrl => { number: 544, name: "req_set_url", command: None, args: Some(&[ValueClass::String]), result: None },
    ResponseGetHeader => { number: 545, name: "resp_get_header", command: None, args: Some(&[ValueClass::String]), result: Some(ValueClass::String) },
    ResponseHasHeader => { number: 545, name: "resp_has_header", command: None, args: Some(&[ValueClass::String]), result: Some(ValueClass::Scalar) },
    ResponseSetHeader => { number: 546, name: "resp_set_header", command: None, args: Some(&[ValueClass::String, ValueClass::String]), result: None },
    RequestRemoveHeader => { number: 560, name: "req_remove_header", command: Some(19), args: Some(&[ValueClass::Scalar, ValueClass::String]), result: None },
    ResponseRemoveHeader => { number: 560, name: "resp_remove_header", command: Some(20), args: Some(&[ValueClass::Scalar, ValueClass::String]), result: None },
    // The three calls `headerplus` uses. None is new host surface: the
    // snapshot is the existing read-only sub-command 23, and the two commits
    // are the *generic* header commits a C or Rust guest already uses, so a
    // vmod write goes through the same phase gate, framing-header refusal,
    // `Host`/`variant_headers` protection and mutation ceiling as any other.
    HeadersSnapshot => { number: 560, name: "headers_snapshot", command: Some(23), args: Some(&[ValueClass::Scalar]), result: Some(ValueClass::String) },
    ClientIp => { number: 560, name: "client_ip", command: Some(26), args: None, result: None },
    RequestHeadersCommit => { number: 560, name: "req_headers_commit", command: Some(2), args: Some(&[ValueClass::Scalar, ValueClass::String]), result: None },
    ResponseHeadersCommit => { number: 560, name: "resp_headers_commit", command: Some(4), args: Some(&[ValueClass::Scalar, ValueClass::String]), result: None },
    Log => { number: 548, name: "log", command: None, args: Some(&[ValueClass::String]), result: None },
    ReturnAction => { number: 549, name: "return_action", command: None, args: None, result: None },
    SetTtl => { number: 551, name: "set_ttl", command: None, args: Some(&[ValueClass::Scalar]), result: None },
    RegexMatch => { number: 552, name: "regex_match", command: None, args: Some(&[ValueClass::String, ValueClass::String]), result: Some(ValueClass::Scalar) },
    DigestHashSha256 => { number: 560, name: "digest.hash_sha256", command: Some(8), args: Some(&[ValueClass::String]), result: Some(ValueClass::String) },
    DigestHmacSha256 => { number: 560, name: "digest.hmac_sha256", command: Some(9), args: Some(&[ValueClass::String, ValueClass::String]), result: Some(ValueClass::String) },
    DigestVerifyHmacSha256 => { number: 560, name: "digest.verify_hmac_sha256", command: Some(10), args: Some(&[ValueClass::String, ValueClass::String, ValueClass::String]), result: Some(ValueClass::Scalar) },
    SetStaleWhileRevalidate => { number: 560, name: "set_stale_while_revalidate", command: Some(17), args: Some(&[ValueClass::Scalar, ValueClass::Scalar]), result: None },
    SetStaleIfError => { number: 560, name: "set_stale_if_error", command: Some(18), args: Some(&[ValueClass::Scalar, ValueClass::Scalar]), result: None },
    // The read side of the three setters above: one sub-command, one
    // selector, three names. The host answers with the number that would
    // apply if this hook said nothing, or with what the hook has already set.
    GetTtl => { number: 560, name: "get_ttl", command: Some(27), args: Some(&[ValueClass::Scalar, ValueClass::Scalar]), result: Some(ValueClass::Scalar) },
    GetStaleWhileRevalidate => { number: 560, name: "get_stale_while_revalidate", command: Some(27), args: Some(&[ValueClass::Scalar, ValueClass::Scalar]), result: Some(ValueClass::Scalar) },
    GetStaleIfError => { number: 560, name: "get_stale_if_error", command: Some(27), args: Some(&[ValueClass::Scalar, ValueClass::Scalar]), result: Some(ValueClass::Scalar) },
    // The generic variable calls: a `HostVar` number selects the variable,
    // and the host gates it by the Varnish subroutine that is running.
    VarGetString => { number: 560, name: "var_get_string", command: Some(32), args: Some(&[ValueClass::Scalar, ValueClass::Scalar]), result: Some(ValueClass::String) },
    VarGetScalar => { number: 560, name: "var_get_scalar", command: Some(33), args: Some(&[ValueClass::Scalar, ValueClass::Scalar]), result: Some(ValueClass::Scalar) },
    VarSetScalar => { number: 560, name: "var_set_scalar", command: Some(34), args: Some(&[ValueClass::Scalar, ValueClass::Scalar, ValueClass::Scalar]), result: None },
    VarSetString => { number: 560, name: "var_set_string", command: Some(35), args: Some(&[ValueClass::Scalar, ValueClass::Scalar, ValueClass::String]), result: None },
    HashData => { number: 560, name: "hash_data", command: Some(36), args: Some(&[ValueClass::Scalar, ValueClass::String]), result: None },
    // `synthetic()` (selector 0, append) and `set resp.body` /
    // `set beresp.body` (selector 1, replace).
    SynthBody => { number: 560, name: "synth_body", command: Some(37), args: Some(&[ValueClass::Scalar, ValueClass::Scalar, ValueClass::String]), result: None },
    RegexMatchList => { number: 560, name: "regex_match_list", command: Some(24), args: None, result: None },
    Regsub => { number: 560, name: "regsub", command: Some(22), args: Some(&[ValueClass::Scalar, ValueClass::String, ValueClass::String, ValueClass::String, ValueClass::Scalar]), result: Some(ValueClass::String) },
    // How the delivered response came to be: a `CacheStatus` number, which
    // `req.cache_hit` compares against `hit` and `stale`.
    CacheStatus => { number: 560, name: "cache_status", command: Some(31), args: Some(&[ValueClass::Scalar]), result: Some(ValueClass::Scalar) },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompareKind {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalarBinaryKind {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Max,
    Min,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StringCaseKind {
    Lower,
    Upper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StringPredicateKind {
    Prefix,
    Suffix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionCode {
    Next,
    Pass,
    Deliver,
    Synth,
    Abandon,
    Hash,
    Lookup,
    Fetch,
    Miss,
    Error,
    Fail,
}

impl ActionCode {
    /// The host's `ACTION_*` numbers in `src/vcl/abi.hpp`.
    pub(crate) fn abi_value(self) -> i64 {
        match self {
            Self::Next => 0,
            Self::Pass => 1,
            Self::Deliver => 2,
            Self::Synth => 3,
            Self::Abandon => 4,
            Self::Hash => 5,
            Self::Lookup => 6,
            Self::Fetch => 7,
            Self::Miss => 8,
            Self::Error => 9,
            Self::Fail => 10,
        }
    }

    fn signature(self) -> &'static [ValueClass] {
        match self {
            Self::Next
            | Self::Pass
            | Self::Deliver
            | Self::Abandon
            | Self::Hash
            | Self::Lookup
            | Self::Fetch
            | Self::Miss
            | Self::Fail => &[],
            Self::Synth | Self::Error => &[ValueClass::Scalar, ValueClass::String],
        }
    }
}

macro_rules! define_op_metadata {
    ($( $variant:ident { $($fields:tt)* } span($span:ident) => {
        pure: $pure:literal,
        terminator: $terminator:literal,
        definition: $definition:expr,
        uses: $uses:expr,
        remap: [$($remap:ident),*],
        remap_vectors: [$($remap_vector:ident),*]
    } ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum Opcode { $( $variant ),+ }

        impl Opcode {
            pub(crate) fn is_pure(self) -> bool {
                match self { $( Self::$variant => $pure ),+ }
            }

            pub(crate) fn is_terminator(self) -> bool {
                match self { $( Self::$variant => $terminator ),+ }
            }

            pub(crate) fn name(self) -> &'static str {
                match self { $( Self::$variant => stringify!($variant) ),+ }
            }
        }

        impl Op {
            #[allow(unused_variables)]
            pub(crate) fn opcode(&self) -> Opcode {
                match self { $( Self::$variant { $($fields)* } => Opcode::$variant ),+ }
            }

            #[allow(unused_variables)]
            pub(crate) fn definition(&self) -> Option<(ValueId, ValueClass)> {
                match self { $( Self::$variant { $($fields)* } => $definition ),+ }
            }

            #[allow(unused_variables)]
            pub(crate) fn uses(&self) -> Vec<ValueId> {
                match self { $( Self::$variant { $($fields)* } => $uses ),+ }
            }

            #[allow(unused_variables)]
            pub(crate) fn span(&self) -> Span {
                match self { $( Self::$variant { $($fields)* } => *$span ),+ }
            }

            /// Rewrite every virtual value named by this instruction.
            ///
            /// Operand rewriting comes from the same row as definitions and
            /// uses, so a newly-added opcode cannot silently evade a value
            /// renumbering pass.
            #[allow(unused_variables)]
            pub(crate) fn remap_values(
                &mut self,
                remap: &BTreeMap<ValueId, ValueId>,
            ) -> Result<(), String> {
                let mapped = |value: &ValueId| {
                    remap
                        .get(value)
                        .copied()
                        .ok_or_else(|| format!("value remap has no entry for v{}", value.0))
                };
                match self {
                    $( Self::$variant { $($fields)* } => {
                        $( *$remap = mapped($remap)?; )*
                        $( for value in $remap_vector {
                            *value = mapped(value)?;
                        } )*
                    } ),+
                }
                Ok(())
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Op {
    ConstInt {
        dst: ValueId,
        value: i64,
        span: Span,
    },
    ConstString {
        dst: ValueId,
        value: String,
        span: Span,
    },
    LoadLocal {
        dst: ValueId,
        slot: LocalId,
        class: ValueClass,
        span: Span,
    },
    StoreLocal {
        slot: LocalId,
        value: ValueId,
        span: Span,
    },
    LoadStatic {
        dst: ValueId,
        static_id: StaticId,
        class: ValueClass,
        span: Span,
    },
    StoreStatic {
        static_id: StaticId,
        value: ValueId,
        span: Span,
    },
    /// Read a request global. A `STRING` global is copied out of its
    /// inline buffer into the arena, so the value is immutable like every
    /// other string: a later store to the same global cannot change a value
    /// already read from it.
    LoadGlobal {
        dst: ValueId,
        global: GlobalId,
        class: ValueClass,
        span: Span,
    },
    /// Write a request global. Never dead: a global written and not read
    /// again in this hook is read by the next phase, which is the point of
    /// it. A `STRING` store copies into the inline buffer, and traps when
    /// the value does not fit.
    StoreGlobal {
        global: GlobalId,
        value: ValueId,
        span: Span,
    },
    ReadString {
        dst: ValueId,
        syscall: Syscall,
        args: Vec<ValueId>,
        span: Span,
    },
    ReadScalar {
        dst: ValueId,
        syscall: Syscall,
        args: Vec<ValueId>,
        span: Span,
    },
    StringConcat {
        dst: ValueId,
        left: ValueId,
        right: ValueId,
        span: Span,
    },
    StringConvert {
        dst: ValueId,
        value: ValueId,
        conversion: StringConversion,
        span: Span,
    },
    StringCase {
        dst: ValueId,
        value: ValueId,
        kind: StringCaseKind,
        span: Span,
    },
    StringFind {
        dst: ValueId,
        haystack: ValueId,
        needle: ValueId,
        span: Span,
    },
    StringPredicate {
        dst: ValueId,
        value: ValueId,
        affix: ValueId,
        kind: StringPredicateKind,
        span: Span,
    },
    ParseScalar {
        dst: ValueId,
        value: ValueId,
        fallback: ValueId,
        duration: bool,
        time: bool,
        span: Span,
    },
    Fnmatch {
        dst: ValueId,
        pattern: ValueId,
        subject: ValueId,
        pathname: ValueId,
        noescape: ValueId,
        period: ValueId,
        span: Span,
    },
    Querysort {
        dst: ValueId,
        value: ValueId,
        span: Span,
    },
    /// The integer-valued half of `str`: `len`, the two affix tests,
    /// `contains` and `token_intersect`.  One op rather than five because
    /// the runtime already dispatches on the operation word, and every one
    /// of them is two strings and a separator set.
    StrTest {
        dst: ValueId,
        op: vcl_rt::StrTest,
        subject: ValueId,
        other: ValueId,
        separators: ValueId,
        span: Span,
    },
    /// `str.substr` and `str.reverse`.
    StrEdit {
        dst: ValueId,
        op: vcl_rt::StrEdit,
        subject: ValueId,
        count: ValueId,
        offset: ValueId,
        span: Span,
    },
    /// `str.split`, whose second operand is a separator *set* rather than
    /// the position `StrEdit` takes, so it is its own op and its own
    /// runtime routine.
    StrSplit {
        dst: ValueId,
        subject: ValueId,
        index: ValueId,
        separators: ValueId,
        span: Span,
    },
    /// Seed a module's per-hook state from its source string.
    ///
    /// The three list-shaped vmods differ only in where that string comes
    /// from and which routine parses it, so they share one op; see
    /// [`crate::vmod`] for why the alternative -- one op triple per module --
    /// did not survive its third copy.
    ModuleInit {
        dst: ValueId,
        module: Module,
        /// headerplus only: the map `init(scope)` named.
        response: bool,
        /// `cookieplus.setcookie_parse(header)`: the header name the state is
        /// seeded from, in place of the module's own source.
        source: Option<String>,
        span: Span,
    },
    /// A module read producing a string, falling back to `default` when the
    /// routine reports the value absent.
    ModuleRead {
        dst: ValueId,
        module: Module,
        code: i64,
        state: ValueId,
        /// The routine's single string argument, or nothing.  Several VCL
        /// arguments are joined with a NUL before they reach here, because
        /// the runtime ABI has one argument register pair.
        arguments: Vec<ValueId>,
        default: ValueId,
        span: Span,
    },
    /// A module read producing an integer.
    ModuleCount {
        dst: ValueId,
        module: Module,
        code: i64,
        state: ValueId,
        arguments: Vec<ValueId>,
        span: Span,
    },
    /// A module state mutation: a state in, a state out.
    ModuleTransform {
        dst: ValueId,
        module: Module,
        code: i64,
        state: ValueId,
        arguments: Vec<ValueId>,
        span: Span,
    },
    /// The match step of a `_regex` vmod form: project the module's records
    /// and apply one or two host patterns to them.
    ///
    /// The result is the bitmap block the module's own read, count or
    /// transform routine then takes as its argument, one fixed-stride bitmap
    /// per pattern. One op rather than a projection op and a match op because
    /// the packed record list between them has no other consumer and no name
    /// in VCL: keeping it inside the emitter costs a scratch slot instead of
    /// a value, and keeps the interpreter to one arm.
    RegexMatchList {
        dst: ValueId,
        module: Module,
        /// The record-projection read, from `Module::select_code`.
        select: i64,
        state: ValueId,
        /// One or two pattern literals, in bitmap-slot order.
        patterns: Vec<ValueId>,
        /// Bit `i`: pattern `i` matches the record value rather than its name.
        value_fields: u8,
        span: Span,
    },
    /// `std.collect(hdr, sep)`: snapshot one header name, join its values and
    /// store the result back as the name's only header.
    ///
    /// One op rather than a snapshot, a join and a set, because the store has
    /// to be skipped entirely when the name has no header -- collecting an
    /// absent header must not create one -- and the IR has no way to spell
    /// "the routine reported nothing" as a value.
    Collect {
        name: ValueId,
        separator: ValueId,
        response: bool,
        span: Span,
    },
    /// `headerplus.write()`: build the guest header vector from the state and
    /// hand it to the host's generic header commit.
    HeaderCommit {
        state: ValueId,
        response: bool,
        span: Span,
    },
    /// `now`, read once from the guest kernel ABI and retained for this hook.
    ReadNow {
        dst: ValueId,
        span: Span,
    },
    /// `client.ip`, read once per hook into its `.bss` slot. The value is the
    /// 16 normalised address bytes.
    ReadClientIp {
        dst: ValueId,
        span: Span,
    },
    /// `client.ip ~ <acl>`: one masked compare per table entry, in the
    /// runtime blob.
    AclMatch {
        dst: ValueId,
        address: ValueId,
        acl: AclId,
        span: Span,
    },
    Not {
        dst: ValueId,
        value: ValueId,
        span: Span,
    },
    ScalarBinary {
        dst: ValueId,
        kind: ScalarBinaryKind,
        left: ValueId,
        right: ValueId,
        span: Span,
    },
    Compare {
        dst: ValueId,
        kind: CompareKind,
        left: ValueId,
        right: ValueId,
        span: Span,
    },
    /// Materialise a short-circuit boolean's result, seeded with the value the
    /// expression has when the branches fall straight through.
    BoolSlot {
        dst: ValueId,
        value: bool,
        span: Span,
    },
    /// Overwrite a [`Op::BoolSlot`] on the path that decides the other way.
    ///
    /// The only instruction that writes a value it does not define. `&&` and
    /// `||` must not evaluate their right operand when the left already
    /// settles the answer, and the answer has to survive the join — which
    /// needs one storage location written from two paths.
    BoolStore {
        target: ValueId,
        value: bool,
        span: Span,
    },
    Host {
        syscall: Syscall,
        args: Vec<ValueId>,
        span: Span,
    },
    Label {
        label: LabelId,
        span: Span,
    },
    Jump {
        target: LabelId,
        span: Span,
    },
    BranchZero {
        value: ValueId,
        target: LabelId,
        span: Span,
    },
    ReturnAction {
        action: ActionCode,
        args: Vec<ValueId>,
        span: Span,
    },
}

// Operand shape and shared effects have one owner. Adding an `Op` without a
// row here fails every generated query at compile time.
define_op_metadata! {
    ConstInt { dst, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    ConstString { dst, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::String)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    LoadLocal { dst, class, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, *class)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    StoreLocal { value, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: vec![*value], remap: [value], remap_vectors: [] },
    LoadStatic { dst, class, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, *class)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    StoreStatic { value, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: vec![*value], remap: [value], remap_vectors: [] },
    LoadGlobal { dst, class, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, *class)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    StoreGlobal { value, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: vec![*value], remap: [value], remap_vectors: [] },
    ReadString { dst, args, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: args.clone(), remap: [dst], remap_vectors: [args] },
    ReadScalar { dst, args, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: args.clone(), remap: [dst], remap_vectors: [args] },
    StringConcat { dst, left, right, span } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: vec![*left, *right], remap: [dst, left, right], remap_vectors: [] },
    StringConvert { dst, value, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: vec![*value], remap: [dst, value], remap_vectors: [] },
    StringCase { dst, value, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: vec![*value], remap: [dst, value], remap_vectors: [] },
    StringFind { dst, haystack, needle, span } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::String)), uses: vec![*haystack, *needle], remap: [dst, haystack, needle], remap_vectors: [] },
    StringPredicate { dst, value, affix, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*value, *affix], remap: [dst, value, affix], remap_vectors: [] },
    ParseScalar { dst, value, fallback, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*value, *fallback], remap: [dst, value, fallback], remap_vectors: [] },
    Fnmatch { dst, pattern, subject, pathname, noescape, period, span } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*pattern, *subject, *pathname, *noescape, *period], remap: [dst, pattern, subject, pathname, noescape, period], remap_vectors: [] },
    Querysort { dst, value, span } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: vec![*value], remap: [dst, value], remap_vectors: [] },
    StrTest { dst, subject, other, separators, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*subject, *other, *separators], remap: [dst, subject, other, separators], remap_vectors: [] },
    StrEdit { dst, subject, count, offset, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: vec![*subject, *count, *offset], remap: [dst, subject, count, offset], remap_vectors: [] },
    StrSplit { dst, subject, index, separators, span } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: vec![*subject, *index, *separators], remap: [dst, subject, index, separators], remap_vectors: [] },
    ModuleInit { dst, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    ModuleRead { dst, state, arguments, default, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: { let mut values = vec![*state]; values.extend(arguments.iter().copied()); values.push(*default); values }, remap: [dst, state, default], remap_vectors: [arguments] },
    ModuleCount { dst, state, arguments, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: { let mut values = vec![*state]; values.extend(arguments.iter().copied()); values }, remap: [dst, state], remap_vectors: [arguments] },
    ModuleTransform { dst, state, arguments, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: { let mut values = vec![*state]; values.extend(arguments.iter().copied()); values }, remap: [dst, state], remap_vectors: [arguments] },
    RegexMatchList { dst, state, patterns, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: { let mut values = vec![*state]; values.extend(patterns.iter().copied()); values }, remap: [dst, state], remap_vectors: [patterns] },
    Collect { name, separator, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: vec![*name, *separator], remap: [name, separator], remap_vectors: [] },
    HeaderCommit { state, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: vec![*state], remap: [state], remap_vectors: [] },
    ReadNow { dst, span } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    ReadClientIp { dst, span } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::String)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    AclMatch { dst, address, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*address], remap: [dst, address], remap_vectors: [] },
    Not { dst, value, span } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*value], remap: [dst, value], remap_vectors: [] },
    ScalarBinary { dst, left, right, span, .. } span(span) => { pure: false, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*left, *right], remap: [dst, left, right], remap_vectors: [] },
    Compare { dst, left, right, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: vec![*left, *right], remap: [dst, left, right], remap_vectors: [] },
    BoolSlot { dst, span, .. } span(span) => { pure: true, terminator: false, definition: Some((*dst, ValueClass::Scalar)), uses: Vec::new(), remap: [dst], remap_vectors: [] },
    BoolStore { target, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: vec![*target], remap: [target], remap_vectors: [] },
    Host { args, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: args.clone(), remap: [], remap_vectors: [args] },
    Label { span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: Vec::new(), remap: [], remap_vectors: [] },
    Jump { span, .. } span(span) => { pure: false, terminator: true, definition: None, uses: Vec::new(), remap: [], remap_vectors: [] },
    BranchZero { value, span, .. } span(span) => { pure: false, terminator: false, definition: None, uses: vec![*value], remap: [value], remap_vectors: [] },
    ReturnAction { args, span, .. } span(span) => { pure: false, terminator: true, definition: None, uses: args.clone(), remap: [], remap_vectors: [args] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Function {
    pub phase: Phase,
    pub ops: Vec<Op>,
    pub value_count: u32,
    pub locals: Vec<ValueClass>,
}

impl Function {
    pub(crate) fn hook(&self) -> &'static str {
        self.phase.hook()
    }

    /// Restore dense, definition-ordered virtual ids after an IR pass removes
    /// or aliases values.
    pub(crate) fn renumber_values(&mut self) -> Result<(), String> {
        let mut remap = BTreeMap::new();
        let mut next = 0u32;
        for op in &self.ops {
            if let Some((value, _)) = op.definition() {
                if remap.insert(value, ValueId(next)).is_some() {
                    return Err(format!(
                        "{} defines v{} more than once",
                        self.hook(),
                        value.0
                    ));
                }
                next = next
                    .checked_add(1)
                    .ok_or_else(|| "VCL function has too many values".to_string())?;
            }
        }
        for op in &mut self.ops {
            op.remap_values(&remap)?;
        }
        self.value_count = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Program {
    pub functions: Vec<Function>,
    pub statics: Vec<StaticDef>,
    pub globals: Vec<GlobalDef>,
    /// Packed ACL entry tables, indexed by [`AclId`]. Emitted into rodata.
    pub acls: Vec<Vec<u8>>,
    /// Regular-expression literals, deduplicated and in first-use order.
    /// Carried through untouched: they are metadata for the engine, not
    /// something any pass reads or rewrites.
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticDef {
    pub name: String,
    pub class: ValueClass,
    pub value_type: ValueType,
    pub initial: i64,
    /// Carried through untouched, like [`Program::patterns`]: metadata for
    /// the host, not something any pass reads or rewrites.
    pub stat: Option<StatSpec>,
}

/// One request global: a slot in the region the host copies in and out at
/// every phase boundary. See [`crate::types::global_slot_size`] for its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalDef {
    pub name: String,
    pub class: ValueClass,
    pub value_type: ValueType,
    pub initial: GlobalInit,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineTable {
    pub entries: Vec<LineEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineEntry {
    pub address: u64,
    pub line: u32,
    /// Which file the line is in: 0 is the compiled unit's own source, and N
    /// the Nth included library, numbering `Compiled::files` from 1.
    pub file: u32,
}

struct Builder {
    ops: Vec<Op>,
    next_value: u32,
    next_label: u32,
    leave_labels: Vec<LabelId>,
    /// The local holding each module's per-hook state, for the modules this
    /// hook uses.  One map rather than a field per module: adding a module
    /// must not mean threading another `LocalId` through the builder.
    states: BTreeMap<Module, LocalId>,
}

impl Builder {
    fn new(states: BTreeMap<Module, LocalId>) -> Self {
        Self {
            ops: Vec::new(),
            next_value: 0,
            next_label: 0,
            leave_labels: Vec::new(),
            states,
        }
    }

    fn value(&mut self) -> ValueId {
        let value = ValueId(self.next_value);
        self.next_value += 1;
        value
    }

    fn integer(&mut self, value: i64, span: Span) -> ValueId {
        let dst = self.value();
        self.ops.push(Op::ConstInt { dst, value, span });
        dst
    }

    fn string(&mut self, value: String, span: Span) -> ValueId {
        let dst = self.value();
        self.ops.push(Op::ConstString { dst, value, span });
        dst
    }

    /// The local holding a module's per-hook state.
    ///
    /// `modules_used` decides which modules get one, and it runs over the
    /// same statements this does, so a missing entry is a compiler bug rather
    /// than a program error.
    fn state_slot(&self, module: Module) -> LocalId {
        *self
            .states
            .get(&module)
            .expect("a module reached lowering without a state local")
    }

    fn load_state(&mut self, module: Module, span: Span) -> ValueId {
        let dst = self.value();
        let slot = self.state_slot(module);
        self.ops.push(Op::LoadLocal {
            dst,
            slot,
            class: ValueClass::String,
            span,
        });
        dst
    }

    fn store_state(&mut self, module: Module, value: ValueId, span: Span) {
        let slot = self.state_slot(module);
        self.ops.push(Op::StoreLocal { slot, value, span });
    }

    /// Seed a module's state, at hook entry and at every `init()`/`reset()`.
    fn seed_state(&mut self, module: Module, response: bool, source: Option<String>, span: Span) {
        // A module whose source names its own map ignores the phase's, which
        // is what keeps the Set-Cookie state on the response in the synth
        // body `on_recv` carries.
        let response = module
            .source()
            .and_then(Source::response_map)
            .unwrap_or(response);
        let dst = self.value();
        match module.source() {
            Some(_) => self.ops.push(Op::ModuleInit {
                dst,
                module,
                response,
                source,
                span,
            }),
            // `uri` has no single source string to read: the vmod builds one
            // out of `req.http.Host` and the URL, so the seed is those two
            // reads, joined, handed to the same parse the explicit
            // `uri.parse()` runs.
            None => {
                let input = self.string(String::new(), span);
                let implicit = self.implicit_uri(span);
                self.ops.push(Op::ModuleTransform {
                    dst,
                    module,
                    code: vcl_rt::OpCode::new(module.parse_op()).encode(),
                    state: input,
                    arguments: vec![implicit],
                    span,
                });
            }
        }
        self.store_state(module, dst, span);
    }

    /// The request's own `Host` and URL as one `host \0 url` argument.
    ///
    /// It is an argument rather than the routine's input because the input
    /// operand carries the URI `uri.parse()` was handed, and the fallback
    /// only applies when that is empty. The join is the one
    /// [`Builder::join_arguments`] already performs for a two-string call,
    /// so the runtime undoes it with the same `name_and_value`.
    fn implicit_uri(&mut self, span: Span) -> ValueId {
        let name = self.string("Host".to_string(), span);
        let host = self.value();
        self.ops.push(Op::ReadString {
            dst: host,
            syscall: Syscall::RequestGetHeader,
            args: vec![name],
            span,
        });
        let separator = self.string("\0".to_string(), span);
        let prefixed = self.value();
        self.ops.push(Op::StringConcat {
            dst: prefixed,
            left: host,
            right: separator,
            span,
        });
        let url = self.value();
        self.ops.push(Op::ReadString {
            dst: url,
            syscall: Syscall::RequestGetUrl,
            args: Vec::new(),
            span,
        });
        let joined = self.value();
        self.ops.push(Op::StringConcat {
            dst: joined,
            left: prefixed,
            right: url,
            span,
        });
        joined
    }

    /// Lower a `_regex` form's project/match step and hand back the bitmap
    /// block, which is the call's one runtime argument.
    fn regex_argument(
        &mut self,
        module: Module,
        state: ValueId,
        regex: &RegexSelect,
        span: Span,
    ) -> Vec<ValueId> {
        let patterns = regex
            .patterns
            .iter()
            .map(|pattern| self.string(pattern.clone(), span))
            .collect();
        let dst = self.value();
        self.ops.push(Op::RegexMatchList {
            dst,
            module,
            select: regex.select,
            state,
            patterns,
            value_fields: regex.value_fields,
            span,
        });
        vec![dst]
    }

    /// Join a call's runtime arguments into the one the routine ABI carries.
    ///
    /// A NUL is the separator the runtime's `name_and_value` splits back
    /// apart.  It cannot collide with a value byte: a VCL string is UTF-8 and
    /// the host refuses a control character in a header value.
    fn join_arguments(&mut self, arguments: &[TypedExpr], span: Span) -> Vec<ValueId> {
        let values: Vec<ValueId> = arguments
            .iter()
            .map(|argument| self.expr(argument))
            .collect();
        let mut joined = match values.first() {
            Some(first) => *first,
            None => return Vec::new(),
        };
        for value in &values[1..] {
            let separator = self.string("\0".to_string(), span);
            let left = self.value();
            self.ops.push(Op::StringConcat {
                dst: left,
                left: joined,
                right: separator,
                span,
            });
            let pair = self.value();
            self.ops.push(Op::StringConcat {
                dst: pair,
                left,
                right: *value,
                span,
            });
            joined = pair;
        }
        vec![joined]
    }

    /// Multiply by (or divide by) a second's worth of nanoseconds.
    ///
    /// Division truncates toward zero, exactly as the emitted RV64 `div`
    /// does — a sub-second remainder is dropped rather than rounded, which
    /// is why every duration *literal* in a cache assignment must already be
    /// a whole number of seconds.
    fn scale(&mut self, value: ValueId, kind: ScalarBinaryKind, span: Span) -> ValueId {
        let factor = self.integer(NANOS_PER_SECOND, span);
        let dst = self.value();
        self.ops.push(Op::ScalarBinary {
            dst,
            kind,
            left: value,
            right: factor,
            span,
        });
        dst
    }

    fn host(&mut self, syscall: Syscall, args: Vec<ValueId>, span: Span) {
        self.ops.push(Op::Host {
            syscall,
            args,
            span,
        });
    }

    fn label_id(&mut self) -> LabelId {
        let label = LabelId(self.next_label);
        self.next_label += 1;
        label
    }

    fn label(&mut self, label: LabelId, span: Span) {
        self.ops.push(Op::Label { label, span });
    }

    fn expr(&mut self, expression: &TypedExpr) -> ValueId {
        match &expression.kind {
            TypedExprKind::Extreme { max, left, right } => {
                let left = self.expr(left);
                let right = self.expr(right);
                let dst = self.value();
                self.ops.push(Op::ScalarBinary {
                    dst,
                    kind: if *max {
                        ScalarBinaryKind::Max
                    } else {
                        ScalarBinaryKind::Min
                    },
                    left,
                    right,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::String(value) => self.string(value.clone(), expression.span),
            TypedExprKind::Integer(value) => self.integer(*value, expression.span),
            TypedExprKind::Duration(value) => self.integer(*value as i64, expression.span),
            TypedExprKind::Boolean(value) => self.integer(i64::from(*value), expression.span),
            TypedExprKind::Local(slot) => {
                let dst = self.value();
                self.ops.push(Op::LoadLocal {
                    dst,
                    slot: *slot,
                    class: value_class(expression.value_type),
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::AclMatch {
                address,
                acl,
                negated,
            } => {
                let address = self.expr(address);
                let dst = self.value();
                self.ops.push(Op::AclMatch {
                    dst,
                    address,
                    acl: *acl,
                    span: expression.span,
                });
                if !*negated {
                    return dst;
                }
                let inverted = self.value();
                self.ops.push(Op::Not {
                    dst: inverted,
                    value: dst,
                    span: expression.span,
                });
                inverted
            }
            TypedExprKind::Global(global) => {
                let dst = self.value();
                self.ops.push(Op::LoadGlobal {
                    dst,
                    global: *global,
                    class: value_class(expression.value_type),
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Static(static_id) => {
                let dst = self.value();
                self.ops.push(Op::LoadStatic {
                    dst,
                    static_id: *static_id,
                    class: value_class(expression.value_type),
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Read { lowering, name } => {
                let (syscall, args) = match lowering {
                    Lowering::RequestHeader => (
                        Syscall::RequestGetHeader,
                        vec![self.string(
                            name.clone().expect("header read has a name"),
                            expression.span,
                        )],
                    ),
                    Lowering::ResponseHeader => (
                        Syscall::ResponseGetHeader,
                        vec![self.string(
                            name.clone().expect("header read has a name"),
                            expression.span,
                        )],
                    ),
                    Lowering::RequestUrl => (Syscall::RequestGetUrl, Vec::new()),
                    Lowering::RequestMethod => (Syscall::RequestGetMethod, Vec::new()),
                    Lowering::Host(var) => {
                        let syscall = if expression.value_type == ValueType::String {
                            Syscall::VarGetString
                        } else {
                            Syscall::VarGetScalar
                        };
                        let command = self.integer(
                            syscall.typed_subcommand().expect("variable read uses typed ABI"),
                            expression.span,
                        );
                        let id = self.integer(var.abi_id(), expression.span);
                        (syscall, vec![command, id])
                    }
                    Lowering::Body => unreachable!("a synthetic body is write-only"),
                    Lowering::Now => {
                        let dst = self.value();
                        self.ops.push(Op::ReadNow {
                            dst,
                            span: expression.span,
                        });
                        return dst;
                    }
                    Lowering::ClientIp => {
                        let dst = self.value();
                        self.ops.push(Op::ReadClientIp {
                            dst,
                            span: expression.span,
                        });
                        return dst;
                    }
                    Lowering::Ttl | Lowering::StaleWhileRevalidate | Lowering::StaleIfError => {
                        // The host counts in seconds and VCL counts in
                        // nanoseconds, so the read scales up on the way out.
                        // The host holds the answer to the ABI's own TTL
                        // ceiling, so the product cannot overflow.
                        let (syscall, selector) = cache_metadata_read(*lowering);
                        let command = self.integer(
                            syscall
                                .typed_subcommand()
                                .expect("cache-metadata read uses the typed ABI"),
                            expression.span,
                        );
                        let selector = self.integer(selector, expression.span);
                        let seconds = self.value();
                        self.ops.push(Op::ReadScalar {
                            dst: seconds,
                            syscall,
                            args: vec![command, selector],
                            span: expression.span,
                        });
                        return self.scale(seconds, ScalarBinaryKind::Multiply, expression.span);
                    }
                    Lowering::CacheHit => {
                        // `status == hit || status == stale`, without a
                        // branch: both compares are 0 or 1, so their max is
                        // their disjunction. A refused read is -1, neither.
                        let span = expression.span;
                        let command = self.integer(
                            Syscall::CacheStatus
                                .typed_subcommand()
                                .expect("cache status uses the typed ABI"),
                            span,
                        );
                        let status = self.value();
                        self.ops.push(Op::ReadScalar {
                            dst: status,
                            syscall: Syscall::CacheStatus,
                            args: vec![command],
                            span,
                        });
                        let [hit, stale] = [CACHE_STATUS_HIT, CACHE_STATUS_STALE].map(|value| {
                            let value = self.integer(value, span);
                            let dst = self.value();
                            self.ops.push(Op::Compare {
                                dst,
                                kind: CompareKind::Equal,
                                left: status,
                                right: value,
                                span,
                            });
                            dst
                        });
                        let dst = self.value();
                        self.ops.push(Op::ScalarBinary {
                            dst,
                            kind: ScalarBinaryKind::Max,
                            left: hit,
                            right: stale,
                            span,
                        });
                        return dst;
                    }
                    Lowering::Uncacheable => {
                        let command = self.integer(
                            Syscall::VarGetScalar
                                .typed_subcommand()
                                .expect("variable read uses typed ABI"),
                            expression.span,
                        );
                        let id = self.integer(HostVar::BerespUncacheable.abi_id(), expression.span);
                        (Syscall::VarGetScalar, vec![command, id])
                    }
                };
                let dst = self.value();
                if syscall.result() == Some(ValueClass::String) {
                    self.ops.push(Op::ReadString {
                        dst,
                        syscall,
                        args,
                        span: expression.span,
                    });
                } else {
                    self.ops.push(Op::ReadScalar {
                        dst,
                        syscall,
                        args,
                        span: expression.span,
                    });
                }
                dst
            }
            TypedExprKind::HeaderPresent { response, name } => {
                let name = self.string(name.clone(), expression.span);
                let dst = self.value();
                self.ops.push(Op::ReadScalar {
                    dst,
                    syscall: if *response {
                        Syscall::ResponseHasHeader
                    } else {
                        Syscall::RequestHasHeader
                    },
                    args: vec![name],
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Digest {
                function,
                arguments,
            } => {
                let args = arguments
                    .iter()
                    .map(|argument| self.expr(argument))
                    .collect();
                let syscall = match function {
                    DigestFunction::HashSha256 => Syscall::DigestHashSha256,
                    DigestFunction::HmacSha256 => Syscall::DigestHmacSha256,
                    DigestFunction::VerifyHmacSha256 => Syscall::DigestVerifyHmacSha256,
                };
                let dst = self.value();
                if syscall.result() == Some(ValueClass::String) {
                    self.ops.push(Op::ReadString {
                        dst,
                        syscall,
                        args,
                        span: expression.span,
                    });
                } else {
                    self.ops.push(Op::ReadScalar {
                        dst,
                        syscall,
                        args,
                        span: expression.span,
                    });
                }
                dst
            }
            TypedExprKind::Regsub {
                subject,
                pattern,
                replacement,
                all,
            } => {
                let syscall = Syscall::Regsub;
                let command = self.integer(
                    syscall.typed_subcommand().expect("regsub uses typed ABI"),
                    expression.span,
                );
                let pattern = self.expr(pattern);
                let subject = self.expr(subject);
                let replacement = self.expr(replacement);
                let all = self.integer(i64::from(*all), expression.span);
                let dst = self.value();
                self.ops.push(Op::ReadString {
                    dst,
                    syscall,
                    args: vec![command, pattern, subject, replacement, all],
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Concat(parts) => {
                // Folded left to right, which is how `+` associates and
                // therefore what the checker's operand order already means.
                let mut joined = None;
                for part in parts {
                    let value = self.expr(part);
                    joined = Some(match joined {
                        None => value,
                        Some(left) => {
                            let dst = self.value();
                            self.ops.push(Op::StringConcat {
                                dst,
                                left,
                                right: value,
                                span: expression.span,
                            });
                            dst
                        }
                    });
                }
                joined.unwrap_or_else(|| self.string(String::new(), expression.span))
            }
            TypedExprKind::ToString { value, conversion } => {
                let value = self.expr(value);
                let dst = self.value();
                self.ops.push(Op::StringConvert {
                    dst,
                    value,
                    conversion: *conversion,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::StringCase { value, upper } => {
                let value = self.expr(value);
                let dst = self.value();
                self.ops.push(Op::StringCase {
                    dst,
                    value,
                    kind: if *upper {
                        StringCaseKind::Upper
                    } else {
                        StringCaseKind::Lower
                    },
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Strstr { haystack, needle } => {
                let haystack = self.expr(haystack);
                let needle = self.expr(needle);
                let dst = self.value();
                self.ops.push(Op::StringFind {
                    dst,
                    haystack,
                    needle,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::StringPredicate {
                value,
                affix,
                prefix,
            } => {
                let value = self.expr(value);
                let affix = self.expr(affix);
                let dst = self.value();
                self.ops.push(Op::StringPredicate {
                    dst,
                    value,
                    affix,
                    kind: if *prefix {
                        StringPredicateKind::Prefix
                    } else {
                        StringPredicateKind::Suffix
                    },
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::ParseInteger { value, fallback }
            | TypedExprKind::ParseDuration { value, fallback }
            | TypedExprKind::ParseTime { value, fallback } => {
                let duration = matches!(&expression.kind, TypedExprKind::ParseDuration { .. });
                let time = matches!(&expression.kind, TypedExprKind::ParseTime { .. });
                let value = self.expr(value);
                let fallback = self.expr(fallback);
                let dst = self.value();
                self.ops.push(Op::ParseScalar {
                    dst,
                    value,
                    fallback,
                    duration,
                    time,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Fnmatch {
                subject,
                pattern,
                pathname,
                noescape,
                period,
            } => {
                let pattern = self.expr(pattern);
                let subject = self.expr(subject);
                let pathname = self.expr(pathname);
                let noescape = self.expr(noescape);
                let period = self.expr(period);
                let dst = self.value();
                self.ops.push(Op::Fnmatch {
                    dst,
                    pattern,
                    subject,
                    pathname,
                    noescape,
                    period,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Querysort { value } => {
                let value = self.expr(value);
                let dst = self.value();
                self.ops.push(Op::Querysort {
                    dst,
                    value,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::StrTest {
                op,
                subject,
                other,
                separators,
            } => {
                let subject = self.expr(subject);
                let other = self.expr(other);
                let separators = self.expr(separators);
                let dst = self.value();
                self.ops.push(Op::StrTest {
                    dst,
                    op: *op,
                    subject,
                    other,
                    separators,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::StrEdit {
                op,
                subject,
                count,
                offset,
            } => {
                let subject = self.expr(subject);
                let count = self.expr(count);
                let offset = self.expr(offset);
                let dst = self.value();
                self.ops.push(Op::StrEdit {
                    dst,
                    op: *op,
                    subject,
                    count,
                    offset,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::StrSplit {
                subject,
                index,
                separators,
            } => {
                let subject = self.expr(subject);
                let index = self.expr(index);
                let separators = self.expr(separators);
                let dst = self.value();
                self.ops.push(Op::StrSplit {
                    dst,
                    subject,
                    index,
                    separators,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::VmodRead {
                module,
                code,
                arguments,
                default,
                regex,
            } => {
                let state = self.load_state(*module, expression.span);
                let arguments = match regex {
                    Some(regex) => self.regex_argument(*module, state, regex, expression.span),
                    None => self.join_arguments(arguments, expression.span),
                };
                let default = self.expr(default);
                let dst = self.value();
                self.ops.push(Op::ModuleRead {
                    dst,
                    module: *module,
                    code: *code,
                    state,
                    arguments,
                    default,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::VmodCount {
                module,
                code,
                arguments,
                regex,
            } => {
                let state = self.load_state(*module, expression.span);
                let arguments = match regex {
                    Some(regex) => self.regex_argument(*module, state, regex, expression.span),
                    None => self.join_arguments(arguments, expression.span),
                };
                let dst = self.value();
                self.ops.push(Op::ModuleCount {
                    dst,
                    module: *module,
                    code: *code,
                    state,
                    arguments,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Not(operand) => {
                let value = self.expr(operand);
                let dst = self.value();
                self.ops.push(Op::Not {
                    dst,
                    value,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Negate(operand) => {
                let left = self.integer(0, expression.span);
                let right = self.expr(operand);
                let dst = self.value();
                self.ops.push(Op::ScalarBinary {
                    dst,
                    kind: ScalarBinaryKind::Subtract,
                    left,
                    right,
                    span: expression.span,
                });
                dst
            }
            TypedExprKind::Binary {
                op: op @ (BinaryOp::And | BinaryOp::Or),
                left,
                right,
            } => self.short_circuit(*op == BinaryOp::And, left, right, expression.span),
            TypedExprKind::Binary { op, left, right } => {
                let left = self.expr(left);
                let right = self.expr(right);
                let dst = self.value();
                match op {
                    BinaryOp::Add
                    | BinaryOp::Subtract
                    | BinaryOp::Multiply
                    | BinaryOp::Divide
                    | BinaryOp::Modulo => self.ops.push(Op::ScalarBinary {
                        dst,
                        kind: match op {
                            BinaryOp::Add => ScalarBinaryKind::Add,
                            BinaryOp::Subtract => ScalarBinaryKind::Subtract,
                            BinaryOp::Multiply => ScalarBinaryKind::Multiply,
                            BinaryOp::Divide => ScalarBinaryKind::Divide,
                            BinaryOp::Modulo => ScalarBinaryKind::Modulo,
                            BinaryOp::Equal
                            | BinaryOp::NotEqual
                            | BinaryOp::Less
                            | BinaryOp::LessEqual
                            | BinaryOp::Greater
                            | BinaryOp::GreaterEqual
                            | BinaryOp::Match
                            | BinaryOp::NotMatch
                            | BinaryOp::And
                            | BinaryOp::Or => unreachable!(),
                        },
                        left,
                        right,
                        span: expression.span,
                    }),
                    BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::Greater
                    | BinaryOp::GreaterEqual => self.ops.push(Op::Compare {
                        dst,
                        kind: match op {
                            BinaryOp::Equal => CompareKind::Equal,
                            BinaryOp::NotEqual => CompareKind::NotEqual,
                            BinaryOp::Less => CompareKind::Less,
                            BinaryOp::LessEqual => CompareKind::LessEqual,
                            BinaryOp::Greater => CompareKind::Greater,
                            BinaryOp::GreaterEqual => CompareKind::GreaterEqual,
                            BinaryOp::Add
                            | BinaryOp::Subtract
                            | BinaryOp::Multiply
                            | BinaryOp::Divide
                            | BinaryOp::Modulo
                            | BinaryOp::Match
                            | BinaryOp::NotMatch
                            | BinaryOp::And
                            | BinaryOp::Or => unreachable!(),
                        },
                        left,
                        right,
                        span: expression.span,
                    }),
                    BinaryOp::Match | BinaryOp::NotMatch => {
                        // The ABI orders its arguments as pattern, subject.
                        self.ops.push(Op::ReadScalar {
                            dst,
                            syscall: Syscall::RegexMatch,
                            args: vec![right, left],
                            span: expression.span,
                        });
                        if *op == BinaryOp::NotMatch {
                            let inverted = self.value();
                            self.ops.push(Op::Not {
                                dst: inverted,
                                value: dst,
                                span: expression.span,
                            });
                            return inverted;
                        }
                    }
                    BinaryOp::And | BinaryOp::Or => {
                        unreachable!("short-circuit operators are lowered as branches")
                    }
                }
                dst
            }
        }
    }

    /// Lower `&&` / `||` used as a *value* the way they are lowered as a
    /// condition: with branches, so the right operand does not run when the
    /// left already settles the answer.
    ///
    /// `set req.http.X = true || (10 / 0 > 0);` must not trap, exactly as
    /// `if (true || 10 / 0 > 0)` does not. The result lives in one
    /// [`Op::BoolSlot`] seeded with the answer for the fall-through path; the
    /// deciding path stores the other value and joins.
    fn short_circuit(
        &mut self,
        and: bool,
        left: &TypedExpr,
        right: &TypedExpr,
        span: Span,
    ) -> ValueId {
        // `a && b` is true only if both branches fall through, so seed false
        // and store true at the end. `a || b` is the mirror image.
        let dst = self.value();
        self.ops.push(Op::BoolSlot {
            dst,
            value: !and,
            span,
        });
        let join = self.label_id();
        if and {
            self.condition_false(left, join);
            self.condition_false(right, join);
        } else {
            self.condition_true(left, join);
            self.condition_true(right, join);
        }
        self.ops.push(Op::BoolStore {
            target: dst,
            value: and,
            span,
        });
        self.label(join, span);
        dst
    }

    fn branch_zero(&mut self, value: ValueId, target: LabelId, span: Span) {
        self.ops.push(Op::BranchZero {
            value,
            target,
            span,
        });
    }

    fn condition_false(&mut self, expression: &TypedExpr, target: LabelId) {
        match &expression.kind {
            TypedExprKind::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => {
                self.condition_false(left, target);
                self.condition_false(right, target);
            }
            TypedExprKind::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => {
                let done = self.label_id();
                self.condition_true(left, done);
                self.condition_false(right, target);
                self.label(done, expression.span);
            }
            TypedExprKind::Not(operand) => self.condition_true(operand, target),
            TypedExprKind::String(_)
            | TypedExprKind::Integer(_)
            | TypedExprKind::Duration(_)
            | TypedExprKind::ParseTime { .. }
            | TypedExprKind::Boolean(_)
            | TypedExprKind::Local(_)
            | TypedExprKind::Static(_)
            | TypedExprKind::Global(_)
            | TypedExprKind::Negate(_)
            | TypedExprKind::Read { .. }
            | TypedExprKind::HeaderPresent { .. }
            | TypedExprKind::Digest { .. }
            | TypedExprKind::Regsub { .. }
            | TypedExprKind::Concat(_)
            | TypedExprKind::ToString { .. }
            | TypedExprKind::StringCase { .. }
            | TypedExprKind::Strstr { .. }
            | TypedExprKind::StringPredicate { .. }
            | TypedExprKind::ParseInteger { .. }
            | TypedExprKind::ParseDuration { .. }
            | TypedExprKind::Fnmatch { .. }
            | TypedExprKind::Querysort { .. }
            | TypedExprKind::StrTest { .. }
            | TypedExprKind::StrEdit { .. }
            | TypedExprKind::StrSplit { .. }
            | TypedExprKind::VmodRead { .. }
            | TypedExprKind::VmodCount { .. }
            | TypedExprKind::AclMatch { .. }
            | TypedExprKind::Extreme { .. }
            | TypedExprKind::Binary {
                op:
                    BinaryOp::Add
                    | BinaryOp::Subtract
                    | BinaryOp::Multiply
                    | BinaryOp::Divide
                    | BinaryOp::Modulo
                    | BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::Greater
                    | BinaryOp::GreaterEqual
                    | BinaryOp::Match
                    | BinaryOp::NotMatch,
                ..
            } => {
                let value = self.expr(expression);
                self.branch_zero(value, target, expression.span);
            }
        }
    }

    fn condition_true(&mut self, expression: &TypedExpr, target: LabelId) {
        match &expression.kind {
            TypedExprKind::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => {
                self.condition_true(left, target);
                self.condition_true(right, target);
            }
            TypedExprKind::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => {
                let done = self.label_id();
                self.condition_false(left, done);
                self.condition_true(right, target);
                self.label(done, expression.span);
            }
            TypedExprKind::Not(operand) => self.condition_false(operand, target),
            TypedExprKind::String(_)
            | TypedExprKind::Integer(_)
            | TypedExprKind::Duration(_)
            | TypedExprKind::ParseTime { .. }
            | TypedExprKind::Boolean(_)
            | TypedExprKind::Local(_)
            | TypedExprKind::Static(_)
            | TypedExprKind::Global(_)
            | TypedExprKind::Negate(_)
            | TypedExprKind::Read { .. }
            | TypedExprKind::HeaderPresent { .. }
            | TypedExprKind::Digest { .. }
            | TypedExprKind::Regsub { .. }
            | TypedExprKind::Concat(_)
            | TypedExprKind::ToString { .. }
            | TypedExprKind::StringCase { .. }
            | TypedExprKind::Strstr { .. }
            | TypedExprKind::StringPredicate { .. }
            | TypedExprKind::ParseInteger { .. }
            | TypedExprKind::ParseDuration { .. }
            | TypedExprKind::Fnmatch { .. }
            | TypedExprKind::Querysort { .. }
            | TypedExprKind::StrTest { .. }
            | TypedExprKind::StrEdit { .. }
            | TypedExprKind::StrSplit { .. }
            | TypedExprKind::VmodRead { .. }
            | TypedExprKind::VmodCount { .. }
            | TypedExprKind::AclMatch { .. }
            | TypedExprKind::Extreme { .. }
            | TypedExprKind::Binary {
                op:
                    BinaryOp::Add
                    | BinaryOp::Subtract
                    | BinaryOp::Multiply
                    | BinaryOp::Divide
                    | BinaryOp::Modulo
                    | BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::Greater
                    | BinaryOp::GreaterEqual
                    | BinaryOp::Match
                    | BinaryOp::NotMatch,
                ..
            } => {
                let value = self.expr(expression);
                let inverted = self.value();
                self.ops.push(Op::Not {
                    dst: inverted,
                    value,
                    span: expression.span,
                });
                self.branch_zero(inverted, target, expression.span);
            }
        }
    }

    fn action(&mut self, action: &TypedReturnAction, span: Span) {
        let (action, args) = match action {
            TypedReturnAction::Next => (ActionCode::Next, Vec::new()),
            TypedReturnAction::Hash => (ActionCode::Hash, Vec::new()),
            TypedReturnAction::Lookup => (ActionCode::Lookup, Vec::new()),
            TypedReturnAction::Fetch => (ActionCode::Fetch, Vec::new()),
            TypedReturnAction::Miss => (ActionCode::Miss, Vec::new()),
            TypedReturnAction::Pass => (ActionCode::Pass, Vec::new()),
            TypedReturnAction::Deliver => (ActionCode::Deliver, Vec::new()),
            TypedReturnAction::Abandon => (ActionCode::Abandon, Vec::new()),
            TypedReturnAction::Fail => (ActionCode::Fail, Vec::new()),
            TypedReturnAction::Synth { status, reason } => {
                let status = self.integer(i64::from(*status), span);
                let reason = self.string(reason.clone(), span);
                (ActionCode::Synth, vec![status, reason])
            }
            TypedReturnAction::Error { status, reason } => {
                let status = self.integer(i64::from(*status), span);
                let reason = self.string(reason.clone(), span);
                (ActionCode::Error, vec![status, reason])
            }
            TypedReturnAction::Leave => {
                self.ops.push(Op::Jump {
                    target: *self
                        .leave_labels
                        .last()
                        .expect("leave is inside an inlined plain sub"),
                    span,
                });
                return;
            }
        };
        self.ops.push(Op::ReturnAction { action, args, span });
    }

    fn synth_body(&mut self, value: &TypedExpr, replace: bool, span: Span) {
        let command = self.integer(
            Syscall::SynthBody.typed_subcommand().expect("typed command"),
            span,
        );
        let selector = self.integer(i64::from(replace), span);
        let value = self.expr(value);
        self.host(Syscall::SynthBody, vec![command, selector, value], span);
    }

    fn statements(&mut self, statements: &[TypedStatement]) {
        for statement in statements {
            match statement {
                TypedStatement::Declare {
                    local,
                    value_type,
                    init,
                    span,
                } => {
                    let value = if let Some(init) = init {
                        self.expr(init)
                    } else if *value_type == ValueType::String {
                        self.string(String::new(), *span)
                    } else {
                        self.integer(0, *span)
                    };
                    self.ops.push(Op::StoreLocal {
                        slot: *local,
                        value,
                        span: *span,
                    });
                }
                TypedStatement::SetLocal { local, value, span } => {
                    let value = self.expr(value);
                    self.ops.push(Op::StoreLocal {
                        slot: *local,
                        value,
                        span: *span,
                    });
                }
                TypedStatement::SetGlobal {
                    global,
                    value,
                    span,
                } => {
                    let value = self.expr(value);
                    self.ops.push(Op::StoreGlobal {
                        global: *global,
                        value,
                        span: *span,
                    });
                }
                TypedStatement::SetStatic {
                    static_id,
                    value,
                    span,
                } => {
                    let value = self.expr(value);
                    self.ops.push(Op::StoreStatic {
                        static_id: *static_id,
                        value,
                        span: *span,
                    });
                }
                TypedStatement::Inlined { body, span, .. } => {
                    let end = self.label_id();
                    self.leave_labels.push(end);
                    self.statements(body);
                    self.leave_labels.pop();
                    self.label(end, *span);
                }
                TypedStatement::Call { .. } => {
                    unreachable!("desugar verifier rejects symbolic calls before IR lowering")
                }
                TypedStatement::SetHeader {
                    response,
                    name,
                    value,
                    span,
                } => {
                    let name = self.string(name.clone(), *span);
                    let value = self.expr(value);
                    self.host(
                        if *response {
                            Syscall::ResponseSetHeader
                        } else {
                            Syscall::RequestSetHeader
                        },
                        vec![name, value],
                        *span,
                    );
                }
                TypedStatement::UnsetHeader {
                    response,
                    name,
                    span,
                } => {
                    let syscall = if *response {
                        Syscall::ResponseRemoveHeader
                    } else {
                        Syscall::RequestRemoveHeader
                    };
                    let command = self.integer(
                        syscall.typed_subcommand().expect("remove uses typed ABI"),
                        *span,
                    );
                    let name = self.string(name.clone(), *span);
                    self.host(syscall, vec![command, name], *span);
                }
                TypedStatement::SetUrl { value, span } => {
                    let value = self.expr(value);
                    self.host(Syscall::RequestSetUrl, vec![value], *span);
                }
                TypedStatement::SetVar { var, value, span } => {
                    let syscall = if value.value_type == ValueType::String {
                        Syscall::VarSetString
                    } else {
                        Syscall::VarSetScalar
                    };
                    let command = self.integer(
                        syscall.typed_subcommand().expect("variable write uses typed ABI"),
                        *span,
                    );
                    let id = self.integer(var.abi_id(), *span);
                    let value = self.expr(value);
                    self.host(syscall, vec![command, id, value], *span);
                }
                TypedStatement::HashData { value, span } => {
                    let command = self.integer(
                        Syscall::HashData.typed_subcommand().expect("typed command"),
                        *span,
                    );
                    let value = self.expr(value);
                    self.host(Syscall::HashData, vec![command, value], *span);
                }
                TypedStatement::SetBody { value, span } => self.synth_body(value, true, *span),
                TypedStatement::Synthetic { value, span } => self.synth_body(value, false, *span),
                // A cache duration the desugarer could not fold: the value
                // is computed here, in nanoseconds, and truncated to the
                // seconds the ABI speaks. A result outside the host's range
                // is refused there and leaves the previous number in place.
                TypedStatement::SetCacheDuration {
                    lowering,
                    value,
                    span,
                    ..
                } => {
                    let nanoseconds = self.expr(value);
                    let seconds = self.scale(nanoseconds, ScalarBinaryKind::Divide, *span);
                    match lowering {
                        Lowering::Ttl => self.host(Syscall::SetTtl, vec![seconds], *span),
                        Lowering::StaleWhileRevalidate | Lowering::StaleIfError => {
                            let syscall = if *lowering == Lowering::StaleWhileRevalidate {
                                Syscall::SetStaleWhileRevalidate
                            } else {
                                Syscall::SetStaleIfError
                            };
                            let command = self.integer(
                                syscall
                                    .typed_subcommand()
                                    .expect("stale-window call uses the typed ABI"),
                                *span,
                            );
                            self.host(syscall, vec![command, seconds], *span);
                        }
                        Lowering::RequestHeader
                        | Lowering::ResponseHeader
                        | Lowering::RequestUrl
                        | Lowering::RequestMethod
                        | Lowering::Now
                        | Lowering::ClientIp
                        | Lowering::Uncacheable
                        | Lowering::CacheHit
                        | Lowering::Body
                        | Lowering::Host(_) => {
                            unreachable!("type checking rejects other cache-duration targets")
                        }
                    }
                }
                TypedStatement::SetTtl { seconds, span } => {
                    let value = self.integer(*seconds as i64, *span);
                    self.host(Syscall::SetTtl, vec![value], *span);
                }
                TypedStatement::SetStaleWhileRevalidate { seconds, span } => {
                    let syscall = Syscall::SetStaleWhileRevalidate;
                    let command = self.integer(
                        syscall
                            .typed_subcommand()
                            .expect("stale-window call uses the typed ABI"),
                        *span,
                    );
                    let value = self.integer(*seconds as i64, *span);
                    self.host(syscall, vec![command, value], *span);
                }
                TypedStatement::SetStaleIfError { seconds, span } => {
                    let syscall = Syscall::SetStaleIfError;
                    let command = self.integer(
                        syscall
                            .typed_subcommand()
                            .expect("stale-window call uses the typed ABI"),
                        *span,
                    );
                    let value = self.integer(*seconds as i64, *span);
                    self.host(syscall, vec![command, value], *span);
                }
                TypedStatement::SetUncacheable { span } => {
                    let command = self.integer(
                        Syscall::VarSetScalar.typed_subcommand().expect("typed command"),
                        *span,
                    );
                    let id = self.integer(HostVar::BerespUncacheable.abi_id(), *span);
                    let value = self.integer(1, *span);
                    self.host(Syscall::VarSetScalar, vec![command, id, value], *span);
                }
                TypedStatement::Collect {
                    response,
                    name,
                    separator,
                    span,
                } => {
                    let name = self.string(name.clone(), *span);
                    let separator = self.expr(separator);
                    self.ops.push(Op::Collect {
                        name,
                        separator,
                        response: *response,
                        span: *span,
                    });
                }
                TypedStatement::Vmod {
                    module,
                    action,
                    span,
                } => match action {
                    VmodAction::Reseed { response, source } => {
                        self.seed_state(*module, *response, source.clone(), *span)
                    }
                    VmodAction::Transform {
                        code,
                        arguments,
                        regex,
                    } => {
                        // A module's `parse()` replaces the state from an
                        // explicit string, so that string is the routine's
                        // input rather than its argument -- the same position
                        // the source occupies when the hook prologue seeds
                        // the state.
                        let parsing =
                            vcl_rt::OpCode::decode(*code).op == module.parse_op();
                        let (state, arguments) = if parsing {
                            let source = arguments
                                .first()
                                .map(|source| self.expr(source))
                                .unwrap_or_else(|| self.string(String::new(), *span));
                            // `uri.parse()` with no input, or with one that
                            // is empty at run time, parses the request's own
                            // Host and URL instead, so every parse carries
                            // them.
                            let arguments = match module.source() {
                                Some(_) => Vec::new(),
                                None => vec![self.implicit_uri(*span)],
                            };
                            (source, arguments)
                        } else {
                            let state = self.load_state(*module, *span);
                            let arguments = match regex {
                                Some(regex) => self.regex_argument(*module, state, regex, *span),
                                None => self.join_arguments(arguments, *span),
                            };
                            (state, arguments)
                        };
                        let dst = self.value();
                        self.ops.push(Op::ModuleTransform {
                            dst,
                            module: *module,
                            code: *code,
                            state,
                            arguments,
                            span: *span,
                        });
                        self.store_state(*module, dst, *span);
                    }
                    VmodAction::Write {
                        code,
                        response,
                        header,
                    } => {
                        let state = self.load_state(*module, *span);
                        match module.commit() {
                            // cookieplus and urlplus write a string through
                            // the ordinary setters, so the host sees exactly
                            // what `set req.http.Cookie` or a URL rewrite
                            // would produce.
                            Commit::String => {
                                let empty = self.string(String::new(), *span);
                                let rendered = self.value();
                                self.ops.push(Op::ModuleRead {
                                    dst: rendered,
                                    module: *module,
                                    code: *code,
                                    state,
                                    arguments: Vec::new(),
                                    default: empty,
                                    span: *span,
                                });
                                match module {
                                    Module::Cookieplus => {
                                        let name = self.string("Cookie".to_string(), *span);
                                        self.host(
                                            Syscall::RequestSetHeader,
                                            vec![name, rendered],
                                            *span,
                                        );
                                    }
                                    Module::Urlplus => {
                                        self.host(Syscall::RequestSetUrl, vec![rendered], *span)
                                    }
                                    Module::Setcookie | Module::Headerplus | Module::Uri => {
                                        unreachable!("{module:?} does not commit a string")
                                    }
                                }
                            }
                            // The vmod replaces the Host header and the
                            // URL together, because its state spans both:
                            // the authority is one store and the rest is the
                            // other. The scheme, userinfo and fragment are
                            // dropped, as `vmod_write()` drops them -- none
                            // of the three is on the wire, and a fragment
                            // that reached the URL would be sent to the
                            // origin as part of the request target.
                            //
                            // Either half can render as nothing: a state
                            // parsed from a relative URI has no host, and one
                            // parsed without `norm` from an authority alone
                            // has no path. Storing that would blank the
                            // request's own `Host` or URL, so each store is
                            // skipped when its half is empty -- the state has
                            // no other way to spell "leave this one alone".
                            Commit::HostAndUrl => {
                                let empty = self.string(String::new(), *span);
                                for (fmt, store) in [
                                    ("%H%p", Syscall::RequestSetHeader),
                                    ("%P%Q", Syscall::RequestSetUrl),
                                ] {
                                    let fmt = self.string(fmt.to_string(), *span);
                                    let rendered = self.value();
                                    self.ops.push(Op::ModuleRead {
                                        dst: rendered,
                                        module: *module,
                                        code: *code,
                                        state,
                                        arguments: vec![fmt],
                                        default: empty,
                                        span: *span,
                                    });
                                    let filled = self.value();
                                    self.ops.push(Op::Compare {
                                        dst: filled,
                                        kind: CompareKind::NotEqual,
                                        left: rendered,
                                        right: empty,
                                        span: *span,
                                    });
                                    let skip = self.label_id();
                                    self.ops.push(Op::BranchZero {
                                        value: filled,
                                        target: skip,
                                        span: *span,
                                    });
                                    let args = if store == Syscall::RequestSetHeader {
                                        let name = self.string("Host".to_string(), *span);
                                        vec![name, rendered]
                                    } else {
                                        vec![rendered]
                                    };
                                    self.host(store, args, *span);
                                    self.label(skip, *span);
                                }
                            }
                            Commit::Headers => self.ops.push(Op::HeaderCommit {
                                state,
                                response: *response,
                                span: *span,
                            }),
                            // The Set-Cookie list is rendered into a
                            // header-shaped state first, so the write is the
                            // same generic commit headerplus performs.
                            Commit::RenderedHeaders => {
                                let name = self.string(
                                    header.clone().unwrap_or_else(|| "Set-Cookie".to_string()),
                                    *span,
                                );
                                let rendered = self.value();
                                self.ops.push(Op::ModuleTransform {
                                    dst: rendered,
                                    module: *module,
                                    code: *code,
                                    state,
                                    arguments: vec![name],
                                    span: *span,
                                });
                                self.ops.push(Op::HeaderCommit {
                                    state: rendered,
                                    response: *response,
                                    span: *span,
                                });
                                // The vmod frees its Set-Cookie context after
                                // a write, so a second one starts from the
                                // headers this one just left.
                                self.seed_state(*module, *response, None, *span);
                            }
                        }
                    }
                },
                TypedStatement::Log { value, span } => {
                    let value = self.expr(value);
                    self.host(Syscall::Log, vec![value], *span);
                }
                TypedStatement::If {
                    branches,
                    otherwise,
                    span,
                } => {
                    let end = self.label_id();
                    for (condition, body) in branches {
                        let next = self.label_id();
                        self.condition_false(condition, next);
                        self.statements(body);
                        if !matches!(
                            self.ops.last(),
                            Some(Op::ReturnAction { .. } | Op::Jump { .. })
                        ) {
                            self.ops.push(Op::Jump {
                                target: end,
                                span: *span,
                            });
                        }
                        self.label(next, *span);
                    }
                    self.statements(otherwise);
                    self.label(end, *span);
                }
                TypedStatement::Return { action, span } => self.action(action, *span),
            }
            // A return ends the block in a terminator. Anything after is
            // unreachable.
            if matches!(statement, TypedStatement::Return { .. }) {
                break;
            }
        }
    }
}

pub(crate) fn lower(typed: &TypedProgram) -> Program {
    let functions = typed
        .subs
        .iter()
        .map(|sub| {
            // A module's state is one extra local per module the hook uses,
            // appended after the VCL locals, and seeded before the first
            // statement runs.
            let used = modules_used(&sub.statements);
            let states: BTreeMap<Module, LocalId> = used
                .iter()
                .enumerate()
                .map(|(index, module)| (*module, LocalId(sub.locals.len() as u32 + index as u32)))
                .collect();
            let mut builder = Builder::new(states);
            for module in &used {
                builder.seed_state(
                    *module,
                    sub.phase.writes_response_headers(),
                    None,
                    Span::default(),
                );
            }
            builder.statements(&sub.statements);
            Function {
                phase: sub.phase,
                value_count: builder.next_value,
                ops: builder.ops,
                locals: sub
                    .locals
                    .iter()
                    .copied()
                    .map(value_class)
                    .chain(used.iter().map(|_| ValueClass::String))
                    .collect(),
            }
        })
        .collect();
    let statics = typed
        .statics
        .iter()
        .map(|static_| StaticDef {
            name: static_.name.clone(),
            class: value_class(static_.value_type),
            value_type: static_.value_type,
            initial: static_.initial,
            stat: static_.stat.clone(),
        })
        .collect();
    let globals = typed
        .globals
        .iter()
        .map(|global| GlobalDef {
            name: global.name.clone(),
            class: value_class(global.value_type),
            value_type: global.value_type,
            initial: global.initial.clone(),
        })
        .collect();
    Program {
        functions,
        statics,
        globals,
        acls: typed.acls.clone(),
        patterns: typed.patterns.clone(),
    }
}

/// Which vmod modules a hook body touches.
///
/// One walk for all of them.  The three hand-written copies this replaces had
/// each been written to notice its *own* module and had each stopped at the
/// other two: `headerplus.set("X", cookieplus.get("a"))` reached lowering
/// with no cookieplus state local at all.  Going through
/// [`crate::typecheck::statement_expressions`] and
/// [`crate::typecheck::statement_bodies`] means a new statement or expression
/// kind is covered by construction rather than by remembering.
fn modules_used(statements: &[TypedStatement]) -> BTreeSet<Module> {
    fn self_expression(expression: &TypedExpr, found: &mut BTreeSet<Module>) {
        if let TypedExprKind::VmodRead { module, .. } | TypedExprKind::VmodCount { module, .. } =
            &expression.kind
        {
            found.insert(*module);
        }
        for operand in crate::typecheck::operands(expression) {
            self_expression(operand, found);
        }
    }

    fn visit(statements: &[TypedStatement], found: &mut BTreeSet<Module>) {
        for statement in statements {
            if let TypedStatement::Vmod { module, .. } = statement {
                found.insert(*module);
            }
            for value in crate::typecheck::statement_expressions(statement) {
                self_expression(value, found);
            }
            for body in crate::typecheck::statement_bodies(statement) {
                visit(body, found);
            }
        }
    }
    let mut found = BTreeSet::new();
    visit(statements, &mut found);
    found
}

fn value_class(value_type: ValueType) -> ValueClass {
    match value_type {
        ValueType::String | ValueType::Ip => ValueClass::String,
        ValueType::Integer | ValueType::Duration | ValueType::Time | ValueType::Boolean => {
            ValueClass::Scalar
        }
    }
}

pub(crate) fn verify(program: &Program) -> Result<(), BackendError> {
    verify_text(program).map_err(|message| {
        let span = program
            .functions
            .first()
            .and_then(|function| function.ops.first())
            .map(Op::span);
        BackendError::new("IR verifier", span, message)
    })
}

fn verify_text(program: &Program) -> Result<(), String> {
    if program.functions.is_empty() {
        return Err("IR program has no functions".to_string());
    }
    let mut hooks = BTreeSet::new();
    if program
        .statics
        .iter()
        .any(|static_| static_.class == ValueClass::String)
    {
        return Err("IR contains a STRING static".to_string());
    }
    for function in &program.functions {
        if !hooks.insert(function.phase) {
            return Err(format!("IR has duplicate function {}", function.hook()));
        }
        verify_function(
            function,
            &program.statics,
            &program.globals,
            &program.acls,
        )?;
    }
    Ok(())
}

fn verify_function(
    function: &Function,
    statics: &[StaticDef],
    globals: &[GlobalDef],
    acls: &[Vec<u8>],
) -> Result<(), String> {
    if function.ops.is_empty() {
        return Err(format!("IR function {} is empty", function.hook()));
    }
    let mut values = BTreeMap::new();
    let mut label_positions = BTreeMap::new();
    for (index, op) in function.ops.iter().enumerate() {
        if let Op::Label { label, .. } = op {
            if label_positions.insert(*label, index).is_some() {
                return Err(format!(
                    "IR function {} defines label l{} more than once",
                    function.hook(),
                    label.0
                ));
            }
        }
    }
    let labels: BTreeSet<_> = function
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Label { label, .. } => Some(*label),
            Op::ConstInt { .. }
            | Op::ConstString { .. }
            | Op::LoadLocal { .. }
            | Op::StoreLocal { .. }
            | Op::LoadStatic { .. }
            | Op::StoreStatic { .. }
            | Op::LoadGlobal { .. }
            | Op::StoreGlobal { .. }
            | Op::ReadString { .. }
            | Op::ReadScalar { .. }
            | Op::ReadNow { .. }
            | Op::ReadClientIp { .. }
            | Op::AclMatch { .. }
            | Op::StringConcat { .. }
            | Op::StringConvert { .. }
            | Op::StringCase { .. }
            | Op::StringFind { .. }
            | Op::StringPredicate { .. }
            | Op::ParseScalar { .. }
            | Op::Fnmatch { .. }
            | Op::Querysort { .. }
            | Op::StrTest { .. }
            | Op::StrEdit { .. }
            | Op::StrSplit { .. }
            | Op::ModuleInit { .. }
            | Op::ModuleRead { .. }
            | Op::ModuleCount { .. }
            | Op::ModuleTransform { .. }
            | Op::RegexMatchList { .. }
            | Op::Collect { .. }
            | Op::HeaderCommit { .. }
            | Op::Not { .. }
            | Op::ScalarBinary { .. }
            | Op::Compare { .. }
            | Op::BoolSlot { .. }
            | Op::BoolStore { .. }
            | Op::Host { .. }
            | Op::Jump { .. }
            | Op::BranchZero { .. }
            | Op::ReturnAction { .. } => None,
        })
        .collect();
    let mut bool_slots = BTreeSet::new();
    for (index, op) in function.ops.iter().enumerate() {
        let opcode = op.opcode();
        if opcode.is_terminator()
            && index + 1 != function.ops.len()
            && !matches!(function.ops[index + 1], Op::Label { .. })
        {
            return Err(format!(
                "IR function {} has instructions after its {} terminator",
                function.hook(),
                opcode.name()
            ));
        }
        for value in op.uses() {
            if !values.contains_key(&value) {
                return Err(format!(
                    "IR function {} uses undefined value v{}",
                    function.hook(),
                    value.0
                ));
            }
        }
        match op {
            Op::ConstInt { .. } | Op::ConstString { .. } => {}
            Op::LoadLocal { slot, class, .. } => {
                let actual = function.locals.get(slot.0 as usize).ok_or_else(|| {
                    format!(
                        "IR function {} loads out-of-range local {}",
                        function.hook(),
                        slot.0
                    )
                })?;
                if actual != class {
                    return Err(format!(
                        "IR function {} loads local {} with the wrong class",
                        function.hook(),
                        slot.0
                    ));
                }
            }
            Op::StoreLocal { slot, value, .. } => {
                let class = function.locals.get(slot.0 as usize).ok_or_else(|| {
                    format!(
                        "IR function {} stores out-of-range local {}",
                        function.hook(),
                        slot.0
                    )
                })?;
                verify_signature(function, opcode.name(), &[*value], &[*class], &values)?;
            }
            Op::LoadStatic {
                static_id, class, ..
            } => {
                let actual = statics.get(static_id.0 as usize).ok_or_else(|| {
                    format!(
                        "IR function {} loads out-of-range static {}",
                        function.hook(),
                        static_id.0
                    )
                })?;
                if actual.class != *class {
                    return Err(format!(
                        "IR function {} loads static {} with the wrong class",
                        function.hook(),
                        static_id.0
                    ));
                }
            }
            Op::LoadGlobal { global, class, .. } => {
                let actual = globals.get(global.0 as usize).ok_or_else(|| {
                    format!(
                        "IR function {} loads out-of-range request global {}",
                        function.hook(),
                        global.0
                    )
                })?;
                if actual.class != *class {
                    return Err(format!(
                        "IR function {} loads request global {} with the wrong class",
                        function.hook(),
                        global.0
                    ));
                }
            }
            Op::StoreGlobal { global, value, .. } => {
                let global = globals.get(global.0 as usize).ok_or_else(|| {
                    format!(
                        "IR function {} stores out-of-range request global {}",
                        function.hook(),
                        global.0
                    )
                })?;
                verify_signature(function, opcode.name(), &[*value], &[global.class], &values)?;
            }
            Op::StoreStatic {
                static_id, value, ..
            } => {
                let static_ = statics.get(static_id.0 as usize).ok_or_else(|| {
                    format!(
                        "IR function {} stores out-of-range static {}",
                        function.hook(),
                        static_id.0
                    )
                })?;
                verify_signature(
                    function,
                    opcode.name(),
                    &[*value],
                    &[static_.class],
                    &values,
                )?;
            }
            Op::ReadString { syscall, args, .. } | Op::ReadScalar { syscall, args, .. } => {
                let expected_result = if matches!(op, Op::ReadString { .. }) {
                    ValueClass::String
                } else {
                    ValueClass::Scalar
                };
                if syscall.result() != Some(expected_result) {
                    return Err(format!(
                        "read syscall {} has the wrong IR result class",
                        syscall.name()
                    ));
                }
                verify_signature(
                    function,
                    syscall.name(),
                    args,
                    syscall.signature().expect("read syscall has a signature"),
                    &values,
                )?;
            }
            Op::ReadNow { .. } | Op::ReadClientIp { .. } => {}
            Op::AclMatch { address, acl, .. } => {
                if acl.0 as usize >= acls.len() {
                    return Err(format!(
                        "IR function {} matches out-of-range acl {}",
                        function.hook(),
                        acl.0
                    ));
                }
                verify_signature(
                    function,
                    opcode.name(),
                    &[*address],
                    &[ValueClass::String],
                    &values,
                )?;
            }
            Op::Not { value, .. } => {
                verify_signature(
                    function,
                    opcode.name(),
                    &[*value],
                    &[ValueClass::Scalar],
                    &values,
                )?;
            }
            Op::StringConcat { left, right, .. }
            | Op::StringFind {
                haystack: left,
                needle: right,
                ..
            }
            | Op::StringPredicate {
                value: left,
                affix: right,
                ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*left, *right],
                &[ValueClass::String, ValueClass::String],
                &values,
            )?,
            Op::StringConvert {
                value, conversion, ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*value],
                if *conversion == StringConversion::Ip {
                    &[ValueClass::String]
                } else {
                    &[ValueClass::Scalar]
                },
                &values,
            )?,
            Op::StringCase { value, .. } => verify_signature(
                function,
                opcode.name(),
                &[*value],
                &[ValueClass::String],
                &values,
            )?,
            Op::ParseScalar {
                value, fallback, ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*value, *fallback],
                &[ValueClass::String, ValueClass::Scalar],
                &values,
            )?,
            Op::Fnmatch {
                subject,
                pattern,
                pathname,
                noescape,
                period,
                ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*pattern, *subject, *pathname, *noescape, *period],
                &[
                    ValueClass::String,
                    ValueClass::String,
                    ValueClass::Scalar,
                    ValueClass::Scalar,
                    ValueClass::Scalar,
                ],
                &values,
            )?,
            Op::Querysort { value, .. } => verify_signature(
                function,
                opcode.name(),
                &[*value],
                &[ValueClass::String],
                &values,
            )?,
            Op::StrTest {
                subject,
                other,
                separators,
                ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*subject, *other, *separators],
                &[ValueClass::String, ValueClass::String, ValueClass::String],
                &values,
            )?,
            Op::StrEdit {
                subject,
                count,
                offset,
                ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*subject, *count, *offset],
                &[ValueClass::String, ValueClass::Scalar, ValueClass::Scalar],
                &values,
            )?,
            Op::StrSplit {
                subject,
                index,
                separators,
                ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*subject, *index, *separators],
                &[ValueClass::String, ValueClass::Scalar, ValueClass::String],
                &values,
            )?,
            // A module call has one state operand, at most one string
            // argument -- the runtime ABI has one argument register pair --
            // and, for a read, a fallback.
            Op::ModuleRead {
                state,
                arguments,
                default,
                ..
            } => {
                let mut operands = vec![*state];
                operands.extend(arguments);
                operands.push(*default);
                verify_module_arity(function, opcode.name(), arguments.len())?;
                verify_signature(
                    function,
                    opcode.name(),
                    &operands,
                    &vec![ValueClass::String; operands.len()],
                    &values,
                )?;
            }
            Op::ModuleCount {
                state, arguments, ..
            }
            | Op::ModuleTransform {
                state, arguments, ..
            } => {
                let mut operands = vec![*state];
                operands.extend(arguments);
                verify_module_arity(function, opcode.name(), arguments.len())?;
                verify_signature(
                    function,
                    opcode.name(),
                    &operands,
                    &vec![ValueClass::String; operands.len()],
                    &values,
                )?;
            }
            Op::RegexMatchList {
                state, patterns, ..
            } => {
                if patterns.is_empty() || patterns.len() > 2 {
                    return Err(format!(
                        "IR function {} matches {} patterns against a record list; \
                         the argument carries one or two",
                        function.hook(),
                        patterns.len()
                    ));
                }
                let mut operands = vec![*state];
                operands.extend(patterns);
                verify_signature(
                    function,
                    opcode.name(),
                    &operands,
                    &vec![ValueClass::String; operands.len()],
                    &values,
                )?;
            }
            Op::ModuleInit { .. } => {}
            Op::Collect {
                name, separator, ..
            } => verify_signature(
                function,
                opcode.name(),
                &[*name, *separator],
                &[ValueClass::String, ValueClass::String],
                &values,
            )?,
            Op::HeaderCommit { state, .. } => verify_signature(
                function,
                opcode.name(),
                &[*state],
                &[ValueClass::String],
                &values,
            )?,
            Op::ScalarBinary { left, right, .. } => verify_signature(
                function,
                opcode.name(),
                &[*left, *right],
                &[ValueClass::Scalar, ValueClass::Scalar],
                &values,
            )?,
            Op::BranchZero { value, target, .. } => {
                verify_signature(
                    function,
                    opcode.name(),
                    &[*value],
                    &[ValueClass::Scalar],
                    &values,
                )?;
                if !labels.contains(target) {
                    return Err(format!(
                        "IR function {} jumps to undefined label l{}",
                        function.hook(),
                        target.0
                    ));
                }
                if label_positions[target] <= index {
                    return Err(format!(
                        "IR function {} has a non-forward branch to l{}",
                        function.hook(),
                        target.0
                    ));
                }
            }
            Op::Compare {
                kind, left, right, ..
            } => {
                let left_class = values[left];
                if values[right] != left_class {
                    return Err(format!(
                        "comparison in {} has mismatched operand classes",
                        function.hook()
                    ));
                }
                if !matches!(kind, CompareKind::Equal | CompareKind::NotEqual)
                    && left_class != ValueClass::Scalar
                {
                    return Err(format!(
                        "ordered comparison in {} requires scalar operands",
                        function.hook()
                    ));
                }
            }
            Op::BoolSlot { dst, .. } => {
                bool_slots.insert(*dst);
            }
            Op::BoolStore { target, .. } => {
                verify_signature(
                    function,
                    opcode.name(),
                    &[*target],
                    &[ValueClass::Scalar],
                    &values,
                )?;
                if !bool_slots.contains(target) {
                    return Err(format!(
                        "IR function {} stores through v{}, which is not a BoolSlot",
                        function.hook(),
                        target.0
                    ));
                }
            }
            Op::Host { syscall, args, .. } => {
                let Some(signature) = syscall.signature() else {
                    return Err(format!(
                        "host syscall {} ({}) must use a dedicated IR terminator",
                        syscall.name(),
                        syscall.number()
                    ));
                };
                verify_signature(function, syscall.name(), args, signature, &values)?;
            }
            Op::ReturnAction { action, args, .. } => {
                verify_signature(function, "return_action", args, action.signature(), &values)?;
            }
            Op::Label { .. } => {}
            Op::Jump { target, .. } => {
                if !labels.contains(target) {
                    return Err(format!(
                        "IR function {} jumps to undefined label l{}",
                        function.hook(),
                        target.0
                    ));
                }
                if label_positions[target] <= index {
                    return Err(format!(
                        "IR function {} has a non-forward jump to l{}",
                        function.hook(),
                        target.0
                    ));
                }
            }
        }
        if let Some((value, class)) = op.definition() {
            if value.0 >= function.value_count {
                return Err(format!(
                    "IR function {} defines out-of-range value v{}",
                    function.hook(),
                    value.0
                ));
            }
            if values.insert(value, class).is_some() {
                return Err(format!(
                    "IR function {} defines v{} more than once",
                    function.hook(),
                    value.0
                ));
            }
        }
    }
    if values.len() != function.value_count as usize {
        return Err(format!(
            "IR function {} declares {} values but defines {}",
            function.hook(),
            function.value_count,
            values.len()
        ));
    }
    if !function
        .ops
        .last()
        .is_some_and(|op| op.opcode().is_terminator())
    {
        return Err(format!("IR function {} has no terminator", function.hook()));
    }
    Ok(())
}

/// A module routine takes at most one string argument.
///
/// Several VCL arguments are joined with a NUL during lowering, so more than
/// one arriving here means a lowering bug rather than a program error -- and
/// silently dropping the extras is exactly how `headerplus.append` lost its
/// delimiter before this check existed.
fn verify_module_arity(function: &Function, name: &str, arity: usize) -> Result<(), String> {
    if arity > 1 {
        return Err(format!(
            "{} in {} passes {arity} arguments to a routine that takes one",
            name,
            function.phase.vcl_name()
        ));
    }
    Ok(())
}

fn verify_signature(
    function: &Function,
    operation: &str,
    args: &[ValueId],
    expected: &[ValueClass],
    values: &BTreeMap<ValueId, ValueClass>,
) -> Result<(), String> {
    let actual: Vec<_> = args.iter().map(|value| values[value]).collect();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "invalid arguments for {operation} in {}: expected {expected:?}, found {actual:?}",
            function.hook()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(ops: Vec<Op>, value_count: u32) -> Function {
        Function {
            phase: Phase::Recv,
            ops,
            value_count,
            locals: Vec::new(),
        }
    }

    #[test]
    fn verifier_refuses_instructions_after_a_terminator() {
        let span = Span::default();
        let program = Program {
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            patterns: Vec::new(),
            functions: vec![function(
                vec![
                    Op::ReturnAction {
                        action: ActionCode::Next,
                        args: Vec::new(),
                        span,
                    },
                    Op::ConstString {
                        dst: ValueId(0),
                        value: "late".into(),
                        span,
                    },
                ],
                1,
            )],
        };
        assert!(verify(&program).unwrap_err().contains("after its"));
    }

    #[test]
    fn verifier_refuses_an_empty_program() {
        assert_eq!(
            verify(&Program {
                statics: Vec::new(),
                globals: Vec::new(),
                acls: Vec::new(),
                patterns: Vec::new(),
                functions: Vec::new()
            })
            .unwrap_err(),
            "IR program has no functions"
        );
    }

    #[test]
    fn verifier_rejects_undefined_and_wrong_class_values() {
        let span = Span::default();
        let undefined = Program {
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            patterns: Vec::new(),
            functions: vec![function(
                vec![
                    Op::Host {
                        syscall: Syscall::Log,
                        args: vec![ValueId(0)],
                        span,
                    },
                    Op::ReturnAction {
                        action: ActionCode::Next,
                        args: vec![],
                        span,
                    },
                ],
                0,
            )],
        };
        assert!(verify(&undefined).unwrap_err().contains("undefined value"));

        let wrong_class = Program {
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            patterns: Vec::new(),
            functions: vec![function(
                vec![
                    Op::ConstInt {
                        dst: ValueId(0),
                        value: 1,
                        span,
                    },
                    Op::Host {
                        syscall: Syscall::Log,
                        args: vec![ValueId(0)],
                        span,
                    },
                    Op::ReturnAction {
                        action: ActionCode::Next,
                        args: vec![],
                        span,
                    },
                ],
                1,
            )],
        };
        assert!(verify(&wrong_class)
            .unwrap_err()
            .contains("invalid arguments for log"));
    }

    #[test]
    fn verifier_enforces_forward_unique_labels_and_bool_slots() {
        let span = Span::new(7, 11);
        let label = LabelId(0);
        let duplicate = Program {
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            patterns: Vec::new(),
            functions: vec![function(
                vec![
                    Op::Label { label, span },
                    Op::Label { label, span },
                    Op::ReturnAction {
                        action: ActionCode::Next,
                        args: vec![],
                        span,
                    },
                ],
                0,
            )],
        };
        assert!(verify(&duplicate)
            .unwrap_err()
            .contains("label l0 more than once"));

        let backward = Program {
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            patterns: Vec::new(),
            functions: vec![function(
                vec![
                    Op::Label { label, span },
                    Op::Jump {
                        target: label,
                        span,
                    },
                ],
                0,
            )],
        };
        assert!(verify(&backward).unwrap_err().contains("non-forward jump"));

        let wrong_store = Program {
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            patterns: Vec::new(),
            functions: vec![function(
                vec![
                    Op::ConstInt {
                        dst: ValueId(0),
                        value: 0,
                        span,
                    },
                    Op::BoolStore {
                        target: ValueId(0),
                        value: true,
                        span,
                    },
                    Op::ReturnAction {
                        action: ActionCode::Next,
                        args: vec![],
                        span,
                    },
                ],
                1,
            )],
        };
        assert!(verify(&wrong_store).unwrap_err().contains("not a BoolSlot"));
    }

    #[test]
    fn opcode_metadata_is_central_and_consistent() {
        assert!(Opcode::ConstInt.is_pure());
        assert!(Opcode::ConstString.is_pure());
        assert!(!Opcode::Host.is_pure());
        assert!(Opcode::ReturnAction.is_terminator());
    }
}
