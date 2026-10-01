use std::collections::BTreeSet;

use crate::ast;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub(crate) fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// Block-nesting bound, shared by type checking and desugaring.
///
/// The parser bounds how deep one body may nest, but desugaring re-enters a
/// fresh body at every inlined `call`, so a chain of subroutines multiplies
/// that bound and would overflow the stack. Both walks count against the same
/// limit and report a diagnostic instead. It sits above the parser's own limit
/// so nesting the parser accepts is never rejected here for depth alone; the
/// two walks must agree, or a body the checker accepted could fail to
/// desugar.
pub(crate) const MAX_BLOCK_DEPTH: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Phase {
    Recv,
    BackendRequest,
    BackendResponse,
    Deliver,
    Synth,
    Hash,
    Hit,
    Miss,
    Pass,
    BackendError,
}

impl Phase {
    /// The client-side subroutines Varnish's tables call `client`. A tenant
    /// cannot reach `vcl_purge`, `vcl_pipe` or `vcl_connect`, so they are not
    /// phases at all.
    pub(crate) const CLIENT: &'static [Self] = &[
        Self::Recv,
        Self::Hash,
        Self::Hit,
        Self::Miss,
        Self::Pass,
        Self::Deliver,
        Self::Synth,
    ];

    /// The backend-side subroutines, Varnish's `backend`.
    pub(crate) const BACKEND: &'static [Self] = &[
        Self::BackendRequest,
        Self::BackendResponse,
        Self::BackendError,
    ];

    /// Every phase.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Recv,
        Self::Hash,
        Self::Hit,
        Self::Miss,
        Self::Pass,
        Self::Deliver,
        Self::Synth,
        Self::BackendRequest,
        Self::BackendResponse,
        Self::BackendError,
    ];

    /// Whether the phase's writable header map is the response's.
    ///
    /// This is the header map `headerplus` reads and commits, which is why
    /// its scope needs no state carried between statements: the phase decides
    /// it, and `init(scope)` is checked against it.
    pub(crate) fn writes_response_headers(self) -> bool {
        matches!(
            self,
            Self::BackendResponse | Self::BackendError | Self::Deliver | Self::Synth
        )
    }

    pub(crate) fn is_backend(self) -> bool {
        Self::BACKEND.contains(&self)
    }

    /// The symbol the compiled policy exports for the phase. The host maps
    /// each one to the VMOD callback `riscv.run()` invokes from the matching
    /// Varnish subroutine (`src/vcl/vcl_program.cpp`).
    pub(crate) fn hook(self) -> &'static str {
        match self {
            Self::Recv => "on_recv",
            Self::Hash => "on_hash",
            Self::Hit => "on_hit",
            Self::Miss => "on_miss",
            Self::Pass => "on_pass",
            Self::Deliver => "on_deliver",
            Self::Synth => "on_synth",
            Self::BackendRequest => "on_backend_fetch",
            Self::BackendResponse => "on_backend_response",
            Self::BackendError => "on_backend_error",
        }
    }

    pub(crate) fn vcl_name(self) -> &'static str {
        match self {
            Self::Recv => "vcl_recv",
            Self::Hash => "vcl_hash",
            Self::Hit => "vcl_hit",
            Self::Miss => "vcl_miss",
            Self::Pass => "vcl_pass",
            Self::Deliver => "vcl_deliver",
            Self::Synth => "vcl_synth",
            Self::BackendRequest => "vcl_backend_fetch",
            Self::BackendResponse => "vcl_backend_response",
            Self::BackendError => "vcl_backend_error",
        }
    }

    pub(crate) fn from_vcl_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|phase| phase.vcl_name() == name)
    }

    fn from_hook(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|phase| phase.hook() == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueType {
    String,
    Integer,
    Duration,
    Time,
    Boolean,
    /// A peer address, normalised to 16 bytes. Produced only by `client.ip`;
    /// compares against an ACL and converts implicitly to its text form.
    Ip,
}

impl From<ast::TypeName> for ValueType {
    fn from(value: ast::TypeName) -> Self {
        match value {
            ast::TypeName::String => Self::String,
            ast::TypeName::Integer => Self::Integer,
            ast::TypeName::Duration => Self::Duration,
            ast::TypeName::Time => Self::Time,
            ast::TypeName::Boolean => Self::Boolean,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocalId(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StaticId(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GlobalId(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AclId(pub(crate) u32);

/// The inline capacity of one `STRING` request global, in bytes.
///
/// A compiler constant, not a knob: a global's bytes live inside the region
/// the host copies at every phase boundary, so its size is fixed when the
/// program is compiled. A `set` that would exceed it traps at the VCL line.
pub const MAX_GLOBAL_STRING: u64 = 256;

/// The largest request-global region a program may declare, in bytes.
///
/// The host refuses the same total at engine construction
/// (`carapace_scripting::MAX_GUEST_GLOBALS`); refusing it here as well is what
/// lets a policy author see it before a reload does.
pub const MAX_REQUEST_GLOBALS: u64 = 8 * 1024;

/// Bytes one request global occupies in the region: an 8-byte scalar, or a
/// `STRING`'s 8-byte length followed by its inline buffer. Every slot is a
/// multiple of eight, so every slot is 8-byte aligned.
pub(crate) fn global_slot_size(value_type: ValueType) -> u64 {
    match value_type {
        ValueType::String => 8 + MAX_GLOBAL_STRING,
        ValueType::Integer
        | ValueType::Boolean
        | ValueType::Duration
        | ValueType::Time
        | ValueType::Ip => 8,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StringConversion {
    Integer,
    Duration,
    Time,
    Boolean,
    Ip,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhaseSet(BTreeSet<Phase>);

impl PhaseSet {
    pub fn contains(&self, hook: &str) -> bool {
        Phase::from_hook(hook).is_some_and(|phase| self.0.contains(&phase))
    }

    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.iter().copied().map(Phase::hook)
    }

    pub(crate) fn from_phases(phases: impl IntoIterator<Item = Phase>) -> Self {
        Self(phases.into_iter().collect())
    }

    /// Every phase, in the order [`PhaseSet::bits`] numbers them. The values
    /// are wire ABI between a sandboxed compiler guest and its host, so the
    /// order is fixed: append, never reorder.
    const ORDER: [Phase; 10] = [
        Phase::Recv,
        Phase::BackendRequest,
        Phase::BackendResponse,
        Phase::Deliver,
        Phase::Synth,
        Phase::Hash,
        Phase::Hit,
        Phase::Miss,
        Phase::Pass,
        Phase::BackendError,
    ];

    /// The set as a bitmask, for [`crate::wire`].
    pub fn bits(&self) -> u16 {
        Self::ORDER
            .iter()
            .enumerate()
            .filter(|(_, phase)| self.0.contains(phase))
            .fold(0, |bits, (index, _)| bits | 1 << index)
    }

    /// Inverse of [`PhaseSet::bits`]. Bits above the known phases are
    /// ignored: a host decoding a guest's answer must not be able to panic on
    /// one, and there is nothing for an unknown phase to mean.
    pub fn from_bits(bits: u16) -> Self {
        Self(
            Self::ORDER
                .into_iter()
                .enumerate()
                .filter(|(index, _)| bits & 1 << index != 0)
                .map(|(_, phase)| phase)
                .collect(),
        )
    }
}

/// What a `stat`-annotated static means to the exposition.
///
/// The discriminants are the `kind` column of a `.carapace.stats` row, so
/// they are the ABI (`src/vcl/vcl_stats.cpp` on the host side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatKind {
    Counter = 0,
    Gauge = 1,
    Max = 2,
    Min = 3,
}

impl StatKind {
    /// The annotation word, for a diagnostic and for the default help.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Max => "max",
            Self::Min => "min",
        }
    }

    pub(crate) fn from_word(word: &str) -> Option<Self> {
        match word {
            "counter" => Some(Self::Counter),
            "gauge" => Some(Self::Gauge),
            "max" => Some(Self::Max),
            "min" => Some(Self::Min),
            _ => None,
        }
    }
}

/// A statistic declared by a `stat` annotation, resolved to what the ELF row
/// carries: a kind and a help string. The help is never `None` past type
/// checking — an annotation with no string gets the derived default, which
/// must be reproducible from the declaration alone so two engines declaring
/// one name do not disagree about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatSpec {
    pub kind: StatKind,
    pub help: String,
}

/// The longest a statistic name may be. Both caps exist because the name and
/// the help reach a Varnish counter descriptor that lives for the process.
pub(crate) const MAX_STAT_NAME: usize = 64;

/// The longest a statistic description may be.
pub(crate) const MAX_STAT_HELP: usize = 200;

/// The most statistics a tenant may declare. Each is a Varnish counter that
/// lives for the process, in shared memory every tenant and `varnishstat`
/// use, so the host caps them too: per program, and per tenant across
/// reloads (`MAX_STATS` in src/vcl/vcl_stats.cpp).
pub(crate) const MAX_STATS: usize = 64;

/// Whether `name` matches the statistic name grammar, `[a-z][a-z0-9_]*` not
/// ending in `_`. Carapace's grammar, kept so a policy moves between the two
/// unchanged.
pub(crate) fn stat_name_ok(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !name.ends_with('_')
}
