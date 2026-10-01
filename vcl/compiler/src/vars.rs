//! The single VCL variable access table.
//!
//! Variable families with a `*` suffix match arbitrary HTTP header names.
//! Type checking and lowering both consume this table; no phase permission is
//! duplicated in either stage.

use crate::types::{Phase, ValueType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lowering {
    RequestHeader,
    ResponseHeader,
    RequestUrl,
    RequestMethod,
    Now,
    ClientIp,
    Ttl,
    StaleWhileRevalidate,
    StaleIfError,
    Uncacheable,
    CacheHit,
    /// `resp.body` in vcl_synth and `beresp.body` in vcl_backend_error: a
    /// write replaces the synthetic body, as `synthetic()` appends to it.
    Body,
    /// A variable the host reads and writes through the generic variable
    /// calls, by number. See [`HostVar`].
    Host(HostVar),
}

/// A Varnish variable the host answers by number, through
/// `TYPED_VAR_GET`/`TYPED_VAR_SET` (`src/vcl/abi.hpp`).
///
/// The numbers are ABI: the host's table in `src/vcl/vcl_varnish.c` uses
/// the same ones, and also gates each by the Varnish subroutine running, so
/// a variable is never read where Varnish's own accessor would assert. A
/// `DURATION` crosses as nanoseconds and a `BOOL` as 0 or 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostVar {
    /// The method of the request side's header map: `req.method` or
    /// `bereq.method`. Only written through this; read with
    /// `req_get_method`.
    Method = 1,
    /// `req.xid` or `bereq.xid`.
    Xid = 2,
    Restarts = 3,
    EsiLevel = 4,
    CanGzip = 5,
    HashAlwaysMiss = 6,
    HashIgnoreBusy = 7,
    BereqRetries = 8,
    BereqUncacheable = 9,
    BereqIsBgfetch = 10,
    BerespStatus = 11,
    BerespReason = 12,
    BerespDoStream = 13,
    BerespDoGzip = 14,
    BerespDoGunzip = 15,
    BerespAge = 16,
    BerespUncacheable = 17,
    ObjStatus = 18,
    ObjReason = 19,
    ObjHits = 20,
    ObjTtl = 21,
    ObjGrace = 22,
    ObjKeep = 23,
    ObjAge = 24,
    ObjUncacheable = 25,
    RespStatus = 26,
    RespReason = 27,
    ServerHostname = 28,
    ServerIdentity = 29,
    /// `req.proto` or `bereq.proto`.
    RequestProto = 30,
    /// `resp.proto` or `beresp.proto`.
    ResponseProto = 31,
    ObjProto = 32,
}

impl HostVar {
    pub(crate) fn abi_id(self) -> i64 {
        self as i64
    }
}

/// Identity-specific restrictions on writes to a variable family.
///
/// Phase permissions and value types are not enough for HTTP framing, the
/// routing-owned Host header, or the one-way uncacheable flag. Keeping those
/// facts in the variable row prevents the checker from growing a parallel
/// list keyed by variable spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteConstraint {
    None,
    Header,
    /// `req.http.*`: never `Host`, which picked the tenant, and in vcl_recv
    /// never a route's variant header.
    ClientRequestHeader,
    TrueOnly,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VariableSpec {
    pub pattern: &'static str,
    pub value_type: ValueType,
    pub readable: &'static [Phase],
    pub writable: &'static [Phase],
    pub lowering: Lowering,
    pub write_constraint: WriteConstraint,
}

include!("vcl_vars.def");

pub(crate) fn is_framing_header(name: &str) -> bool {
    FRAMING_HEADERS
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

pub(crate) fn resolve(name: &str) -> Option<(&'static VariableSpec, Option<&str>)> {
    VARIABLES.iter().find_map(|spec| {
        if let Some(prefix) = spec.pattern.strip_suffix('*') {
            name.strip_prefix(prefix)
                .filter(|suffix| !suffix.is_empty())
                .map(|suffix| (spec, Some(suffix)))
        } else if name == spec.pattern {
            Some((spec, None))
        } else {
            None
        }
    })
}
