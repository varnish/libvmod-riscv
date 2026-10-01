//! The one place the compiler knows what a vmod module is.
//!
//! `cookieplus`, `urlplus` and `headerplus` are the same mechanism three
//! times: a per-hook working state held in a string local, seeded once at
//! hook entry, read and mutated through runtime routines, and written back
//! through the host syscalls that already exist.  Before this module they
//! were three near-copies -- of the IR ops, of the emitter, of the reference
//! interpreter, of the liveness walk -- and the copies had already drifted
//! apart: each had invented its own packing for the operation word, and no
//! two agreed on where a range argument lived.
//!
//! So the rule for the next module is: add a [`Module`] variant and a row per
//! function in `typecheck.rs`'s `VMODS`.  If that is not enough, the missing
//! piece belongs *here*, shared, and not as a fourth copy in `codegen.rs`.

use vcl_rt::Routine;

/// A vmod whose per-hook state is a list of records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Module {
    Cookieplus,
    /// The `setcookie_*` half of cookieplus.  It is a module of its own
    /// rather than a second operation set on [`Module::Cookieplus`] because
    /// it is a second *state*: a different list, from a different source,
    /// written back a different way.  The VCL name is still `cookieplus`.
    Setcookie,
    Urlplus,
    Headerplus,
    /// The seven RFC 3986 components of one URI.  It is the first module
    /// whose state is a fixed vector rather than a list the VCL can grow,
    /// and the first whose implicit source is two host reads instead of one;
    /// both differences are absorbed here and in [`vcl_rt`], not in
    /// the emitter.
    Uri,
}

/// Which of a module's three runtime routines a call reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Routines {
    /// A string result with a fallback when the value is absent.
    Read,
    /// An integer result.
    Count,
    /// A state in, a state out.
    Transform,
}

impl Module {
    pub(crate) fn vcl_name(self) -> &'static str {
        match self {
            Module::Cookieplus | Module::Setcookie => "cookieplus",
            Module::Urlplus => "urlplus",
            Module::Headerplus => "headerplus",
            Module::Uri => "uri",
        }
    }

    /// The runtime jump-table entry for one kind of call, or `None` when the
    /// module has no call of that kind.
    ///
    /// The triples are grouped in `Routine` so this stays a table rather than
    /// nine separate constants that a new module would have to be threaded
    /// through by hand.  `uri` is the module that breaks the triple: the vmod
    /// exposes no INT function, so `VMODS` holds no `Shape::Count` row for
    /// it and no caller ever asks for one.
    pub(crate) fn routine(self, kind: Routines) -> Option<Routine> {
        Some(match (self, kind) {
            (Module::Cookieplus, Routines::Read) => Routine::CookieRead,
            (Module::Cookieplus, Routines::Count) => Routine::CookieCount,
            (Module::Cookieplus, Routines::Transform) => Routine::CookieTransform,
            (Module::Setcookie, Routines::Read) => Routine::SetcookieRead,
            (Module::Setcookie, Routines::Count) => Routine::SetcookieCount,
            (Module::Setcookie, Routines::Transform) => Routine::SetcookieTransform,
            (Module::Urlplus, Routines::Read) => Routine::UrlRead,
            (Module::Urlplus, Routines::Count) => Routine::UrlCount,
            (Module::Urlplus, Routines::Transform) => Routine::UrlTransform,
            (Module::Headerplus, Routines::Read) => Routine::HeaderRead,
            (Module::Headerplus, Routines::Count) => Routine::HeaderCount,
            (Module::Headerplus, Routines::Transform) => Routine::HeaderTransform,
            (Module::Uri, Routines::Read) => Routine::UriRead,
            (Module::Uri, Routines::Transform) => Routine::UriTransform,
            (Module::Uri, Routines::Count) => return None,
        })
    }

    /// The transform operation that turns the module's *source* into a state.
    ///
    /// The transform routine takes a state for every operation but this one,
    /// whose input is the string the state is parsed from.
    pub(crate) fn parse_op(self) -> u8 {
        match self {
            Module::Cookieplus => vcl_rt::CookieOp::Parse as u8,
            Module::Setcookie => vcl_rt::SetcookieOp::Parse as u8,
            Module::Urlplus => vcl_rt::UrlOp::Parse as u8,
            Module::Headerplus => vcl_rt::HeaderOp::Parse as u8,
            Module::Uri => vcl_rt::UriOp::Parse as u8,
        }
    }

    /// The record projection a `_regex` form matches against, as the
    /// operation word of this module's record-list read.
    ///
    /// The projection and the routine that applies the bitmap live next to
    /// each other in `vcl-rt`; all the compiler owns is which one to
    /// ask for.
    ///
    /// `None` is a module with no `_regex` form, which for `uri` is every
    /// function it has: the vmod matches no patterns.
    pub(crate) fn select_code(self, set: RecordSet) -> Option<i64> {
        let read = match self {
            Module::Cookieplus => vcl_rt::CookieRead::Records as u8,
            Module::Setcookie => vcl_rt::SetcookieRead::Records as u8,
            Module::Urlplus => vcl_rt::UrlRead::Records as u8,
            Module::Headerplus => vcl_rt::HEADER_READ_RECORDS,
            Module::Uri => return None,
        };
        let code = vcl_rt::OpCode::new(read);
        Some(
            match set {
                RecordSet::Whole => code,
                RecordSet::Segments => {
                    code.with_extra(vcl_rt::url_extra(0, 0, vcl_rt::PART_URL))
                }
                RecordSet::Queries => code.with_extra(vcl_rt::url_extra(
                    0,
                    0,
                    vcl_rt::PART_QUERY,
                )),
            }
            .encode(),
        )
    }

    /// How `write()` gets this module's state back out.
    pub(crate) fn commit(self) -> Commit {
        match self {
            Module::Cookieplus | Module::Urlplus => Commit::String,
            Module::Headerplus => Commit::Headers,
            Module::Setcookie => Commit::RenderedHeaders,
            Module::Uri => Commit::HostAndUrl,
        }
    }

    /// The VCL spelling of this module's `write()`, for a diagnostic.
    pub(crate) fn write_call(self) -> &'static str {
        match self {
            Module::Cookieplus => "cookieplus.write()",
            Module::Setcookie => "cookieplus.setcookie_write()",
            Module::Urlplus => "urlplus.write()",
            Module::Headerplus => "headerplus.write()",
            Module::Uri => "uri.write()",
        }
    }

    /// Where the hook prologue reads this module's state from, or `None`
    /// when the state is built in the IR instead.
    ///
    /// `uri` is the `None`. Its implicit source is the request's `Host`
    /// *and* its URL -- the vmod glues them into `//host` + url -- which is
    /// two host reads and a join, where `Op::ModuleInit` reads one string
    /// into one scratch slot. Assembling it from the ops the IR already has
    /// costs `seed_state` a branch and the emitter nothing.
    pub(crate) fn source(self) -> Option<Source> {
        Some(match self {
            Module::Cookieplus => Source::RequestHeader("Cookie"),
            Module::Setcookie => Source::NamedHeaderSnapshot("Set-Cookie"),
            Module::Urlplus => Source::RequestUrl,
            Module::Headerplus => Source::HeaderSnapshot,
            Module::Uri => return None,
        })
    }
}

/// How a module's `write()` stores its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Commit {
    /// Render the state to a string and store it with an ordinary setter, so
    /// the host sees what `set req.http.Cookie` or a URL rewrite would.
    String,
    /// Build the guest header vector from the state as it stands.
    Headers,
    /// Transform the state into a header-shaped one first -- one entry of the
    /// target header per surviving record -- and commit that.  It is the only
    /// way to write a header more than once: the host has a setter and a
    /// commit, and no adder.
    RenderedHeaders,
    /// Render the authority into the `Host` header and the rest into the
    /// URL, which is the pair `vmod_write()` replaces. It is two stores
    /// rather than one because the vmod's state spans both, and it is the
    /// only reason a write needs more than the state's own rendering.
    HostAndUrl,
}

/// The sub-list a `_regex` form matches its patterns against.
///
/// urlplus interleaves two lists in one state, so the projection needs to say
/// which; the other two modules have exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordSet {
    /// The module's only list: the cookie pairs, or the live header list.
    Whole,
    /// urlplus path segments.
    Segments,
    /// urlplus query pairs.
    Queries,
}

/// The list-shaped regex step a `_regex` form runs before its own routine.
///
/// Every one of them is the same three straight-line steps -- project, match,
/// apply -- so the frontend carries them as data on the call rather than as a
/// lowering per function. See `ir::Op::RegexMatchList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegexSelect {
    /// The record-projection read that renders the sub-list being matched.
    pub(crate) select: i64,
    /// The pattern literals, in bitmap-slot order.  A form with two patterns
    /// hands both bitmaps to its routine in one argument, at the fixed stride
    /// `vcl_rt::REGEX_BITMAP_STRIDE`.
    pub(crate) patterns: Vec<String>,
    /// Bit `i` set: pattern `i` matches the record *value* rather than its
    /// name.  This is the host descriptor's field selector, one bit a slot.
    pub(crate) value_fields: u8,
}

/// The string a module's state is parsed from at hook entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// One request header, read with the ordinary single-value syscall.
    RequestHeader(&'static str),
    /// `req.url` or `bereq.url`, whichever the phase has.
    RequestUrl,
    /// The packed record stream of `headers_snapshot`, which is the only
    /// call that can see more than the first header of a name.
    HeaderSnapshot,
    /// The same stream filtered to one header name, which is what a
    /// multi-valued `Set-Cookie` needs and what `setcookie_parse(header)`
    /// points somewhere else.
    NamedHeaderSnapshot(&'static str),
}

impl Source {
    /// The header map this source reads, when the module fixes it rather than
    /// following the phase.
    ///
    /// Only `headerplus` follows the phase, because `init(scope)` is what
    /// names its map. A `Set-Cookie` is a response header in every phase the
    /// family is legal in -- including `vcl_synth`, which is inlined into
    /// `on_recv`, whose *writable* map is the request's.
    pub(crate) fn response_map(self) -> Option<bool> {
        match self {
            Source::NamedHeaderSnapshot(_) => Some(true),
            Source::RequestHeader(_) | Source::RequestUrl | Source::HeaderSnapshot => None,
        }
    }
}
