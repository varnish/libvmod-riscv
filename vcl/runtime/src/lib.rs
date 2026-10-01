//! The small, allocation-free routines shared by the VCL reference
//! interpreter and the RV64 runtime image.
//!
//! The crate deliberately accepts bytes at its boundary: VCL strings are
//! UTF-8, but these numeric parsers only need their ASCII subset.  Keeping
//! that boundary byte-oriented makes the guest entry points simple and keeps
//! malformed input an ordinary fallback rather than a guest fault.
//!
//! # The entry-point contract
//!
//! Every `rt_*` symbol is a guest entry point that takes its arguments as
//! pointer/length pairs, which is why each one is `unsafe`: a pair must
//! describe a slice of exactly that length -- readable, or writable where
//! the pair is an output buffer and its capacity.
//!
//! A null pointer is allowed only with a length of zero, and only at the
//! entry points that go through `raw_bytes`.  That is not a courtesy: the
//! sizing pass of the measure-then-fill protocol passes a null output
//! buffer, and it is how a zero-length string reaches a routine, so the
//! boundary rule lives in one function rather than in twenty-seven.  The
//! handful that call `core::slice::from_raw_parts` directly want a real
//! pointer even for an empty slice, and each records why in its own
//! comment.

#![no_std]

/// Bump when the fixed runtime-image ABI changes.
///
/// `vcl-compiler` verifies the word directly after the jump table before it
/// copies the load segment into a policy ELF.
pub const IMAGE_VERSION: u32 = 6;

// A zero-length C ABI string is represented by a null pointer in the
// compiler's sizing calls. Rust still requires a non-null pointer for
// `from_raw_parts`, even when the length is zero, so keep that boundary rule
// in one place for every guest entry point.
unsafe fn raw_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

unsafe fn raw_bytes_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
}

/// A routine refused the operation.
///
/// The routines here carry no error detail because there is none to carry: a
/// refusal is one thing, a phase failure at the VCL line, and every function
/// that can produce one documents its single cause.  The type exists so that
/// is what the signature says, rather than a `()` a caller has to read the
/// prose to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseFailure;

/// The largest number of records one module state may hold.
///
/// The ceiling is what bounds both the runtime's stack frame and its
/// instruction count by construction: every list routine is one pass over at
/// most this many records.  Exceeding it is a phase failure at the VCL line,
/// never a truncated URL or header sent onward.
pub const MAX_LIST_ITEMS: usize = 256;

/// The width of an RFC 7231 HTTP-date, which is fixed: `time_format` writes
/// exactly this many bytes, and `setcookie_add` sizes its buffer by it.
pub const TIME_FORMAT_LEN: usize = 29;

/// The fixed width of one match bitmap inside a regex routine's argument.
///
/// Every `_regex` form of the three list-shaped vmods is the same three
/// steps: project the module's records as the packed list the host's
/// list-regex sub-commands read, cross once per pattern, and apply the
/// bitmaps that come back.  A bitmap reaches the applying routine in the one
/// argument the routine ABI carries, so a form with two patterns needs the
/// second bitmap to start where both sides already agree it starts.  A state
/// holds at most [`MAX_LIST_ITEMS`] records, so a bitmap over one is never
/// wider than this: fixing the stride costs a few unused bytes of arena and
/// saves a length word and its decoder.
pub const REGEX_BITMAP_STRIDE: usize = MAX_LIST_ITEMS / 8;

/// Whether the record at `index` of a projected list matched pattern `slot`.
///
/// A bit past the argument reads as "did not match".  The host writes only
/// the bytes a bitmap of that record count needs, so this is what keeps a
/// routine from reading a stale arena byte as a match if the two ever
/// disagreed about the list length.
fn matched(bitmaps: &[u8], slot: usize, index: usize) -> bool {
    let at = slot * REGEX_BITMAP_STRIDE + index / 8;
    bitmaps
        .get(at)
        .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

/// A bounded, allocation-free byte sink.
///
/// Every serialising routine writes through one of these, and the reason is
/// the measure-then-fill protocol the compiler emits: a sizing call passes
/// `cap = 0` and a filling call passes the length the sizing call returned.
/// Both calls run the *same* code here -- the writer always counts and copies
/// only while the bytes fit -- so the two passes cannot disagree about a
/// length the way a hand-written counting twin can.  It also means a routine
/// needs no scratch buffer of its own to measure into.
pub struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    pub fn byte(&mut self, byte: u8) {
        if let Some(slot) = self.out.get_mut(self.at) {
            *slot = byte;
        }
        self.at = self.at.saturating_add(1);
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        if let Some(slot) = self
            .at
            .checked_add(bytes.len())
            .and_then(|end| self.out.get_mut(self.at..end))
        {
            slot.copy_from_slice(bytes);
        }
        self.at = self.at.saturating_add(bytes.len());
    }

    /// Write `bytes` with an ASCII case mapping applied.
    ///
    /// ASCII only, because that is the mapping `std.tolower` and
    /// `urlplus.tolower` perform: a VCL string is UTF-8, but Varnish maps
    /// only the bytes below 0x80, and matching that keeps a multi-byte
    /// sequence intact rather than half-converted.
    pub fn bytes_case(&mut self, bytes: &[u8], case: Case) {
        match case {
            Case::Keep => self.bytes(bytes),
            Case::Lower => {
                for byte in bytes {
                    self.byte(byte.to_ascii_lowercase());
                }
            }
            Case::Upper => {
                for byte in bytes {
                    self.byte(byte.to_ascii_uppercase());
                }
            }
        }
    }

    pub fn decimal(&mut self, mut value: usize) {
        let mut digits = [0u8; 20];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        while count > 0 {
            count -= 1;
            self.byte(digits[count]);
        }
    }

    /// The number of bytes the output needs, whether or not they all fit.
    pub fn finish(self) -> usize {
        self.at
    }
}

/// The packed operation word every list routine takes in `a2`.
///
/// One encoder and one decoder, shared by the compiler, the reference
/// interpreter and the RV64 image.  Earlier drafts packed these fields at
/// three separate call sites and the three disagreed about where `start`
/// lived; a single type is what makes that class of bug unrepresentable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpCode {
    /// Which operation, from the per-module `*Op` enums.
    pub op: u8,
    /// Operation-specific booleans; see the `flag` constants.
    pub flags: u8,
    /// First index argument: a position, a range start, or an occurrence.
    pub first: i16,
    /// Second index argument: a range end.
    pub second: i16,
    /// Packed enum arguments, whose meaning is per operation.
    pub extra: u16,
}

/// `OpCode::flags` bits.  Each carries the VCL parameter of the same name for
/// the operations that have one, and is zero everywhere else.
pub mod flag {
    /// `keep`: the record this call adds is marked keep.
    pub const KEEP: u8 = 1 << 0;
    /// `delete_keep`: the call also removes records marked keep.
    pub const DELETE_KEEP: u8 = 1 << 1;
    /// `all`: the call affects every match rather than the first.
    pub const ALL: u8 = 1 << 2;
    /// `override`: an add replaces an existing record of the same name.
    pub const OVERRIDE: u8 = 1 << 3;
    /// The read wants the last match rather than the first.
    pub const LAST: u8 = 1 << 4;
    /// `sort_query`: a rendered query is sorted bytewise by pair.
    pub const SORT_QUERY: u8 = 1 << 5;
    /// `query_keep_equal_sign`: an empty value keeps the `=` it was parsed
    /// with.
    pub const KEEP_EQUAL_SIGN: u8 = 1 << 6;
    /// A case conversion maps to upper case rather than lower.
    pub const UPPER: u8 = 1 << 7;
}

impl OpCode {
    pub const fn new(op: u8) -> Self {
        Self {
            op,
            flags: 0,
            first: 0,
            second: 0,
            extra: 0,
        }
    }

    pub const fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub const fn with_range(mut self, first: i16, second: i16) -> Self {
        self.first = first;
        self.second = second;
        self
    }

    pub const fn with_extra(mut self, extra: u16) -> Self {
        self.extra = extra;
        self
    }

    pub const fn encode(self) -> i64 {
        (self.op as i64)
            | ((self.flags as i64) << 8)
            | (((self.first as u16) as i64) << 16)
            | (((self.second as u16) as i64) << 32)
            | ((self.extra as i64) << 48)
    }

    pub const fn decode(word: i64) -> Self {
        Self {
            op: word as u8,
            flags: (word >> 8) as u8,
            first: (word >> 16) as i16,
            second: (word >> 32) as i16,
            extra: (word >> 48) as u16,
        }
    }

    pub const fn has(self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Record flags in a serialised module state.
pub mod record {
    /// The record is marked keep, and survives a keep-mode write.
    pub const KEEP: u8 = 1 << 0;
    /// The record is marked deleted and no longer participates.
    pub const DELETED: u8 = 1 << 1;
    /// The record's *name* was written to during this hook.  headerplus
    /// replays only touched names, so this is what keeps an untouched
    /// header's duplicates and transport order intact.
    pub const TOUCHED: u8 = 1 << 2;
    /// urlplus: the record is a query parameter rather than a path segment.
    pub const QUERY: u8 = 1 << 3;
    /// urlplus: the query parameter carried an `=` in the source URL, which
    /// `a=` must keep and `a` must not gain.
    pub const EQUALS: u8 = 1 << 4;
    /// uri: the record's value still owes the percent-encoding of its own
    /// component, which `uri_write` applies when the state is next
    /// serialised.  A record cannot be rewritten in place -- its value is a
    /// borrowed slice of the state it was parsed from -- so an encoding is
    /// carried the way a case mapping is, as one bit and no buffer.
    pub const ENCODE: u8 = 1 << 5;
    /// uri: as above, for the safe normalisation of RFC 3986 Section 6.
    pub const NORMALIZE: u8 = 1 << 6;
}

/// List-level flags in a serialised module state, held in its prelude.
pub mod list {
    /// urlplus: the path began with `/`.
    pub const LEADING_SLASH: u8 = 1 << 0;
    /// urlplus: the path ended with `/`.
    pub const TRAILING_SLASH: u8 = 1 << 1;
    /// A `keep`-family call has switched the path segments into keep mode:
    /// a write drops every segment not marked keep.
    pub const SEGMENT_KEEP_MODE: u8 = 1 << 2;
    /// As above, for query parameters and for a header list.
    pub const KEEP_MODE: u8 = 1 << 3;
}

/// An ASCII case mapping a record still owes its bytes.
///
/// `urlplus.tolower()` cannot rewrite a record in place: every record is a
/// borrowed slice of the state string it was parsed from, and this crate
/// allocates nothing.  Recording the mapping and applying it when the bytes
/// are next written costs one byte of state and no buffer at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Case {
    #[default]
    Keep,
    Lower,
    Upper,
}

/// One (name, value, flags) record of a module's per-hook working state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Record<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
    pub flags: u8,
    pub case: Case,
}

impl Record<'_> {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn write_name(&self, out: &mut Writer<'_>) {
        out.bytes_case(self.name, self.case);
    }

    pub fn write_value(&self, out: &mut Writer<'_>) {
        out.bytes_case(self.value, self.case);
    }

    /// Write a slice of this record's own bytes under its case mapping.
    pub fn write_slice(&self, bytes: &[u8], out: &mut Writer<'_>) {
        out.bytes_case(bytes, self.case);
    }
}

/// The working state of a list-shaped vmod module, decoded from its string.
///
/// Both urlplus and headerplus hold their per-hook state in an ordinary
/// string local, so it lives in the same arena as every other string, dies
/// with the hook the way V4 requires, and can be read in a fault report
/// without a decoder.  The encoding is therefore ASCII-framed rather than
/// binary: `list_flags ';'` followed by `flags ',' name_len ',' value_len ','
/// name value` per record.  Names and values are copied through byte for
/// byte, so the state is valid UTF-8 exactly when its inputs were.
pub struct ListState<'a> {
    pub flags: u8,
    pub records: [Record<'a>; MAX_LIST_ITEMS],
    pub count: usize,
}

impl<'a> ListState<'a> {
    pub fn empty() -> Self {
        Self {
            flags: 0,
            records: [Record::default(); MAX_LIST_ITEMS],
            count: 0,
        }
    }

    /// Decode a state string.  `None` means the string was not produced by
    /// [`ListState::write`], which the compiler's own lowering makes
    /// impossible; the guest reports it as a phase failure rather than
    /// guessing at a repair.
    pub fn parse(mut input: &'a [u8]) -> Option<Self> {
        let mut state = Self::empty();
        let (flags, rest) = split_number(input, b';')?;
        state.flags = u8::try_from(flags).ok()?;
        input = rest;
        while !input.is_empty() {
            let (flags, rest) = split_number(input, b',')?;
            let (name_len, rest) = split_number(rest, b',')?;
            let (value_len, rest) = split_number(rest, b',')?;
            let name_end = name_len;
            let value_end = name_end.checked_add(value_len)?;
            let name = rest.get(..name_end)?;
            let value = rest.get(name_end..value_end)?;
            state.push(Record {
                name,
                value,
                flags: u8::try_from(flags).ok()?,
                case: Case::Keep,
            })?;
            input = rest.get(value_end..)?;
        }
        Some(state)
    }

    pub fn push(&mut self, entry: Record<'a>) -> Option<()> {
        *self.records.get_mut(self.count)? = entry;
        self.count += 1;
        Some(())
    }

    pub fn insert(&mut self, at: usize, entry: Record<'a>) -> Option<()> {
        if self.count >= MAX_LIST_ITEMS {
            return None;
        }
        let at = at.min(self.count);
        self.records.copy_within(at..self.count, at + 1);
        self.records[at] = entry;
        self.count += 1;
        Some(())
    }

    pub fn entries(&self) -> &[Record<'a>] {
        &self.records[..self.count]
    }

    pub fn entries_mut(&mut self) -> &mut [Record<'a>] {
        &mut self.records[..self.count]
    }

    /// Drop every record the predicate rejects, preserving order.
    ///
    /// urlplus deletes remove a record outright, because its positions are
    /// indexes into the surviving list.  headerplus instead marks a record
    /// deleted, because its `write()` needs the *name* to survive in order to
    /// know the name must go.
    pub fn retain(&mut self, mut keep: impl FnMut(&Record<'a>) -> bool) {
        let mut kept = 0;
        for index in 0..self.count {
            if keep(&self.records[index]) {
                self.records[kept] = self.records[index];
                kept += 1;
            }
        }
        self.count = kept;
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Serialise back to the string form [`ListState::parse`] reads.
    pub fn write(&self, out: &mut Writer<'_>) {
        out.decimal(usize::from(self.flags));
        out.byte(b';');
        for entry in self.entries() {
            out.decimal(usize::from(entry.flags));
            out.byte(b',');
            out.decimal(entry.name.len());
            out.byte(b',');
            out.decimal(entry.value.len());
            out.byte(b',');
            entry.write_name(&mut *out);
            entry.write_value(&mut *out);
        }
    }
}

/// Whether a record survives a list-wide keep mode.
///
/// urlplus needs [`kept`] instead: its state interleaves two sub-lists with a
/// keep mode each.
fn kept_in_mode(state: &ListState<'_>, entry: &Record<'_>) -> bool {
    !state.has(list::KEEP_MODE) || entry.has(record::KEEP)
}

/// Render the records a regex form matches against, in the packed layout the
/// host's `headers_snapshot`, `regex_match_list` and `regex_sub_list`
/// sub-commands share: `u32 name_len, u32 value_len, name, value`.
///
/// The projection and the routine that applies the bitmap walk the same
/// predicate in the same order.  That is the whole contract behind bit `i`
/// meaning record `i`, so the two loops belong next to each other in one
/// module rather than in a compiler emitter and a routine.
fn write_records<'a>(
    state: &ListState<'a>,
    selected: impl Fn(&Record<'a>) -> bool,
    out: &mut Writer<'_>,
) {
    for entry in state.entries() {
        if !selected(entry) {
            continue;
        }
        out.bytes(&(entry.name.len() as u32).to_le_bytes());
        out.bytes(&(entry.value.len() as u32).to_le_bytes());
        entry.write_name(&mut *out);
        entry.write_value(&mut *out);
    }
}

/// A guest entry point that produces a string.
pub type StringEntry =
    unsafe extern "C" fn(*const u8, usize, i64, *const u8, usize, *mut u8, usize) -> i64;

/// A guest entry point that produces an integer.
pub type CountEntry = unsafe extern "C" fn(*const u8, usize, i64, *const u8, usize) -> i64;

impl Routine {
    /// The string-producing entry point for a routine, for callers that hold
    /// a [`Routine`] rather than a symbol.
    ///
    /// The VCL reference interpreter dispatches through this so it runs the
    /// same entry points the RV64 image exposes, marshalling included, rather
    /// than reaching past them to the inner functions.
    pub fn string_entry(self) -> Option<StringEntry> {
        Some(match self {
            Routine::CookieRead => rt_cookie_read,
            Routine::CookieTransform => rt_cookie_transform,
            Routine::SetcookieRead => rt_setcookie_read,
            Routine::SetcookieTransform => rt_setcookie_transform,
            Routine::UrlRead => rt_url_read,
            Routine::UrlTransform => rt_url_transform,
            Routine::HeaderRead => rt_header_read,
            Routine::HeaderTransform => rt_header_transform,
            Routine::UriRead => rt_uri_read,
            Routine::UriTransform => rt_uri_transform,
            Routine::Collect => rt_collect,
            _ => return None,
        })
    }

    /// The integer-producing entry point for a routine.
    pub fn count_entry(self) -> Option<CountEntry> {
        Some(match self {
            Routine::CookieCount => rt_cookie_count,
            Routine::SetcookieCount => rt_setcookie_count,
            Routine::UrlCount => rt_url_count,
            Routine::HeaderCount => rt_header_count,
            _ => return None,
        })
    }
}

/// Read one ASCII decimal field up to `terminator`.
fn split_number(input: &[u8], terminator: u8) -> Option<(usize, &[u8])> {
    let end = input.iter().position(|byte| *byte == terminator)?;
    let digits = input.get(..end)?;
    if digits.is_empty() {
        return None;
    }
    let mut value = 0usize;
    for byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(usize::from(byte - b'0'))?;
    }
    Some((value, input.get(end + 1..)?))
}

fn split_at_byte(value: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let at = value.iter().position(|candidate| *candidate == byte)?;
    Some((&value[..at], &value[at + 1..]))
}

/// Split a compiler-built `name\0value` argument.  A call whose VCL signature
/// has one string argument passes it whole and gets an empty value back.
fn name_and_value(argument: &[u8]) -> (&[u8], &[u8]) {
    split_at_byte(argument, 0).unwrap_or((argument, &[]))
}

/// A callable entry in the RV64 runtime image's fixed jump table.
///
/// This is shared by the host compiler and the freestanding image so adding a
/// routine cannot silently change the two sides' table order.
///
/// The three list-shaped modules present the same `read`/`count`/`transform`
/// triple, in the same order, because the compiler emits one call sequence
/// per *kind* rather than one per module.  Keep that grouping when adding a
/// module: it is what stops the emitter from growing a fourth near-copy.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routine {
    IntParse = 0,
    DurationParse = 1,
    TimeParse = 2,
    TimeFormat = 3,
    Fnmatch = 4,
    Querysort = 5,
    CookieRead = 6,
    CookieCount = 7,
    CookieTransform = 8,
    UrlRead = 9,
    UrlCount = 10,
    UrlTransform = 11,
    HeaderRead = 12,
    HeaderCount = 13,
    HeaderTransform = 14,
    HeaderCommit = 15,
    Collect = 16,
    AclMatch = 17,
    IpFormat = 18,
    StrTest = 19,
    StrEdit = 20,
    StrSplit = 21,
    SetcookieRead = 22,
    SetcookieCount = 23,
    SetcookieTransform = 24,
    UriRead = 25,
    UriTransform = 26,
}

impl Routine {
    pub const COUNT: usize = 27;
}

/// A cookieplus state mutation.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieOp {
    /// Parse a `Cookie` field into a state.  The routine input is the field,
    /// not a state.
    Parse = 0,
    /// `keep(name)`: retain only cookies of this name.
    Keep = 1,
    /// `delete(name, delete_keep)`.
    Delete = 2,
    /// `add(name, value, keep, override)`; the argument is `name\0value`.
    Add = 3,
    /// `keep_regex(regex)`.  The argument is the match bitmap over the cookie
    /// list, not a name.
    KeepRegex = 4,
    /// `delete_regex(regex, delete_keep)`, likewise.
    DeleteRegex = 5,
}

/// A cookieplus read.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieRead {
    /// `get(name, default, occurrence)`; `flag::LAST` picks the last match.
    Get = 0,
    /// `as_string()`, and the value `write()` stores in the `Cookie` field.
    AsString = 1,
    /// The packed record list the `_regex` forms match against.
    Records = 2,
    /// `get_regex(regex, default)`: the value of the first cookie whose name
    /// the bitmap selects.
    GetRegex = 3,
}

/// Parse a `Cookie` field the way `cookie_parse()` in `vmod_cookieplus.c`
/// does: leading bytes at or below a space are trimmed from a name, a pair
/// with no `=` is dropped, and trailing whitespace stays inside a value.
pub fn cookie_parse(input: &[u8]) -> Option<ListState<'_>> {
    let mut state = ListState::empty();
    for part in input.split(|byte| *byte == b';') {
        let part = trim_start_ascii(part);
        let Some((name, value)) = split_at_byte(part, b'=') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        state.push(Record {
            name,
            value,
            flags: 0,
            case: Case::Keep,
        })?;
    }
    Some(state)
}

pub fn cookie_transform<'a>(
    state: &mut ListState<'a>,
    code: OpCode,
    argument: &'a [u8],
) -> Result<(), PhaseFailure> {
    let (name, value) = name_and_value(argument);
    if code.op == CookieOp::Keep as u8 || code.op == CookieOp::KeepRegex as u8 {
        // Keep mode is enabled even by an empty name, or by a pattern that
        // selects nothing: that is how a policy says "drop everything but
        // what I name next", and it is what lets two keeps accumulate rather
        // than the second one emptying the list.
        state.flags |= list::KEEP_MODE;
        if code.op == CookieOp::KeepRegex as u8 {
            for (index, entry) in state.entries_mut().iter_mut().enumerate() {
                if matched(argument, 0, index) {
                    entry.flags |= record::KEEP;
                }
            }
        } else if !name.is_empty() {
            for entry in state.entries_mut() {
                if entry.name == name {
                    entry.flags |= record::KEEP;
                }
            }
        }
        return Ok(());
    }
    if code.op == CookieOp::Delete as u8 {
        let delete_keep = code.has(flag::DELETE_KEEP);
        state.retain(|entry| entry.name != name || (!delete_keep && entry.has(record::KEEP)));
        return Ok(());
    }
    if code.op == CookieOp::DeleteRegex as u8 {
        let delete_keep = code.has(flag::DELETE_KEEP);
        let mut index = 0;
        state.retain(|entry| {
            let selected = matched(argument, 0, index);
            index += 1;
            !selected || (!delete_keep && entry.has(record::KEEP))
        });
        return Ok(());
    }
    if code.op == CookieOp::Add as u8 {
        if name.is_empty() {
            return Ok(());
        }
        if code.has(flag::OVERRIDE) {
            state.retain(|entry| entry.name != name);
        }
        let flags = if code.has(flag::KEEP) {
            record::KEEP
        } else {
            0
        };
        return state
            .push(Record {
                name,
                value,
                flags,
                case: Case::Keep,
            })
            .ok_or(PhaseFailure);
    }
    Err(PhaseFailure)
}

pub fn cookie_read(
    state: &ListState<'_>,
    code: OpCode,
    argument: &[u8],
    out: &mut Writer<'_>,
) -> bool {
    if code.op == CookieRead::AsString as u8 {
        cookie_write(state, out);
        return true;
    }
    if code.op == CookieRead::Records as u8 {
        write_records(state, |_| true, out);
        return true;
    }
    if code.op == CookieRead::GetRegex as u8 {
        // The vmod answers the first match and has no occurrence selector
        // here, unlike `get`.
        for (index, entry) in state.entries().iter().enumerate() {
            if matched(argument, 0, index) {
                entry.write_value(out);
                return true;
            }
        }
        return false;
    }
    let mut found = None;
    for entry in state.entries() {
        if entry.name != argument {
            continue;
        }
        found = Some(entry);
        if !code.has(flag::LAST) {
            break;
        }
    }
    match found {
        Some(entry) => {
            entry.write_value(out);
            true
        }
        None => false,
    }
}

/// `count()`.  In keep mode only kept cookies count, as in `vmod_count`.
pub fn cookie_count(state: &ListState<'_>) -> i64 {
    state
        .entries()
        .iter()
        .filter(|entry| kept_in_mode(state, entry))
        .count() as i64
}

/// Serialise a `Cookie` field: `name=value` pairs joined by `"; "`.
///
/// Keep mode prunes here, which is where `cookie_string()` prunes: a read
/// through `get` still sees a cookie the next `write()` will drop.
fn cookie_write(state: &ListState<'_>, out: &mut Writer<'_>) {
    let mut first = true;
    for entry in state.entries() {
        if !kept_in_mode(state, entry) {
            continue;
        }
        if !first {
            out.bytes(b"; ");
        }
        first = false;
        entry.write_name(out);
        out.byte(b'=');
        entry.write_value(out);
    }
}

fn trim_start_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| *byte <= b' ') {
        value = &value[1..];
    }
    value
}

// ---------------------------------------------------------------------------
// cookieplus, the response half
//
// `Set-Cookie` is a list like the request jar, but it is multi-valued on the
// wire and every entry carries attributes.  A record is therefore (name,
// everything after the first `=`): the attributes stay in the value, verbatim
// and unparsed, which is what lets a record borrow its bytes like every other
// module's does.  `setcookie_get` splits the value at its first `;`, which is
// exactly the split `setcookie_parse()` in `vmod_cookieplus.c` performs.
// ---------------------------------------------------------------------------

/// A Set-Cookie state mutation.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetcookieOp {
    /// Build a state from a packed snapshot of one header name.  The routine
    /// input is the snapshot, not a state.
    Parse = 0,
    /// `setcookie_keep(name)`: retain only Set-Cookies of this name.
    Keep = 1,
    /// `setcookie_delete(name, delete_keep)`.
    Delete = 2,
    /// `setcookie_add(...)`; see [`setcookie_field`] for the argument.
    Add = 3,
    /// `setcookie_keep_regex(regex)`.  The argument is the match bitmap.
    KeepRegex = 4,
    /// `setcookie_delete_regex(regex, delete_keep)`, likewise.
    DeleteRegex = 5,
    /// `setcookie_write([header])`: render the surviving records into the
    /// header-shaped state [`header_commit`] takes.  The argument is the
    /// target header name.
    Render = 6,
}

/// A Set-Cookie read.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetcookieRead {
    /// `setcookie_get(name, default)`.
    Get = 0,
    /// The packed record list the `_regex` forms match against.
    Records = 1,
    /// `setcookie_get_regex(regex, default)`.
    GetRegex = 2,
}

/// The two `setcookie_add` attributes that are a bit rather than a string.
///
/// They ride in [`OpCode::extra`] because [`flag`] has no bit left, and
/// `extra` is otherwise urlplus's alone.
pub mod setcookie_attr {
    pub const SECURE: u16 = 1 << 0;
    pub const HTTPONLY: u16 = 1 << 1;
}

/// The fields of the argument `setcookie_add` is called with, in order.
///
/// It is the one call whose VCL signature does not fit the two strings
/// `name_and_value` splits, so the compiler joins six with the same NUL.  The
/// two numbers are decimal nanoseconds: `Expires` is `now + ttl`, and the
/// guest cannot read the clock, so both cross as arguments.
pub mod setcookie_field {
    pub const NAME: usize = 0;
    pub const VALUE: usize = 1;
    pub const TTL: usize = 2;
    pub const NOW: usize = 3;
    pub const DOMAIN: usize = 4;
    pub const PATH: usize = 5;
    pub const EXTRA: usize = 6;
    /// How many fields the compiler joins, which is also the cap the vmod
    /// table's runtime-argument check enforces.
    pub const COUNT: usize = 7;
}

/// The `index`-th NUL-separated field of a routine argument.
fn nul_field(argument: &[u8], index: usize) -> &[u8] {
    let mut fields = argument.split(|byte| *byte == 0);
    fields.nth(index).unwrap_or(&[])
}

/// Parse the `Set-Cookie` headers of a packed snapshot into a state.
///
/// The split is `setcookie_parse()`'s: the name runs to the first `=`, and
/// everything after it -- value and attributes both -- is the record's value.
/// A field with no `=` is a name with an empty value, as the vmod has it, and
/// an empty name is dropped.
pub fn setcookie_parse(snapshot: &[u8]) -> Option<ListState<'_>> {
    let mut state = ListState::empty();
    let mut input = snapshot;
    while !input.is_empty() {
        let (_, field, rest) = snapshot_record(input)?;
        input = rest;
        let (name, value) = split_at_byte(field, b'=').unwrap_or((field, &field[field.len()..]));
        if name.is_empty() {
            continue;
        }
        state.push(Record {
            name,
            value,
            flags: 0,
            case: Case::Keep,
        })?;
    }
    Some(state)
}

/// The value half of a record: what `setcookie_get` answers.
///
/// The attributes stay in the stored value so a record can borrow its bytes;
/// the vmod splits at the first `;` and returns the left half, so this does.
fn setcookie_value<'a>(entry: &Record<'a>) -> &'a [u8] {
    match entry.value.iter().position(|byte| *byte == b';') {
        Some(at) => &entry.value[..at],
        None => entry.value,
    }
}

fn setcookie_read(
    state: &ListState<'_>,
    code: OpCode,
    argument: &[u8],
    out: &mut Writer<'_>,
) -> bool {
    if code.op == SetcookieRead::Records as u8 {
        write_records(state, |_| true, out);
        return true;
    }
    if code.op == SetcookieRead::GetRegex as u8 {
        for (index, entry) in state.entries().iter().enumerate() {
            if matched(argument, 0, index) {
                entry.write_slice(setcookie_value(entry), out);
                return true;
            }
        }
        return false;
    }
    // An empty name answers the VCL default, as `SEMPTY(name)` does; there is
    // no occurrence selector here, so the first match wins.
    if argument.is_empty() {
        return false;
    }
    for entry in state.entries() {
        if entry.name == argument {
            entry.write_slice(setcookie_value(entry), out);
            return true;
        }
    }
    false
}

/// `setcookie_count()`.  Keep mode counts only what a write would keep.
pub fn setcookie_count(state: &ListState<'_>) -> i64 {
    state
        .entries()
        .iter()
        .filter(|entry| kept_in_mode(state, entry))
        .count() as i64
}

/// Every mutation but the append half of `Add`, which [`setcookie_append`]
/// writes once the rest of the state has been serialised.
fn setcookie_transform<'a>(
    state: &mut ListState<'a>,
    code: OpCode,
    argument: &'a [u8],
) -> Result<(), PhaseFailure> {
    if code.op == SetcookieOp::Keep as u8 || code.op == SetcookieOp::KeepRegex as u8 {
        state.flags |= list::KEEP_MODE;
        if code.op == SetcookieOp::KeepRegex as u8 {
            for (index, entry) in state.entries_mut().iter_mut().enumerate() {
                if matched(argument, 0, index) {
                    entry.flags |= record::KEEP;
                }
            }
        } else if !argument.is_empty() {
            for entry in state.entries_mut() {
                if entry.name == argument {
                    entry.flags |= record::KEEP;
                }
            }
        }
        return Ok(());
    }
    if code.op == SetcookieOp::Delete as u8 {
        let delete_keep = code.has(flag::DELETE_KEEP);
        state.retain(|entry| entry.name != argument || (!delete_keep && entry.has(record::KEEP)));
        return Ok(());
    }
    if code.op == SetcookieOp::DeleteRegex as u8 {
        let delete_keep = code.has(flag::DELETE_KEEP);
        let mut index = 0;
        state.retain(|entry| {
            let selected = matched(argument, 0, index);
            index += 1;
            !selected || (!delete_keep && entry.has(record::KEEP))
        });
        return Ok(());
    }
    if code.op == SetcookieOp::Add as u8 {
        // `override` deletes kept records too, which is the `delete_keep = 1`
        // the vmod passes; the append itself happens at serialisation.
        let name = nul_field(argument, setcookie_field::NAME);
        if code.has(flag::OVERRIDE) && !name.is_empty() {
            state.retain(|entry| entry.name != name);
        }
        return Ok(());
    }
    Err(PhaseFailure)
}

/// The `Expires` value an `add` writes, or nothing when `ttl` is zero.
///
/// The vmod formats this in `setcookie_write()`; within one hook that differs
/// from formatting it here by microseconds against a field with one-second
/// resolution, and here is where the record's bytes are built.  A negative
/// `ttl` is the epoch, which is how the vmod expires a cookie outright.
fn setcookie_expires(argument: &[u8], buffer: &mut [u8]) -> usize {
    let ttl = int_parse(nul_field(argument, setcookie_field::TTL), 0);
    if ttl == 0 {
        return 0;
    }
    let at = if ttl < 0 {
        0
    } else {
        int_parse(nul_field(argument, setcookie_field::NOW), 0).saturating_add(ttl)
    };
    time_format(at, buffer)
}

/// The pieces of the record value `setcookie_add` builds, in wire order.
///
/// Emitted rather than returned: the value is a composition of six arguments
/// and seven literals, and it is measured before it is written.
fn setcookie_pieces<'a>(
    code: OpCode,
    argument: &'a [u8],
    expires: &'a [u8],
    mut emit: impl FnMut(&'a [u8]),
) {
    emit(nul_field(argument, setcookie_field::VALUE));
    if !expires.is_empty() {
        emit(b"; Expires=");
        emit(expires);
    }
    let domain = nul_field(argument, setcookie_field::DOMAIN);
    if !domain.is_empty() {
        emit(b"; Domain=");
        emit(domain);
    }
    let path = nul_field(argument, setcookie_field::PATH);
    if !path.is_empty() {
        emit(b"; Path=");
        emit(path);
    }
    if code.extra & setcookie_attr::SECURE != 0 {
        emit(b"; Secure");
    }
    if code.extra & setcookie_attr::HTTPONLY != 0 {
        emit(b"; HttpOnly");
    }
    let extra = nul_field(argument, setcookie_field::EXTRA);
    if !extra.is_empty() {
        emit(b"; ");
        emit(extra);
    }
}

/// Append the record `setcookie_add` builds to an already-serialised state.
///
/// A [`Record`] borrows its bytes and this crate allocates nothing, so a
/// value composed from six arguments cannot be pushed onto the list and
/// written with the rest.  `add` always appends, so writing it at the tail is
/// the same list.
fn setcookie_append(code: OpCode, argument: &[u8], out: &mut Writer<'_>) {
    let name = nul_field(argument, setcookie_field::NAME);
    if name.is_empty() {
        return;
    }
    let mut buffer = [0u8; TIME_FORMAT_LEN];
    let dated = setcookie_expires(argument, &mut buffer).min(TIME_FORMAT_LEN);
    let expires = &buffer[..dated];
    let mut length = 0usize;
    setcookie_pieces(code, argument, expires, |piece| {
        length = length.saturating_add(piece.len())
    });
    let flags = if code.has(flag::KEEP) {
        record::KEEP
    } else {
        0
    };
    out.decimal(usize::from(flags));
    out.byte(b',');
    out.decimal(name.len());
    out.byte(b',');
    out.decimal(length);
    out.byte(b',');
    out.bytes(name);
    setcookie_pieces(code, argument, expires, |piece| out.bytes(piece));
}

/// Render the state into the header-shaped one [`header_commit`] reads.
///
/// Every surviving cookie becomes one entry of the target header, marked
/// touched, which is what makes the commit replace the response's Set-Cookie
/// headers rather than add to them.  The leading deleted marker carries the
/// name alone: it is what still unsets the header when keep mode has pruned
/// every cookie, which is the `http_Unset()` the vmod performs first.
fn setcookie_render(state: &ListState<'_>, header: &[u8], out: &mut Writer<'_>) {
    out.decimal(0);
    out.byte(b';');
    out.decimal(usize::from(record::TOUCHED | record::DELETED));
    out.byte(b',');
    out.decimal(header.len());
    out.byte(b',');
    out.decimal(0);
    out.byte(b',');
    out.bytes(header);
    for entry in state.entries() {
        if !kept_in_mode(state, entry) {
            continue;
        }
        out.decimal(usize::from(record::TOUCHED));
        out.byte(b',');
        out.decimal(header.len());
        out.byte(b',');
        out.decimal(entry.name.len() + 1 + entry.value.len());
        out.byte(b',');
        out.bytes(header);
        entry.write_name(out);
        out.byte(b'=');
        entry.write_value(out);
    }
}

/// A urlplus state mutation.
///
/// The numbering is the runtime ABI between `vcl-compiler` and this crate.
/// It is not a host ABI: nothing outside these two crates sees it, which is
/// why urlplus semantics may live here without teaching the host about VCL.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlOp {
    /// Parse a URL into a state.  The routine input is the URL, not a state.
    Parse = 0,
    /// `query_add(name, value, keep, position)`; `first` is the position.
    QueryAdd = 1,
    /// `query_set(name, value, keep, all)`.
    QuerySet = 2,
    /// `query_delete(name, delete_keep)`.
    QueryDelete = 3,
    /// `query_keep(name)`; also switches the query list into keep mode.
    QueryKeep = 4,
    /// `url_add(name, keep, position)`; `first` is the position.
    UrlAdd = 5,
    /// `url_delete(name, delete_keep)`.
    UrlDelete = 6,
    /// `url_keep(name)`; also switches the segment list into keep mode.
    UrlKeep = 7,
    /// `url_delete_range(start, end, delete_keep)`.
    UrlDeleteRange = 8,
    /// `tolower`/`toupper`; `extra` selects the part, `flags` the direction.
    CaseMap = 9,
    /// `query_keep_regex(regex)`.  The argument is the match bitmap over the
    /// query pairs, not a name.
    QueryKeepRegex = 10,
    /// `query_delete_regex(regex, delete_keep)`, likewise.
    QueryDeleteRegex = 11,
    /// `url_keep_regex(regex)`, over the path segments.
    UrlKeepRegex = 12,
    /// `url_delete_regex(regex, delete_keep)`, over the path segments.
    UrlDeleteRegex = 13,
}

/// A urlplus read.  Every one renders through a [`Writer`], because a value
/// such as `get_basename()` is assembled rather than sliced out of the state.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRead {
    /// The last path segment, filename and extension rejoined.
    Basename = 0,
    /// The last path segment up to its final `.`.
    Filename = 1,
    /// The last path segment after its final `.`.
    Extension = 2,
    /// Every path segment but the last.
    Dirname = 3,
    /// `query_get(name, def, position)`; `first` is the position.
    QueryGet = 4,
    /// `url_get(start, end, leading_slash, trailing_slash)`.
    UrlGet = 5,
    /// `as_string(...)`, and the value `write()` stores.
    AsString = 6,
    /// `query_as_string(...)`.
    QueryAsString = 7,
    /// `url_as_string(leading_slash, trailing_slash)`: the path alone.
    UrlAsString = 8,
    /// The packed record list the `_regex` forms match against; the part
    /// selector in `extra` picks the segments or the query pairs.
    Records = 9,
    /// `query_get_regex(regex, def)`: the value of the first query pair whose
    /// name the bitmap selects.
    QueryGetRegex = 10,
}

/// A urlplus count selector, in `OpCode::op`.
pub const URL_COUNT_SEGMENTS: u8 = 0;
pub const URL_COUNT_QUERIES: u8 = 1;

/// `OpCode::extra` values for the parts a case conversion covers.
pub const PART_ALL: u16 = 0;
pub const PART_URL: u16 = 1;
pub const PART_QUERY: u16 = 2;

/// A `ENUM {FROM_INPUT, TRUE, FALSE}` slash argument, packed into
/// `OpCode::extra` two bits at a time.
pub const SLASH_FROM_INPUT: u16 = 0;
pub const SLASH_TRUE: u16 = 1;
pub const SLASH_FALSE: u16 = 2;

/// Pack the two slash arguments and the part selector into `OpCode::extra`.
pub const fn url_extra(leading: u16, trailing: u16, part: u16) -> u16 {
    (leading & 0x3) | ((trailing & 0x3) << 2) | ((part & 0x3) << 4)
}

const fn extra_leading(extra: u16) -> u16 {
    extra & 0x3
}

const fn extra_trailing(extra: u16) -> u16 {
    (extra >> 2) & 0x3
}

const fn extra_part(extra: u16) -> u16 {
    (extra >> 4) & 0x3
}

/// Parse a URL exactly as `urlplus_parse.c` does: no percent-decoding and no
/// canonicalisation, duplicate slashes collapsed, empty query pairs dropped,
/// and the first `=` of a pair splitting name from value.
///
/// Byte preservation is not a detail here.  urlplus is reachable from
/// `vcl_backend_fetch`, where the URL it writes is the origin request line;
/// decoding it would change what the origin sees, and (were `write()` ever
/// allowed earlier) would move the cache key.
pub fn url_parse(input: &[u8]) -> Option<ListState<'_>> {
    let mut state = ListState::empty();
    if input.is_empty() {
        return Some(state);
    }
    let split = input.iter().position(|byte| *byte == b'?');
    let path = &input[..split.unwrap_or(input.len())];
    let query = split.map(|at| &input[at + 1..]).unwrap_or(&[]);

    let path = if let Some(rest) = path.strip_prefix(b"/") {
        state.flags |= list::LEADING_SLASH;
        rest
    } else {
        path
    };
    if path.last() == Some(&b'/') {
        state.flags |= list::TRAILING_SLASH;
    }
    for segment in path.split(|byte| *byte == b'/') {
        if segment.is_empty() {
            continue;
        }
        state.push(Record {
            name: segment,
            value: &[],
            flags: 0,
            case: Case::Keep,
        })?;
    }
    for pair in query.split(|byte| *byte == b'&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value, flags) = match split_at_byte(pair, b'=') {
            Some((name, value)) => (name, value, record::QUERY | record::EQUALS),
            None => (pair, &[][..], record::QUERY),
        };
        state.push(Record {
            name,
            value,
            flags,
            case: Case::Keep,
        })?;
    }
    Some(state)
}

fn is_query(entry: &Record<'_>) -> bool {
    entry.has(record::QUERY)
}

/// Whether a record survives its list's keep mode.
fn kept(state: &ListState<'_>, entry: &Record<'_>) -> bool {
    let mode = if is_query(entry) {
        list::KEEP_MODE
    } else {
        list::SEGMENT_KEEP_MODE
    };
    !state.has(mode) || entry.has(record::KEEP)
}

/// Apply one mutation to a urlplus state.
///
/// [`PhaseFailure`] is reserved for exceeding [`MAX_LIST_ITEMS`], which the
/// compiler turns into a phase failure at the VCL line.  Every other input is
/// handled the way the vmod handles it: an empty name is a no-op, an
/// out-of-range position appends, and an inverted range does nothing.
pub fn url_transform<'a>(
    state: &mut ListState<'a>,
    code: OpCode,
    argument: &'a [u8],
) -> Result<(), PhaseFailure> {
    let (name, value) = name_and_value(argument);
    let op = code.op;
    if op == UrlOp::CaseMap as u8 {
        let part = extra_part(code.extra);
        for entry in state.entries_mut() {
            let selected = match part {
                PART_URL => !is_query(entry),
                PART_QUERY => is_query(entry),
                _ => true,
            };
            if selected {
                entry.case = if code.has(flag::UPPER) {
                    Case::Upper
                } else {
                    Case::Lower
                };
            }
        }
        return Ok(());
    }
    if op == UrlOp::QueryKeep as u8 || op == UrlOp::UrlKeep as u8 {
        // Varnish enables keep mode even for an empty name, which is how a
        // policy expresses "drop everything but what I name next".
        let query = op == UrlOp::QueryKeep as u8;
        state.flags |= if query {
            list::KEEP_MODE
        } else {
            list::SEGMENT_KEEP_MODE
        };
        if !name.is_empty() {
            for entry in state.entries_mut() {
                if is_query(entry) == query && entry.name == name {
                    entry.flags |= record::KEEP;
                }
            }
        }
        return Ok(());
    }
    if op == UrlOp::QueryKeepRegex as u8 || op == UrlOp::UrlKeepRegex as u8 {
        let query = op == UrlOp::QueryKeepRegex as u8;
        state.flags |= if query {
            list::KEEP_MODE
        } else {
            list::SEGMENT_KEEP_MODE
        };
        let mut index = 0;
        for entry in state.entries_mut() {
            if is_query(entry) != query {
                continue;
            }
            if matched(argument, 0, index) {
                entry.flags |= record::KEEP;
            }
            index += 1;
        }
        return Ok(());
    }
    if op == UrlOp::QueryDeleteRegex as u8 || op == UrlOp::UrlDeleteRegex as u8 {
        let query = op == UrlOp::QueryDeleteRegex as u8;
        let delete_keep = code.has(flag::DELETE_KEEP);
        let mut index = 0;
        state.retain(|entry| {
            if is_query(entry) != query {
                return true;
            }
            let selected = matched(argument, 0, index);
            index += 1;
            !selected || (!delete_keep && entry.has(record::KEEP))
        });
        return Ok(());
    }
    if op == UrlOp::QueryDelete as u8 || op == UrlOp::UrlDelete as u8 {
        if name.is_empty() {
            return Ok(());
        }
        let query = op == UrlOp::QueryDelete as u8;
        let delete_keep = code.has(flag::DELETE_KEEP);
        state.retain(|entry| {
            is_query(entry) != query
                || entry.name != name
                || (!delete_keep && entry.has(record::KEEP))
        });
        return Ok(());
    }
    if op == UrlOp::UrlDeleteRange as u8 {
        let delete_keep = code.has(flag::DELETE_KEEP);
        let total = state
            .entries()
            .iter()
            .filter(|entry| !is_query(entry))
            .count();
        let end = if code.second < 0 {
            total as i32
        } else {
            i32::from(code.second)
        };
        let start = i32::from(code.first).max(0);
        if end < start {
            return Ok(());
        }
        // `pos` advances only for records the delete may touch, matching
        // `vmod_url_delete_range`: a kept segment does not consume an index.
        let mut pos = -1i32;
        state.retain(|entry| {
            if is_query(entry) {
                return true;
            }
            if !delete_keep && entry.has(record::KEEP) {
                return true;
            }
            pos += 1;
            pos < start || pos > end
        });
        return Ok(());
    }
    if op == UrlOp::QuerySet as u8 {
        if name.is_empty() {
            return Ok(());
        }
        let mut matched = false;
        for entry in state.entries_mut() {
            if !is_query(entry) || entry.name != name {
                continue;
            }
            entry.value = value;
            entry.flags |= record::EQUALS;
            matched = true;
            if !code.has(flag::ALL) {
                break;
            }
        }
        if matched {
            return Ok(());
        }
        return state
            .push(query_record(name, value, code))
            .ok_or(PhaseFailure);
    }
    if op == UrlOp::QueryAdd as u8 {
        if name.is_empty() {
            return Ok(());
        }
        let entry = query_record(name, value, code);
        let queries = state
            .entries()
            .iter()
            .filter(|entry| is_query(entry))
            .count();
        return insert_positional(state, entry, code.first, queries, true).ok_or(PhaseFailure);
    }
    if op == UrlOp::UrlAdd as u8 {
        if name.is_empty() {
            return Ok(());
        }
        let mut entry = Record {
            name,
            value: &[],
            flags: 0,
            case: Case::Keep,
        };
        if code.has(flag::KEEP) {
            entry.flags |= record::KEEP;
        }
        let segments = state
            .entries()
            .iter()
            .filter(|entry| !is_query(entry))
            .count();
        return insert_positional(state, entry, code.first, segments, false).ok_or(PhaseFailure);
    }
    Err(PhaseFailure)
}

fn query_record<'a>(name: &'a [u8], value: &'a [u8], code: OpCode) -> Record<'a> {
    let mut flags = record::QUERY;
    if !value.is_empty() {
        flags |= record::EQUALS;
    }
    if code.has(flag::KEEP) {
        flags |= record::KEEP;
    }
    Record {
        name,
        value,
        flags,
        case: Case::Keep,
    }
}

/// Insert into one of the two interleaved sub-lists at a sub-list position.
///
/// A position outside the sub-list appends, which is what `query_add` and
/// `url_add` document for their default `position = -1`.
fn insert_positional<'a>(
    state: &mut ListState<'a>,
    entry: Record<'a>,
    position: i16,
    len: usize,
    query: bool,
) -> Option<()> {
    if position < 0 || usize::from(position as u16) >= len {
        // Segments precede queries in the state, so appending a segment means
        // inserting before the first query rather than at the very end.
        let at = if query {
            state.count
        } else {
            state
                .entries()
                .iter()
                .position(is_query)
                .unwrap_or(state.count)
        };
        return state.insert(at, entry);
    }
    let target = usize::from(position as u16);
    let mut seen = 0;
    for index in 0..state.count {
        if is_query(&state.records[index]) != query {
            continue;
        }
        if seen == target {
            return state.insert(index, entry);
        }
        seen += 1;
    }
    state.insert(state.count, entry)
}

pub fn url_count(state: &ListState<'_>, code: OpCode) -> i64 {
    let query = code.op == URL_COUNT_QUERIES;
    state
        .entries()
        .iter()
        .filter(|entry| is_query(entry) == query && kept(state, entry))
        .count() as i64
}

/// Render a urlplus read.  `false` means the value is absent, and the caller
/// substitutes the VCL `default` argument, exactly as an absent header does.
pub fn url_read(
    state: &ListState<'_>,
    code: OpCode,
    argument: &[u8],
    out: &mut Writer<'_>,
) -> bool {
    let read = code.op;
    if read == UrlRead::QueryGet as u8 {
        // `position` wins over `name` when both are given, per the vmod.
        if code.first >= 0 {
            let Some(entry) = state
                .entries()
                .iter()
                .filter(|entry| is_query(entry) && kept(state, entry))
                .nth(usize::from(code.first as u16))
            else {
                return false;
            };
            entry.write_value(out);
            return true;
        }
        if argument.is_empty() {
            return false;
        }
        let Some(entry) = state
            .entries()
            .iter()
            .find(|entry| is_query(entry) && kept(state, entry) && entry.name == argument)
        else {
            return false;
        };
        entry.write_value(out);
        return true;
    }
    if read == UrlRead::QueryAsString as u8 {
        return write_query(state, code, out);
    }
    if read == UrlRead::AsString as u8 {
        write_path(state, code, 0, -1, out);
        if !state
            .entries()
            .iter()
            .any(|entry| is_query(entry) && kept(state, entry))
        {
            return true;
        }
        out.byte(b'?');
        write_query(state, code, out);
        return true;
    }
    if read == UrlRead::UrlGet as u8 {
        write_path(state, code, code.first, code.second, out);
        return true;
    }
    if read == UrlRead::UrlAsString as u8 {
        // `url_as_string` is `url_get` over the whole path: the vmod renders
        // both through `urlplus_url_as_string()` and differs only in taking
        // no range.
        write_path(state, code, 0, -1, out);
        return true;
    }
    if read == UrlRead::Records as u8 {
        let query = extra_part(code.extra) == PART_QUERY;
        write_records(state, |entry| is_query(entry) == query, out);
        return true;
    }
    if read == UrlRead::QueryGetRegex as u8 {
        // The vmod matches every pair, kept or not, exactly as `query_get`
        // does not: this read has no position argument to honour keep mode
        // with.
        for (index, entry) in state.entries().iter().filter(|e| is_query(e)).enumerate() {
            if matched(argument, 0, index) {
                entry.write_value(out);
                return true;
            }
        }
        return false;
    }

    // The name-shaped reads all derive from the last live segment. Varnish
    // freezes these at parse time; deriving them from the current state is
    // the one deliberate divergence, and it is the direction a policy that
    // reads after a mutation expects.
    let Some(last) = state
        .entries()
        .iter()
        .rev()
        .find(|entry| !is_query(entry) && kept(state, entry))
    else {
        if read == UrlRead::Dirname as u8 {
            out.byte(b'/');
            return true;
        }
        return false;
    };
    let (filename, extension) = split_extension(last.name);
    match read {
        value if value == UrlRead::Basename as u8 => {
            last.write_name(out);
            true
        }
        value if value == UrlRead::Filename as u8 => match filename {
            Some(filename) => {
                last.write_slice(filename, out);
                true
            }
            None => false,
        },
        value if value == UrlRead::Extension as u8 => match extension {
            Some(extension) => {
                last.write_slice(extension, out);
                true
            }
            None => false,
        },
        _ => {
            let segments = state
                .entries()
                .iter()
                .filter(|entry| !is_query(entry) && kept(state, entry))
                .count();
            if segments < 2 {
                out.byte(b'/');
            } else {
                let mut code = code;
                code.extra = url_extra(SLASH_FROM_INPUT, SLASH_FALSE, PART_ALL);
                write_path(state, code, 0, (segments - 2) as i16, out);
            }
            true
        }
    }
}

/// Split a segment into its filename and extension around the final `.`.
///
/// A trailing `.` has no extension, which is `strlen(extension) <= 1` in
/// `urlplus_parse.c`; a leading `.` gives an empty filename, not an absent
/// one, so `.bashrc` renders as `.bashrc` and not as `bashrc`.
fn split_extension(segment: &[u8]) -> (Option<&[u8]>, Option<&[u8]>) {
    let Some(dot) = segment.iter().rposition(|byte| *byte == b'.') else {
        return (None, None);
    };
    let extension = &segment[dot + 1..];
    if extension.is_empty() {
        return (None, None);
    }
    (Some(&segment[..dot]), Some(extension))
}

/// Render the path, honouring keep mode, the `start..=end` range and the two
/// tri-state slash arguments.
fn write_path(state: &ListState<'_>, code: OpCode, start: i16, end: i16, out: &mut Writer<'_>) {
    let total = state
        .entries()
        .iter()
        .filter(|entry| !is_query(entry) && kept(state, entry))
        .count();
    let end = if end < 0 {
        total as i32
    } else {
        i32::from(end)
    };
    let start = i32::from(start).max(0);
    if total == 0 || end < start {
        out.byte(b'/');
        return;
    }
    let leading = match extra_leading(code.extra) {
        SLASH_TRUE => true,
        SLASH_FALSE => false,
        _ => state.has(list::LEADING_SLASH) || start > 0,
    };
    let mut separator = leading;
    let mut wrote = false;
    for (index, entry) in state
        .entries()
        .iter()
        .filter(|entry| !is_query(entry) && kept(state, entry))
        .enumerate()
    {
        let index = index as i32;
        if index < start || index > end {
            continue;
        }
        if separator {
            out.byte(b'/');
        }
        entry.write_name(out);
        separator = true;
        wrote = true;
    }
    if !wrote {
        out.byte(b'/');
        return;
    }
    let trailing = match extra_trailing(code.extra) {
        SLASH_TRUE => true,
        SLASH_FALSE => false,
        _ => state.has(list::TRAILING_SLASH),
    };
    if trailing {
        out.byte(b'/');
    }
}

/// Render the query, honouring keep mode, `sort_query` and
/// `query_keep_equal_sign`.  Returns false when no pair survives.
fn write_query(state: &ListState<'_>, code: OpCode, out: &mut Writer<'_>) -> bool {
    let mut order = [0u16; MAX_LIST_ITEMS];
    let mut count = 0usize;
    for (index, entry) in state.entries().iter().enumerate() {
        if is_query(entry) && kept(state, entry) {
            order[count] = index as u16;
            count += 1;
        }
    }
    if count == 0 {
        return false;
    }
    if code.has(flag::SORT_QUERY) {
        sort_pairs(state, &mut order[..count]);
    }
    for (position, index) in order[..count].iter().enumerate() {
        if position != 0 {
            out.byte(b'&');
        }
        let entry = &state.records[usize::from(*index)];
        entry.write_name(out);
        if !entry.value.is_empty() || (entry.has(record::EQUALS) && code.has(flag::KEEP_EQUAL_SIGN))
        {
            out.byte(b'=');
        }
        entry.write_value(out);
    }
    true
}

/// Insertion sort over the surviving pairs, bytewise by `name` then `value`.
///
/// Insertion sort rather than a library sort because the crate is `no_std`
/// and allocation-free, and `MAX_LIST_ITEMS` bounds the quadratic term at a
/// size the instruction budget does not notice.
fn sort_pairs(state: &ListState<'_>, order: &mut [u16]) {
    for index in 1..order.len() {
        let mut at = index;
        while at > 0 {
            let left = &state.records[usize::from(order[at - 1])];
            let right = &state.records[usize::from(order[at])];
            if pair_order(left, right) != core::cmp::Ordering::Greater {
                break;
            }
            order.swap(at - 1, at);
            at -= 1;
        }
    }
}

fn pair_order(left: &Record<'_>, right: &Record<'_>) -> core::cmp::Ordering {
    left.name
        .cmp(right.name)
        .then_with(|| left.value.cmp(right.value))
}

/// A headerplus state mutation.  As with [`UrlOp`], the numbering is the
/// runtime ABI between `vcl-compiler` and this crate and reaches no host.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderOp {
    /// Build a state from a packed host header snapshot.  The routine input
    /// is the snapshot, not a state.
    Parse = 0,
    /// `keep(name)`; also switches the list into keep mode.
    Keep = 1,
    /// `delete(name, delete_keep)`.
    Delete = 2,
    /// `set(name, value, keep)`: every header of the name becomes this one.
    Set = 3,
    /// `add(name, value, keep)`.
    Add = 4,
    /// `keep_regex(name_re)`.  The argument is the match bitmap over the live
    /// header list, not a name.
    KeepRegex = 5,
    /// `delete_regex(name_re, delete_keep)`, likewise.
    DeleteRegex = 6,
}

/// A headerplus read: `get(name, def)`, where `first` is the occurrence.
pub const HEADER_READ_GET: u8 = 0;
/// The packed record list the `_regex` forms match against.
pub const HEADER_READ_RECORDS: u8 = 1;
/// `get_regex(name_re, value_re, def)`: the *value* of the first live header
/// both bitmaps select.
pub const HEADER_READ_GET_REGEX: u8 = 2;
/// `get_name_regex(name_re, value_re)`: its *name* instead.
pub const HEADER_READ_NAME_REGEX: u8 = 3;

/// `count(name)`, where the argument is the name.
pub const HEADER_COUNT_NAME: u8 = 0;
/// `count_regex(name_re)`, where the argument is the match bitmap.
pub const HEADER_COUNT_REGEX: u8 = 1;

/// The packed record layout of the host's `headers_snapshot` sub-command:
/// `u32 name_len, u32 value_len, name bytes, value bytes`, repeated.
///
/// The host side is deliberately generic -- it knows nothing about VCL, and
/// the C SDK gets header iteration out of the same call -- so the decoding
/// lives here, next to the only consumer that wants a vmod's view of it.
pub fn header_parse(snapshot: &[u8]) -> Option<ListState<'_>> {
    let mut state = ListState::empty();
    let mut input = snapshot;
    while !input.is_empty() {
        let (name, value, rest) = snapshot_record(input)?;
        state.push(Record {
            name,
            value,
            flags: 0,
            case: Case::Keep,
        })?;
        input = rest;
    }
    Some(state)
}

/// One record of a packed snapshot, and the bytes that follow it.
fn snapshot_record(input: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let head = input.get(..8)?;
    let name_len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let value_len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
    let rest = input.get(8..)?;
    let value_end = name_len.checked_add(value_len)?;
    let name = rest.get(..name_len)?;
    let value = rest.get(name_len..value_end)?;
    Some((name, value, rest.get(value_end..)?))
}

/// The separator `std.collect` uses when the policy names none -- and when it
/// names an empty one, which is what `http_CollectHdrSep` does with a `sep`
/// that is `NULL` or `""`.
pub const COLLECT_SEPARATOR: &[u8] = b", ";

/// `std.collect(hdr, sep)`: join every value in a packed header snapshot.
///
/// The snapshot is the whole input because the host filtered it: sub-command
/// 23 takes a name and matches it case-insensitively, so the routine never
/// needs the name and never counts the records against
/// [`MAX_LIST_ITEMS`] -- a name with more occurrences than a module state
/// could hold still collapses.
///
/// Returns false when the name has no header at all, which is what keeps
/// `std.collect` from creating one, and -- as with every read in this crate
/// -- when the input is not a snapshot this crate's host produced.
pub fn collect(snapshot: &[u8], separator: &[u8], out: &mut Writer<'_>) -> bool {
    let separator = if separator.is_empty() {
        COLLECT_SEPARATOR
    } else {
        separator
    };
    let mut input = snapshot;
    let mut wrote = false;
    while !input.is_empty() {
        let Some((_, value, rest)) = snapshot_record(input) else {
            return false;
        };
        if wrote {
            out.bytes(separator);
        }
        out.bytes(value);
        wrote = true;
        input = rest;
    }
    wrote
}

fn live(entry: &Record<'_>) -> bool {
    !entry.has(record::DELETED)
}

/// Apply one headerplus mutation.
///
/// A deleted record is marked rather than dropped: `write()` replays only the
/// names this hook touched, so the *name* has to survive the delete for the
/// commit to know it must go.  An untouched name keeps its duplicates and its
/// transport order because nothing replays it at all.
pub fn header_transform<'a>(
    state: &mut ListState<'a>,
    code: OpCode,
    argument: &'a [u8],
) -> Result<(), PhaseFailure> {
    let (name, value) = name_and_value(argument);
    if code.op == HeaderOp::Keep as u8 {
        // An empty name still enables keep mode: that is how a policy says
        // "drop everything except what I name next".
        state.flags |= list::KEEP_MODE;
        for entry in state.entries_mut() {
            if !name.is_empty() && entry.name.eq_ignore_ascii_case(name) {
                entry.flags |= record::KEEP;
            }
        }
        return Ok(());
    }
    if code.op == HeaderOp::KeepRegex as u8 {
        state.flags |= list::KEEP_MODE;
        let mut index = 0;
        for entry in state.entries_mut() {
            if entry.has(record::DELETED) {
                continue;
            }
            if matched(argument, 0, index) {
                entry.flags |= record::KEEP;
            }
            index += 1;
        }
        return Ok(());
    }
    if code.op == HeaderOp::DeleteRegex as u8 {
        let delete_keep = code.has(flag::DELETE_KEEP);
        let mut index = 0;
        for entry in state.entries_mut() {
            if entry.has(record::DELETED) {
                continue;
            }
            let selected = matched(argument, 0, index);
            index += 1;
            if !selected || (!delete_keep && entry.has(record::KEEP)) {
                continue;
            }
            entry.flags |= record::DELETED | record::TOUCHED;
        }
        return Ok(());
    }
    // Past here the argument is a name, and an empty one is a no-op.  The
    // regex forms are above it because their argument is a bitmap, whose
    // first byte is routinely zero.
    if name.is_empty() {
        return Ok(());
    }
    if code.op == HeaderOp::Delete as u8 {
        let delete_keep = code.has(flag::DELETE_KEEP);
        for entry in state.entries_mut() {
            if !entry.name.eq_ignore_ascii_case(name) {
                continue;
            }
            if !delete_keep && entry.has(record::KEEP) {
                continue;
            }
            entry.flags |= record::DELETED | record::TOUCHED;
        }
        return Ok(());
    }
    if code.op == HeaderOp::Set as u8 || code.op == HeaderOp::Add as u8 {
        if code.op == HeaderOp::Set as u8 {
            for entry in state.entries_mut() {
                if entry.name.eq_ignore_ascii_case(name) {
                    entry.flags |= record::DELETED | record::TOUCHED;
                }
            }
        }
        let mut flags = record::TOUCHED;
        if code.has(flag::KEEP) {
            flags |= record::KEEP;
        }
        return state
            .push(Record {
                name,
                value,
                flags,
                case: Case::Keep,
            })
            .ok_or(PhaseFailure);
    }
    Err(PhaseFailure)
}

/// `get(name, def)` and `get(name, def)` at an occurrence.
pub fn header_read(
    state: &ListState<'_>,
    code: OpCode,
    argument: &[u8],
    out: &mut Writer<'_>,
) -> bool {
    if code.op == HEADER_READ_RECORDS {
        write_records(state, live, out);
        return true;
    }
    if code.op == HEADER_READ_GET_REGEX || code.op == HEADER_READ_NAME_REGEX {
        // Two bitmaps, always: the vmod's `value_re` is optional, and an
        // absent one is spelled here as the empty pattern, which matches
        // every record and makes the AND a no-op.
        for (index, entry) in state
            .entries()
            .iter()
            .filter(|entry| live(entry))
            .enumerate()
        {
            if !matched(argument, 0, index) || !matched(argument, 1, index) {
                continue;
            }
            if code.op == HEADER_READ_NAME_REGEX {
                entry.write_name(out);
            } else {
                entry.write_value(out);
            }
            return true;
        }
        return false;
    }
    if code.op != HEADER_READ_GET {
        return false;
    }
    let mut seen = 0i16;
    let wanted = code.first;
    for entry in state.entries() {
        if !live(entry) || !entry.name.eq_ignore_ascii_case(argument) {
            continue;
        }
        if wanted < 0 || seen == wanted {
            entry.write_value(out);
            return true;
        }
        seen += 1;
    }
    false
}

/// `count(name)`; an empty name counts every live header.  `count_regex`
/// counts the live headers the bitmap selects instead.
pub fn header_count(state: &ListState<'_>, code: OpCode, argument: &[u8]) -> i64 {
    if code.op == HEADER_COUNT_REGEX {
        return state
            .entries()
            .iter()
            .filter(|entry| live(entry))
            .enumerate()
            .filter(|(index, _)| matched(argument, 0, *index))
            .count() as i64;
    }
    state
        .entries()
        .iter()
        .filter(|entry| {
            live(entry) && (argument.is_empty() || entry.name.eq_ignore_ascii_case(argument))
        })
        .count() as i64
}

/// The `Vec<Header>` the host's header-commit sub-command reads.
///
/// This is the whole reason headerplus needs no host addition of its own:
/// `write()` builds the vector the *existing*, generic commit already takes,
/// so the host's phase gate, framing-header refusal, `Host`/`variant_headers`
/// protection and per-phase mutation ceiling all apply unchanged, and the
/// host never learns what a headerplus is.
///
/// The vector is three regions in one arena block: the `Vec` itself, then its
/// entries, then the name and value bytes the entries point at.  `base` is
/// the guest address `out` is mapped at, which is what turns the third region
/// into pointers the host can follow.
pub fn header_commit(
    state: &ListState<'_>,
    live_snapshot: &ListState<'_>,
    base: u64,
    out: &mut Writer<'_>,
) -> Result<(), PhaseFailure> {
    if base % 8 != 0 {
        return Err(PhaseFailure);
    }
    // Pass one: how many entries, so the entry array's size is known before
    // the first pointer into the byte region is written.
    let mut count = 0usize;
    each_committed(state, live_snapshot, |_, _, _| count += 1);
    let entries_at = GUEST_VEC_SIZE
        .checked_add(count.checked_mul(GUEST_HEADER_SIZE).ok_or(PhaseFailure)?)
        .ok_or(PhaseFailure)?;

    // The `Vec` header: capacity, pointer, length.
    write_u64(out, count as u64);
    write_u64(
        out,
        base.checked_add(GUEST_VEC_SIZE as u64)
            .ok_or(PhaseFailure)?,
    );
    write_u64(out, count as u64);

    // Pass two: one entry per record, each pointing into the byte region.
    let bytes_base = base.checked_add(entries_at as u64).ok_or(PhaseFailure)?;
    let mut at = 0u64;
    let mut failed = false;
    each_committed(state, live_snapshot, |name, value, dirty| {
        let Some(name_at) = bytes_base.checked_add(at) else {
            failed = true;
            return;
        };
        write_u64(out, name.len() as u64);
        write_u64(out, name_at);
        write_u64(out, name.len() as u64);
        let value_at = name_at.saturating_add(name.len() as u64);
        write_u64(out, value.len() as u64);
        write_u64(out, value_at);
        write_u64(out, value.len() as u64);
        write_u64(out, u64::from(dirty));
        at = at.saturating_add((name.len() + value.len()) as u64);
    });
    if failed {
        return Err(PhaseFailure);
    }

    // Pass three: the bytes the entries point at.
    each_committed(state, live_snapshot, |name, value, _| {
        out.bytes(name);
        out.bytes(value);
    });
    Ok(())
}

/// The size of `carapace_scripting::abi::GuestVec`.
const GUEST_VEC_SIZE: usize = 24;
/// The size of `carapace_scripting::abi::GuestHeader`: two `GuestVec`s, a
/// dirty byte and its padding.
const GUEST_HEADER_SIZE: usize = 56;

fn write_u64(out: &mut Writer<'_>, value: u64) {
    out.bytes(&value.to_le_bytes());
}

/// Walk the headers `write()` commits, in wire order.
///
/// A name the hook never touched passes through *clean*, carrying whatever
/// the live map holds. That is what leaves its duplicates and its transport
/// order alone, and it is also what keeps it out of the host's changed-name
/// set, so an untouched `Host` is neither counted against the per-phase
/// mutation ceiling nor tested against the forbidden names.
///
/// Keep mode is a whitelist over the module's own list, not over the map: a
/// header the policy added after `init()` -- with `set req.http.X`, say --
/// is not in the list at all, so it is untouched and survives. Varnish does
/// the same, and it is the difference between a whitelist and a purge.
///
/// `touched` rescans the list per candidate, so the walk is quadratic in the
/// header count. Both sides are bounded by [`MAX_LIST_ITEMS`], which puts the
/// worst case at a few hundred thousand short name comparisons against a
/// hundred-million-instruction budget; an index would cost more state than
/// it saves.
fn each_committed(
    state: &ListState<'_>,
    live_snapshot: &ListState<'_>,
    mut emit: impl FnMut(&[u8], &[u8], u8),
) {
    let keep_mode = state.has(list::KEEP_MODE);
    // In keep mode every name the list holds is decided, whether by being
    // kept or by being dropped, so every one of them counts as touched.
    let touched = |name: &[u8]| {
        state.entries().iter().any(|entry| {
            entry.name.eq_ignore_ascii_case(name) && (keep_mode || entry.has(record::TOUCHED))
        })
    };
    for entry in live_snapshot.entries() {
        if !touched(entry.name) {
            emit(entry.name, entry.value, 0);
        }
    }
    for entry in state.entries() {
        if !live(entry) || (keep_mode && !entry.has(record::KEEP)) {
            continue;
        }
        if touched(entry.name) {
            emit(entry.name, entry.value, 1);
        }
    }
}

// ── uri ─────────────────────────────────────────────────────────────────
//
// The fourth module, and the first whose state is not a list the VCL can
// grow: it is exactly the seven generic components of RFC 3986, always all
// seven, so a component lookup is an array index and the records need no
// names.  It still rides on [`ListState`], because the encoding, the
// capacity discipline and the measure-then-fill protocol are the ones the
// other three already pay for.  What it adds is a *pending* per-record byte
// transform, for the two operations -- `encode` and `norm` -- whose output
// exists in no buffer this crate is allowed to allocate.

/// The seven generic components of a URI, in the order RFC 3986 Section 5.3
/// renders them.  The discriminant is the record's index in a `uri` state.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriPart {
    Scheme = 0,
    Userinfo = 1,
    Host = 2,
    Port = 3,
    Path = 4,
    Query = 5,
    Fragment = 6,
}

/// How many records a `uri` state always holds.
pub const URI_PARTS: usize = 7;

const URI_ORDER: [UriPart; URI_PARTS] = [
    UriPart::Scheme,
    UriPart::Userinfo,
    UriPart::Host,
    UriPart::Port,
    UriPart::Path,
    UriPart::Query,
    UriPart::Fragment,
];

/// The most path segments `norm` will consider.
///
/// `remove_dot_segments` needs the surviving segments' bounds before it can
/// emit the first of them, and this crate allocates nothing, so the bound is
/// a fixed array.  A path deeper than this is a phase failure at the VCL
/// line, the way exceeding [`MAX_LIST_ITEMS`] is -- never a path normalised
/// halfway.
pub const URI_MAX_SEGMENTS: usize = 128;

/// A `uri` state mutation.
///
/// The seven `Set*` operations are one per component rather than one
/// operation carrying the component in `OpCode::extra`, so the VCL name and
/// the operation keep the one-to-one relation every other module's table
/// has: `uri.set_host` is a row, not a row plus an argument.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriOp {
    /// `parse(input, norm)`.  The routine input is the URI rather than a
    /// state; an empty one falls back to the argument, which carries the
    /// request's own `Host` and URL as `host \0 url`.
    Parse = 0,
    SetScheme = 1,
    SetUserinfo = 2,
    SetHost = 3,
    SetPort = 4,
    SetPath = 5,
    SetQuery = 6,
    SetFragment = 7,
}

/// A `uri` read.  The first seven are `get_<component>()`, and share their
/// discriminant with [`UriPart`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriRead {
    Scheme = 0,
    Userinfo = 1,
    Host = 2,
    Port = 3,
    Path = 4,
    Query = 5,
    Fragment = 6,
    /// `as_string(fmt, decode)`; the argument is the format string.
    AsString = 7,
}

/// The one boolean parameter a `uri` call may carry, in `OpCode::extra`.
///
/// One bit rather than three names, because no `uri` function has two
/// booleans: it is `decode` on a read, `encode` on a set and `norm` on a
/// parse.  It lives in `extra` because `flag` has no bit left.
pub const URI_EXTRA_OPTION: u16 = 1 << 0;

/// The default port each scheme that has one drops under normalisation.
const URI_DEFAULT_PORTS: [(&[u8], &[u8]); 4] = [
    (b"http", b"80"),
    (b"https", b"443"),
    (b"ftp", b"21"),
    (b"ssh", b"22"),
];

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => byte - b'A' + 10,
    }
}

/// A complete `%XX` at `at`, decoded.
///
/// The vmod reads the two bytes after a `%` whether or not they are hex
/// digits and decodes whatever the arithmetic produces; this refuses a
/// malformed escape instead, and every caller then passes the bytes through
/// untouched.
fn percent_at(input: &[u8], at: usize) -> Option<u8> {
    let high = *input.get(at + 1)?;
    let low = *input.get(at + 2)?;
    if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
        return None;
    }
    Some((hex_value(high) << 4) | hex_value(low))
}

fn is_sub_delim(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn is_reserved(byte: u8) -> bool {
    matches!(byte, b':' | b'/' | b'?' | b'#' | b'[' | b']' | b'@') || is_sub_delim(byte)
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Whether the byte at `at` is one the component may carry unescaped, as the
/// `URI_USERINFO`/`URI_HOST`/`URI_PATH`/`URI_QUERY`/`URI_FRAGMENT` macros
/// define it.  A `%` that opens a complete escape is allowed, which is what
/// keeps an already-encoded value from being encoded twice.
fn uri_allows(part: UriPart, input: &[u8], at: usize) -> bool {
    let byte = input[at];
    if is_unreserved(byte) || is_sub_delim(byte) {
        return true;
    }
    if byte == b'%' && percent_at(input, at).is_some() {
        return true;
    }
    match part {
        UriPart::Userinfo => byte == b':',
        UriPart::Host => matches!(byte, b':' | b'[' | b']'),
        UriPart::Path => matches!(byte, b':' | b'@' | b'/'),
        UriPart::Query | UriPart::Fragment => matches!(byte, b':' | b'@' | b'/' | b'?'),
        // The two components the vmod gives no `encode` parameter.
        UriPart::Scheme | UriPart::Port => false,
    }
}

fn write_percent(byte: u8, out: &mut Writer<'_>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.byte(b'%');
    out.byte(HEX[usize::from(byte >> 4)]);
    out.byte(HEX[usize::from(byte & 0x0f)]);
}

/// Percent-encode every byte the component may not carry.
fn uri_encode(part: UriPart, value: &[u8], out: &mut Writer<'_>) {
    for at in 0..value.len() {
        if uri_allows(part, value, at) {
            out.byte(value[at]);
        } else {
            write_percent(value[at], out);
        }
    }
}

/// Percent-decode the *reserved* characters and leave everything else, which
/// is what the `decode` parameter of a read does.
///
/// Reserved characters are all ASCII, so a decoded read is valid UTF-8
/// exactly when the state it came from was.  The same holds of
/// [`uri_normalize_generic`], which decodes only unreserved characters, and
/// of [`uri_encode`], whose output is ASCII by construction: nothing in this
/// module can hand a VCL guest a string it cannot hold.
fn uri_decode_reserved(value: &[u8], out: &mut Writer<'_>) {
    let mut at = 0;
    while at < value.len() {
        match percent_at(value, at) {
            Some(byte) if value[at] == b'%' => {
                if is_reserved(byte) {
                    out.byte(byte);
                } else {
                    out.bytes(&value[at..at + 3]);
                }
                at += 3;
            }
            _ => {
                out.byte(value[at]);
                at += 1;
            }
        }
    }
}

/// RFC 3986 Section 6.2.2 for one component: decode the unreserved escapes,
/// upper-case the ones that survive, and optionally lower-case the literal
/// bytes.
fn uri_normalize_generic(value: &[u8], to_lower: bool, out: &mut Writer<'_>) {
    let case = |byte: u8| {
        if to_lower {
            byte.to_ascii_lowercase()
        } else {
            byte
        }
    };
    let mut at = 0;
    while at < value.len() {
        match percent_at(value, at) {
            Some(byte) if value[at] == b'%' => {
                if is_unreserved(byte) {
                    out.byte(case(byte));
                } else {
                    out.byte(b'%');
                    out.byte(value[at + 1].to_ascii_uppercase());
                    out.byte(value[at + 2].to_ascii_uppercase());
                }
                at += 3;
            }
            _ => {
                out.byte(case(value[at]));
                at += 1;
            }
        }
    }
}

/// Whether a segment normalises to `.` or to `..`.
///
/// The test is on the *normalised* bytes, because `%2E` is an unreserved
/// escape and so a dot segment in disguise.  Two bytes of stack are enough:
/// [`Writer`] counts what does not fit, so a longer segment fails the length
/// test rather than the content one.
fn uri_dot_segment(value: &[u8], want: usize) -> bool {
    let mut buffer = [0u8; 2];
    let mut writer = Writer::new(&mut buffer);
    uri_normalize_generic(value, false, &mut writer);
    writer.finish() == want && buffer[..want].iter().all(|byte| *byte == b'.')
}

/// `remove_dot_segments` of RFC 3986 Section 5.2.4, over the segments of a
/// path, answering their surviving bounds.
///
/// The vmod runs a byte loop with a rewinding write head instead, which this
/// crate cannot do -- a [`Writer`] never unwrites -- and which mangles an
/// ordinary path whose segment merely *ends* in a dot: `/dir./x` loses both
/// the dot and the slash after it.  The RFC's algorithm is the one the vmod
/// documents, so it is the one this implements.
fn uri_remove_dot_segments(
    value: &[u8],
    stack: &mut [(u16, u16); URI_MAX_SEGMENTS],
) -> Option<usize> {
    if u16::try_from(value.len()).is_err() {
        return None;
    }
    let rooted = value.first() == Some(&b'/');
    let body = if rooted { &value[1..] } else { value };
    let offset = value.len() - body.len();
    let mut kept = 0usize;
    let mut at = 0usize;
    loop {
        let end = body[at..]
            .iter()
            .position(|byte| *byte == b'/')
            .map_or(body.len(), |found| at + found);
        let last = end == body.len();
        let segment = &body[at..end];
        let dots =
            usize::from(uri_dot_segment(segment, 1)) + 2 * usize::from(uri_dot_segment(segment, 2));
        if dots == 2 {
            kept = kept.saturating_sub(1);
        }
        if dots == 0 || last {
            // A trailing `.` or `..` leaves an empty segment behind, which
            // is what gives the result its trailing slash.
            let bounds = if dots == 0 {
                ((offset + at) as u16, (offset + end) as u16)
            } else {
                (0, 0)
            };
            *stack.get_mut(kept)? = bounds;
            kept += 1;
        }
        if last {
            return Some(kept);
        }
        at = end + 1;
    }
}

/// Normalise a path: the generic rules first, so an escaped dot segment is
/// visible, then `remove_dot_segments`.
fn uri_normalize_path(value: &[u8], out: &mut Writer<'_>) {
    let mut stack = [(0u16, 0u16); URI_MAX_SEGMENTS];
    let Some(kept) = uri_remove_dot_segments(value, &mut stack) else {
        // Refused when the state was built, so this is unreachable; leaving
        // the path generically normalised still beats truncating it.
        uri_normalize_generic(value, false, out);
        return;
    };
    if value.first() == Some(&b'/') {
        out.byte(b'/');
    }
    for (index, (start, end)) in stack[..kept].iter().enumerate() {
        if index > 0 {
            out.byte(b'/');
        }
        uri_normalize_generic(&value[usize::from(*start)..usize::from(*end)], false, out);
    }
}

/// The byte transform a record still owes, applied on its way into the next
/// state string.
fn uri_render(part: UriPart, entry: &Record<'_>, out: &mut Writer<'_>) {
    if entry.has(record::ENCODE) {
        uri_encode(part, entry.value, out);
    } else if entry.has(record::NORMALIZE) {
        match part {
            UriPart::Scheme => out.bytes_case(entry.value, Case::Lower),
            UriPart::Host => uri_normalize_generic(entry.value, true, out),
            UriPart::Path => uri_normalize_path(entry.value, out),
            _ => uri_normalize_generic(entry.value, false, out),
        }
    } else {
        out.bytes(entry.value);
    }
}

fn uri_rendered_len(part: UriPart, entry: &Record<'_>) -> usize {
    let mut writer = Writer::new(&mut []);
    uri_render(part, entry, &mut writer);
    writer.finish()
}

/// Serialise a `uri` state, applying every pending byte transform.
///
/// This is [`ListState::write`] with one difference, and the difference is
/// why it exists: a record whose value is *about* to be encoded or normalised
/// has no buffer holding the bytes the state must carry, so the length word
/// and the value both come from [`uri_render`] and the pending bits are
/// cleared on the way out.  Nothing downstream sees a half-applied
/// transform, and a state that has been written once is inert.
pub fn uri_write(state: &ListState<'_>, out: &mut Writer<'_>) {
    out.decimal(usize::from(state.flags));
    out.byte(b';');
    for (index, part) in URI_ORDER.iter().enumerate() {
        let entry = &state.records[index];
        out.decimal(usize::from(
            entry.flags & !(record::ENCODE | record::NORMALIZE),
        ));
        out.byte(b',');
        // A uri record has no name: the index is the component.
        out.decimal(0);
        out.byte(b',');
        out.decimal(uri_rendered_len(*part, entry));
        out.byte(b',');
        uri_render(*part, entry, out);
    }
}

fn uri_empty<'a>() -> ListState<'a> {
    let mut state = ListState::empty();
    for _ in 0..URI_PARTS {
        let _ = state.push(Record {
            name: &[],
            value: &[],
            // Absent, which is the vmod's NULL, and distinct from a
            // component that is present and empty -- which still renders its
            // separator, so `http://h/p?` keeps its `?`.
            flags: record::DELETED,
            case: Case::Keep,
        });
    }
    state
}

fn uri_present(state: &ListState<'_>, part: UriPart) -> bool {
    !state.records[part as usize].has(record::DELETED)
}

fn uri_value<'a>(state: &ListState<'a>, part: UriPart) -> &'a [u8] {
    state.records[part as usize].value
}

/// Present and non-empty, which is the vmod's `SOK`.
fn uri_filled(state: &ListState<'_>, part: UriPart) -> bool {
    uri_present(state, part) && !uri_value(state, part).is_empty()
}

fn uri_has_auth(state: &ListState<'_>) -> bool {
    uri_filled(state, UriPart::Userinfo)
        || uri_filled(state, UriPart::Host)
        || uri_filled(state, UriPart::Port)
}

fn uri_set<'a>(state: &mut ListState<'a>, part: UriPart, value: &'a [u8], flags: u8) {
    state.records[part as usize] = Record {
        name: &[],
        value,
        flags,
        case: Case::Keep,
    };
}

fn uri_clear(state: &mut ListState<'_>, part: UriPart) {
    uri_set(state, part, &[], record::DELETED);
}

// ── parsing ─────────────────────────────────────────────────────────────
//
// Each step takes the input and an offset, sets at most one component and
// answers where the next step starts.  That is `uri_parse.c` with its `const
// char *` cursors replaced by indexes, so a component borrows the string the
// state was parsed from rather than a copy of it.

fn uri_parse_scheme<'a>(
    state: &mut ListState<'a>,
    input: &'a [u8],
    at: usize,
    colon: bool,
) -> usize {
    if !input.get(at).is_some_and(u8::is_ascii_alphabetic) {
        return at;
    }
    let mut end = at + 1;
    while input
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        end += 1;
    }
    if colon && input.get(end) != Some(&b':') {
        return at;
    }
    uri_set(state, UriPart::Scheme, &input[at..end], 0);
    end + usize::from(colon)
}

/// `URI_PORT_EXP`: every byte up to the end, a `#`, a `?` or a `/`.  It is
/// deliberately not "digits" -- the vmod stores whatever stands there.
fn uri_port_byte(byte: u8) -> bool {
    !matches!(byte, b'#' | b'?' | b'/')
}

fn uri_parse_port<'a>(state: &mut ListState<'a>, input: &'a [u8], at: usize, colon: bool) -> usize {
    let start = if colon {
        if input.get(at) != Some(&b':') {
            return at;
        }
        at + 1
    } else {
        at
    };
    let mut end = start;
    while input.get(end).copied().is_some_and(uri_port_byte) {
        end += 1;
    }
    uri_set(state, UriPart::Port, &input[start..end], 0);
    end
}

fn uri_parse_host<'a>(
    state: &mut ListState<'a>,
    input: &'a [u8],
    at: usize,
    ip_literal: bool,
) -> usize {
    let mut end = at;
    while input
        .get(end)
        .copied()
        .is_some_and(|byte| uri_port_byte(byte) && byte != if ip_literal { b']' } else { b':' })
    {
        end += 1;
    }
    if ip_literal {
        if input.get(end) != Some(&b']') {
            return at;
        }
        end += 1;
    }
    uri_set(state, UriPart::Host, &input[at..end], 0);
    end
}

fn uri_parse_userinfo<'a>(state: &mut ListState<'a>, input: &'a [u8], at: usize) -> usize {
    let mut end = at;
    while end < input.len() && uri_allows(UriPart::Userinfo, input, end) {
        end += 1;
    }
    if input.get(end) != Some(&b'@') {
        return at;
    }
    uri_set(state, UriPart::Userinfo, &input[at..end], 0);
    end + 1
}

/// The authority body: `[userinfo '@'] host [':' port]`, with no `//`.
fn uri_parse_authority<'a>(state: &mut ListState<'a>, input: &'a [u8], at: usize) -> usize {
    // The bracket that marks an IPv6 literal is the first byte of the *host*,
    // which is where the cursor lands only once any `user@` is consumed --
    // so the test comes after userinfo, not before it. Userinfo commits
    // nothing without an `@`, and its charset carries neither `@` nor `[`,
    // so running it first is safe even when the authority is a literal.
    let next = uri_parse_userinfo(state, input, at);
    let ip_literal = input.get(next) == Some(&b'[');
    let next = uri_parse_host(state, input, next, ip_literal);
    uri_parse_port(state, input, next, true)
}

fn uri_parse_auth<'a>(state: &mut ListState<'a>, input: &'a [u8], at: usize) -> usize {
    if input.get(at) != Some(&b'/') || input.get(at + 1) != Some(&b'/') {
        return at;
    }
    uri_parse_authority(state, input, at + 2)
}

fn uri_parse_path<'a>(state: &mut ListState<'a>, input: &'a [u8], at: usize, auth: bool) -> usize {
    // Under an authority a path must start with exactly one slash, or it is
    // not this URI's path at all.
    if auth && (input.get(at) != Some(&b'/') || input.get(at + 1) == Some(&b'/')) {
        return at;
    }
    let mut end = at;
    while input
        .get(end)
        .is_some_and(|byte| !matches!(byte, b'#' | b'?'))
    {
        end += 1;
    }
    uri_set(state, UriPart::Path, &input[at..end], 0);
    end
}

fn uri_parse_query<'a>(state: &mut ListState<'a>, input: &'a [u8], at: usize) -> usize {
    if input.get(at) != Some(&b'?') {
        return at;
    }
    let start = at + 1;
    let mut end = start;
    while input.get(end).is_some_and(|byte| *byte != b'#') {
        end += 1;
    }
    uri_set(state, UriPart::Query, &input[start..end], 0);
    end
}

fn uri_parse_fragment<'a>(state: &mut ListState<'a>, input: &'a [u8], at: usize) {
    if input.get(at) != Some(&b'#') {
        return;
    }
    uri_set(state, UriPart::Fragment, &input[at + 1..], 0);
}

/// The safe normalisation of RFC 3986 Section 6.
///
/// Every component is *marked* rather than rewritten -- the bytes it will
/// carry exist nowhere yet -- and the two rules that are decisions rather
/// than byte transforms are applied here: a default port for a scheme that
/// has one is dropped, and an empty path under an authority becomes `/`.
fn uri_normalize(state: &mut ListState<'_>) -> Option<()> {
    for part in URI_ORDER {
        if uri_present(state, part) {
            state.records[part as usize].flags |= record::NORMALIZE;
        }
    }
    if uri_filled(state, UriPart::Scheme) && uri_present(state, UriPart::Port) {
        let scheme = uri_value(state, UriPart::Scheme);
        let port = uri_value(state, UriPart::Port);
        if URI_DEFAULT_PORTS
            .iter()
            .any(|(name, default)| scheme.eq_ignore_ascii_case(name) && port == *default)
        {
            uri_clear(state, UriPart::Port);
        }
    }
    let auth = uri_has_auth(state);
    let path = uri_value(state, UriPart::Path);
    if path.is_empty() {
        if auth {
            uri_set(state, UriPart::Path, b"/", 0);
        }
        return Some(());
    }
    // Refuse here rather than in the renderer, which has no way to fail.
    uri_remove_dot_segments(path, &mut [(0, 0); URI_MAX_SEGMENTS]).map(|_| ())
}

/// `parse(input, norm)`.
///
/// An empty input falls back to the request's own `Host` and URL, which
/// reach the routine as `host \0 url` because the input operand is taken.
/// The vmod glues the two into `//host` + url and parses that; parsing them
/// apart is the same authority and keeps a URL that happens to begin with
/// `//` from being read as one. The URL is therefore parsed with no
/// authority in force: the authority came from the `Host` header and is
/// already consumed, so `//foo/bar` is this request's path -- the rule that
/// rejects it belongs to the explicit form, where `//` really does open an
/// authority.
fn uri_parse<'a>(input: &'a [u8], code: OpCode, implicit: &'a [u8]) -> Option<ListState<'a>> {
    let mut state = uri_empty();
    if input.is_empty() {
        let (host, url) = name_and_value(implicit);
        if !host.is_empty() {
            uri_parse_authority(&mut state, host, 0);
        }
        let mut at = 0;
        if !url.is_empty() {
            at = uri_parse_path(&mut state, url, at, false);
        }
        if at < url.len() {
            at = uri_parse_query(&mut state, url, at);
        }
        if at < url.len() {
            uri_parse_fragment(&mut state, url, at);
        }
    } else {
        let mut at = uri_parse_scheme(&mut state, input, 0, true);
        if at < input.len() {
            at = uri_parse_auth(&mut state, input, at);
        }
        if at < input.len() {
            let auth = uri_has_auth(&state);
            at = uri_parse_path(&mut state, input, at, auth);
        }
        if at < input.len() {
            at = uri_parse_query(&mut state, input, at);
        }
        if at < input.len() {
            uri_parse_fragment(&mut state, input, at);
        }
    }
    if code.extra & URI_EXTRA_OPTION != 0 {
        uri_normalize(&mut state)?;
    }
    Some(state)
}

fn uri_set_part(op: u8) -> Option<UriPart> {
    Some(match op {
        1 => UriPart::Scheme,
        2 => UriPart::Userinfo,
        3 => UriPart::Host,
        4 => UriPart::Port,
        5 => UriPart::Path,
        6 => UriPart::Query,
        7 => UriPart::Fragment,
        _ => return None,
    })
}

/// `set_<component>(new, encode)`.
///
/// An empty `new` clears the component, which is what the vmod's default
/// argument does.  `scheme` and `port` have no `encode` parameter and are
/// re-parsed instead: a value their own grammar does not consume whole
/// clears the component, exactly as `URI_SET` does.
fn uri_apply<'a>(
    state: &mut ListState<'a>,
    code: OpCode,
    argument: &'a [u8],
) -> Result<(), PhaseFailure> {
    // A state of any other length was not written by `uri_write`, which the
    // compiler's lowering makes impossible; refusing beats repairing it into
    // seven components that were never there.
    let Some(part) = uri_set_part(code.op).filter(|_| state.count == URI_PARTS) else {
        return Err(PhaseFailure);
    };
    if argument.is_empty() {
        uri_clear(state, part);
        return Ok(());
    }
    match part {
        UriPart::Scheme | UriPart::Port => {
            let mut parsed = uri_empty();
            let end = if part == UriPart::Scheme {
                uri_parse_scheme(&mut parsed, argument, 0, false)
            } else {
                uri_parse_port(&mut parsed, argument, 0, false)
            };
            if end < argument.len() {
                uri_clear(state, part);
            } else {
                state.records[part as usize] = parsed.records[part as usize];
            }
        }
        _ => {
            let flags = if code.extra & URI_EXTRA_OPTION != 0 {
                record::ENCODE
            } else {
                0
            };
            uri_set(state, part, argument, flags);
        }
    }
    Ok(())
}

/// The output side of `as_string` and of a decoding read.
///
/// The vmod formats the whole URI and only then decodes the result, so the
/// decoder has to span the separators `as_string` itself inserted.  Holding
/// the at most two bytes of a half-seen escape does that in one streaming
/// pass, with no buffer for the formatted string.
struct UriOut<'a, 'b> {
    out: &'a mut Writer<'b>,
    decode: bool,
    held: u8,
    count: usize,
}

impl<'a, 'b> UriOut<'a, 'b> {
    fn new(out: &'a mut Writer<'b>, decode: bool) -> Self {
        Self {
            out,
            decode,
            held: 0,
            count: 0,
        }
    }

    fn byte(&mut self, byte: u8) {
        if !self.decode {
            self.out.byte(byte);
            return;
        }
        match self.count {
            0 if byte == b'%' => self.count = 1,
            0 => self.out.byte(byte),
            1 if byte.is_ascii_hexdigit() => {
                self.held = byte;
                self.count = 2;
            }
            1 => {
                self.out.byte(b'%');
                self.count = 0;
                self.byte(byte);
            }
            _ if byte.is_ascii_hexdigit() => {
                self.count = 0;
                let value = (hex_value(self.held) << 4) | hex_value(byte);
                if is_reserved(value) {
                    self.out.byte(value);
                } else {
                    self.out.byte(b'%');
                    self.out.byte(self.held);
                    self.out.byte(byte);
                }
            }
            _ => {
                self.out.byte(b'%');
                self.out.byte(self.held);
                self.count = 0;
                self.byte(byte);
            }
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.byte(*byte);
        }
    }

    /// Flush the `%` or `%X` the input ended on, which decodes to itself.
    fn finish(self) {
        if self.count >= 1 {
            self.out.byte(b'%');
        }
        if self.count == 2 {
            self.out.byte(self.held);
        }
    }
}

/// One component of `as_string`, with the separators it owns.  An absent
/// component contributes nothing, including its separators; a present but
/// empty one contributes them.
fn uri_component_as_string(
    state: &ListState<'_>,
    part: UriPart,
    prefix: Option<u8>,
    postfix: Option<u8>,
    out: &mut UriOut<'_, '_>,
) {
    if !uri_present(state, part) {
        return;
    }
    if let Some(byte) = prefix {
        out.byte(byte);
    }
    out.bytes(uri_value(state, part));
    if let Some(byte) = postfix {
        out.byte(byte);
    }
}

fn uri_as_string(state: &ListState<'_>, fmt: &[u8], decode: bool, out: &mut Writer<'_>) {
    let mut sink = UriOut::new(out, decode);
    let mut at = 0;
    while at < fmt.len() {
        if fmt[at] != b'%' {
            sink.byte(fmt[at]);
            at += 1;
            continue;
        }
        let Some(token) = fmt.get(at + 1) else {
            sink.byte(b'%');
            break;
        };
        at += 2;
        match token {
            b'%' => sink.byte(b'%'),
            b'S' => uri_component_as_string(state, UriPart::Scheme, None, Some(b':'), &mut sink),
            b'A' => {
                if URI_ORDER[1..4].iter().any(|part| uri_present(state, *part)) {
                    sink.byte(b'/');
                    sink.byte(b'/');
                    uri_component_as_string(state, UriPart::Userinfo, None, Some(b'@'), &mut sink);
                    uri_component_as_string(state, UriPart::Host, None, None, &mut sink);
                    uri_component_as_string(state, UriPart::Port, Some(b':'), None, &mut sink);
                }
            }
            b'U' => uri_component_as_string(state, UriPart::Userinfo, None, Some(b'@'), &mut sink),
            b'H' => uri_component_as_string(state, UriPart::Host, None, None, &mut sink),
            b'p' => uri_component_as_string(state, UriPart::Port, Some(b':'), None, &mut sink),
            b'P' => uri_component_as_string(state, UriPart::Path, None, None, &mut sink),
            b'Q' => uri_component_as_string(state, UriPart::Query, Some(b'?'), None, &mut sink),
            b'F' => uri_component_as_string(state, UriPart::Fragment, Some(b'#'), None, &mut sink),
            other => {
                sink.byte(b'%');
                sink.byte(*other);
            }
        }
    }
    sink.finish();
}

/// `get_<component>(decode)` and `as_string(fmt, decode)`.
pub fn uri_read<'a>(
    state: &ListState<'a>,
    code: OpCode,
    argument: &'a [u8],
    out: &mut Writer<'_>,
) -> bool {
    if state.count != URI_PARTS {
        return false;
    }
    let decode = code.extra & URI_EXTRA_OPTION != 0;
    if code.op == UriRead::AsString as u8 {
        uri_as_string(state, argument, decode, out);
        return true;
    }
    let Some(part) = URI_ORDER.get(usize::from(code.op)) else {
        return false;
    };
    if !uri_present(state, *part) {
        return false;
    }
    let value = uri_value(state, *part);
    if decode {
        uri_decode_reserved(value, out);
    } else {
        out.bytes(value);
    }
    true
}

/// `uri.decode(in, strict)`: percent-decoding limited to the *unreserved*
/// characters -- a narrower set than a read's `decode` uses, and the vmod's
/// one stand-alone call, touching no state.
///
/// `Err` is the strict refusal, which fails the phase at the VCL line.  A
/// lenient run never fails and preserves what it could not parse.
pub fn uri_decode_unreserved(
    input: &[u8],
    strict: bool,
    out: &mut Writer<'_>,
) -> Result<(), PhaseFailure> {
    let mut at = 0;
    while at < input.len() {
        if input[at] != b'%' {
            out.byte(input[at]);
            at += 1;
            continue;
        }
        match percent_at(input, at) {
            Some(byte) if is_unreserved(byte) => out.byte(byte),
            Some(_) => out.bytes(&input[at..at + 3]),
            None => {
                if strict {
                    return Err(PhaseFailure);
                }
                out.byte(b'%');
                at += 1;
                continue;
            }
        }
        at += 3;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Guest entry points
//
// Every list-shaped module presents the same three calls, with the same
// register assignment, so `vcl-compiler` emits one call sequence per kind
// rather than one per module.  The shape is exactly the host-syscall shape a
// VCL guest already knows:
//
//     (input, input_len, code, argument, argument_len, output, output_cap)
//
// `code` is an `OpCode`.  `input` is the module's serialised state, except
// for each module's `Parse` operation, whose input is the source string the
// state is built from.  A string result follows the measure-then-fill
// protocol: `output_cap = 0` returns the length needed and writes nothing.
// ---------------------------------------------------------------------------

/// The read shape: `-1` means the value is absent and the caller substitutes
/// the VCL `default` argument.
fn read_entry<'a>(
    input: &'a [u8],
    code: i64,
    argument: &'a [u8],
    output: &mut [u8],
    read: fn(&ListState<'a>, OpCode, &'a [u8], &mut Writer<'_>) -> bool,
) -> i64 {
    let Some(state) = ListState::parse(input) else {
        return -1;
    };
    let mut writer = Writer::new(output);
    if !read(&state, OpCode::decode(code), argument, &mut writer) {
        return -1;
    }
    writer.finish() as i64
}

/// The count shape.  `-1` means the state string was not one this crate
/// produced, which the compiler's lowering makes unreachable.
fn count_entry<'a>(
    input: &'a [u8],
    code: i64,
    argument: &'a [u8],
    count: fn(&ListState<'a>, OpCode, &'a [u8]) -> i64,
) -> i64 {
    match ListState::parse(input) {
        Some(state) => count(&state, OpCode::decode(code), argument),
        None => -1,
    }
}

/// The transform shape: a state in, a state out.  `-1` is a phase failure at
/// the VCL line -- the module ran out of its fixed record capacity, or the
/// operation code was not one this module has.
///
/// `parse` takes the whole call rather than only the source string, because
/// `uri.parse()` falls back to an argument when its input is empty, and
/// `write` is a parameter because a `uri` record may still owe a byte
/// transform that only the serialiser can apply.
// Eight arguments, because this is the one transform entry all four modules
// share: splitting it would be four near-copies of the sizing protocol, which
// is exactly what `crate::vmod` in vcl-compiler exists to prevent.
#[allow(clippy::too_many_arguments)]
fn transform_entry<'a>(
    input: &'a [u8],
    code: i64,
    argument: &'a [u8],
    output: &mut [u8],
    parse_op: u8,
    parse: fn(&'a [u8], OpCode, &'a [u8]) -> Option<ListState<'a>>,
    transform: fn(&mut ListState<'a>, OpCode, &'a [u8]) -> Result<(), PhaseFailure>,
    write: fn(&ListState<'a>, &mut Writer<'_>),
) -> i64 {
    let decoded = OpCode::decode(code);
    let state = if decoded.op == parse_op {
        parse(input, decoded, argument)
    } else {
        match ListState::parse(input) {
            Some(mut state) => match transform(&mut state, decoded, argument) {
                Ok(()) => Some(state),
                Err(PhaseFailure) => None,
            },
            None => None,
        }
    };
    let Some(state) = state else {
        return -1;
    };
    let mut writer = Writer::new(output);
    write(&state, &mut writer);
    writer.finish() as i64
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_cookie_read(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    read_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        cookie_read,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_cookie_count(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
) -> i64 {
    count_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        |state, _, _| cookie_count(state),
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_cookie_transform(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    transform_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        CookieOp::Parse as u8,
        |input, _, _| cookie_parse(input),
        cookie_transform,
        ListState::write,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_setcookie_read(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    read_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        setcookie_read,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_setcookie_count(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
) -> i64 {
    count_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        |state, _, _| setcookie_count(state),
    )
}

/// The Set-Cookie transform, which is the one module that cannot use
/// [`transform_entry`]: `Add` composes a record value out of six arguments
/// and `Render` writes a state of a different shape, so both need the writer
/// rather than a mutated list.
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_setcookie_transform(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    let input = unsafe { raw_bytes(input, len) };
    let argument = unsafe { raw_bytes(argument, argument_len) };
    let decoded = OpCode::decode(code);
    let mut writer = Writer::new(unsafe { raw_bytes_mut(output, cap) });
    if decoded.op == SetcookieOp::Parse as u8 {
        let Some(state) = setcookie_parse(input) else {
            return -1;
        };
        state.write(&mut writer);
        return writer.finish() as i64;
    }
    let Some(mut state) = ListState::parse(input) else {
        return -1;
    };
    if decoded.op == SetcookieOp::Render as u8 {
        setcookie_render(&state, argument, &mut writer);
        return writer.finish() as i64;
    }
    if setcookie_transform(&mut state, decoded, argument).is_err() {
        return -1;
    }
    if decoded.op == SetcookieOp::Add as u8 && state.count >= MAX_LIST_ITEMS {
        return -1;
    }
    state.write(&mut writer);
    if decoded.op == SetcookieOp::Add as u8 {
        setcookie_append(decoded, argument, &mut writer);
    }
    writer.finish() as i64
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_url_read(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    read_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        url_read,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_url_count(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
) -> i64 {
    count_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        |state, code, _| url_count(state, code),
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_url_transform(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    transform_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        UrlOp::Parse as u8,
        |input, _, _| url_parse(input),
        url_transform,
        ListState::write,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_header_read(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    read_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        header_read,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_header_count(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
) -> i64 {
    count_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        header_count,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_header_transform(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    transform_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        HeaderOp::Parse as u8,
        |input, _, _| header_parse(input),
        header_transform,
        ListState::write,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_uri_read(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    read_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        uri_read,
    )
}

/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_uri_transform(
    input: *const u8,
    len: usize,
    code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    transform_entry(
        unsafe { raw_bytes(input, len) },
        code,
        unsafe { raw_bytes(argument, argument_len) },
        unsafe { raw_bytes_mut(output, cap) },
        UriOp::Parse as u8,
        uri_parse,
        uri_apply,
        uri_write,
    )
}

/// `std.collect`.  The [`StringEntry`] shape, with the name-filtered snapshot
/// where a module state would sit and the separator as the argument; `code`
/// is unused because the call has no options to carry.
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_collect(
    input: *const u8,
    len: usize,
    _code: i64,
    argument: *const u8,
    argument_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    let mut writer = Writer::new(unsafe { raw_bytes_mut(output, cap) });
    if !collect(
        unsafe { raw_bytes(input, len) },
        unsafe { raw_bytes(argument, argument_len) },
        &mut writer,
    ) {
        return -1;
    }
    writer.finish() as i64
}

/// Build the `Vec<Header>` for the host's generic header commit.
///
/// The odd argument out is `base`: the guest address `output` is mapped at.
/// The vector's entries hold pointers, and a pointer is only meaningful in
/// the guest's own address space, so the caller passes the address rather
/// than the routine guessing it from a `*mut u8` -- which is what lets the
/// host build run and test this at all.
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_header_commit(
    input: *const u8,
    len: usize,
    snapshot: *const u8,
    snapshot_len: usize,
    output: *mut u8,
    cap: usize,
    base: u64,
) -> i64 {
    let input = unsafe { raw_bytes(input, len) };
    let snapshot = unsafe { raw_bytes(snapshot, snapshot_len) };
    let (Some(state), Some(live)) = (ListState::parse(input), header_parse(snapshot)) else {
        return -1;
    };
    let mut writer = Writer::new(unsafe { raw_bytes_mut(output, cap) });
    match header_commit(&state, &live, base, &mut writer) {
        Ok(()) => writer.finish() as i64,
        Err(PhaseFailure) => -1,
    }
}

/// Match a Varnish `std.fnmatch` pattern.
///
/// This is the useful POSIX `fnmatch(3)` subset exposed by the VMOD: `*`,
/// `?`, ranges and negated ranges, plus `pathname`, `noescape`, and `period`.
/// The matcher deliberately keeps only the most recent star checkpoint, so
/// it uses constant space even for a host-sized header value.
///
/// Two documented departures from glibc, both verified by a randomised
/// differential and both left as they are because the corner is not worth the
/// matcher they would need:
///
/// * Bracket sub-expressions are literal bytes: `[[:digit:]]`, `[[.a.]]` and
///   `[[=a=]]` are not recognised as classes, collating symbols or
///   equivalence classes.
/// * With `pathname` and `period` together, an *escaped* separator (`\/`)
///   re-arms leading-period protection for the next segment, where glibc
///   arms it only after an unescaped one.
pub fn fnmatch(
    pattern: &[u8],
    subject: &[u8],
    pathname: bool,
    noescape: bool,
    period: bool,
) -> bool {
    let (mut text, mut pat) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;

    loop {
        if pat == pattern.len() {
            if text == subject.len() {
                return true;
            }
        } else {
            match pattern[pat] {
                b'*' => {
                    while pat < pattern.len() && pattern[pat] == b'*' {
                        pat += 1;
                    }
                    // POSIX only lets a leading period be matched by a period
                    // that is itself the first byte of the pattern (or the
                    // byte after a matched `/` under FNM_PATHNAME).  A star
                    // reaching one therefore fails outright: it may not
                    // consume the period, and matching the empty string here
                    // would hand the period to a pattern byte that is not in
                    // a leading position either.
                    if text < subject.len() && wildcard_forbidden(subject, text, pathname, period) {
                        return false;
                    }
                    star = Some((pat, text));
                    if pat == pattern.len() {
                        return !subject[text..].iter().enumerate().any(|(offset, byte)| {
                            (pathname && *byte == b'/')
                                || wildcard_forbidden(subject, text + offset, pathname, period)
                        });
                    }
                    continue;
                }
                b'?' if text < subject.len()
                    && (!pathname || subject[text] != b'/')
                    && !wildcard_forbidden(subject, text, pathname, period) =>
                {
                    pat += 1;
                    text += 1;
                    continue;
                }
                b'[' if text < subject.len()
                    && (!pathname || subject[text] != b'/')
                    && !wildcard_forbidden(subject, text, pathname, period) =>
                {
                    if let Some((next, matched)) = bracket(pattern, pat, subject[text], noescape) {
                        if matched {
                            pat = next;
                            text += 1;
                            continue;
                        }
                    } else if subject[text] == b'[' {
                        pat += 1;
                        text += 1;
                        continue;
                    }
                }
                b'\\' if !noescape => {
                    // POSIX: a pattern ending in an unpaired escape matches
                    // nothing, and no amount of backtracking can change that.
                    let Some(escaped) = pattern.get(pat + 1) else {
                        return false;
                    };
                    // A star's tail is confined to the path segment the star
                    // opened, so an escaped separator cannot be the byte that
                    // closes it.  An unescaped `/` still can, which is what
                    // makes `*/b` work and `*\/b` not.
                    let separator = pathname && *escaped == b'/';
                    if text < subject.len()
                        && subject[text] == *escaped
                        && !(separator && star.is_some())
                    {
                        pat += 2;
                        text += 1;
                        continue;
                    }
                }
                byte if text < subject.len() && subject[text] == byte => {
                    if pathname && byte == b'/' {
                        // A matched separator ends the segment, and with it
                        // any pending star: one may not cross a `/` anyway.
                        star = None;
                    }
                    pat += 1;
                    text += 1;
                    continue;
                }
                _ => {}
            }
        }

        let Some((resume_pat, matched)) = star else {
            return false;
        };
        if matched == subject.len()
            || (pathname && subject[matched] == b'/')
            || wildcard_forbidden(subject, matched, pathname, period)
        {
            return false;
        }
        text = matched + 1;
        pat = resume_pat;
        star = Some((resume_pat, text));
    }
}

fn wildcard_forbidden(subject: &[u8], at: usize, pathname: bool, period: bool) -> bool {
    period && subject[at] == b'.' && (at == 0 || (pathname && subject[at - 1] == b'/'))
}

/// Return the byte after a bracket expression and whether it matched.  An
/// unterminated expression is not a wildcard; POSIX treats its opening `[` as
/// an ordinary byte.
fn bracket(pattern: &[u8], start: usize, byte: u8, noescape: bool) -> Option<(usize, bool)> {
    let mut index = start + 1;
    let mut negate = false;
    if pattern
        .get(index)
        .is_some_and(|candidate| *candidate == b'!' || *candidate == b'^')
    {
        negate = true;
        index += 1;
    }
    let mut matched = false;
    let mut first = true;
    while index < pattern.len() {
        if pattern[index] == b']' && !first {
            return Some((index + 1, matched != negate));
        }
        let (left, after_left) = bracket_byte(pattern, index, noescape)?;
        index = after_left;
        if index + 1 < pattern.len() && pattern[index] == b'-' && pattern[index + 1] != b']' {
            let (right, after_right) = bracket_byte(pattern, index + 1, noescape)?;
            matched |= left <= byte && byte <= right;
            index = after_right;
        } else {
            matched |= byte == left;
        }
        first = false;
    }
    None
}

fn bracket_byte(pattern: &[u8], index: usize, noescape: bool) -> Option<(u8, usize)> {
    let byte = *pattern.get(index)?;
    if byte == b'\\' && !noescape && index + 1 < pattern.len() {
        Some((pattern[index + 1], index + 2))
    } else {
        Some((byte, index + 1))
    }
}

/// Parse Varnish's `VNUMpfx` numeric form: outer whitespace, sign, decimal
/// fraction, and exponent. The retained mantissa is deliberately bounded;
/// extra significant digits cannot affect a representable integer result.
fn decimal(input: &[u8]) -> Option<(bool, u128, i32)> {
    let input = trim_ascii(input);
    let (negative, input) = match input.first() {
        Some(b'-') => (true, &input[1..]),
        Some(b'+') => (false, &input[1..]),
        _ => (false, input),
    };
    let mut at = 0;
    let mut fraction = 0i32;
    let mut saw_digit = false;
    let mut after_decimal = false;
    let mut mantissa = 0u128;
    let mut significant = 0i32;
    let mut kept = 0i32;
    let mut nonzero = false;
    while let Some(byte) = input.get(at) {
        if byte.is_ascii_digit() {
            saw_digit = true;
            if after_decimal {
                fraction = fraction.saturating_add(1).min(10_000);
            }
            if *byte != b'0' || nonzero {
                nonzero = true;
                significant = significant.saturating_add(1).min(10_000);
                if kept < 19 {
                    mantissa = mantissa * 10 + u128::from(*byte - b'0');
                    kept += 1;
                }
            }
            at += 1;
        } else if *byte == b'.' && !after_decimal {
            after_decimal = true;
            at += 1;
        } else {
            break;
        }
    }
    if !saw_digit {
        return None;
    }
    let mut exponent = 0i32;
    if input
        .get(at)
        .is_some_and(|byte| *byte == b'e' || *byte == b'E')
    {
        at += 1;
        let negative_exponent = input.get(at) == Some(&b'-');
        if matches!(input.get(at), Some(b'-' | b'+')) {
            at += 1;
        }
        let start = at;
        while let Some(byte) = input.get(at).filter(|byte| byte.is_ascii_digit()) {
            exponent = exponent
                .saturating_mul(10)
                .saturating_add(i32::from(*byte - b'0'))
                .min(10_000);
            at += 1;
        }
        if at == start {
            return None;
        }
        if negative_exponent {
            exponent = -exponent;
        }
    }
    if at != input.len() {
        return None;
    }
    if !nonzero {
        return Some((false, 0, 0));
    }
    Some((
        negative,
        mantissa,
        exponent
            .saturating_sub(fraction)
            .saturating_add(significant - kept),
    ))
}

fn decimal_i64(input: &[u8], unit: u64) -> Option<i64> {
    let (negative, mantissa, scale) = decimal(input)?;
    let mut value = mantissa.checked_mul(u128::from(unit))?;
    if scale >= 0 {
        for _ in 0..scale {
            value = value.checked_mul(10)?;
        }
    } else if scale <= -39 {
        value = 0;
    } else {
        for _ in 0..-scale {
            value /= 10;
        }
    }
    let limit = if negative {
        1u128 << 63
    } else {
        i64::MAX as u128
    };
    if value > limit {
        return None;
    }
    if negative && value == 1u128 << 63 {
        Some(i64::MIN)
    } else if negative {
        Some(-(value as i64))
    } else {
        Some(value as i64)
    }
}

/// Parse `std.integer`, truncating fractions towards zero.
pub fn int_parse(input: &[u8], fallback: i64) -> i64 {
    decimal_i64(input, 1).unwrap_or(fallback)
}

/// Parse `std.duration` into nanoseconds. `y` is 365 days.
pub fn duration_parse(input: &[u8], fallback: i64) -> i64 {
    let input = trim_ascii(input);
    let (number, multiplier) = if let Some(number) = input.strip_suffix(b"ms") {
        (number, 1_000_000u64)
    } else if let Some(number) = input.strip_suffix(b"s") {
        (number, 1_000_000_000)
    } else if let Some(number) = input.strip_suffix(b"m") {
        (number, 60_000_000_000)
    } else if let Some(number) = input.strip_suffix(b"h") {
        (number, 3_600_000_000_000)
    } else if let Some(number) = input.strip_suffix(b"d") {
        (number, 86_400_000_000_000)
    } else if let Some(number) = input.strip_suffix(b"w") {
        (number, 604_800_000_000_000)
    } else if let Some(number) = input.strip_suffix(b"y") {
        (number, 31_536_000_000_000_000)
    } else {
        return fallback;
    };
    decimal_i64(number, multiplier).unwrap_or(fallback)
}

/// RV64 entry point for [`int_parse`].
///
/// The runtime jump table calls this with `(ptr, len, fallback)` in a0-a2.
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_int_parse(ptr: *const u8, len: usize, fallback: i64) -> i64 {
    // The compiler only passes string pairs it created or received from the
    // host, and their pointer/length validity is already an ABI invariant.
    int_parse(unsafe { core::slice::from_raw_parts(ptr, len) }, fallback)
}

/// RV64 entry point for [`duration_parse`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_duration_parse(ptr: *const u8, len: usize, fallback: i64) -> i64 {
    duration_parse(unsafe { core::slice::from_raw_parts(ptr, len) }, fallback)
}

#[derive(Clone, Copy)]
struct QueryPair {
    start: usize,
    len: usize,
}

/// Sort a URL query as `std.querysort` does: whole wire pairs, bytewise, no
/// decoding, and empty pairs discarded. A complete URL keeps its path and
/// drops a bare `?` when no pair survives.
///
/// The pair table is a fixed stack array, so a query with more pairs than it
/// holds is returned unsorted rather than refused. Varnish does the same when
/// its workspace allocation fails, and the alternative here is worse: the
/// client picks the pair count, so a refusal would be a request-triggered
/// guest fault.
pub fn querysort(input: &[u8], out: &mut [u8]) -> usize {
    const MAX_PAIRS: usize = 256;
    let question = input.iter().position(|byte| *byte == b'?');
    let (path, query) = match question {
        Some(at) => (&input[..at], &input[at + 1..]),
        None => (&[][..], input),
    };
    let query_start = input.len() - query.len();
    let mut pairs = [QueryPair { start: 0, len: 0 }; MAX_PAIRS];
    let mut count = 0;
    let mut at = 0;
    while at <= query.len() {
        let end = query[at..]
            .iter()
            .position(|byte| *byte == b'&')
            .map_or(query.len(), |offset| at + offset);
        if end != at {
            if count == MAX_PAIRS {
                return verbatim(input, out);
            }
            pairs[count] = QueryPair {
                start: query_start + at,
                len: end - at,
            };
            count += 1;
        }
        if end == query.len() {
            break;
        }
        at = end + 1;
    }
    let mut sorted = 1;
    while sorted < count {
        let current = pairs[sorted];
        let mut index = sorted;
        while index > 0
            && input[current.start..current.start + current.len]
                < input[pairs[index - 1].start..pairs[index - 1].start + pairs[index - 1].len]
        {
            pairs[index] = pairs[index - 1];
            index -= 1;
        }
        pairs[index] = current;
        sorted += 1;
    }
    let prefix_len = match question {
        Some(_) if count > 0 => path.len() + 1,
        Some(_) => path.len(),
        None => 0,
    };
    let mut needed = prefix_len;
    for (index, pair) in pairs[..count].iter().enumerate() {
        needed += pair.len + usize::from(index != 0);
    }
    if out.len() < needed {
        return needed;
    }
    let mut written = 0;
    if question.is_some() {
        out[..path.len()].copy_from_slice(path);
        written = path.len();
        if count > 0 {
            out[written] = b'?';
            written += 1;
        }
    }
    for (index, pair) in pairs[..count].iter().enumerate() {
        if index != 0 {
            out[written] = b'&';
            written += 1;
        }
        out[written..written + pair.len].copy_from_slice(&input[pair.start..pair.start + pair.len]);
        written += pair.len;
    }
    needed
}

/// Return the input unchanged, honouring the two-call measure-then-write
/// protocol the sorted path uses.
fn verbatim(input: &[u8], out: &mut [u8]) -> usize {
    if out.len() >= input.len() {
        out[..input.len()].copy_from_slice(input);
    }
    input.len()
}

/// RV64 entry point for [`querysort`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_querysort(ptr: *const u8, len: usize, out: *mut u8, cap: usize) -> i64 {
    let out = if out.is_null() {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(out, cap) }
    };
    let needed = querysort(unsafe { core::slice::from_raw_parts(ptr, len) }, out);
    i64::try_from(needed).unwrap_or(-1)
}

/// Parse the HTTP-date forms accepted by Varnish's `std.time`, returning the
/// caller's fallback for malformed or out-of-range input.  The result is a
/// signed nanosecond count since the Unix epoch.
pub fn time_parse(input: &[u8], fallback: i64) -> i64 {
    let input = trim_ascii(input);
    let seconds = if input.contains(&b',') {
        parse_http_date(input)
    } else if input.first().is_some_and(u8::is_ascii_alphabetic) {
        parse_asctime(input)
    } else {
        parse_iso_date(input)
    };
    seconds
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .unwrap_or(fallback)
}

/// Render a timestamp as the RFC 7231 HTTP-date form.  It returns the number
/// of bytes required (always 29), and only writes when the supplied output
/// capacity is large enough.
pub fn time_format(time: i64, out: &mut [u8]) -> usize {
    const LEN: usize = TIME_FORMAT_LEN;
    if out.len() < LEN {
        return LEN;
    }
    let seconds = time.div_euclid(1_000_000_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = ((days + 4).rem_euclid(7)) as usize;
    let hour = day_seconds / 3600;
    let minute = (day_seconds % 3600) / 60;
    let second = day_seconds % 60;
    out[..3].copy_from_slice(WEEKDAYS[weekday]);
    out[3] = b',';
    out[4] = b' ';
    write_two(&mut out[5..7], day);
    out[7] = b' ';
    out[8..11].copy_from_slice(MONTHS[(month - 1) as usize]);
    out[11] = b' ';
    write_four(&mut out[12..16], year);
    out[16] = b' ';
    write_two(&mut out[17..19], hour);
    out[19] = b':';
    write_two(&mut out[20..22], minute);
    out[22] = b':';
    write_two(&mut out[23..25], second);
    out[25..29].copy_from_slice(b" GMT");
    LEN
}

/// RV64 entry point for [`time_parse`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_time_parse(ptr: *const u8, len: usize, fallback: i64) -> i64 {
    time_parse(unsafe { core::slice::from_raw_parts(ptr, len) }, fallback)
}

/// RV64 entry point for [`time_format`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_time_format(time: i64, out: *mut u8, cap: usize) -> i64 {
    let out = if out.is_null() {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(out, cap) }
    };
    time_format(time, out) as i64
}

/// RV64 entry point for [`fnmatch`]. String pairs occupy a0-a3 and the
/// `pathname`, `noescape`, and `period` flags occupy a4-a6.
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_fnmatch(
    pattern_ptr: *const u8,
    pattern_len: usize,
    subject_ptr: *const u8,
    subject_len: usize,
    pathname: i64,
    noescape: i64,
    period: i64,
) -> i64 {
    i64::from(fnmatch(
        unsafe { core::slice::from_raw_parts(pattern_ptr, pattern_len) },
        unsafe { core::slice::from_raw_parts(subject_ptr, subject_len) },
        pathname != 0,
        noescape != 0,
        period != 0,
    ))
}

// ── str ─────────────────────────────────────────────────────────────────
//
// The whole `str` vmod, ported from `varnish-cache-plus/lib/libvmod_str`.
// It is the one module in the survey that needs no host surface at all:
// every function is a pure transformation of bytes the guest already holds,
// so all eight live here and the compiler only marshals arguments.
//
// Where the enterprise `.vcc` documentation and `vmod_str.c` disagree -- the
// `substr` examples in the manual are off by a character or two from what the
// C actually computes -- the C is what runs in production, so it is what these
// routines reproduce.
//
// Varnish returns a NULL STRING from `len` (as -1), `substr` and `split` when
// the input is absent or the field does not exist.  VCL v1 here has no null
// string, so those cases are the empty string and, for `len`, zero.

/// A `str` operation whose result is an integer.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrTest {
    /// `len(S)`: the number of bytes in `S`.
    Len = 0,
    /// `startswith(S1, S2)`.
    StartsWith = 1,
    /// `endswith(S1, S2)`.
    EndsWith = 2,
    /// `contains(S1, S2)`.
    Contains = 3,
    /// `token_intersect(S1, S2, separators)`.
    TokenIntersect = 4,
}

/// A builtin that builds a string out of one subject and two integers.
///
/// Named for `str`, which is where the shape came from, but it is the shape
/// and not the module that decides membership: `uri.decode` has one subject
/// and one boolean and belongs here rather than in a routine of its own.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrEdit {
    /// `str.substr(S, N, OFFSET)`.
    Substr = 0,
    /// `str.reverse(S)`, which reverses bytes exactly as the enterprise
    /// module does; a multi-byte UTF-8 sequence does not survive it.
    Reverse = 1,
    /// `uri.decode(IN, STRICT)`; `count` carries `strict`.  It is the one
    /// member that can refuse, which is what `strict` asks for.
    UriDecode = 2,
}

/// The integer-valued half of `str`.
pub fn str_test(op: StrTest, subject: &[u8], other: &[u8], separators: &[u8]) -> i64 {
    match op {
        StrTest::Len => subject.len() as i64,
        StrTest::StartsWith => i64::from(subject.starts_with(other)),
        StrTest::EndsWith => i64::from(subject.ends_with(other)),
        StrTest::Contains => i64::from(contains(subject, other)),
        StrTest::TokenIntersect => i64::from(token_intersect(subject, other, separators)),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The first token of `input` at or after `from`, and where it ends.
///
/// This is `tokenize()` in `vmod_str.c`: separators are skipped, the token
/// runs to the next separator or the end, and an empty token is never
/// produced.
fn next_token(input: &[u8], from: usize, separators: &[u8]) -> Option<(usize, usize)> {
    let mut start = from;
    while start < input.len() && separators.contains(&input[start]) {
        start += 1;
    }
    if start == input.len() {
        return None;
    }
    let mut end = start;
    while end < input.len() && !separators.contains(&input[end]) {
        end += 1;
    }
    Some((start, end))
}

/// `token_intersect`: true when one token of `left` is also a token of
/// `right`.  Empty tokens are ignored on both sides.
pub fn token_intersect(left: &[u8], right: &[u8], separators: &[u8]) -> bool {
    let mut at = 0;
    while let Some((start, end)) = next_token(left, at, separators) {
        let token = &left[start..end];
        let mut other = 0;
        while let Some((from, to)) = next_token(right, other, separators) {
            if &right[from..to] == token {
                return true;
            }
            other = to;
        }
        at = end;
    }
    false
}

/// `substr(S, N, OFFSET)`, byte for byte as `vmod_substr()` computes it.
///
/// A negative `OFFSET` counts from the end; a negative `N` takes the bytes to
/// the left of `OFFSET` rather than to its right.  Everything is clipped to
/// the subject, so an out-of-range window is the empty string rather than an
/// error.
pub fn str_substr(subject: &[u8], count: i64, offset: i64, out: &mut Writer<'_>) {
    let length = subject.len() as i64;
    let mut count = count;
    let mut offset = offset;
    if offset < 0 || (offset == 0 && count < 0) {
        offset = offset.saturating_add(length);
    }
    if count < 0 {
        count = count.saturating_neg();
        offset = offset.saturating_sub(count);
    }
    if offset.saturating_add(count) < 0 || (offset > 0 && offset > length) || count == 0 {
        return;
    }
    if offset < 0 {
        count = count.saturating_add(offset);
        offset = 0;
    }
    if offset.saturating_add(count) > length {
        count = length - offset;
    }
    if count <= 0 {
        return;
    }
    let start = offset as usize;
    out.bytes(&subject[start..start + count as usize]);
}

/// The string-valued builtins that take two integers.
///
/// `Err` is a refusal the guest reports as a phase failure; only
/// [`StrEdit::UriDecode`] has one.
pub fn str_edit(
    op: StrEdit,
    subject: &[u8],
    count: i64,
    offset: i64,
    out: &mut Writer<'_>,
) -> Result<(), PhaseFailure> {
    match op {
        StrEdit::Substr => str_substr(subject, count, offset, out),
        StrEdit::Reverse => {
            for byte in subject.iter().rev() {
                out.byte(*byte);
            }
        }
        StrEdit::UriDecode => return uri_decode_unreserved(subject, count != 0, out),
    }
    Ok(())
}

/// `split(S, N, SEP)`: the `N`-th token of `S`, counting from 1, or from the
/// end when `N` is negative.  Every byte of `SEP` is a separator.
///
/// A field that does not exist is the empty string here where Varnish returns
/// NULL; a field that does exist is never empty, so the two cases stay
/// distinguishable to a VCL that cares.
pub fn str_split(subject: &[u8], index: i64, separators: &[u8], out: &mut Writer<'_>) {
    if subject.is_empty() || index == 0 || separators.is_empty() {
        return;
    }
    let length = subject.len() as i64;
    let forward = index > 0;
    let (step, mut at, limit) = if forward {
        (1i64, 0i64, length)
    } else {
        (-1i64, length - 1, -1i64)
    };
    let mut wanted = index.unsigned_abs();
    let (mut begin, mut end);
    loop {
        while at != limit && separators.contains(&subject[at as usize]) {
            at += step;
        }
        begin = at;
        while at != limit && !separators.contains(&subject[at as usize]) {
            at += step;
        }
        end = at;
        if begin != end {
            wanted -= 1;
        }
        if at == limit || wanted == 0 {
            break;
        }
    }
    if wanted > 0 {
        return;
    }
    // Walking backwards leaves the token as (end, begin] rather than
    // [begin, end); the enterprise module performs the same swap.
    let (start, stop) = if forward {
        (begin as usize, end as usize)
    } else {
        ((end + 1) as usize, (begin + 1) as usize)
    };
    out.bytes(&subject[start..stop]);
}

/// RV64 entry point for [`str_test`].  The operation is in a0, the subject in
/// a1-a2, the second string in a3-a4 and the separators in a5-a6.
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_str_test(
    op: i64,
    subject: *const u8,
    subject_len: usize,
    other: *const u8,
    other_len: usize,
    separators: *const u8,
    separators_len: usize,
) -> i64 {
    let op = match op {
        0 => StrTest::Len,
        1 => StrTest::StartsWith,
        2 => StrTest::EndsWith,
        3 => StrTest::Contains,
        4 => StrTest::TokenIntersect,
        _ => return -1,
    };
    str_test(
        op,
        unsafe { raw_bytes(subject, subject_len) },
        unsafe { raw_bytes(other, other_len) },
        unsafe { raw_bytes(separators, separators_len) },
    )
}

/// RV64 entry point for [`str_edit`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_str_edit(
    op: i64,
    subject: *const u8,
    subject_len: usize,
    count: i64,
    offset: i64,
    output: *mut u8,
    cap: usize,
) -> i64 {
    let op = match op {
        0 => StrEdit::Substr,
        1 => StrEdit::Reverse,
        2 => StrEdit::UriDecode,
        _ => return -1,
    };
    let mut writer = Writer::new(unsafe { raw_bytes_mut(output, cap) });
    if str_edit(
        op,
        unsafe { raw_bytes(subject, subject_len) },
        count,
        offset,
        &mut writer,
    )
    .is_err()
    {
        return -1;
    }
    writer.finish() as i64
}

/// RV64 entry point for [`str_split`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_str_split(
    subject: *const u8,
    subject_len: usize,
    index: i64,
    separators: *const u8,
    separators_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    let mut writer = Writer::new(unsafe { raw_bytes_mut(output, cap) });
    str_split(
        unsafe { raw_bytes(subject, subject_len) },
        index,
        unsafe { raw_bytes(separators, separators_len) },
        &mut writer,
    );
    writer.finish() as i64
}

const WEEKDAYS: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| *byte <= b' ') {
        input = &input[1..];
    }
    while input.last().is_some_and(|byte| *byte <= b' ') {
        input = &input[..input.len() - 1];
    }
    input
}

fn parse_http_date(input: &[u8]) -> Option<i64> {
    let comma = input.iter().position(|byte| *byte == b',')?;
    let rest = trim_ascii(&input[comma + 1..]);
    let (parts, count) = split_spaces(rest);
    if count == 0 {
        return None;
    }
    let (day, month, year) = if parts[0].contains(&b'-') {
        if count != 3 || parts[2] != b"GMT" {
            return None;
        }
        let mut date = parts[0].split(|byte| *byte == b'-');
        let day = number(date.next()?)?;
        let month = month(date.next()?)?;
        let short_year = number(date.next()?)?;
        if short_year > 99 {
            return None;
        }
        // POSIX's conventional two-digit-year window, which Varnish's
        // strptime-based implementation follows.
        (
            day,
            month,
            if short_year >= 69 {
                1900 + short_year
            } else {
                2000 + short_year
            },
        )
    } else {
        if count != 5 || parts[4] != b"GMT" {
            return None;
        }
        (number(parts[0])?, month(parts[1])?, number(parts[2])?)
    };
    date_time(
        year,
        month,
        day,
        if count == 3 { parts[1] } else { parts[3] },
    )
}

fn parse_asctime(input: &[u8]) -> Option<i64> {
    let (parts, count) = split_spaces(input);
    if count != 5 || parts[0].len() != 3 {
        return None;
    }
    date_time(
        number(parts[4])?,
        month(parts[1])?,
        number(parts[2])?,
        parts[3],
    )
}

fn parse_iso_date(input: &[u8]) -> Option<i64> {
    let (date, time) = if let Some((date, time)) = split_once(input, b'T') {
        (date, Some(time.strip_suffix(b"Z").unwrap_or(time)))
    } else if let Some((date, time)) = split_once(input, b' ') {
        (date, Some(time))
    } else {
        (input, None)
    };
    let mut date = date.split(|byte| *byte == b'-');
    let year = number(date.next()?)?;
    let month = number(date.next()?)?;
    let day = number(date.next()?)?;
    if date.next().is_some() {
        return None;
    }
    let seconds = if let Some(time) = time {
        time_of_day(time)?
    } else {
        0
    };
    days_from_civil(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(seconds)
}

fn date_time(year: i64, month: i64, day: i64, time: &[u8]) -> Option<i64> {
    days_from_civil(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(time_of_day(time)?)
}

fn time_of_day(input: &[u8]) -> Option<i64> {
    let mut parts = input.split(|byte| *byte == b':');
    let hour = number(parts.next()?)?;
    let minute = number(parts.next()?)?;
    let second = number(parts.next()?)?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    hour.checked_mul(3600)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

fn split_spaces(input: &[u8]) -> ([&[u8]; 5], usize) {
    let mut parts: [&[u8]; 5] = [&[]; 5];
    let mut count = 0;
    for part in input
        .split(|byte| *byte == b' ')
        .filter(|part| !part.is_empty())
    {
        if count == parts.len() {
            return (parts, 0);
        }
        parts[count] = part;
        count += 1;
    }
    (parts, count)
}

fn split_once(input: &[u8], needle: u8) -> Option<(&[u8], &[u8])> {
    let at = input.iter().position(|byte| *byte == needle)?;
    Some((&input[..at], &input[at + 1..]))
}

fn number(input: &[u8]) -> Option<i64> {
    if input.is_empty() {
        return None;
    }
    input.iter().try_fold(0i64, |value, byte| {
        let digit = byte.checked_sub(b'0').filter(|digit| *digit < 10)?;
        value.checked_mul(10)?.checked_add(i64::from(digit))
    })
}

fn month(input: &[u8]) -> Option<i64> {
    MONTHS
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(input))
        .map(|index| index as i64 + 1)
}

// Howard Hinnant's public-domain civil calendar algorithms, with the range
// checks VCL needs around them.  They handle Gregorian leap years for dates
// on either side of the epoch without pulling a time crate into the runtime.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month, day)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn write_two(out: &mut [u8], value: i64) {
    out[0] = b'0' + (value / 10) as u8;
    out[1] = b'0' + (value % 10) as u8;
}
fn write_four(out: &mut [u8], value: i64) {
    out[0] = b'0' + ((value / 1000) % 10) as u8;
    out[1] = b'0' + ((value / 100) % 10) as u8;
    out[2] = b'0' + ((value / 10) % 10) as u8;
    out[3] = b'0' + (value % 10) as u8;
}

#[cfg(test)]
extern crate std;

/// The `str` vmod, checked against `varnish-cache-plus/lib/libvmod_str`.
#[cfg(test)]
mod str_tests {
    use super::*;
    use std::string::String;
    use std::vec;

    fn edit(op: StrEdit, subject: &str, count: i64, offset: i64) -> String {
        let needed = {
            let mut writer = Writer::new(&mut []);
            let _ = str_edit(op, subject.as_bytes(), count, offset, &mut writer);
            writer.finish()
        };
        let mut out = vec![0u8; needed];
        let mut writer = Writer::new(&mut out);
        let _ = str_edit(op, subject.as_bytes(), count, offset, &mut writer);
        assert_eq!(writer.finish(), needed, "sizing and filling must agree");
        String::from_utf8(out).expect("ASCII fixtures")
    }

    fn split(subject: &str, index: i64, separators: &str) -> String {
        let needed = {
            let mut writer = Writer::new(&mut []);
            str_split(
                subject.as_bytes(),
                index,
                separators.as_bytes(),
                &mut writer,
            );
            writer.finish()
        };
        let mut out = vec![0u8; needed];
        let mut writer = Writer::new(&mut out);
        str_split(
            subject.as_bytes(),
            index,
            separators.as_bytes(),
            &mut writer,
        );
        assert_eq!(writer.finish(), needed, "sizing and filling must agree");
        String::from_utf8(out).expect("ASCII fixtures")
    }

    #[test]
    fn len_counts_bytes() {
        assert_eq!(str_test(StrTest::Len, b"", b"", b""), 0);
        assert_eq!(str_test(StrTest::Len, b"abcdef", b"", b""), 6);
        // Varnish counts bytes, not characters, and so do we.
        assert_eq!(
            str_test(StrTest::Len, "bl\u{e5}b\u{e6}r".as_bytes(), b"", b""),
            8
        );
    }

    #[test]
    fn affix_and_containment_tests_match_the_c_module() {
        for (op, subject, other, expected) in [
            (StrTest::StartsWith, "/api/v1", "/api", 1),
            (StrTest::StartsWith, "/api", "/api/v1", 0),
            (StrTest::StartsWith, "/api", "", 1),
            (StrTest::EndsWith, "video.m4s", ".m4s", 1),
            (StrTest::EndsWith, "m4s", "video.m4s", 0),
            (StrTest::EndsWith, "video.m4s", "", 1),
            (StrTest::Contains, "a/b/c", "/b/", 1),
            (StrTest::Contains, "a/b/c", "/d/", 0),
            // strstr(s, "") is s in C, so an empty needle is always contained
            // -- including in an empty subject.
            (StrTest::Contains, "", "", 1),
            (StrTest::Contains, "abc", "", 1),
        ] {
            assert_eq!(
                str_test(op, subject.as_bytes(), other.as_bytes(), b""),
                expected,
                "{op:?}({subject:?}, {other:?})"
            );
        }
    }

    #[test]
    fn token_intersect_ignores_empty_tokens() {
        let separators = b" ,";
        for (left, right, expected) in [
            ("gzip, br", "br", true),
            ("gzip, br", "deflate", false),
            ("  ,, gzip ,,", ",,gzip,", true),
            ("", "gzip", false),
            ("gzip", "", false),
            ("gzipped", "gzip", false),
        ] {
            assert_eq!(
                token_intersect(left.as_bytes(), right.as_bytes(), separators),
                expected,
                "{left:?} vs {right:?}"
            );
        }
        // No separators at all makes each string a single token.
        assert!(token_intersect(b"a b", b"a b", b""));
        assert!(!token_intersect(b"a b", b"a", b""));
    }

    /// The windows `vmod_substr()` actually computes.  The manual's own
    /// examples disagree with its C by a character or two; the C is what
    /// runs, so it is what this pins.
    #[test]
    fn substr_clips_both_ends() {
        const SUBJECT: &str = "0123456789abcdef";
        for (count, offset, expected) in [
            (2, 5, "56"),
            (2, -5, "bc"),
            (-2, 5, "34"),
            (-2, -5, "9a"),
            (10, 10, "abcdef"),
            (10, 20, ""),
            (0, 0, ""),
            (100, 0, "0123456789abcdef"),
            (-100, 0, "0123456789abcdef"),
            (2, 16, ""),
            // The C overflows here; saturating arithmetic makes the
            // extremes an empty window rather than undefined behaviour.
            (i64::MIN, i64::MIN, ""),
            (i64::MAX, i64::MAX, ""),
        ] {
            assert_eq!(
                edit(StrEdit::Substr, SUBJECT, count, offset),
                expected,
                "substr({count}, {offset})"
            );
        }
        assert_eq!(edit(StrEdit::Substr, "", 4, 0), "");
    }

    #[test]
    fn reverse_reverses_bytes() {
        assert_eq!(edit(StrEdit::Reverse, "abcdef", 0, 0), "fedcba");
        assert_eq!(edit(StrEdit::Reverse, "", 0, 0), "");
        assert_eq!(edit(StrEdit::Reverse, "a", 0, 0), "a");
    }

    #[test]
    fn split_counts_fields_from_either_end() {
        const PLAYLIST: &str = "/item_1.mp4|/item_2.mp4|/item_3.mp4";
        assert_eq!(split(PLAYLIST, 1, "|"), "/item_1.mp4");
        assert_eq!(split(PLAYLIST, 2, "|"), "/item_2.mp4");
        assert_eq!(split(PLAYLIST, 3, "|"), "/item_3.mp4");
        assert_eq!(split(PLAYLIST, -1, "|@"), "/item_3.mp4");
        assert_eq!(split(PLAYLIST, -3, "|"), "/item_1.mp4");
        assert_eq!(
            split("/item_1.mp4|/item_2.mp4@/item_3.mp4", -1, "|@"),
            "/item_3.mp4"
        );
        assert_eq!(split("a b\tc", 2, " \t"), "b");
        // Runs of separators, and leading and trailing ones, make no fields.
        assert_eq!(split("||a||b||", 1, "|"), "a");
        assert_eq!(split("||a||b||", 2, "|"), "b");
        assert_eq!(split("||a||b||", -1, "|"), "b");
    }

    #[test]
    fn split_reports_a_missing_field_as_the_empty_string() {
        assert_eq!(split("a|b", 3, "|"), "");
        assert_eq!(split("a|b", -3, "|"), "");
        assert_eq!(split("a|b", 0, "|"), "");
        assert_eq!(split("", 1, "|"), "");
        assert_eq!(split("a|b", 1, ""), "");
        assert_eq!(split("|||", 1, "|"), "");
        assert_eq!(split("a|b", i64::MIN, "|"), "");
    }

    #[test]
    fn the_entry_points_refuse_an_unknown_operation() {
        // Null with a zero length is the sizing call's own convention; see
        // `raw_bytes`.
        assert_eq!(
            unsafe {
                rt_str_test(
                    99,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                )
            },
            -1
        );
        assert_eq!(
            unsafe { rt_str_edit(99, core::ptr::null(), 0, 0, 0, core::ptr::null_mut(), 0) },
            -1
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_matches_vnumpfx() {
        for (text, fallback, expected) in [
            (b"0".as_slice(), 7, 0),
            (b"+12", 7, 12),
            (b"-12", 7, -12),
            (b" 12.9 ", 7, 12),
            (b"-12.9", 7, -12),
            (b"1.2e3", 7, 1200),
            (b"1e-2", 7, 0),
            (b"-9223372036854775808", 7, i64::MIN),
            (b"9223372036854775807", 7, i64::MAX),
            (b"", 7, 7),
            (b" 1", 7, 1),
            (b"1x", 7, 7),
            (b"9223372036854775808", 7, 7),
        ] {
            assert_eq!(int_parse(text, fallback), expected, "{text:?}");
        }
    }

    #[test]
    fn duration_matches_vnum_duration() {
        for (text, fallback, expected) in [
            (b"1ms".as_slice(), 7, 1_000_000),
            (b"1s", 7, 1_000_000_000),
            (b"1m", 7, 60_000_000_000),
            (b"1h", 7, 3_600_000_000_000),
            (b"1d", 7, 86_400_000_000_000),
            (b"-1s", 7, -1_000_000_000),
            (b"1.5s", 7, 1_500_000_000),
            (b"1e3ms", 7, 1_000_000_000),
            (b"1w", 7, 604_800_000_000_000),
            (b"1y", 7, 31_536_000_000_000_000),
            (b"9223372037s", 7, 7),
        ] {
            assert_eq!(duration_parse(text, fallback), expected, "{text:?}");
        }
    }

    /// Every expectation here was taken from glibc `fnmatch(3)` on the host,
    /// which is what Varnish's `std.fnmatch` calls.
    #[test]
    fn fnmatch_matches_posix_fnmatch() {
        // (pattern, subject, pathname, noescape, period, expected)
        for (pattern, subject, pathname, noescape, period, expected) in [
            (
                b"/media/*.m4s".as_slice(),
                b"/media/a.m4s".as_slice(),
                true,
                false,
                false,
                true,
            ),
            (
                b"/media/*/*.m4s",
                b"/media/x/a.m4s",
                true,
                false,
                false,
                true,
            ),
            (
                b"segment-[0-9].m4s",
                b"segment-7.m4s",
                false,
                false,
                false,
                true,
            ),
            (
                b"segment-[!0-9].m4s",
                b"segment-7.m4s",
                false,
                false,
                false,
                false,
            ),
            (b"*a/b", b"xa/b", true, false, false, true),
            (b"*[/]b", b"xa/b", true, false, false, false),
            // A star may not consume a leading period, and neither may the
            // pattern byte after it: POSIX only lets a period in a leading
            // position be matched by one in a leading position.
            (b"*", b".well-known", false, false, true, false),
            (b"*.*", b".a", false, false, true, false),
            (b"*.*", b".a", false, false, false, true),
            (b"*.", b".", false, false, true, false),
            (b"***.", b".", false, false, true, false),
            (b".*", b".a", false, false, true, true),
            (b"?", b".", false, false, true, false),
            (b"*", b"a.b", false, false, true, true),
            (b"/*", b"/.a", true, false, true, false),
            (b"/*", b"/.a", false, false, true, true),
            (b"a/*", b"a/.b", true, false, true, false),
            (b"*/.*", b"a/.b", true, false, true, true),
            // A pattern ending in an unpaired escape matches nothing.
            (b"\\", b"\\", false, false, false, false),
            (b"*\\", b"-*\\", false, false, false, false),
            (b"a\\", b"a\\", false, false, false, false),
            (b"\\", b"\\", false, true, false, true),
            // A star's tail stays inside the segment the star opened, so an
            // escaped separator cannot close it; an unescaped one can.
            (b"*/b", b"xa/b", true, false, false, true),
            (b"*\\/b", b"xa/b", true, false, false, false),
            (b"*\\/", b"a/", true, false, false, false),
            (b"a/*\\/b", b"a/x/b", true, false, false, false),
            (b"\\/b", b"/b", true, false, false, true),
            (b"?\\/b", b"a/b", true, false, false, true),
            (b"*/a\\/b", b"x/a/b", true, false, false, true),
            (b"*/\\/b", b"x//b", true, false, false, true),
            (b"*\\/b", b"a/b", false, false, false, true),
            (
                b"media/*.m4s",
                b"media/segment.m4s",
                true,
                false,
                false,
                true,
            ),
            (
                b"media/*.m4s",
                b"media/a/segment.m4s",
                true,
                false,
                false,
                false,
            ),
            (
                b"media/*.m4s",
                b"media/a/segment.m4s",
                false,
                false,
                false,
                true,
            ),
            (
                b"segment-[!0-9].m4s",
                b"segment-x.m4s",
                false,
                false,
                false,
                true,
            ),
            (
                b"literal\\*.m4s",
                b"literal*.m4s",
                false,
                false,
                false,
                true,
            ),
            (
                b"literal\\?.m4s",
                b"literal\\x.m4s",
                false,
                true,
                false,
                true,
            ),
            (b".*", b".well-known", false, false, true, true),
            (b"path/*", b"path/.well-known", true, false, true, false),
        ] {
            assert_eq!(
                fnmatch(pattern, subject, pathname, noescape, period),
                expected,
                "{:?} {:?} pathname={pathname} noescape={noescape} period={period}",
                core::str::from_utf8(pattern),
                core::str::from_utf8(subject),
            );
        }
    }

    #[test]
    fn querysort_returns_a_query_it_cannot_sort_unchanged() {
        // The pair table is fixed, and the client picks the pair count.
        let mut url = std::string::String::from("/a?");
        for index in 0..300 {
            if index != 0 {
                url.push('&');
            }
            url.push_str(&std::format!("p{index}=1"));
        }
        let needed = querysort(url.as_bytes(), &mut []);
        assert_eq!(needed, url.len());
        let mut output = std::vec![0; needed];
        assert_eq!(querysort(url.as_bytes(), &mut output), needed);
        assert_eq!(output, url.as_bytes());
    }

    #[test]
    fn querysort_sorts_wire_pairs_and_preserves_the_url_path() {
        for (input, expected) in [
            (b"/a?z=1&&a=2&b".as_slice(), b"/a?a=2&b&z=1".as_slice()),
            (b"z=1&a=2", b"a=2&z=1"),
            (b"/a?&&", b"/a"),
        ] {
            let needed = querysort(input, &mut []);
            let mut output = std::vec![0; needed];
            assert_eq!(querysort(input, &mut output), needed);
            assert_eq!(output, expected, "{input:?}");
        }
    }

    /// A `(input, code, argument, output)` guest entry point.
    type StringEntry =
        unsafe extern "C" fn(*const u8, usize, i64, *const u8, usize, *mut u8, usize) -> i64;

    /// Drive an entry point through the measure-then-fill protocol the
    /// compiler emits, asserting the two passes agree.  Every string-shaped
    /// test goes through this rather than calling the inner function, because
    /// a sizing pass that disagreed with its filling pass was exactly the
    /// class of bug the shared `Writer` exists to make unrepresentable.
    fn call(
        entry: StringEntry,
        input: &[u8],
        code: OpCode,
        argument: &[u8],
    ) -> Option<std::vec::Vec<u8>> {
        let word = code.encode();
        // Every pointer below is taken from a live slice, and the length
        // beside it is that slice's own -- which is the whole contract the
        // entry points ask of a caller.
        let needed = unsafe {
            entry(
                input.as_ptr(),
                input.len(),
                word,
                argument.as_ptr(),
                argument.len(),
                core::ptr::null_mut(),
                0,
            )
        };
        if needed < 0 {
            return None;
        }
        let mut output = std::vec![0u8; needed as usize];
        let written = unsafe {
            entry(
                input.as_ptr(),
                input.len(),
                word,
                argument.as_ptr(),
                argument.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(written, needed, "the sizing and filling passes disagreed");
        Some(output)
    }

    fn url_state(url: &str) -> std::vec::Vec<u8> {
        call(
            rt_url_transform,
            url.as_bytes(),
            OpCode::new(UrlOp::Parse as u8),
            b"",
        )
        .expect("parse")
    }

    fn url_string(state: &[u8]) -> std::string::String {
        let code = OpCode::new(UrlRead::AsString as u8);
        let bytes = call(rt_url_read, state, code, b"").expect("as_string");
        std::string::String::from_utf8(bytes).expect("UTF-8")
    }

    fn url_apply(state: &[u8], code: OpCode, argument: &[u8]) -> std::vec::Vec<u8> {
        call(rt_url_transform, state, code, argument).expect("transform")
    }

    #[test]
    fn cookie_state_round_trips_through_the_shared_list_encoding() {
        let jar = b" bad; one=1; two=  x  ; one=last";
        let state = call(
            rt_cookie_transform,
            jar,
            OpCode::new(CookieOp::Parse as u8),
            b"",
        )
        .expect("parse");

        let first = OpCode::new(CookieRead::Get as u8);
        let last = first.with_flags(flag::LAST);
        assert_eq!(
            call(rt_cookie_read, &state, first, b"one").as_deref(),
            Some(&b"1"[..])
        );
        assert_eq!(
            call(rt_cookie_read, &state, last, b"one").as_deref(),
            Some(&b"last"[..])
        );
        // A value keeps its trailing whitespace, as cookieplus does.
        assert_eq!(
            call(rt_cookie_read, &state, first, b"two").as_deref(),
            Some(&b"  x  "[..])
        );
        // A pair with no `=` is dropped rather than counted.
        assert_eq!(
            unsafe { rt_cookie_count(state.as_ptr(), state.len(), 0, core::ptr::null(), 0) },
            3
        );

        let as_string = OpCode::new(CookieRead::AsString as u8);
        let kept = call(
            rt_cookie_transform,
            &state,
            OpCode::new(CookieOp::Keep as u8),
            b"two",
        )
        .expect("keep");
        assert_eq!(
            call(rt_cookie_read, &kept, as_string, b"").as_deref(),
            Some(&b"two=  x  "[..])
        );

        let deleted = call(
            rt_cookie_transform,
            &state,
            OpCode::new(CookieOp::Delete as u8),
            b"one",
        )
        .expect("delete");
        assert_eq!(
            call(rt_cookie_read, &deleted, as_string, b"").as_deref(),
            Some(&b"two=  x  "[..])
        );

        let added = call(
            rt_cookie_transform,
            &state,
            OpCode::new(CookieOp::Add as u8).with_flags(flag::OVERRIDE),
            b"one\0replaced",
        )
        .expect("add");
        assert_eq!(
            call(rt_cookie_read, &added, as_string, b"").as_deref(),
            Some(&b"two=  x  ; one=replaced"[..])
        );
    }

    fn setcookie_state(headers: &[&str]) -> std::vec::Vec<u8> {
        let packed: std::vec::Vec<(&str, &str)> =
            headers.iter().map(|value| ("Set-Cookie", *value)).collect();
        call(
            rt_setcookie_transform,
            &snapshot(&packed),
            OpCode::new(SetcookieOp::Parse as u8),
            b"",
        )
        .expect("parse")
    }

    /// The Set-Cookie parse keeps the attributes in the record's value and
    /// `setcookie_get` answers the half before the first `;`, which is the
    /// split `setcookie_parse()` in `vmod_cookieplus.c` performs.
    #[test]
    fn setcookie_state_splits_a_name_off_and_keeps_its_attributes() {
        let state = setcookie_state(&[
            "SESS=abc; Path=/; HttpOnly",
            "=nameless",
            "flagonly",
            "empty=",
        ]);
        let get = OpCode::new(SetcookieRead::Get as u8);
        assert_eq!(
            call(rt_setcookie_read, &state, get, b"SESS").as_deref(),
            Some(&b"abc"[..])
        );
        assert_eq!(
            call(rt_setcookie_read, &state, get, b"flagonly").as_deref(),
            Some(&b""[..])
        );
        assert_eq!(
            call(rt_setcookie_read, &state, get, b"empty").as_deref(),
            Some(&b""[..])
        );
        // An empty name reads as absent, as `SEMPTY(name)` does, and the
        // field with no name at all never entered the list.
        assert_eq!(call(rt_setcookie_read, &state, get, b""), None);
        assert_eq!(
            unsafe { rt_setcookie_count(state.as_ptr(), state.len(), 0, core::ptr::null(), 0) },
            3
        );
    }

    /// Join the seven fields the compiler joins, so a NUL never has to be an
    /// invisible byte of a source literal.
    fn setcookie_argument(fields: [&str; setcookie_field::COUNT]) -> std::vec::Vec<u8> {
        fields.join("\0").into_bytes()
    }

    fn setcookie_written(state: &[u8]) -> std::vec::Vec<std::string::String> {
        let rendered = call(
            rt_setcookie_transform,
            state,
            OpCode::new(SetcookieOp::Render as u8),
            b"Set-Cookie",
        )
        .expect("render");
        committed(&rendered, &[])
            .into_iter()
            .map(|(_, value, _)| value)
            .collect()
    }

    /// `setcookie_add` composes the record value out of its arguments, in the
    /// order `setcookie_write()` prints them.
    #[test]
    fn setcookie_add_builds_the_attribute_list_the_vmod_prints() {
        // A ttl of one day against an epoch `now`, so the date is checkable.
        let argument = setcookie_argument([
            "edge",
            "v1",
            "86400000000000",
            "0",
            "example.com",
            "/media",
            "SameSite=Strict",
        ]);
        let code = OpCode::new(SetcookieOp::Add as u8)
            .with_flags(flag::KEEP)
            .with_extra(setcookie_attr::SECURE | setcookie_attr::HTTPONLY);
        let state = call(
            rt_setcookie_transform,
            &setcookie_state(&[]),
            code,
            &argument,
        )
        .expect("add");
        assert_eq!(
            setcookie_written(&state),
            std::vec![std::string::String::from(
                "edge=v1; Expires=Fri, 02 Jan 1970 00:00:00 GMT; \
                 Domain=example.com; Path=/media; Secure; HttpOnly; SameSite=Strict"
            )]
        );

        // A zero ttl writes no Expires at all; a negative one is the epoch.
        for (ttl, expected) in [
            ("0", "s=1"),
            ("-1", "s=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
        ] {
            let argument = setcookie_argument(["s", "1", ttl, "0", "", "", ""]);
            let state = call(
                rt_setcookie_transform,
                &setcookie_state(&[]),
                OpCode::new(SetcookieOp::Add as u8),
                &argument,
            )
            .expect("add");
            assert_eq!(
                setcookie_written(&state),
                std::vec![std::string::String::from(expected)]
            );
        }

        // `override` replaces every record of the name, kept or not.
        let jar = setcookie_state(&["s=old", "t=keep"]);
        let replaced = call(
            rt_setcookie_transform,
            &jar,
            OpCode::new(SetcookieOp::Add as u8).with_flags(flag::OVERRIDE),
            &setcookie_argument(["s", "new", "0", "0", "", "", ""]),
        )
        .expect("add");
        assert_eq!(
            setcookie_written(&replaced),
            std::vec![
                std::string::String::from("t=keep"),
                std::string::String::from("s=new"),
            ]
        );
    }

    /// The render is what makes a write replace the response's Set-Cookie
    /// headers: every entry is marked touched, and the leading deleted marker
    /// carries the name even when keep mode has pruned every cookie.
    #[test]
    fn setcookie_render_replaces_the_header_and_leaves_the_rest_alone() {
        let state = setcookie_state(&["a=1", "b=2"]);
        let kept = call(
            rt_setcookie_transform,
            &state,
            OpCode::new(SetcookieOp::Keep as u8),
            b"a",
        )
        .expect("keep");
        let rendered = call(
            rt_setcookie_transform,
            &kept,
            OpCode::new(SetcookieOp::Render as u8),
            b"Set-Cookie",
        )
        .expect("render");
        assert_eq!(
            committed(
                &rendered,
                &[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("X", "keep")]
            ),
            std::vec![
                (
                    std::string::String::from("X"),
                    std::string::String::from("keep"),
                    false
                ),
                (
                    std::string::String::from("Set-Cookie"),
                    std::string::String::from("a=1"),
                    true
                ),
            ]
        );

        // Nothing kept: the header is unset and nothing replaces it.
        let emptied = call(
            rt_setcookie_transform,
            &state,
            OpCode::new(SetcookieOp::Keep as u8),
            b"",
        )
        .expect("keep");
        let rendered = call(
            rt_setcookie_transform,
            &emptied,
            OpCode::new(SetcookieOp::Render as u8),
            b"Set-Cookie",
        )
        .expect("render");
        assert!(committed(&rendered, &[("Set-Cookie", "a=1")]).is_empty());
    }

    #[test]
    fn url_parse_and_render_preserve_bytes_and_collapse_slashes() {
        for (input, expected) in [
            ("/media//clip.m4s?b=2&a=1", "/media/clip.m4s?b=2&a=1"),
            ("/dir/", "/dir/"),
            ("relative/path", "relative/path"),
            // An empty pair is dropped; `a=` keeps its sign only on request.
            ("/x?&&a=&b", "/x?a&b"),
            ("/", "/"),
            ("", "/"),
        ] {
            assert_eq!(url_string(&url_state(input)), expected, "{input}");
        }
        // Percent escapes and `+` are carried through untouched: urlplus does
        // not decode, and neither may this.
        let escaped = "/a%2Fb/c+d?q=%20x";
        assert_eq!(url_string(&url_state(escaped)), escaped);
    }

    #[test]
    fn url_query_keep_switches_the_list_into_keep_mode() {
        let state = url_state("/a?utm_source=x&id=7&utm_medium=y");
        let kept = url_apply(&state, OpCode::new(UrlOp::QueryKeep as u8), b"id");
        assert_eq!(url_string(&kept), "/a?id=7");
        // Keep mode with no name at all drops the whole query.
        let empty = url_apply(&state, OpCode::new(UrlOp::QueryKeep as u8), b"");
        assert_eq!(url_string(&empty), "/a");
    }

    #[test]
    fn url_query_delete_spares_kept_pairs_unless_asked() {
        let state = url_state("/a?id=7&id=8");
        let kept = url_apply(
            &state,
            OpCode::new(UrlOp::QueryAdd as u8)
                .with_flags(flag::KEEP)
                .with_range(-1, 0),
            b"id\09",
        );
        // The added pair is marked keep, so a plain delete leaves it.
        let deleted = url_apply(&kept, OpCode::new(UrlOp::QueryDelete as u8), b"id");
        assert_eq!(url_string(&deleted), "/a?id=9");
        let forced = url_apply(
            &kept,
            OpCode::new(UrlOp::QueryDelete as u8).with_flags(flag::DELETE_KEEP),
            b"id",
        );
        assert_eq!(url_string(&forced), "/a");
    }

    #[test]
    fn url_query_set_updates_the_first_match_or_appends() {
        let state = url_state("/a?p=1&p=2");
        let one = url_apply(&state, OpCode::new(UrlOp::QuerySet as u8), b"p\0x");
        assert_eq!(url_string(&one), "/a?p=x&p=2");
        let all = url_apply(
            &state,
            OpCode::new(UrlOp::QuerySet as u8).with_flags(flag::ALL),
            b"p\0x",
        );
        assert_eq!(url_string(&all), "/a?p=x&p=x");
        let appended = url_apply(&state, OpCode::new(UrlOp::QuerySet as u8), b"q\0y");
        assert_eq!(url_string(&appended), "/a?p=1&p=2&q=y");
    }

    #[test]
    fn url_segments_add_at_a_position_and_delete_by_range() {
        let state = url_state("/one/two/three");
        let added = url_apply(
            &state,
            OpCode::new(UrlOp::UrlAdd as u8).with_range(1, 0),
            b"mid",
        );
        assert_eq!(url_string(&added), "/one/mid/two/three");
        let appended = url_apply(
            &state,
            OpCode::new(UrlOp::UrlAdd as u8).with_range(-1, 0),
            b"tail",
        );
        assert_eq!(url_string(&appended), "/one/two/three/tail");
        let ranged = url_apply(
            &state,
            OpCode::new(UrlOp::UrlDeleteRange as u8).with_range(0, 1),
            b"",
        );
        assert_eq!(url_string(&ranged), "/three");
    }

    #[test]
    fn url_name_reads_follow_the_last_segment() {
        let state = url_state("/media/clips/clip.m4s?page=7");
        for (read, expected) in [
            (UrlRead::Basename, Some("clip.m4s")),
            (UrlRead::Filename, Some("clip")),
            (UrlRead::Extension, Some("m4s")),
            (UrlRead::Dirname, Some("/media/clips")),
        ] {
            let value = call(rt_url_read, &state, OpCode::new(read as u8), b"")
                .map(|bytes| std::string::String::from_utf8(bytes).expect("UTF-8"));
            assert_eq!(value.as_deref(), expected, "{read:?}");
        }
        // A segment with no extension has neither a filename nor one of its
        // own, and the read falls back to the VCL default.
        let plain = url_state("/media/clips");
        assert_eq!(
            call(
                rt_url_read,
                &plain,
                OpCode::new(UrlRead::Extension as u8),
                b""
            ),
            None
        );
        assert_eq!(
            call(
                rt_url_read,
                &plain,
                OpCode::new(UrlRead::Basename as u8),
                b""
            )
            .as_deref(),
            Some(&b"clips"[..])
        );
        // A single segment has no directory above it.
        let root = url_state("/only");
        assert_eq!(
            call(rt_url_read, &root, OpCode::new(UrlRead::Dirname as u8), b"").as_deref(),
            Some(&b"/"[..])
        );
    }

    #[test]
    fn url_get_ranges_and_slash_arguments() {
        let state = url_state("/one/two/three/");
        for (start, end, leading, trailing, expected) in [
            (
                0i16,
                -1i16,
                SLASH_FROM_INPUT,
                SLASH_FROM_INPUT,
                "/one/two/three/",
            ),
            (0, 0, SLASH_FROM_INPUT, SLASH_FALSE, "/one"),
            (1, 2, SLASH_FALSE, SLASH_FALSE, "two/three"),
            (0, 0, SLASH_FALSE, SLASH_FALSE, "one"),
            (1, 1, SLASH_TRUE, SLASH_TRUE, "/two/"),
            // An inverted range renders as the root, as `url_as_string` does.
            (2, 1, SLASH_FROM_INPUT, SLASH_FROM_INPUT, "/"),
        ] {
            let code = OpCode::new(UrlRead::UrlGet as u8)
                .with_range(start, end)
                .with_extra(url_extra(leading, trailing, PART_ALL));
            let value = call(rt_url_read, &state, code, b"").expect("url_get");
            assert_eq!(
                std::string::String::from_utf8(value).expect("UTF-8"),
                expected,
                "{start}..={end}"
            );
        }
    }

    #[test]
    fn url_query_get_reads_by_name_or_position() {
        let state = url_state("/a?first=1&second=2");
        let by_name = OpCode::new(UrlRead::QueryGet as u8).with_range(-1, 0);
        assert_eq!(
            call(rt_url_read, &state, by_name, b"second").as_deref(),
            Some(&b"2"[..])
        );
        assert_eq!(call(rt_url_read, &state, by_name, b"absent"), None);
        let by_position = OpCode::new(UrlRead::QueryGet as u8).with_range(0, 0);
        assert_eq!(
            call(rt_url_read, &state, by_position, b"").as_deref(),
            Some(&b"1"[..])
        );
        let out_of_range = OpCode::new(UrlRead::QueryGet as u8).with_range(9, 0);
        assert_eq!(call(rt_url_read, &state, out_of_range, b""), None);
    }

    #[test]
    fn url_write_sorts_and_keeps_the_equal_sign_on_request() {
        let state = url_state("/a?z=1&a=2&b=");
        let sorted = OpCode::new(UrlRead::AsString as u8).with_flags(flag::SORT_QUERY);
        assert_eq!(
            std::string::String::from_utf8(call(rt_url_read, &state, sorted, b"").unwrap())
                .unwrap(),
            "/a?a=2&b&z=1"
        );
        let with_sign = sorted.with_flags(flag::SORT_QUERY | flag::KEEP_EQUAL_SIGN);
        assert_eq!(
            std::string::String::from_utf8(call(rt_url_read, &state, with_sign, b"").unwrap())
                .unwrap(),
            "/a?a=2&b=&z=1"
        );
    }

    #[test]
    fn url_case_conversion_covers_the_requested_part_only() {
        let state = url_state("/Media/Clip.M4S?Q=Value");
        for (part, expected) in [
            (PART_ALL, "/media/clip.m4s?q=value"),
            (PART_URL, "/media/clip.m4s?Q=Value"),
            (PART_QUERY, "/Media/Clip.M4S?q=value"),
        ] {
            let code = OpCode::new(UrlOp::CaseMap as u8).with_extra(url_extra(
                SLASH_FROM_INPUT,
                SLASH_FROM_INPUT,
                part,
            ));
            assert_eq!(url_string(&url_apply(&state, code, b"")), expected);
        }
        let upper = OpCode::new(UrlOp::CaseMap as u8).with_flags(flag::UPPER);
        assert_eq!(
            url_string(&url_apply(&state, upper, b"")),
            "/MEDIA/CLIP.M4S?Q=VALUE"
        );
    }

    /// Build the packed record stream the host's `headers_snapshot` returns.
    fn snapshot(headers: &[(&str, &str)]) -> std::vec::Vec<u8> {
        let mut packed = std::vec::Vec::new();
        for (name, value) in headers {
            packed.extend_from_slice(&(name.len() as u32).to_le_bytes());
            packed.extend_from_slice(&(value.len() as u32).to_le_bytes());
            packed.extend_from_slice(name.as_bytes());
            packed.extend_from_slice(value.as_bytes());
        }
        packed
    }

    fn header_state(headers: &[(&str, &str)]) -> std::vec::Vec<u8> {
        call(
            rt_header_transform,
            &snapshot(headers),
            OpCode::new(HeaderOp::Parse as u8),
            b"",
        )
        .expect("parse")
    }

    /// Decode the guest `Vec<Header>` a commit builds, the way the host does.
    fn committed(
        state: &[u8],
        live: &[(&str, &str)],
    ) -> std::vec::Vec<(std::string::String, std::string::String, bool)> {
        const BASE: u64 = 0x40_0000;
        let packed = snapshot(live);
        let call_commit = |output: &mut [u8]| -> i64 {
            // Three live slices, each with its own length.
            unsafe {
                rt_header_commit(
                    state.as_ptr(),
                    state.len(),
                    packed.as_ptr(),
                    packed.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    BASE,
                )
            }
        };
        let needed = call_commit(&mut []);
        assert!(needed >= 0, "commit failed");
        let mut image = std::vec![0u8; needed as usize];
        assert_eq!(call_commit(&mut image), needed);

        let word = |at: usize| u64::from_le_bytes(image[at..at + 8].try_into().unwrap());
        let count = word(16) as usize;
        assert_eq!(word(0), count as u64, "capacity");
        assert_eq!(word(8), BASE + 24, "entry pointer");
        let slice = |pointer: u64, len: u64| {
            let at = (pointer - BASE) as usize;
            std::string::String::from_utf8(image[at..at + len as usize].to_vec()).unwrap()
        };
        (0..count)
            .map(|index| {
                let entry = 24 + index * 56;
                (
                    slice(word(entry + 8), word(entry + 16)),
                    slice(word(entry + 32), word(entry + 40)),
                    word(entry + 48) != 0,
                )
            })
            .collect()
    }

    #[test]
    fn header_state_reads_the_packed_host_snapshot() {
        let state = header_state(&[("Host", "example.test"), ("X-A", "1"), ("X-A", "2")]);
        let get = OpCode::new(HEADER_READ_GET).with_range(-1, 0);
        assert_eq!(
            call(rt_header_read, &state, get, b"host").as_deref(),
            Some(&b"example.test"[..])
        );
        // Unlike the single-value header syscall, the list sees duplicates.
        let second = OpCode::new(HEADER_READ_GET).with_range(1, 0);
        assert_eq!(
            call(rt_header_read, &state, second, b"X-A").as_deref(),
            Some(&b"2"[..])
        );
        assert_eq!(
            unsafe { rt_header_count(state.as_ptr(), state.len(), 0, b"x-a".as_ptr(), 3) },
            2
        );
        assert_eq!(
            unsafe { rt_header_count(state.as_ptr(), state.len(), 0, core::ptr::null(), 0) },
            3
        );
    }

    #[test]
    fn collect_joins_every_value_of_a_filtered_snapshot() {
        let packed = snapshot(&[("X-A", "1"), ("X-A", "2"), ("X-A", "3")]);
        let joined = call(rt_collect, &packed, OpCode::default(), b"; ");
        assert_eq!(joined.as_deref(), Some(&b"1; 2; 3"[..]));

        // An empty separator is `", "`, as `http_CollectHdrSep` has it.
        assert_eq!(
            call(rt_collect, &packed, OpCode::default(), b"").as_deref(),
            Some(&b"1, 2, 3"[..])
        );

        // One occurrence collapses to itself, empty values included.
        assert_eq!(
            call(
                rt_collect,
                &snapshot(&[("X-A", "")]),
                OpCode::default(),
                b", "
            )
            .as_deref(),
            Some(&b""[..])
        );

        // No header of the name: the caller must not create one.
        assert_eq!(call(rt_collect, &[], OpCode::default(), b", "), None);

        // More occurrences than a module state could hold still collapse.
        let many: std::vec::Vec<(&str, &str)> = std::vec![("X-A", "v"); MAX_LIST_ITEMS + 1];
        let long = call(rt_collect, &snapshot(&many), OpCode::default(), b",")
            .expect("a snapshot is not a bounded list");
        assert_eq!(long.len(), many.len() * 2 - 1);
    }

    #[test]
    fn header_commit_replays_only_touched_names() {
        let live = [("Host", "example.test"), ("X-A", "1"), ("X-A", "2")];
        let state = header_state(&live);
        let deleted = call(
            rt_header_transform,
            &state,
            OpCode::new(HeaderOp::Delete as u8),
            b"X-A",
        )
        .expect("delete");
        // Host is untouched, so it passes through clean: the host neither
        // counts it against the mutation ceiling nor tests it against the
        // forbidden names.
        assert_eq!(
            committed(&deleted, &live),
            std::vec![("Host".into(), "example.test".into(), false)]
        );

        let set = call(
            rt_header_transform,
            &state,
            OpCode::new(HeaderOp::Set as u8),
            b"X-A\0only",
        )
        .expect("set");
        assert_eq!(
            committed(&set, &live),
            std::vec![
                ("Host".into(), "example.test".into(), false),
                ("X-A".into(), "only".into(), true),
            ]
        );

        let added = call(
            rt_header_transform,
            &state,
            OpCode::new(HeaderOp::Add as u8),
            b"X-B\0new",
        )
        .expect("add");
        assert_eq!(
            committed(&added, &live),
            std::vec![
                ("Host".into(), "example.test".into(), false),
                ("X-A".into(), "1".into(), false),
                ("X-A".into(), "2".into(), false),
                ("X-B".into(), "new".into(), true),
            ]
        );
    }

    #[test]
    fn header_keep_mode_is_a_whitelist_over_the_whole_list() {
        let live = [("Host", "example.test"), ("X-A", "1"), ("Cookie", "a=b")];
        let state = header_state(&live);
        let kept = call(
            rt_header_transform,
            &state,
            OpCode::new(HeaderOp::Keep as u8),
            b"host",
        )
        .expect("keep");
        // Everything the whitelist did not name is absent from the vector,
        // which is how the host's commit removes it.
        assert_eq!(
            committed(&kept, &live),
            std::vec![("Host".into(), "example.test".into(), true)]
        );
    }

    #[test]
    fn header_keep_mode_leaves_names_the_list_never_saw() {
        // The policy set a header after `init()`, so it is not in the list.
        // A whitelist decides the names it holds; it is not a purge of the
        // map, and Varnish draws the line in the same place.
        let state = header_state(&[("Host", "example.test"), ("X-A", "1")]);
        let kept = call(
            rt_header_transform,
            &state,
            OpCode::new(HeaderOp::Keep as u8),
            b"host",
        )
        .expect("keep");
        let live = [
            ("Host", "example.test"),
            ("X-A", "1"),
            ("X-Later", "set after init"),
        ];
        assert_eq!(
            committed(&kept, &live),
            std::vec![
                ("X-Later".into(), "set after init".into(), false),
                ("Host".into(), "example.test".into(), true),
            ]
        );
    }

    #[test]
    fn header_delete_spares_kept_names_unless_asked() {
        let live = [("X-A", "1"), ("X-B", "2")];
        let state = header_state(&live);
        let kept = call(
            rt_header_transform,
            &state,
            OpCode::new(HeaderOp::Keep as u8),
            b"X-A",
        )
        .expect("keep");
        let deleted = call(
            rt_header_transform,
            &kept,
            OpCode::new(HeaderOp::Delete as u8),
            b"X-A",
        )
        .expect("delete");
        assert_eq!(
            committed(&deleted, &live),
            std::vec![("X-A".into(), "1".into(), true)]
        );
        let forced = call(
            rt_header_transform,
            &kept,
            OpCode::new(HeaderOp::Delete as u8).with_flags(flag::DELETE_KEEP),
            b"X-A",
        )
        .expect("delete");
        assert!(committed(&forced, &live).is_empty());
    }

    #[test]
    fn a_state_that_outgrows_its_record_capacity_fails_rather_than_truncates() {
        let mut url = std::string::String::from("/a?");
        for index in 0..MAX_LIST_ITEMS + 1 {
            if index != 0 {
                url.push('&');
            }
            url.push_str(&std::format!("p{index}=1"));
        }
        assert_eq!(
            call(
                rt_url_transform,
                url.as_bytes(),
                OpCode::new(UrlOp::Parse as u8),
                b""
            ),
            None,
            "over-capacity input must fail the phase, never truncate the URL"
        );
    }

    #[test]
    fn an_opcode_survives_its_encoding() {
        for code in [
            OpCode::new(7)
                .with_flags(0b1010_0101)
                .with_range(-1, 300)
                .with_extra(0xbeef),
            OpCode::new(255)
                .with_range(i16::MIN, i16::MAX)
                .with_extra(u16::MAX),
            OpCode::default(),
        ] {
            assert_eq!(OpCode::decode(code.encode()), code);
        }
    }

    #[test]
    fn time_parser_and_formatter_cover_http_dates() {
        let expected = 784_111_777_000_000_000i64;
        for text in [
            b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
            b"Sunday, 06-Nov-94 08:49:37 GMT",
            b"Sun Nov  6 08:49:37 1994",
            b"1994-11-06T08:49:37Z",
            b"1994-11-06 08:49:37",
            b"1994-11-06",
        ] {
            assert_eq!(
                time_parse(text, 7),
                expected
                    - if text == b"1994-11-06" {
                        31_777_000_000_000
                    } else {
                        0
                    }
            );
        }
        let mut output = [0; 29];
        assert_eq!(time_format(expected, &mut output), 29);
        assert_eq!(&output, b"Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(time_parse(b"not a date", 42), 42);
    }

    // ── uri ─────────────────────────────────────────────────────────────
    //
    // The expectations are read off `lib/libvmod_uri` in varnish-cache-plus:
    // `uri_parse.c` for the component boundaries, `uri_as_string.c` for the
    // separators, `uri_encode.c` for the per-component allowed sets and
    // `uri_normalize.c` for RFC 3986 Section 6.  The two places this crate
    // deliberately parts company with it are named in the tests that cover
    // them.

    fn uri_state(input: &str) -> std::vec::Vec<u8> {
        call(
            rt_uri_transform,
            input.as_bytes(),
            OpCode::new(UriOp::Parse as u8),
            b"",
        )
        .expect("parse")
    }

    fn uri_normalized(input: &str) -> std::vec::Vec<u8> {
        call(
            rt_uri_transform,
            input.as_bytes(),
            OpCode::new(UriOp::Parse as u8).with_extra(URI_EXTRA_OPTION),
            b"",
        )
        .expect("parse")
    }

    fn uri_get(state: &[u8], part: UriRead) -> Option<std::string::String> {
        let bytes = call(rt_uri_read, state, OpCode::new(part as u8), b"")?;
        Some(std::string::String::from_utf8(bytes).expect("UTF-8"))
    }

    fn uri_format(state: &[u8], fmt: &str) -> std::string::String {
        let code = OpCode::new(UriRead::AsString as u8);
        let bytes = call(rt_uri_read, state, code, fmt.as_bytes()).expect("as_string");
        std::string::String::from_utf8(bytes).expect("UTF-8")
    }

    fn uri_render(state: &[u8]) -> std::string::String {
        uri_format(state, "%S%A%P%Q%F")
    }

    #[test]
    fn uri_parse_splits_the_seven_generic_components() {
        let state = uri_state("https://bob:pw@example.com:8443/a/b.m4s?x=1&y=2#frag");
        assert_eq!(uri_get(&state, UriRead::Scheme).as_deref(), Some("https"));
        assert_eq!(
            uri_get(&state, UriRead::Userinfo).as_deref(),
            Some("bob:pw")
        );
        assert_eq!(
            uri_get(&state, UriRead::Host).as_deref(),
            Some("example.com")
        );
        assert_eq!(uri_get(&state, UriRead::Port).as_deref(), Some("8443"));
        assert_eq!(uri_get(&state, UriRead::Path).as_deref(), Some("/a/b.m4s"));
        assert_eq!(uri_get(&state, UriRead::Query).as_deref(), Some("x=1&y=2"));
        assert_eq!(uri_get(&state, UriRead::Fragment).as_deref(), Some("frag"));
        assert_eq!(
            uri_render(&state),
            "https://bob:pw@example.com:8443/a/b.m4s?x=1&y=2#frag"
        );
    }

    #[test]
    fn uri_components_are_absent_rather_than_empty_when_they_are_missing() {
        let state = uri_state("/media/clip.m4s");
        // An absent component reads as absent, which is the vmod's NULL and
        // what makes the call fall back to its VCL `default`.
        for part in [
            UriRead::Scheme,
            UriRead::Userinfo,
            UriRead::Host,
            UriRead::Port,
            UriRead::Query,
            UriRead::Fragment,
        ] {
            assert_eq!(uri_get(&state, part), None, "{part:?}");
        }
        assert_eq!(
            uri_get(&state, UriRead::Path).as_deref(),
            Some("/media/clip.m4s")
        );
        // A present-but-empty component still renders its separator, which
        // is how a trailing `?` survives a round trip.
        let empty = uri_state("http://h/p?");
        assert_eq!(uri_get(&empty, UriRead::Query).as_deref(), Some(""));
        assert_eq!(uri_render(&empty), "http://h/p?");
    }

    #[test]
    fn uri_parses_an_ip_literal_host_with_its_brackets() {
        let state = uri_state("http://[2001:db8::1]:8080/x");
        assert_eq!(
            uri_get(&state, UriRead::Host).as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(uri_get(&state, UriRead::Port).as_deref(), Some("8080"));
        assert_eq!(uri_get(&state, UriRead::Userinfo), None);
        assert_eq!(uri_render(&state), "http://[2001:db8::1]:8080/x");
    }

    #[test]
    fn uri_userinfo_is_rewound_when_no_at_sign_follows_it() {
        // `uri_parse_userinfo(at=1)` returns its start when the run is not
        // terminated by `@`, so `example.com` is a host and not a user.
        let state = uri_state("//example.com/x");
        assert_eq!(uri_get(&state, UriRead::Userinfo), None);
        assert_eq!(
            uri_get(&state, UriRead::Host).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn uri_as_string_honours_every_format_token() {
        let state = uri_state("https://bob@example.com:8443/a?q#f");
        assert_eq!(uri_format(&state, "%S"), "https:");
        assert_eq!(uri_format(&state, "%A"), "//bob@example.com:8443");
        assert_eq!(uri_format(&state, "%U"), "bob@");
        assert_eq!(uri_format(&state, "%H"), "example.com");
        assert_eq!(uri_format(&state, "%p"), ":8443");
        assert_eq!(uri_format(&state, "%P"), "/a");
        assert_eq!(uri_format(&state, "%Q"), "?q");
        assert_eq!(uri_format(&state, "%F"), "#f");
        assert_eq!(uri_format(&state, "%H%p"), "example.com:8443");
        assert_eq!(uri_format(&state, "%P%Q%F"), "/a?q#f");
        assert_eq!(uri_format(&state, "100%% of %z"), "100% of %z");
    }

    #[test]
    fn uri_as_string_decode_removes_only_reserved_escapes() {
        // `uri_decode()` decodes the reserved characters and leaves the
        // unreserved ones encoded -- the opposite set from `uri.decode()`.
        let state = uri_state("/a%2Fb%7Ec?x=%3D");
        assert_eq!(uri_render(&state), "/a%2Fb%7Ec?x=%3D");
        let code = OpCode::new(UriRead::AsString as u8).with_extra(URI_EXTRA_OPTION);
        let decoded = call(rt_uri_read, &state, code, b"%P%Q").expect("as_string");
        assert_eq!(decoded, b"/a/b%7Ec?x==");
        // A read decodes the same way.
        let path = OpCode::new(UriRead::Path as u8).with_extra(URI_EXTRA_OPTION);
        assert_eq!(
            call(rt_uri_read, &state, path, b"").as_deref(),
            Some(&b"/a/b%7Ec"[..])
        );
    }

    #[test]
    fn uri_as_string_decodes_across_the_separators_it_inserted() {
        // The vmod formats first and decodes the whole result, so an escape
        // is decoded wherever it lands.  A `%` the output ends on decodes to
        // itself rather than eating the next component.
        let state = uri_state("/a?b%");
        let code = OpCode::new(UriRead::AsString as u8).with_extra(URI_EXTRA_OPTION);
        assert_eq!(
            call(rt_uri_read, &state, code, b"%P%Q").as_deref(),
            Some(&b"/a?b%"[..])
        );
        // The `%%` of the format string and the `3A` after it become one
        // escape in the assembled URI, and the decoder sees it as one --
        // which is exactly what formatting first and decoding after does.
        assert_eq!(
            call(rt_uri_read, &state, code, b"%P%Q%%3A").as_deref(),
            Some(&b"/a?b%:"[..])
        );
    }

    #[test]
    fn uri_set_replaces_a_component_and_an_empty_argument_clears_it() {
        let state = uri_state("http://example.com/a?q");
        let set = |state: &[u8], op: UriOp, value: &str| {
            call(
                rt_uri_transform,
                state,
                OpCode::new(op as u8),
                value.as_bytes(),
            )
            .expect("set")
        };
        let renamed = set(&state, UriOp::SetHost, "cdn.example.net");
        assert_eq!(uri_render(&renamed), "http://cdn.example.net/a?q");
        // `set_port()` with no argument is how the vmod's own example drops
        // a redirect's port.
        let ported = set(&renamed, UriOp::SetPort, "8080");
        assert_eq!(uri_render(&ported), "http://cdn.example.net:8080/a?q");
        assert_eq!(
            uri_render(&set(&ported, UriOp::SetPort, "")),
            "http://cdn.example.net/a?q"
        );
        assert_eq!(
            uri_render(&set(&state, UriOp::SetQuery, "")),
            "http://example.com/a"
        );
    }

    #[test]
    fn uri_set_scheme_and_port_clear_on_a_value_their_grammar_rejects() {
        // `URI_SET` parses the new value with the component's own step and
        // clears the component when anything is left over.
        let state = uri_state("http://h:80/a");
        let set = |op: UriOp, value: &str| {
            call(
                rt_uri_transform,
                &state,
                OpCode::new(op as u8),
                value.as_bytes(),
            )
            .expect("set")
        };
        assert_eq!(uri_render(&set(UriOp::SetScheme, "ftp")), "ftp://h:80/a");
        assert_eq!(uri_render(&set(UriOp::SetScheme, "ht tp")), "//h:80/a");
        assert_eq!(uri_render(&set(UriOp::SetScheme, "1http")), "//h:80/a");
        assert_eq!(uri_render(&set(UriOp::SetPort, "443")), "http://h:443/a");
        assert_eq!(uri_render(&set(UriOp::SetPort, "80/x")), "http://h/a");
    }

    #[test]
    fn uri_set_encode_escapes_what_the_component_may_not_carry() {
        let state = uri_state("http://h/a");
        let encoded = |op: UriOp, value: &str| {
            call(
                rt_uri_transform,
                &state,
                OpCode::new(op as u8).with_extra(URI_EXTRA_OPTION),
                value.as_bytes(),
            )
            .expect("set")
        };
        // A path keeps `/`, a query keeps `?`, a host keeps neither.
        assert_eq!(
            uri_get(&encoded(UriOp::SetPath, "/a b/c"), UriRead::Path).as_deref(),
            Some("/a%20b/c")
        );
        assert_eq!(
            uri_get(&encoded(UriOp::SetQuery, "a=1&b=x y?z"), UriRead::Query).as_deref(),
            Some("a=1&b=x%20y?z")
        );
        assert_eq!(
            uri_get(&encoded(UriOp::SetHost, "a/b"), UriRead::Host).as_deref(),
            Some("a%2Fb")
        );
        // An escape that is already well formed is copied, not doubled.
        assert_eq!(
            uri_get(&encoded(UriOp::SetPath, "/a%20b%zz"), UriRead::Path).as_deref(),
            Some("/a%20b%25zz")
        );
    }

    #[test]
    fn uri_normalize_applies_the_safe_rules_of_rfc_3986_section_6() {
        let state = uri_normalized("HTTP://User@EXAMPLE.com:80/%7Ea/./b/../c%2Fd?Q%7e#F%7e");
        assert_eq!(uri_get(&state, UriRead::Scheme).as_deref(), Some("http"));
        // The host lower-cases, the userinfo does not.
        assert_eq!(uri_get(&state, UriRead::Userinfo).as_deref(), Some("User"));
        assert_eq!(
            uri_get(&state, UriRead::Host).as_deref(),
            Some("example.com")
        );
        // A default port for a scheme that has one is dropped.
        assert_eq!(uri_get(&state, UriRead::Port), None);
        // Unreserved escapes decode; reserved ones only upper-case.
        assert_eq!(uri_get(&state, UriRead::Path).as_deref(), Some("/~a/c%2Fd"));
        assert_eq!(uri_get(&state, UriRead::Query).as_deref(), Some("Q~"));
        assert_eq!(uri_get(&state, UriRead::Fragment).as_deref(), Some("F~"));
        assert_eq!(uri_render(&state), "http://User@example.com/~a/c%2Fd?Q~#F~");
    }

    #[test]
    fn uri_normalize_gives_an_authority_without_a_path_the_root() {
        assert_eq!(uri_render(&uri_normalized("http://h")), "http://h/");
        assert_eq!(uri_render(&uri_normalized("http://h?q")), "http://h/?q");
        // No authority, no root: a relative reference keeps its shape.
        assert_eq!(uri_render(&uri_normalized("?q")), "?q");
    }

    #[test]
    fn uri_normalize_removes_dot_segments_by_the_rfc_rather_than_the_vmod() {
        for (input, expected) in [
            ("/a/b/../c", "/a/c"),
            ("/a/b/./c", "/a/b/c"),
            ("/a/b/..", "/a/"),
            ("/a/b/.", "/a/b/"),
            ("/a/%2E%2E/b", "/b"),
            ("/../../x", "/x"),
            ("/a//b", "/a//b"),
            ("/", "/"),
            // The vmod's byte loop drops the dot and the slash after it and
            // renders this `/dirx`; RFC 3986 Section 5.2.4, which is what
            // the vmod documents, leaves an ordinary segment alone.
            ("/dir./x", "/dir./x"),
            ("/index.html", "/index.html"),
        ] {
            let state = uri_normalized(input);
            assert_eq!(
                uri_get(&state, UriRead::Path).as_deref(),
                Some(expected),
                "{input}"
            );
        }
    }

    #[test]
    fn uri_normalize_refuses_a_path_deeper_than_its_segment_bound() {
        let deep = std::format!("/{}", "a/".repeat(URI_MAX_SEGMENTS));
        assert_eq!(
            call(
                rt_uri_transform,
                deep.as_bytes(),
                OpCode::new(UriOp::Parse as u8).with_extra(URI_EXTRA_OPTION),
                b"",
            ),
            None
        );
        // Without `norm` the same path is only stored, so it is fine.
        assert!(call(
            rt_uri_transform,
            deep.as_bytes(),
            OpCode::new(UriOp::Parse as u8),
            b"",
        )
        .is_some());
    }

    #[test]
    fn uri_parse_falls_back_to_the_request_host_and_url() {
        // An empty input takes the authority from the `Host` argument and
        // the rest from the URL, which is what the vmod builds as
        // `//host` + url.
        let state = call(
            rt_uri_transform,
            b"",
            OpCode::new(UriOp::Parse as u8),
            b"example.com:8080\0/media/clip.m4s?a=1#f",
        )
        .expect("parse");
        assert_eq!(
            uri_get(&state, UriRead::Host).as_deref(),
            Some("example.com")
        );
        assert_eq!(uri_get(&state, UriRead::Port).as_deref(), Some("8080"));
        assert_eq!(
            uri_get(&state, UriRead::Path).as_deref(),
            Some("/media/clip.m4s")
        );
        assert_eq!(uri_get(&state, UriRead::Query).as_deref(), Some("a=1"));
        assert_eq!(uri_get(&state, UriRead::Fragment).as_deref(), Some("f"));
        assert_eq!(uri_get(&state, UriRead::Scheme), None);
        assert_eq!(uri_format(&state, "%H%p"), "example.com:8080");
        assert_eq!(uri_format(&state, "%P%Q%F"), "/media/clip.m4s?a=1#f");
    }

    #[test]
    fn uri_parse_keeps_a_request_target_that_begins_with_two_slashes() {
        // The authority came from the `Host` argument, so the URL is parsed
        // with none in force: `//foo/bar` is this request's path. Reading it
        // as an authority -- or refusing it as the explicit form does --
        // would drop the path, the query and the fragment together, and
        // `uri.write()` would then send an empty target upstream.
        let state = call(
            rt_uri_transform,
            b"",
            OpCode::new(UriOp::Parse as u8),
            b"example.com\0//foo/bar?a=1",
        )
        .expect("parse");
        assert_eq!(
            uri_get(&state, UriRead::Host).as_deref(),
            Some("example.com")
        );
        assert_eq!(uri_get(&state, UriRead::Path).as_deref(), Some("//foo/bar"));
        assert_eq!(uri_get(&state, UriRead::Query).as_deref(), Some("a=1"));
        assert_eq!(uri_format(&state, "%P%Q"), "//foo/bar?a=1");
    }

    #[test]
    fn uri_parse_reads_an_ip_literal_that_follows_userinfo() {
        // The bracket is the first byte of the host, not of the authority,
        // so the literal has to be recognised after `user@` is consumed.
        let state = uri_state("http://bob@[2001:db8::1]:8080/x");
        assert_eq!(uri_get(&state, UriRead::Userinfo).as_deref(), Some("bob"));
        assert_eq!(
            uri_get(&state, UriRead::Host).as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(uri_get(&state, UriRead::Port).as_deref(), Some("8080"));
        assert_eq!(uri_render(&state), "http://bob@[2001:db8::1]:8080/x");
    }

    #[test]
    fn uri_decode_takes_the_unreserved_escapes_and_can_refuse() {
        let decode = |input: &str, strict: bool| {
            let bytes = input.as_bytes();
            let needed = unsafe {
                rt_str_edit(
                    StrEdit::UriDecode as i64,
                    bytes.as_ptr(),
                    bytes.len(),
                    i64::from(strict),
                    0,
                    core::ptr::null_mut(),
                    0,
                )
            };
            if needed < 0 {
                return None;
            }
            let mut out = std::vec![0u8; needed as usize];
            let written = unsafe {
                rt_str_edit(
                    StrEdit::UriDecode as i64,
                    bytes.as_ptr(),
                    bytes.len(),
                    i64::from(strict),
                    0,
                    out.as_mut_ptr(),
                    out.len(),
                )
            };
            assert_eq!(written, needed);
            Some(std::string::String::from_utf8(out).expect("UTF-8"))
        };
        // Unreserved decodes, reserved stays encoded.
        assert_eq!(decode("/%7Ea%2Fb", true).as_deref(), Some("/~a%2Fb"));
        assert_eq!(decode("/plain", true).as_deref(), Some("/plain"));
        // A malformed escape fails the transaction under `strict`, and is
        // preserved without it.
        assert_eq!(decode("/a%zz", true), None);
        assert_eq!(decode("/a%zz", false).as_deref(), Some("/a%zz"));
        assert_eq!(decode("/a%", true), None);
        assert_eq!(decode("/a%", false).as_deref(), Some("/a%"));
        assert_eq!(decode("/a%4", false).as_deref(), Some("/a%4"));
    }

    #[test]
    fn uri_state_survives_a_round_trip_through_its_serialised_form() {
        // Every operation reads a state string and writes one, so a pending
        // encode or normalisation has to be applied exactly once: a second
        // call must not encode the escapes the first one produced.
        let state = uri_state("http://h/a");
        let once = call(
            rt_uri_transform,
            &state,
            OpCode::new(UriOp::SetPath as u8).with_extra(URI_EXTRA_OPTION),
            b"/a b",
        )
        .expect("set");
        let twice = call(
            rt_uri_transform,
            &once,
            OpCode::new(UriOp::SetQuery as u8),
            b"q",
        )
        .expect("set");
        assert_eq!(uri_get(&twice, UriRead::Path).as_deref(), Some("/a%20b"));
        assert_eq!(uri_render(&twice), "http://h/a%20b?q");
        assert_eq!(
            core::str::from_utf8(&twice).expect("a uri state is UTF-8 when its inputs are"),
            "0;0,0,4,http2,0,0,0,0,1,h2,0,0,0,0,6,/a%20b0,0,1,q2,0,0,"
        );
    }
}

// ── ACL matching ────────────────────────────────────────────────────────────
//
// Every address is normalised to 128 bits: an IPv4 address is mapped into
// ::ffff:0:0/96 and its prefix length raised by 96, so one comparison covers
// both families and a v6 subject can never match a v4 rule.
//
// The compiler emits entries pre-masked and sorted by prefix length,
// longest first, so the first hit is the most specific one and its negate
// bit is the answer.  That ordering is the whole matcher: there is no
// second pass looking for a more specific rule.

/// Bytes per encoded ACL entry: 16 address, 1 prefix length, 1 flags, 2 pad.
pub const ACL_ENTRY_SIZE: usize = 20;

/// The entry is a `!` exclusion: matching it means the ACL does not match.
pub const ACL_NEGATE: u8 = 1;

/// The 96-bit prefix an IPv4 address is mapped into.
pub const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// Widen a dotted-quad into its IPv4-mapped 128-bit form.
pub fn v4_mapped(octets: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..12].copy_from_slice(&V4_MAPPED_PREFIX);
    out[12..].copy_from_slice(&octets);
    out
}

/// The leading `bits` of a 128-bit address, with the host bits cleared.
pub fn prefix_mask(bits: u8) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        !(u128::MAX >> bits)
    }
}

pub fn acl_match(table: &[u8], addr: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 16]>::try_from(addr) else {
        return false;
    };
    let subject = u128::from_be_bytes(bytes);
    for entry in table.chunks_exact(ACL_ENTRY_SIZE) {
        let Ok(network) = <[u8; 16]>::try_from(&entry[..16]) else {
            return false;
        };
        if (subject ^ u128::from_be_bytes(network)) & prefix_mask(entry[16]) == 0 {
            return entry[17] & ACL_NEGATE == 0;
        }
    }
    false
}

/// Render a normalised address the way Varnish prints `client.ip`: a mapped
/// IPv4 address as a dotted quad, everything else as RFC 5952 IPv6.
pub fn ip_format(addr: &[u8], out: &mut Writer<'_>) -> bool {
    let Ok(bytes) = <[u8; 16]>::try_from(addr) else {
        return false;
    };
    if bytes[..12] == V4_MAPPED_PREFIX {
        for (index, octet) in bytes[12..].iter().enumerate() {
            if index != 0 {
                out.byte(b'.');
            }
            out.decimal(usize::from(*octet));
        }
        return true;
    }

    let mut groups = [0u16; 8];
    for (index, group) in groups.iter_mut().enumerate() {
        *group = u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    }

    // RFC 5952 §4.2: compress the longest run of two or more zero groups,
    // leftmost on a tie.
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut at = 0usize;
    while at < groups.len() {
        if groups[at] != 0 {
            at += 1;
            continue;
        }
        let start = at;
        while at < groups.len() && groups[at] == 0 {
            at += 1;
        }
        if at - start > best_len {
            best_start = start;
            best_len = at - start;
        }
    }
    if best_len < 2 {
        best_len = 0;
    }

    let mut index = 0usize;
    while index < groups.len() {
        if best_len != 0 && index == best_start {
            out.bytes(b"::");
            index += best_len;
            continue;
        }
        if index != 0 && !(best_len != 0 && index == best_start + best_len) {
            out.byte(b':');
        }
        hex_group(groups[index], out);
        index += 1;
    }
    true
}

fn hex_group(group: u16, out: &mut Writer<'_>) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut started = false;
    for shift in [12u32, 8, 4] {
        let nibble = ((group >> shift) & 0xf) as usize;
        if started || nibble != 0 {
            out.byte(DIGITS[nibble]);
            started = true;
        }
    }
    out.byte(DIGITS[(group & 0xf) as usize]);
}

/// RV64 entry point for [`acl_match`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_acl_match(
    table: *const u8,
    table_len: usize,
    addr: *const u8,
    addr_len: usize,
) -> i64 {
    i64::from(acl_match(unsafe { raw_bytes(table, table_len) }, unsafe {
        raw_bytes(addr, addr_len)
    }))
}

/// RV64 entry point for [`ip_format`].
///
/// # Safety
/// Pointer/length pairs must meet the entry-point contract in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn rt_ip_format(
    addr: *const u8,
    addr_len: usize,
    output: *mut u8,
    cap: usize,
) -> i64 {
    let mut writer = Writer::new(unsafe { raw_bytes_mut(output, cap) });
    if !ip_format(unsafe { raw_bytes(addr, addr_len) }, &mut writer) {
        return -1;
    }
    writer.finish() as i64
}

#[cfg(test)]
mod acl_tests {
    use super::*;
    use std::net::IpAddr;
    use std::string::{String, ToString};
    use std::vec::Vec;

    fn normalise(text: &str) -> [u8; 16] {
        match text.parse::<IpAddr>().unwrap() {
            IpAddr::V4(v4) => v4_mapped(v4.octets()),
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    /// The encoding `vcl_compiler::resolver` produces: pre-masked, negate bit,
    /// longest prefix first.
    fn table(entries: &[(&str, u32, bool)]) -> Vec<u8> {
        let mut rows: Vec<(u8, [u8; 16], bool)> = entries
            .iter()
            .map(|(text, declared, negate)| {
                let width = if text.contains(':') { 128 } else { 32 };
                let bits = (*declared + 128 - width) as u8;
                let network = u128::from_be_bytes(normalise(text)) & prefix_mask(bits);
                (bits, network.to_be_bytes(), *negate)
            })
            .collect();
        rows.sort_by(|left, right| right.0.cmp(&left.0));
        let mut out = Vec::new();
        for (bits, network, negate) in rows {
            out.extend_from_slice(&network);
            out.push(bits);
            out.push(if negate { ACL_NEGATE } else { 0 });
            out.extend_from_slice(&[0, 0]);
        }
        out
    }

    fn render(text: &str) -> String {
        let mut out = [0u8; 64];
        let mut writer = Writer::new(&mut out);
        assert!(ip_format(&normalise(text), &mut writer));
        let length = writer.finish();
        String::from_utf8(out[..length].to_vec()).unwrap()
    }

    #[test]
    fn the_most_specific_entry_decides() {
        let acl = table(&[
            ("192.0.2.0", 24, false),
            ("192.0.2.23", 32, true),
            ("10.0.0.0", 8, false),
            ("2001:db8::", 32, false),
        ]);
        for (peer, expected) in [
            ("192.0.2.1", true),
            ("192.0.2.23", false),
            ("192.0.3.1", false),
            ("10.9.9.9", true),
            ("2001:db8::1", true),
            ("2001:db9::1", false),
            ("::ffff:192.0.2.1", true),
        ] {
            assert_eq!(acl_match(&acl, &normalise(peer)), expected, "{peer}");
        }
    }

    #[test]
    fn a_v6_peer_never_matches_a_v4_rule() {
        let acl = table(&[("0.0.0.0", 0, false)]);
        assert!(acl_match(&acl, &normalise("198.51.100.1")));
        assert!(!acl_match(&acl, &normalise("2001:db8::1")));
        assert!(!acl_match(&acl, &normalise("::")));
    }

    #[test]
    fn a_v6_default_route_matches_a_mapped_v4_peer() {
        let acl = table(&[("::", 0, false)]);
        assert!(acl_match(&acl, &normalise("198.51.100.1")));
        assert!(acl_match(&acl, &normalise("2001:db8::1")));
    }

    #[test]
    fn an_empty_table_matches_nothing() {
        assert!(!acl_match(&[], &normalise("192.0.2.1")));
        assert!(!acl_match(
            &[0; ACL_ENTRY_SIZE - 1],
            &normalise("192.0.2.1")
        ));
    }

    #[test]
    fn a_mistyped_address_length_never_matches() {
        let acl = table(&[("::", 0, false)]);
        assert!(!acl_match(&acl, &[0; 4]));
        assert!(!acl_match(&acl, &[]));
    }

    #[test]
    fn rendering_follows_rfc_5952_and_prints_v4_as_a_quad() {
        for (address, expected) in [
            ("192.0.2.1", "192.0.2.1"),
            ("0.0.0.0", "0.0.0.0"),
            ("255.255.255.255", "255.255.255.255"),
            ("::ffff:192.0.2.1", "192.0.2.1"),
            ("::", "::"),
            ("::1", "::1"),
            ("2001:db8::1", "2001:db8::1"),
            (
                "2001:0db8:0000:0000:0001:0000:0000:0001",
                "2001:db8::1:0:0:1",
            ),
            ("1:0:0:2:0:0:0:3", "1:0:0:2::3"),
            ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:6"),
            ("::2:0:0:0:0", "0:0:0:2::"),
        ] {
            assert_eq!(render(address), expected, "{address}");
        }
    }

    /// The only place this deliberately differs from `Ipv6Addr`'s own RFC 5952
    /// rendering is the mapped range, which prints as the IPv4 address it
    /// carries -- which is what `client.ip` reports for an IPv4 peer.
    #[test]
    fn rendering_agrees_with_std_outside_the_mapped_range() {
        let mut address = 0x2001_0db8_0000_0000_0000_0000_0000_0000u128;
        for _ in 0..512 {
            address = address.wrapping_mul(6364136223846793005).wrapping_add(1);
            let octets = address.to_be_bytes();
            if octets[..12] == V4_MAPPED_PREFIX {
                continue;
            }
            let mut out = [0u8; 64];
            let mut writer = Writer::new(&mut out);
            assert!(ip_format(&octets, &mut writer));
            let length = writer.finish();
            assert_eq!(
                String::from_utf8(out[..length].to_vec()).unwrap(),
                std::net::Ipv6Addr::from(octets).to_string(),
                "{octets:?}"
            );
        }
    }

    #[test]
    fn rendering_refuses_an_address_that_is_not_16_bytes() {
        let mut out = [0u8; 64];
        let mut writer = Writer::new(&mut out);
        assert!(!ip_format(&[0; 4], &mut writer));
    }
}

/// The `_regex` forms of the three list-shaped vmods, checked against
/// `varnish-cache-plus/lib/libvmod_{urlplus,headerplus,cookieplus}`.
///
/// The bitmaps are built here by hand rather than by a regex engine: what
/// these routines own is the projection order, the bit-to-record mapping and
/// the keep/delete rules on top of it.  Which subjects a pattern matches is
/// the host's, and testing it here would only restate `regex_match_list`.
#[cfg(test)]
mod regex_tests {
    use super::*;
    use std::vec::Vec;

    /// Decode a projected record list, as the host's `parse_records` does.
    fn records(packed: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let mut input = packed;
        while !input.is_empty() {
            let (name, value, rest) = snapshot_record(input).expect("a projected record");
            out.push((name.to_vec(), value.to_vec()));
            input = rest;
        }
        out
    }

    /// Whether one pattern matches a projected record's name and value.
    ///
    /// This stands in for the host's regex engine: see the module comment for
    /// why the match itself is not what these tests own.
    type Pattern<'a> = &'a dyn Fn(&[u8], &[u8]) -> bool;

    /// Build the argument the host writes: one fixed-stride bitmap a pattern.
    fn bitmaps(packed: &[u8], patterns: &[Pattern<'_>]) -> Vec<u8> {
        let decoded = records(packed);
        let mut out = std::vec![0u8; patterns.len() * REGEX_BITMAP_STRIDE];
        for (slot, hit) in patterns.iter().enumerate() {
            for (index, (name, value)) in decoded.iter().enumerate() {
                if hit(name, value) {
                    out[slot * REGEX_BITMAP_STRIDE + index / 8] |= 1 << (index % 8);
                }
            }
        }
        out
    }

    fn call(entry: StringEntry, input: &[u8], code: OpCode, argument: &[u8]) -> Option<Vec<u8>> {
        let word = code.encode();
        // Every pointer below is taken from a live slice, and the length
        // beside it is that slice's own -- which is the whole contract the
        // entry points ask of a caller.
        let needed = unsafe {
            entry(
                input.as_ptr(),
                input.len(),
                word,
                argument.as_ptr(),
                argument.len(),
                core::ptr::null_mut(),
                0,
            )
        };
        if needed < 0 {
            return None;
        }
        let mut output = std::vec![0u8; needed as usize];
        let written = unsafe {
            entry(
                input.as_ptr(),
                input.len(),
                word,
                argument.as_ptr(),
                argument.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(written, needed, "the sizing and filling passes disagreed");
        Some(output)
    }

    fn state(entry: StringEntry, source: &[u8], parse: u8) -> Vec<u8> {
        call(entry, source, OpCode::new(parse), b"").expect("a parsed state")
    }

    fn text(bytes: Option<Vec<u8>>) -> Option<std::string::String> {
        bytes.map(|bytes| std::string::String::from_utf8(bytes).expect("ASCII fixtures"))
    }

    #[test]
    fn cookie_projection_is_every_pair_in_order() {
        let parsed = state(
            rt_cookie_transform,
            b"a=1; bb=2; c=3",
            CookieOp::Parse as u8,
        );
        let packed = call(
            rt_cookie_read,
            &parsed,
            OpCode::new(CookieRead::Records as u8),
            b"",
        )
        .expect("projection");
        assert_eq!(
            records(&packed),
            std::vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"bb".to_vec(), b"2".to_vec()),
                (b"c".to_vec(), b"3".to_vec()),
            ]
        );
    }

    #[test]
    fn cookie_get_regex_answers_the_first_selected_pair() {
        let parsed = state(
            rt_cookie_transform,
            b"a=1; bb=2; c=3",
            CookieOp::Parse as u8,
        );
        let packed = call(
            rt_cookie_read,
            &parsed,
            OpCode::new(CookieRead::Records as u8),
            b"",
        )
        .expect("projection");
        let bits = bitmaps(&packed, &[&|name: &[u8], _: &[u8]| name.len() == 2]);
        assert_eq!(
            text(call(
                rt_cookie_read,
                &parsed,
                OpCode::new(CookieRead::GetRegex as u8),
                &bits,
            ))
            .as_deref(),
            Some("2")
        );
        let none = bitmaps(&packed, &[&|_: &[u8], _: &[u8]| false]);
        assert!(call(
            rt_cookie_read,
            &parsed,
            OpCode::new(CookieRead::GetRegex as u8),
            &none,
        )
        .is_none());
    }

    #[test]
    fn cookie_keeps_accumulate_across_calls() {
        let parsed = state(
            rt_cookie_transform,
            b"session=x; utm_a=1; lang=en",
            CookieOp::Parse as u8,
        );
        let packed = call(
            rt_cookie_read,
            &parsed,
            OpCode::new(CookieRead::Records as u8),
            b"",
        )
        .expect("projection");
        // keep_regex("^session") then keep("lang"): the vmod's keep mode
        // accumulates, so both survive the write.
        let bits = bitmaps(
            &packed,
            &[&|name: &[u8], _: &[u8]| name.starts_with(b"session")],
        );
        let kept = call(
            rt_cookie_transform,
            &parsed,
            OpCode::new(CookieOp::KeepRegex as u8),
            &bits,
        )
        .expect("keep_regex");
        let kept = call(
            rt_cookie_transform,
            &kept,
            OpCode::new(CookieOp::Keep as u8),
            b"lang",
        )
        .expect("keep");
        assert_eq!(
            text(call(
                rt_cookie_read,
                &kept,
                OpCode::new(CookieRead::AsString as u8),
                b"",
            ))
            .as_deref(),
            Some("session=x; lang=en")
        );
        assert_eq!(
            unsafe { rt_cookie_count(kept.as_ptr(), kept.len(), 0, core::ptr::null(), 0) },
            2
        );
    }

    #[test]
    fn cookie_delete_regex_spares_kept_pairs_unless_asked() {
        let parsed = state(
            rt_cookie_transform,
            b"utm_a=1; keepme=2",
            CookieOp::Parse as u8,
        );
        let parsed = call(
            rt_cookie_transform,
            &parsed,
            OpCode::new(CookieOp::Add as u8).with_flags(flag::KEEP),
            b"utm_b\x003",
        )
        .expect("add");
        let packed = call(
            rt_cookie_read,
            &parsed,
            OpCode::new(CookieRead::Records as u8),
            b"",
        )
        .expect("projection");
        let bits = bitmaps(
            &packed,
            &[&|name: &[u8], _: &[u8]| name.starts_with(b"utm_")],
        );
        let pruned = call(
            rt_cookie_transform,
            &parsed,
            OpCode::new(CookieOp::DeleteRegex as u8),
            &bits,
        )
        .expect("delete_regex");
        assert_eq!(
            text(call(
                rt_cookie_read,
                &pruned,
                OpCode::new(CookieRead::AsString as u8),
                b"",
            ))
            .as_deref(),
            Some("keepme=2; utm_b=3")
        );
        let pruned = call(
            rt_cookie_transform,
            &parsed,
            OpCode::new(CookieOp::DeleteRegex as u8).with_flags(flag::DELETE_KEEP),
            &bits,
        )
        .expect("delete_regex");
        assert_eq!(
            text(call(
                rt_cookie_read,
                &pruned,
                OpCode::new(CookieRead::AsString as u8),
                b"",
            ))
            .as_deref(),
            Some("keepme=2")
        );
    }

    #[test]
    fn url_projections_separate_segments_from_query_pairs() {
        let parsed = state(rt_url_transform, b"/a/b.jpg?x=1&y=2", UrlOp::Parse as u8);
        let segments = call(
            rt_url_read,
            &parsed,
            OpCode::new(UrlRead::Records as u8).with_extra(url_extra(0, 0, PART_URL)),
            b"",
        )
        .expect("segments");
        assert_eq!(
            records(&segments),
            std::vec![(b"a".to_vec(), Vec::new()), (b"b.jpg".to_vec(), Vec::new()),]
        );
        let queries = call(
            rt_url_read,
            &parsed,
            OpCode::new(UrlRead::Records as u8).with_extra(url_extra(0, 0, PART_QUERY)),
            b"",
        )
        .expect("queries");
        assert_eq!(
            records(&queries),
            std::vec![
                (b"x".to_vec(), b"1".to_vec()),
                (b"y".to_vec(), b"2".to_vec()),
            ]
        );
    }

    #[test]
    fn url_query_regex_forms_keep_and_delete_by_bitmap() {
        let parsed = state(
            rt_url_transform,
            b"/p?utm_source=x&id=7&utm_medium=y",
            UrlOp::Parse as u8,
        );
        let select = OpCode::new(UrlRead::Records as u8).with_extra(url_extra(0, 0, PART_QUERY));
        let packed = call(rt_url_read, &parsed, select, b"").expect("queries");
        let utm = bitmaps(
            &packed,
            &[&|name: &[u8], _: &[u8]| name.starts_with(b"utm_")],
        );

        let deleted = call(
            rt_url_transform,
            &parsed,
            OpCode::new(UrlOp::QueryDeleteRegex as u8),
            &utm,
        )
        .expect("query_delete_regex");
        assert_eq!(
            text(call(
                rt_url_read,
                &deleted,
                OpCode::new(UrlRead::AsString as u8),
                b"",
            ))
            .as_deref(),
            Some("/p?id=7")
        );

        let kept = call(
            rt_url_transform,
            &parsed,
            OpCode::new(UrlOp::QueryKeepRegex as u8),
            &utm,
        )
        .expect("query_keep_regex");
        assert_eq!(
            text(call(
                rt_url_read,
                &kept,
                OpCode::new(UrlRead::AsString as u8),
                b"",
            ))
            .as_deref(),
            Some("/p?utm_source=x&utm_medium=y")
        );
    }

    #[test]
    fn url_segment_regex_forms_index_the_path_alone() {
        let parsed = state(
            rt_url_transform,
            b"/img/v2/logo.png?a=1",
            UrlOp::Parse as u8,
        );
        let select = OpCode::new(UrlRead::Records as u8).with_extra(url_extra(0, 0, PART_URL));
        let packed = call(rt_url_read, &parsed, select, b"").expect("segments");
        let versioned = bitmaps(&packed, &[&|name: &[u8], _: &[u8]| name.starts_with(b"v")]);
        let deleted = call(
            rt_url_transform,
            &parsed,
            OpCode::new(UrlOp::UrlDeleteRegex as u8),
            &versioned,
        )
        .expect("url_delete_regex");
        assert_eq!(
            text(call(
                rt_url_read,
                &deleted,
                OpCode::new(UrlRead::UrlAsString as u8),
                b"",
            ))
            .as_deref(),
            Some("/img/logo.png")
        );
        let kept = call(
            rt_url_transform,
            &parsed,
            OpCode::new(UrlOp::UrlKeepRegex as u8),
            &versioned,
        )
        .expect("url_keep_regex");
        assert_eq!(
            text(call(
                rt_url_read,
                &kept,
                OpCode::new(UrlRead::UrlAsString as u8),
                b"",
            ))
            .as_deref(),
            Some("/v2")
        );
    }

    #[test]
    fn url_as_string_renders_the_path_without_the_query() {
        let parsed = state(rt_url_transform, b"/a/b/?x=1", UrlOp::Parse as u8);
        assert_eq!(
            text(call(
                rt_url_read,
                &parsed,
                OpCode::new(UrlRead::UrlAsString as u8),
                b"",
            ))
            .as_deref(),
            Some("/a/b/")
        );
        assert_eq!(
            text(call(
                rt_url_read,
                &parsed,
                OpCode::new(UrlRead::UrlAsString as u8).with_extra(url_extra(
                    SLASH_FALSE,
                    SLASH_FALSE,
                    PART_ALL
                )),
                b"",
            ))
            .as_deref(),
            Some("a/b")
        );
    }

    fn header_state(headers: &[(&str, &str)]) -> Vec<u8> {
        let mut packed = Vec::new();
        for (name, value) in headers {
            packed.extend_from_slice(&(name.len() as u32).to_le_bytes());
            packed.extend_from_slice(&(value.len() as u32).to_le_bytes());
            packed.extend_from_slice(name.as_bytes());
            packed.extend_from_slice(value.as_bytes());
        }
        call(
            rt_header_transform,
            &packed,
            OpCode::new(HeaderOp::Parse as u8),
            b"",
        )
        .expect("a header state")
    }

    #[test]
    fn header_regex_reads_take_both_bitmaps() {
        let parsed = header_state(&[
            ("X-One", "alpha"),
            ("X-Two", "beta"),
            ("Host", "example.test"),
        ]);
        let packed = call(
            rt_header_read,
            &parsed,
            OpCode::new(HEADER_READ_RECORDS),
            b"",
        )
        .expect("projection");
        let both = bitmaps(
            &packed,
            &[
                &|name: &[u8], _: &[u8]| name.starts_with(b"X-"),
                &|_: &[u8], value: &[u8]| value.starts_with(b"b"),
            ],
        );
        assert_eq!(
            text(call(
                rt_header_read,
                &parsed,
                OpCode::new(HEADER_READ_GET_REGEX),
                &both,
            ))
            .as_deref(),
            Some("beta")
        );
        assert_eq!(
            text(call(
                rt_header_read,
                &parsed,
                OpCode::new(HEADER_READ_NAME_REGEX),
                &both,
            ))
            .as_deref(),
            Some("X-Two")
        );
        // `count_regex` takes one pattern, so it reads slot 0 alone.
        let names = bitmaps(&packed, &[&|name: &[u8], _: &[u8]| name.starts_with(b"X-")]);
        assert_eq!(
            unsafe {
                rt_header_count(
                    parsed.as_ptr(),
                    parsed.len(),
                    OpCode::new(HEADER_COUNT_REGEX).encode(),
                    names.as_ptr(),
                    names.len(),
                )
            },
            2
        );
    }

    #[test]
    fn header_delete_regex_skips_the_records_it_already_deleted() {
        let parsed = header_state(&[("X-A", "1"), ("X-B", "2"), ("Y", "3")]);
        let parsed = call(
            rt_header_transform,
            &parsed,
            OpCode::new(HeaderOp::Delete as u8),
            b"X-A",
        )
        .expect("delete");
        // The projection is the live list, so `X-B` is record 0 for the match
        // and the bitmap the host wrote lines up with the apply loop.
        let packed = call(
            rt_header_read,
            &parsed,
            OpCode::new(HEADER_READ_RECORDS),
            b"",
        )
        .expect("projection");
        assert_eq!(
            records(&packed),
            std::vec![
                (b"X-B".to_vec(), b"2".to_vec()),
                (b"Y".to_vec(), b"3".to_vec()),
            ]
        );
        let bits = bitmaps(&packed, &[&|name: &[u8], _: &[u8]| name.starts_with(b"X-")]);
        let pruned = call(
            rt_header_transform,
            &parsed,
            OpCode::new(HeaderOp::DeleteRegex as u8),
            &bits,
        )
        .expect("delete_regex");
        assert_eq!(
            unsafe {
                rt_header_count(
                    pruned.as_ptr(),
                    pruned.len(),
                    OpCode::new(HEADER_COUNT_NAME).encode(),
                    core::ptr::null(),
                    0,
                )
            },
            1
        );
    }

    #[test]
    fn header_keep_regex_enables_keep_mode_even_with_no_match() {
        let parsed = header_state(&[("X-A", "1"), ("Y", "2")]);
        let packed = call(
            rt_header_read,
            &parsed,
            OpCode::new(HEADER_READ_RECORDS),
            b"",
        )
        .expect("projection");
        let none = bitmaps(&packed, &[&|_: &[u8], _: &[u8]| false]);
        let kept = call(
            rt_header_transform,
            &parsed,
            OpCode::new(HeaderOp::KeepRegex as u8),
            &none,
        )
        .expect("keep_regex");
        let decoded = ListState::parse(&kept).expect("state");
        assert!(decoded.has(list::KEEP_MODE));
        assert!(decoded
            .entries()
            .iter()
            .all(|entry| !entry.has(record::KEEP)));
    }
}
