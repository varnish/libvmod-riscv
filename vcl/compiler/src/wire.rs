//! The framing between a sandboxed compile's host and its compiler guest.
//!
//! Both ends link this module: the guest is `vcl-compiler/guest`
//! (`vcl-compilerc`), the host end is the `carapace` binary, and both depend
//! on this crate. One definition of the format is the whole point — a second
//! copy of a length-prefixed decoder is a place for the two to disagree about
//! what a hostile buffer means.
//!
//! Hand-written and deliberately small. No serde: the compiler crate stays
//! dependency-free so it cross-compiles into a guest
//! (`docs/plans/vcl-compiler-sandbox.md`, S3), and a decoder that runs over
//! output produced inside a sandbox has to be short enough to read in one
//! sitting.
//!
//! # Which side trusts what
//!
//! The **request** travels host → guest. The guest may assume the host wrote
//! it, and [`Request::decode`] therefore reports a malformed buffer as an
//! error the guest turns into a panic: a compiler that cannot read its own
//! input has no diagnostics to render and nothing true to say. `panic =
//! "abort"` makes that a machine exception, which the host reports as a
//! failed compile and a rejected candidate.
//!
//! The **response** travels guest → host, and the host trusts nothing about
//! it but the caps in [`Limits`]. Every length is checked against what is
//! left of the buffer before a single byte is read, so a guest cannot make
//! the host allocate on its say-so. Diagnostics are rendered *in the guest*
//! and arrive as one capped string, so the host never formats untrusted
//! source text.

use crate::{
    Compiled, Diagnostics, LineTable, OptimizationLevel, PhaseSet, MAX_INCLUDE_FILES,
    MAX_SOURCE_BYTES,
};

/// Format identity. A mismatch means the committed compiler guest and the
/// host binary were built from different trees, which CI's blob diff exists
/// to prevent; it is reported rather than assumed away.
const REQUEST_MAGIC: [u8; 4] = *b"VCLQ";
const RESPONSE_MAGIC: [u8; 4] = *b"VCLR";
const VERSION: u32 = 2;

const RESPONSE_OK: u8 = 0;
const RESPONSE_ERR: u8 = 1;

/// Hard ceilings the host applies while decoding a guest's answer.
///
/// These are not the compiler's limits — the compiler has its own, and it ran
/// inside the sandbox where they were enforced. These bound what a *lying*
/// guest can ask the host to do.
pub struct Limits;

impl Limits {
    /// Largest ELF the host will accept back. The largest policy in the
    /// corpus compiles to a few tens of kilobytes; this is room for two
    /// orders of magnitude of growth and no more.
    pub const MAX_ELF: usize = 8 * 1024 * 1024;
    /// Line-table entries. One per emitted instruction transition, so it
    /// scales with the ELF and is bounded well above it.
    pub const MAX_LINE_ENTRIES: usize = 1024 * 1024;
    /// Included library names, the same ceiling the preprocessor applies.
    pub const MAX_FILES: usize = MAX_INCLUDE_FILES;
    /// Rendered diagnostics. Every diagnostic quotes a source line, and the
    /// source is capped at [`MAX_SOURCE_BYTES`]; a megabyte is generous for
    /// the excerpts without letting a guest return the heap.
    pub const MAX_RENDERED: usize = 1024 * 1024;
    /// One include name, and one variant-header name. Both are short by
    /// nature; a path component limit is the only bound that matters.
    pub const MAX_NAME: usize = 4096;
}

/// A malformed buffer. Carries what was expected, because the two ends of
/// this format are built from one tree and a mismatch is a build problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(String);

impl WireError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

type Result<T> = core::result::Result<T, WireError>;

// ── Encoding primitives ─────────────────────────────────────────────────────

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    // A length that does not fit in u32 cannot be produced: every caller's
    // input is already capped far below 4 GiB, and `as` here would silently
    // truncate. Saturate instead, and the decoder's own length check refuses
    // the result rather than mis-reading it.
    put_u32(out, u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(bytes);
}

fn put_str(out: &mut Vec<u8>, text: &str) {
    put_bytes(out, text.as_bytes());
}

fn put_strs(out: &mut Vec<u8>, items: impl ExactSizeIterator<Item = impl AsRef<str>>) {
    put_u32(out, u32::try_from(items.len()).unwrap_or(u32::MAX));
    for item in items {
        put_str(out, item.as_ref());
    }
}

// ── Decoding primitives ─────────────────────────────────────────────────────

/// A cursor that never reads past its buffer and never allocates on a length
/// it has not first checked against what is left.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn take(&mut self, what: &str, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| WireError::new(format!("{what} length {len} overflows the buffer")))?;
        let slice = self.bytes.get(self.at..end).ok_or_else(|| {
            WireError::new(format!(
                "{what} wants {len} bytes but only {} remain",
                self.remaining()
            ))
        })?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(what, 1)?[0])
    }

    fn u32(&mut self, what: &str) -> Result<u32> {
        let bytes = self.take(what, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self, what: &str) -> Result<u64> {
        let bytes = self.take(what, 8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("eight bytes taken"),
        ))
    }

    /// A length-prefixed byte run, refused if it exceeds `cap` *or* what is
    /// left of the buffer. The cap is checked first so a bogus length is
    /// named as a cap violation rather than a truncation.
    fn bytes(&mut self, what: &str, cap: usize) -> Result<&'a [u8]> {
        let len = self.u32(what)? as usize;
        if len > cap {
            return Err(WireError::new(format!(
                "{what} is {len} bytes, over the {cap}-byte limit"
            )));
        }
        self.take(what, len)
    }

    fn string(&mut self, what: &str, cap: usize) -> Result<String> {
        let bytes = self.bytes(what, cap)?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|error| WireError::new(format!("{what} is not UTF-8: {error}")))
    }

    /// An element count, refused when the buffer cannot possibly hold that
    /// many elements of `min_element` bytes. This is what stops a count of
    /// four billion from reserving before the first element is read.
    fn count(&mut self, what: &str, cap: usize, min_element: usize) -> Result<usize> {
        let count = self.u32(what)? as usize;
        if count > cap {
            return Err(WireError::new(format!(
                "{what} has {count} entries, over the {cap} limit"
            )));
        }
        let needed = count
            .checked_mul(min_element)
            .ok_or_else(|| WireError::new(format!("{what} count {count} overflows")))?;
        if needed > self.remaining() {
            return Err(WireError::new(format!(
                "{what} claims {count} entries but only {} bytes remain",
                self.remaining()
            )));
        }
        Ok(count)
    }

    fn magic(&mut self, expected: [u8; 4], what: &str) -> Result<()> {
        let bytes = self.take("magic", 4)?;
        if bytes != expected {
            return Err(WireError::new(format!(
                "not a VCL compiler {what}: magic {bytes:02x?}"
            )));
        }
        let version = self.u32("version")?;
        if version != VERSION {
            return Err(WireError::new(format!(
                "VCL compiler {what} is version {version}, this build speaks {VERSION}"
            )));
        }
        Ok(())
    }

    fn finish(self, what: &str) -> Result<()> {
        if self.remaining() != 0 {
            return Err(WireError::new(format!(
                "{} trailing bytes after the {what}",
                self.remaining()
            )));
        }
        Ok(())
    }
}

// ── Request ─────────────────────────────────────────────────────────────────

/// One compile, as the host asks for it.
///
/// This is the whole of the compiler's input. There is no host call for any
/// of it: the host writes the encoding into the VM's arena and passes the
/// address, because input needs no syscall and every syscall the compiler can
/// reach is exposure to weigh (S5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The main file's name, as diagnostics should name it.
    pub filename: String,
    /// The directory include names are relative to. Display only — it
    /// prefixes the path a diagnostic tells the operator to open, and never
    /// reaches the generated ELF.
    pub root: String,
    pub source: String,
    pub verify_ir: bool,
    pub optimization: OptimizationLevel,
    /// The route's `variant_headers`: the request headers `vcl_recv` may not
    /// write, because variance is derived after it runs.
    pub variant_headers: Vec<String>,
    /// The route's `grace`/`keep` caps in seconds, when it names either. A
    /// policy writing a stale window above its cap is a warning, so the caps
    /// have to reach the compiler on both paths or the two disagree about
    /// what a policy warns about.
    pub stale_caps: Option<(u32, u32)>,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.source.len() + 256);
        out.extend_from_slice(&REQUEST_MAGIC);
        put_u32(&mut out, VERSION);
        put_str(&mut out, &self.filename);
        put_str(&mut out, &self.root);
        put_str(&mut out, &self.source);
        put_u8(&mut out, u8::from(self.verify_ir));
        put_u8(
            &mut out,
            match self.optimization {
                OptimizationLevel::None => 0,
                OptimizationLevel::Basic => 1,
            },
        );
        put_strs(&mut out, self.variant_headers.iter());
        match self.stale_caps {
            None => put_u8(&mut out, 0),
            Some((grace, keep)) => {
                put_u8(&mut out, 1);
                put_u32(&mut out, grace);
                put_u32(&mut out, keep);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.magic(REQUEST_MAGIC, "request")?;
        let filename = reader.string("filename", Limits::MAX_NAME)?;
        let root = reader.string("include root", Limits::MAX_NAME)?;
        let source = reader.string("source", MAX_SOURCE_BYTES)?;
        let verify_ir = reader.u8("verify_ir")? != 0;
        let optimization = match reader.u8("optimization")? {
            0 => OptimizationLevel::None,
            1 => OptimizationLevel::Basic,
            other => {
                return Err(WireError::new(format!(
                    "unknown optimization level {other}"
                )))
            }
        };
        // Four bytes minimum per name: its own length prefix.
        let count = reader.count("variant_headers", Limits::MAX_FILES, 4)?;
        let mut variant_headers = Vec::with_capacity(count);
        for _ in 0..count {
            variant_headers.push(reader.string("variant header", Limits::MAX_NAME)?);
        }
        let stale_caps = match reader.u8("stale_caps tag")? {
            0 => None,
            1 => Some((reader.u32("grace")?, reader.u32("keep")?)),
            other => return Err(WireError::new(format!("unknown stale_caps tag {other}"))),
        };
        reader.finish("request")?;
        Ok(Self {
            filename,
            root,
            source,
            verify_ir,
            optimization,
            variant_headers,
            stale_caps,
        })
    }
}

// ── Response ────────────────────────────────────────────────────────────────

/// What the compiler produced: the same two outcomes
/// [`crate::compile`](crate::compile) has.
///
/// A failed compile carries *rendered* diagnostics rather than a
/// `Diagnostics`, and that is the point: rendering quotes untrusted source
/// text, so it happens inside the sandbox and the host receives one capped
/// string it only ever passes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok {
        elf: Vec<u8>,
        /// `(address, line, file)` per line-table entry.
        lines: Vec<(u64, u32, u32)>,
        files: Vec<String>,
        exports: u16,
        /// Compiler warnings, already rendered. Rendering quotes the tenant's
        /// source, so it happens in the guest and the host passes the strings
        /// through — the same reason a failed compile carries a rendered
        /// string rather than a `Diagnostics`.
        warnings: Vec<String>,
    },
    Err {
        rendered: String,
    },
}

impl Response {
    /// The successful shape, from what the compiler returned.
    ///
    /// `filename` is what warnings are rendered against — the same name the
    /// host would render them against natively.
    pub fn from_compiled(compiled: &Compiled, filename: &str) -> Self {
        Self::Ok {
            warnings: compiled.warnings.render_each(filename),
            elf: compiled.elf.clone(),
            lines: compiled
                .lines
                .entries
                .iter()
                .map(|entry| (entry.address, entry.line, entry.file))
                .collect(),
            files: compiled.files.clone(),
            exports: compiled.exports.bits(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&RESPONSE_MAGIC);
        put_u32(&mut out, VERSION);
        match self {
            Self::Ok {
                elf,
                lines,
                files,
                exports,
                warnings,
            } => {
                put_u8(&mut out, RESPONSE_OK);
                put_bytes(&mut out, elf);
                put_u32(&mut out, u32::try_from(lines.len()).unwrap_or(u32::MAX));
                for (address, line, file) in lines {
                    put_u64(&mut out, *address);
                    put_u32(&mut out, *line);
                    put_u32(&mut out, *file);
                }
                put_strs(&mut out, files.iter());
                put_u32(&mut out, u32::from(*exports));
                put_strs(&mut out, warnings.iter());
            }
            Self::Err { rendered } => {
                put_u8(&mut out, RESPONSE_ERR);
                put_str(&mut out, rendered);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.magic(RESPONSE_MAGIC, "response")?;
        let response = match reader.u8("outcome tag")? {
            RESPONSE_OK => {
                let elf = reader.bytes("elf", Limits::MAX_ELF)?.to_vec();
                let count = reader.count("line table", Limits::MAX_LINE_ENTRIES, 16)?;
                let mut lines = Vec::with_capacity(count);
                for _ in 0..count {
                    let address = reader.u64("line address")?;
                    let line = reader.u32("line number")?;
                    let file = reader.u32("line file")?;
                    lines.push((address, line, file));
                }
                let count = reader.count("files", Limits::MAX_FILES, 4)?;
                let mut files = Vec::with_capacity(count);
                for _ in 0..count {
                    files.push(reader.string("file name", Limits::MAX_NAME)?);
                }
                // Bits past the known phases are ignored, so truncating the
                // word to them loses nothing.
                let exports = reader.u32("exports")? as u16;
                let count = reader.count("warnings", Limits::MAX_FILES, 4)?;
                let mut warnings = Vec::with_capacity(count);
                for _ in 0..count {
                    warnings.push(reader.string("warning", Limits::MAX_RENDERED)?);
                }
                Self::Ok {
                    elf,
                    lines,
                    files,
                    exports,
                    warnings,
                }
            }
            RESPONSE_ERR => Self::Err {
                rendered: reader.string("rendered diagnostics", Limits::MAX_RENDERED)?,
            },
            other => return Err(WireError::new(format!("unknown outcome tag {other}"))),
        };
        reader.finish("response")?;
        Ok(response)
    }

    /// Rebuild the compiler's own return type, so a sandboxed compile and a
    /// native one hand their caller the same thing.
    pub fn into_compiled(self) -> core::result::Result<(Compiled, Vec<String>), String> {
        match self {
            Self::Ok {
                elf,
                lines,
                files,
                exports,
                warnings,
            } => Ok((
                Compiled {
                    elf,
                    lines: LineTable {
                        entries: lines
                            .into_iter()
                            .map(|(address, line, file)| crate::ir::LineEntry {
                                address,
                                line,
                                file,
                            })
                            .collect(),
                    },
                    files,
                    exports: PhaseSet::from_bits(exports),
                    // Rendered in the guest; the structured form does not
                    // cross the boundary because nothing on the host reads it.
                    warnings: Diagnostics::default(),
                },
                warnings,
            )),
            Self::Err { rendered } => Err(rendered),
        }
    }
}

/// The length-prefixed buffer a guest returns the address of.
///
/// The host reads the four-byte prefix, then the payload. Framing the length
/// in the buffer rather than in a register is what lets the guest return one
/// pointer from a C ABI function.
pub fn prefixed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    put_bytes(&mut out, payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            filename: "policy.vcl".into(),
            root: "/etc/carapace/policy".into(),
            source: "vcl 4.1;\nsub vcl_recv { return (hash); }\n".into(),
            verify_ir: true,
            optimization: OptimizationLevel::Basic,
            variant_headers: vec!["accept-encoding".into(), "x-variant".into()],
            stale_caps: Some((10, 3600)),
        }
    }

    #[test]
    fn a_request_round_trips() {
        let request = request();
        assert_eq!(Request::decode(&request.encode()).unwrap(), request);
    }

    #[test]
    fn a_request_with_nothing_optional_round_trips() {
        let request = Request {
            root: String::new(),
            optimization: OptimizationLevel::None,
            verify_ir: false,
            variant_headers: Vec::new(),
            stale_caps: None,
            ..request()
        };
        assert_eq!(Request::decode(&request.encode()).unwrap(), request);
    }

    #[test]
    fn an_ok_response_round_trips() {
        let response = Response::Ok {
            elf: vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0],
            lines: vec![(0x1000, 3, 0), (0x1004, 7, 1)],
            files: vec!["lib.vcl".into()],
            exports: PhaseSet::from_bits(0b1001).bits(),
            warnings: vec!["policy.vcl:4:9: warning: truncated\n".into()],
        };
        assert_eq!(Response::decode(&response.encode()).unwrap(), response);
    }

    #[test]
    fn an_err_response_round_trips() {
        let response = Response::Err {
            rendered: "policy.vcl:2:5: error: nope\n".into(),
        };
        assert_eq!(Response::decode(&response.encode()).unwrap(), response);
        assert_eq!(
            response.into_compiled().unwrap_err(),
            "policy.vcl:2:5: error: nope\n"
        );
    }

    #[test]
    fn a_compiled_program_survives_the_round_trip_unchanged() {
        let compiled = crate::compile(
            "vcl 4.1; sub vcl_recv { set req.http.X = \"1\"; return (hash); }",
            crate::CompileOptions::default(),
        )
        .unwrap();
        let (decoded, warnings) =
            Response::decode(&Response::from_compiled(&compiled, "policy.vcl").encode())
                .unwrap()
                .into_compiled()
                .unwrap();
        assert_eq!(warnings, compiled.warnings.render_each("policy.vcl"));
        // Warnings cross the boundary rendered, so the structured form is
        // empty on the far side; everything else survives byte for byte.
        assert_eq!(
            decoded,
            Compiled {
                warnings: Diagnostics::default(),
                ..compiled
            }
        );
    }

    // ── Caps and malformed input ─────────────────────────────────────────

    #[test]
    fn a_missing_magic_is_named_rather_than_misread() {
        assert!(
            Response::decode(b"nope")
                .unwrap_err()
                .to_string()
                .contains("wants 4 bytes")
                || Response::decode(b"nope\x01\0\0\0")
                    .unwrap_err()
                    .to_string()
                    .contains("not a VCL compiler response")
        );
    }

    #[test]
    fn a_version_the_host_does_not_speak_is_refused() {
        let mut bytes = Response::Err {
            rendered: String::new(),
        }
        .encode();
        bytes[4] = 99;
        assert!(Response::decode(&bytes)
            .unwrap_err()
            .to_string()
            .contains("version 99"));
    }

    #[test]
    fn an_elf_over_the_cap_is_refused_without_allocating_it() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        put_u32(&mut bytes, VERSION);
        put_u8(&mut bytes, RESPONSE_OK);
        put_u32(&mut bytes, u32::MAX);
        let error = Response::decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("elf is 4294967295 bytes"), "{error}");
    }

    #[test]
    fn a_line_count_larger_than_the_buffer_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        put_u32(&mut bytes, VERSION);
        put_u8(&mut bytes, RESPONSE_OK);
        put_bytes(&mut bytes, b"");
        put_u32(&mut bytes, 1000);
        let error = Response::decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("claims 1000 entries"), "{error}");
    }

    #[test]
    fn a_line_count_over_the_cap_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        put_u32(&mut bytes, VERSION);
        put_u8(&mut bytes, RESPONSE_OK);
        put_bytes(&mut bytes, b"");
        put_u32(&mut bytes, Limits::MAX_LINE_ENTRIES as u32 + 1);
        let error = Response::decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("over the 1048576 limit"), "{error}");
    }

    #[test]
    fn more_files_than_the_preprocessor_allows_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        put_u32(&mut bytes, VERSION);
        put_u8(&mut bytes, RESPONSE_OK);
        put_bytes(&mut bytes, b"");
        put_u32(&mut bytes, 0);
        put_u32(&mut bytes, MAX_INCLUDE_FILES as u32 + 1);
        let error = Response::decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("files has 65 entries"), "{error}");
    }

    #[test]
    fn rendered_diagnostics_over_the_cap_are_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        put_u32(&mut bytes, VERSION);
        put_u8(&mut bytes, RESPONSE_ERR);
        put_u32(&mut bytes, Limits::MAX_RENDERED as u32 + 1);
        let error = Response::decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("over the 1048576-byte limit"), "{error}");
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = Response::Err {
            rendered: "x".into(),
        }
        .encode();
        bytes.push(0);
        assert!(Response::decode(&bytes)
            .unwrap_err()
            .to_string()
            .contains("trailing"));
    }

    #[test]
    fn a_truncated_response_is_refused_at_every_length() {
        let full = Response::Ok {
            elf: vec![1, 2, 3],
            lines: vec![(9, 8, 7)],
            files: vec!["lib.vcl".into()],
            exports: 3,
            warnings: vec!["w".into()],
        }
        .encode();
        for cut in 0..full.len() {
            assert!(
                Response::decode(&full[..cut]).is_err(),
                "a {cut}-byte prefix decoded"
            );
        }
        assert!(Response::decode(&full).is_ok());
    }

    #[test]
    fn a_truncated_request_is_refused_at_every_length() {
        let full = request().encode();
        for cut in 0..full.len() {
            assert!(
                Request::decode(&full[..cut]).is_err(),
                "a {cut}-byte prefix decoded"
            );
        }
    }

    #[test]
    fn non_utf8_text_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RESPONSE_MAGIC);
        put_u32(&mut bytes, VERSION);
        put_u8(&mut bytes, RESPONSE_ERR);
        put_bytes(&mut bytes, &[0xff, 0xfe]);
        assert!(Response::decode(&bytes)
            .unwrap_err()
            .to_string()
            .contains("not UTF-8"));
    }

    #[test]
    fn source_over_the_compilers_own_limit_never_reaches_the_compiler() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&REQUEST_MAGIC);
        put_u32(&mut bytes, VERSION);
        put_str(&mut bytes, "policy.vcl");
        put_str(&mut bytes, "");
        put_u32(&mut bytes, MAX_SOURCE_BYTES as u32 + 1);
        let error = Request::decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("source is 1048577 bytes"), "{error}");
    }

    #[test]
    fn the_length_prefix_frames_the_payload() {
        let framed = prefixed(b"hello");
        assert_eq!(&framed[..4], &5u32.to_le_bytes());
        assert_eq!(&framed[4..], b"hello");
    }

    // ── The exports bitmask ──────────────────────────────────────────────

    #[test]
    fn every_export_survives_the_bitmask() {
        let compiled = crate::compile(
            "vcl 4.1;
             sub vcl_recv { return (hash); }
             sub vcl_backend_fetch { return (fetch); }
             sub vcl_backend_response { return (deliver); }
             sub vcl_deliver { return (deliver); }",
            crate::CompileOptions::default(),
        )
        .unwrap();
        let bits = compiled.exports.bits();
        assert_eq!(PhaseSet::from_bits(bits), compiled.exports);
        for hook in [
            "on_recv",
            "on_backend_fetch",
            "on_backend_response",
            "on_deliver",
        ] {
            assert!(PhaseSet::from_bits(bits).contains(hook), "{hook}");
        }
    }

    #[test]
    fn unknown_export_bits_are_ignored_rather_than_panicking() {
        assert_eq!(
            PhaseSet::from_bits(0xffff),
            PhaseSet::from_bits(0b11_1111_1111)
        );
    }
}
