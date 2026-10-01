use std::fmt;

use crate::types::Span;

/// How many diagnostics one rejection renders.
///
/// A rejected candidate's rendering is kept in `ConfigState::last_rejection`,
/// written to the shared log and answered on the admin socket, so a megabyte
/// of garbage must not become a megabyte of rejection. The first few say what
/// is wrong; past that a file is either machine-generated or the parser is
/// recovering through noise, and the count is the useful part.
pub const MAX_DIAGNOSTICS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    /// Something the policy does that compiles, but not to what a Varnish
    /// author would expect. Carried in [`Compiled::warnings`] and written to
    /// the shared log by whoever loaded the policy; it never fails a
    /// candidate, because a policy that stops loading is not a warning.
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub span: Span,
    pub severity: Severity,
    pub message: String,
    pub help: Option<String>,
    pub notes: Vec<(Span, String)>,
}

impl Diagnostic {
    pub(crate) fn error(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            severity: Severity::Error,
            message: message.into(),
            help: None,
            notes: Vec::new(),
        }
    }

    pub(crate) fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub(crate) fn warning(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            severity: Severity::Warning,
            message: message.into(),
            help: None,
            notes: Vec::new(),
        }
    }

    pub(crate) fn with_note(mut self, span: Span, note: impl Into<String>) -> Self {
        self.notes.push((span, note.into()));
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    source: String,
    filename: Option<String>,
    files: Vec<DiagnosticFile>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiagnosticFile {
    pub start: usize,
    pub end: usize,
    /// Resolved path, for a diagnostic the operator has to go and open.
    pub filename: Option<String>,
    /// The name as the `include` statement spells it. This is what a runtime
    /// fault reports, and it goes into the ELF: an absolute path would make
    /// two copies of the same policy tree compile to different bytes.
    pub include: Option<String>,
    pub source: String,
}

impl Diagnostics {
    pub(crate) fn new(source: &str, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            source: source.to_string(),
            filename: None,
            files: Vec::new(),
            diagnostics,
        }
    }

    pub(crate) fn single(source: &str, diagnostic: Diagnostic) -> Self {
        Self::new(source, vec![diagnostic])
    }

    /// Resolve one span to the file it points into, rebased onto that file's
    /// own text.
    ///
    /// A note is not necessarily in the same file as the diagnostic it hangs
    /// off: a duplicate declaration points at the first one, and a call-path
    /// note points at a call site that may be several includes away. Each
    /// span therefore selects its own file.
    fn locate<'a>(&'a self, span: Span, filename: &'a str) -> (&'a str, &'a str, Span) {
        match self
            .files
            .iter()
            .find(|file| (file.start..=file.end).contains(&span.start))
        {
            Some(file) => (
                &file.source,
                file.filename.as_deref().unwrap_or(filename),
                Span::new(
                    span.start.saturating_sub(file.start),
                    span.end.saturating_sub(file.start),
                ),
            ),
            None => (
                &self.source,
                self.filename.as_deref().unwrap_or(filename),
                span,
            ),
        }
    }

    /// Render with a caller-owned filename, suitable for config errors.
    pub fn render(&self, filename: &str) -> String {
        self.render_each(filename).join("\n")
    }

    /// The same rendering, one entry per diagnostic.
    ///
    /// [`render`](Self::render) joins these with newlines, which is what a
    /// config error wants: one blob to print or to carry in a rejection. A
    /// caller that reports diagnostics *individually* — one shared-log record
    /// per warning — needs the boundaries instead, and cannot recover them
    /// from the blob: a single rendering is already several lines (the
    /// location, the offending source line, the carets, an optional `help:`
    /// and any notes), so splitting on newlines turns one warning into five
    /// records, four of which are fragments.
    ///
    /// The first line of an entry is always
    /// `{file}:{line}:{column}: {severity}: {message}`, so a caller with room
    /// for one line has one worth printing.
    ///
    /// A `... and N more` tail is its own final entry when the count is
    /// capped, so the elision is reported whichever way the caller renders.
    pub fn render_each(&self, filename: &str) -> Vec<String> {
        let mut rendered = self
            .diagnostics
            .iter()
            .take(MAX_DIAGNOSTICS)
            .map(|diagnostic| {
                let notes = diagnostic
                    .notes
                    .iter()
                    .map(|(span, note)| {
                        let (source, name, span) = self.locate(*span, filename);
                        render_note(source, name, span, note)
                    })
                    .collect::<Vec<_>>();
                let (source, name, span) = self.locate(diagnostic.span, filename);
                render_one(source, name, span, diagnostic, &notes)
            })
            .collect::<Vec<_>>();
        let elided = self.diagnostics.len().saturating_sub(MAX_DIAGNOSTICS);
        if elided > 0 {
            rendered.push(format!("... and {elided} more"));
        }
        rendered
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub(crate) fn with_files(mut self, files: Vec<DiagnosticFile>) -> Self {
        self.files = files;
        self
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render("<vcl>"))
    }
}

impl std::error::Error for Diagnostics {}

/// Clamp a byte offset onto a character boundary within `source`.
///
/// Spans are rebased per file, so a span that names a file the renderer could
/// not find is reported against a text it does not index. Clamping keeps that
/// a misplaced caret rather than a panic.
fn clamp_offset(source: &str, offset: usize) -> usize {
    let mut offset = offset.min(source.len());
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

/// Line number, column number and the byte offset the line starts at.
fn position(source: &str, offset: usize) -> (usize, usize, usize) {
    let before = &source[..offset];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |at| at + 1);
    let column = source[line_start..offset].chars().count() + 1;
    (line, column, line_start)
}

fn render_note(source: &str, filename: &str, span: Span, note: &str) -> String {
    let offset = clamp_offset(source, span.start);
    let (line, column, _) = position(source, offset);
    format!("note: {note} ({filename}:{line}:{column})")
}

fn render_one(
    source: &str,
    filename: &str,
    span: Span,
    diagnostic: &Diagnostic,
    notes: &[String],
) -> String {
    let offset = clamp_offset(source, span.start);
    let (line, column, line_start) = position(source, offset);
    let line_end = source[offset..]
        .find('\n')
        .map_or(source.len(), |relative| offset + relative);
    let text = &source[line_start..line_end];
    let selected_end = clamp_offset(source, span.end).min(line_end).max(offset);
    let width = source[offset..selected_end].chars().count().max(1);
    let severity = match diagnostic.severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    };
    let mut rendered = format!(
        "{filename}:{line}:{column}: {severity}: {}\n{text}\n{}{}",
        diagnostic.message,
        " ".repeat(column - 1),
        "^".repeat(width)
    );
    if let Some(help) = &diagnostic.help {
        rendered.push_str("\nhelp: ");
        rendered.push_str(help);
    }
    for note in notes {
        rendered.push('\n');
        rendered.push_str(note);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_before_and_inside_a_span_keeps_the_caret_aligned() {
        let source = "blåbær feil";
        let start = source.find("feil").unwrap();
        let rendered = Diagnostics::single(
            source,
            Diagnostic::error(Span::new(start, source.len()), "bad fruit"),
        )
        .render("policy.vcl");
        assert!(rendered.contains("policy.vcl:1:8: error"), "{rendered}");
        assert!(rendered.contains("\n       ^^^^"), "{rendered}");
    }

    #[test]
    fn a_note_renders_against_its_own_file() {
        let main = "sub vcl_recv {\n    set req.http.X = \"1\";\n}\n";
        let library = "sub helper {\n    return;\n}\n";
        let files = vec![
            DiagnosticFile {
                start: 0,
                end: main.len(),
                filename: Some("policy.vcl".into()),
                include: None,
                source: main.into(),
            },
            DiagnosticFile {
                start: main.len() + 1,
                end: main.len() + 1 + library.len(),
                filename: Some("lib.vcl".into()),
                include: Some("lib".into()),
                source: library.into(),
            },
        ];
        // Error in the library, note pointing back into the main file.
        let library_span = Span::new(main.len() + 1, main.len() + 4);
        let main_span = Span::new(4, 12);
        let rendered = Diagnostics::single(
            "",
            Diagnostic::error(library_span, "duplicate declaration")
                .with_note(main_span, "the first declaration is here"),
        )
        .with_files(files)
        .render("<vcl>");
        assert!(rendered.contains("lib.vcl:1:1: error"), "{rendered}");
        assert!(
            rendered.contains("note: the first declaration is here (policy.vcl:1:5)"),
            "{rendered}"
        );
    }

    /// One entry per diagnostic, each several lines, so a caller reporting
    /// them one at a time never has to split the joined blob back apart.
    #[test]
    fn each_diagnostic_renders_as_one_multi_line_entry() {
        let source = "sub vcl_recv {\n    set req.http.X = \"1\";\n}\n";
        let diagnostics = Diagnostics::new(
            source,
            vec![
                Diagnostic::warning(Span::new(4, 12), "first").with_help("try this"),
                Diagnostic::warning(Span::new(19, 27), "second"),
            ],
        );
        let each = diagnostics.render_each("policy.vcl");
        assert_eq!(each.len(), 2, "{each:?}");
        assert!(
            each[0].starts_with("policy.vcl:1:5: warning: first\n"),
            "{each:?}"
        );
        assert!(each[0].contains("\nhelp: try this"), "{each:?}");
        assert!(
            each[1].starts_with("policy.vcl:2:5: warning: second\n"),
            "{each:?}"
        );
        assert_eq!(each.join("\n"), diagnostics.render("policy.vcl"));
    }

    #[test]
    fn a_rendering_is_bounded_and_says_how_much_it_left_out() {
        let source = "vcl 4.1;\n";
        let diagnostics = Diagnostics::new(
            source,
            (0..MAX_DIAGNOSTICS + 9)
                .map(|_| Diagnostic::error(Span::new(0, 3), "bad"))
                .collect(),
        );
        let rendered = diagnostics.render("policy.vcl");
        assert_eq!(rendered.matches("error: bad").count(), MAX_DIAGNOSTICS);
        assert!(rendered.ends_with("... and 9 more"), "{rendered}");
    }
}
