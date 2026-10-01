use std::fmt;

use crate::{Diagnostic, Span};

/// A failure produced after source-language checking has completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackendError {
    pub(crate) span: Option<Span>,
    pub(crate) stage: &'static str,
    pub(crate) message: String,
    pub(crate) help: Option<String>,
}

impl BackendError {
    #[cfg(test)]
    pub(crate) fn contains(&self, needle: &str) -> bool {
        self.message.contains(needle)
    }

    pub(crate) fn new(stage: &'static str, span: Option<Span>, message: impl Into<String>) -> Self {
        Self {
            span,
            stage,
            message: message.into(),
            help: None,
        }
    }

    pub(crate) fn at(stage: &'static str, span: Span, message: impl Into<String>) -> Self {
        Self::new(stage, Some(span), message)
    }

    pub(crate) fn without_span(stage: &'static str, message: impl Into<String>) -> Self {
        Self::new(stage, None, message)
    }

    pub(crate) fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub(crate) fn into_diagnostic(self) -> Diagnostic {
        let mut diagnostic = Diagnostic::error(
            self.span.unwrap_or_default(),
            format!("{}: {}", self.stage, self.message),
        );
        if let Some(help) = self.help {
            diagnostic = diagnostic.with_help(help);
        }
        diagnostic
    }
}

#[cfg(test)]
impl PartialEq<&str> for BackendError {
    fn eq(&self, other: &&str) -> bool {
        self.message == *other
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.message)
    }
}

impl std::error::Error for BackendError {}
