use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use crate::ast;
use crate::diagnostic::DiagnosticFile;
use crate::{
    CompileOptions, Diagnostic, Diagnostics, IncludeResolver, Span, MAX_INCLUDE_FILES,
    MAX_SOURCE_BYTES,
};

pub(crate) struct SourceUnit {
    pub(crate) program: ast::Program,
    pub(crate) text: String,
    pub(crate) files: Vec<DiagnosticFile>,
}

impl SourceUnit {
    pub(crate) fn include_names(&self) -> Vec<String> {
        self.files
            .iter()
            .skip(1)
            .map(|file| file.include.clone().unwrap_or_default())
            .collect()
    }
}

pub(crate) fn preprocess(
    source: &str,
    options: &CompileOptions,
) -> Result<SourceUnit, Diagnostics> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Diagnostics::single(
            "",
            Diagnostic::error(
                Span::default(),
                format!(
                    "VCL source is {} bytes, over the {MAX_SOURCE_BYTES}-byte limit",
                    source.len()
                ),
            ),
        ));
    }
    let tokens = crate::lexer::lex(source)?;
    let mut program = crate::parser::parse(source, &tokens)?;
    let mut text = source.to_string();
    let mut files = vec![DiagnosticFile {
        start: 0,
        end: source.len(),
        filename: None,
        include: None,
        source: source.to_string(),
    }];
    let includes = program
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Include { path, span } => Some((path.clone(), *span)),
            ast::Item::Sub(_)
            | ast::Item::Static { .. }
            | ast::Item::Global { .. }
            | ast::Item::Acl { .. } => None,
        })
        .collect::<Vec<_>>();
    program
        .items
        .retain(|item| !matches!(item, ast::Item::Include { .. }));

    if includes.len() > MAX_INCLUDE_FILES {
        let span = includes[MAX_INCLUDE_FILES].1;
        return Err(Diagnostics::single(
            source,
            Diagnostic::error(
                span,
                format!("VCL policy includes more than the {MAX_INCLUDE_FILES}-file limit"),
            ),
        ));
    }

    let mut seen = HashSet::new();
    let mut aggregate_bytes = source.len();
    for (name, span) in includes {
        let Some(resolver) = options.include_resolver.as_ref() else {
            return Err(Diagnostics::single(
                source,
                Diagnostic::error(
                    span,
                    "include is not available for this configuration source",
                )
                .with_help("includes are not supported from remote configuration yet"),
            ));
        };
        let include = resolver.resolve(&name).map_err(|message| {
            Diagnostics::single(
                source,
                Diagnostic::error(span, format!("failed to include '{name}': {message}")),
            )
        })?;
        let library_source = resolver.read(&include).map_err(|message| {
            Diagnostics::single(
                source,
                Diagnostic::error(span, format!("failed to include '{name}': {message}")),
            )
        })?;
        resolver.observe(&name, &library_source);
        // Identity is the normalized relative name, not the file's device and
        // inode: a sandboxed compile cannot stat anything, and the two paths
        // must agree on what "the same library twice" means.
        if !seen.insert(include.relative.clone()) {
            return Err(Diagnostics::single(
                source,
                Diagnostic::error(span, format!("duplicate include '{name}'")).with_help(
                    "include each library once; definitions share one program namespace",
                ),
            ));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(library_source.len())
            .filter(|bytes| *bytes <= MAX_SOURCE_BYTES)
            .ok_or_else(|| {
                Diagnostics::single(
                    source,
                    Diagnostic::error(
                        span,
                        format!(
                            "VCL policy and included libraries exceed the \
                             {MAX_SOURCE_BYTES}-byte aggregate limit"
                        ),
                    ),
                )
            })?;

        text.push('\n');
        let offset = text.len();
        text.push_str(&library_source);
        files.push(DiagnosticFile {
            start: offset,
            end: offset + library_source.len(),
            filename: Some(include.display.display().to_string()),
            include: Some(name.clone()),
            source: library_source.clone(),
        });

        let library_tokens = crate::lexer::lex_at(&library_source, offset)
            .map_err(|diagnostics| diagnostics.with_files(files.clone()))?;
        let library = crate::parser::parse_library(&text, &library_tokens)
            .map_err(|diagnostics| diagnostics.with_files(files.clone()))?;
        for item in &library.items {
            if let ast::Item::Sub(sub) = item {
                if sub.name.starts_with("vcl_") {
                    return Err(Diagnostics::single(
                        &text,
                        Diagnostic::error(
                            sub.name_span,
                            format!("included library may not define hook {}", sub.name),
                        ),
                    )
                    .with_files(files));
                }
            }
        }
        program.items.extend(library.items);
    }

    Ok(SourceUnit {
        program,
        text,
        files,
    })
}

/// One resolved include: the relative name the provider is asked for, and the
/// path a diagnostic names.
pub(crate) struct IncludePath {
    /// Root-prefixed, for a diagnostic the operator has to go and open.
    display: PathBuf,
    /// What the provider is asked for. Normalized and confined: no absolute
    /// path, no `..`, no empty name.
    pub(crate) relative: PathBuf,
}

impl IncludeResolver {
    pub(crate) fn resolve(&self, name: &str) -> Result<IncludePath, String> {
        let relative = relative_include_path(name)?;
        Ok(IncludePath {
            display: self.root().join(&relative),
            relative,
        })
    }

    pub(crate) fn read(&self, include: &IncludePath) -> Result<String, String> {
        (self.read)(&include.relative)
    }
}

fn relative_include_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if path.is_absolute() {
        return Err(format!(
            "absolute include path '{name}' is not allowed; include a path relative to the policy's directory"
        ));
    }

    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => relative.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(
                    "include resolves outside the policy directory; included libraries must stay under the policy's directory"
                        .to_string(),
                )
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("absolute include path '{name}' is not allowed"))
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err("include path is empty".to_string());
    }
    Ok(relative)
}
