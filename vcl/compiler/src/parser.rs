use crate::ast::{
    AclEntry, BinaryOp, CallArgument, Expr, ExprKind, Item, Literal, Program, ReturnAction, SetOp,
    StatAnnotation, Statement, Sub, TypeName,
};
use crate::lexer::{Kind, Token};
use crate::types::StatKind;
use crate::{Diagnostic, Diagnostics, Span};

/// How deeply expressions and statement blocks may nest.
///
/// Every later stage — the type checker, the IR builder, the interpreter, the
/// code generator, and `Box<Expr>`'s own drop glue — walks the tree the same
/// recursive way this parser builds it, so one bound here bounds all of them.
/// Configuration loading hands the compiler a `.vcl` file of unbounded size,
/// and a reload has to *reject* a bad candidate without disturbing the running
/// one; overflowing the process stack is not a rejection. Deep enough that no
/// policy a person writes reaches it.
const MAX_NESTING: usize = 64;

/// How many values one flat `+` run may join.
///
/// A run costs one nesting level however long it is (see
/// [`Parser::parse_additive_chain`]), so this is the only thing bounding it.
/// String building is the shape that gets long in a policy a person wrote — a
/// log line assembled from twenty headers — and the ceiling is set well above
/// that so the bound is only ever reached by machine-generated source.
const MAX_CHAIN_OPERANDS: usize = 1024;

/// The longest `synth`/`error` reason the host keeps: `MAX_VALUE` in
/// src/vcl/abi.hpp.
const SYNTH_REASON_LIMIT: usize = 64 * 1024;

pub(crate) fn parse(source: &str, tokens: &[Token]) -> Result<Program, Diagnostics> {
    let mut parser = Parser {
        source,
        tokens,
        at: 0,
        depth: 0,
        errors: Vec::new(),
    };
    parser.parse_program()
}

pub(crate) fn parse_library(source: &str, tokens: &[Token]) -> Result<Program, Diagnostics> {
    let mut parser = Parser {
        source,
        tokens,
        at: 0,
        depth: 0,
        errors: Vec::new(),
    };
    parser.parse_library_program()
}

struct Parser<'a> {
    source: &'a str,
    tokens: &'a [Token],
    at: usize,
    /// Current expression/block nesting, bounded by [`MAX_NESTING`].
    depth: usize,
    errors: Vec<Diagnostic>,
}

impl Parser<'_> {
    fn parse_program(&mut self) -> Result<Program, Diagnostics> {
        // A file that does not open with the version marker is most often a
        // fragment meant to be `include`d. One diagnostic says that; letting
        // the version and semicolon checks run as well would bury it under
        // three more about the `sub` that follows.
        if self.peek_word().is_none_or(|(word, _)| word != "vcl") {
            let span = self
                .tokens
                .first()
                .map_or_else(Span::default, |token| token.span);
            self.errors.push(
                Diagnostic::error(span, "a VCL policy must begin with a version marker")
                    .with_help("write 'vcl 4.1;' as the first statement"),
            );
            return Err(Diagnostics::new(
                self.source,
                std::mem::take(&mut self.errors),
            ));
        }
        self.expect_word("vcl");
        let syntax = match self.take_word() {
            Some((version, _span)) if version == "4.0" => 40,
            Some((version, _span)) if version == "4.1" => 41,
            Some((version, span)) => {
                self.errors.push(Diagnostic::error(
                    span,
                    format!("unsupported VCL version '{version}'; expected 4.0 or 4.1"),
                ));
                41
            }
            None => {
                self.expected("VCL version");
                41
            }
        };
        self.expect(Kind::Semicolon, "';' after VCL version");

        while self.peek_word().is_some_and(|(word, _)| word == "import") {
            self.parse_import();
        }

        let mut items = Vec::new();
        while self.at < self.tokens.len() {
            let before = self.at;
            if let Some((name, span)) = self
                .peek_word()
                .filter(|(name, _)| matches!(*name, "backend" | "director" | "probe"))
            {
                // Named rather than left to `parse_sub`, which would report
                // "expected 'sub'" and leave a migrating author guessing what
                // a tenant policy does with a probe.
                let help = if name == "probe" {
                    "health checks belong to the Varnish VCL that forks this tenant"
                } else {
                    "backends and directors belong to the Varnish VCL that forks this tenant"
                };
                self.errors.push(
                    Diagnostic::error(span, format!("{name} declarations are not supported"))
                        .with_help(help),
                );
                self.recover_top_level();
                continue;
            }
            if self.peek_word().is_some_and(|(word, _)| word == "include") {
                if let Some(item) = self.parse_include() {
                    items.push(item);
                }
            } else if self.peek_word().is_some_and(|(word, _)| word == "static") {
                if let Some(item) = self.parse_static() {
                    items.push(item);
                }
            } else if self.peek_word().is_some_and(|(word, _)| word == "var") {
                if let Some(item) = self.parse_global() {
                    items.push(item);
                }
            } else if self.peek_word().is_some_and(|(word, _)| word == "acl") {
                if let Some(item) = self.parse_acl() {
                    items.push(item);
                }
            } else if let Some(sub) = self.parse_sub() {
                items.push(Item::Sub(sub));
            }
            if self.at == before {
                self.at += 1;
            }
        }
        if !items.iter().any(|item| matches!(item, Item::Sub(_))) {
            self.errors.push(Diagnostic::error(
                self.current_span(),
                "a VCL file must define at least one subroutine",
            ));
        }
        if self.errors.is_empty() {
            Ok(Program { items, syntax })
        } else {
            Err(Diagnostics::new(
                self.source,
                std::mem::take(&mut self.errors),
            ))
        }
    }

    fn parse_library_program(&mut self) -> Result<Program, Diagnostics> {
        if self.peek_word().is_some_and(|(word, _)| word == "vcl") {
            let span = self.take_word().expect("peeked vcl").1;
            self.errors.push(Diagnostic::error(
                span,
                "an included VCL library must not contain a vcl version marker",
            ));
            self.recover_statement();
        }
        while self.peek_word().is_some_and(|(word, _)| word == "import") {
            self.parse_import();
        }
        let mut items = Vec::new();
        while self.at < self.tokens.len() {
            let before = self.at;
            if self.peek_word().is_some_and(|(word, _)| word == "include") {
                let span = self.take_word().expect("peeked include").1;
                self.errors.push(
                    Diagnostic::error(span, "nested include is not supported")
                        .with_help("include every library directly from the tenant's main VCL file"),
                );
                self.recover_statement();
            } else if self.peek_word().is_some_and(|(word, _)| word == "static") {
                if let Some(item) = self.parse_static() {
                    items.push(item);
                }
            } else if self.peek_word().is_some_and(|(word, _)| word == "var") {
                if let Some(item) = self.parse_global() {
                    items.push(item);
                }
            } else if self.peek_word().is_some_and(|(word, _)| word == "acl") {
                if let Some(item) = self.parse_acl() {
                    items.push(item);
                }
            } else if let Some(mut sub) = self.parse_sub() {
                sub.included = true;
                items.push(Item::Sub(sub));
            }
            if self.at == before {
                self.at += 1;
            }
        }
        if self.errors.is_empty() {
            // A library declares no version; the including file's level wins.
            Ok(Program { items, syntax: 0 })
        } else {
            Err(Diagnostics::new(
                self.source,
                std::mem::take(&mut self.errors),
            ))
        }
    }

    fn parse_include(&mut self) -> Option<Item> {
        let start = self.take_word().expect("peeked include").1;
        let (path, path_span) = match self.take_string() {
            Some(value) => value,
            None => {
                self.expected("literal path after include");
                self.recover_statement();
                return None;
            }
        };
        let end = self
            .expect(Kind::Semicolon, "';' after include")
            .unwrap_or(path_span.end);
        Some(Item::Include {
            path,
            span: Span::new(start.start, end),
        })
    }

    fn parse_static(&mut self) -> Option<Item> {
        let (_, start) = self.take_word().expect("peeked static");
        if !self.expect_word("var") {
            self.recover_top_level();
            return None;
        }
        let (name, name_span) = self.parse_declaration_name()?;
        self.expect(Kind::Colon, "':' after static variable name");
        let value_type = self.parse_type_name()?;
        let init = if self.check(&Kind::Equal) {
            self.at += 1;
            Some(self.parse_expr()?)
        } else {
            None
        };
        // Only `;` or `stat` can appear here, and an expression parse stops
        // at a bare word that is not an infix operator — so `= 1 stat min;`
        // needs no lookahead trickery. Checked explicitly all the same:
        // relying on where the expression grammar happens to stop would make
        // this a property of another function.
        let stat = self.parse_stat_annotation();
        let end = self.expect(Kind::Semicolon, "';' after static declaration");
        let fallback = stat
            .as_ref()
            .map(|annotation| annotation.help_span.end)
            .or_else(|| init.as_ref().map(|expr| expr.span.end))
            .unwrap_or(name_span.end);
        Some(Item::Static {
            name,
            name_span,
            value_type,
            init,
            stat,
            span: Span::new(start.start, end.unwrap_or(fallback)),
        })
    }

    /// A top-level `var NAME: TYPE [= LITERAL];` — a request global.
    ///
    /// The same spelling as a local; the position is the storage class. The
    /// initialiser is parsed as an expression so the type checker can say
    /// why anything but a literal is refused, rather than the parser saying
    /// only that it expected `;`.
    fn parse_global(&mut self) -> Option<Item> {
        let (_, start) = self.take_word().expect("peeked var");
        let (name, name_span) = self.parse_declaration_name()?;
        self.expect(Kind::Colon, "':' after request global name");
        let value_type = self.parse_type_name()?;
        let init = if self.check(&Kind::Equal) {
            self.at += 1;
            Some(self.parse_expr()?)
        } else {
            None
        };
        let end = self.expect(Kind::Semicolon, "';' after request global declaration");
        let fallback = init
            .as_ref()
            .map(|expr| expr.span.end)
            .unwrap_or(name_span.end);
        Some(Item::Global {
            name,
            name_span,
            value_type,
            init,
            span: Span::new(start.start, end.unwrap_or(fallback)),
        })
    }

    /// `stat [counter|gauge|max|min] [STRING]`, or nothing.
    ///
    /// `stat` and the kind words are contextual keywords: they are ordinary
    /// `Word` tokens everywhere else, so a policy that already has a static
    /// or a sub called `stat` keeps compiling.
    fn parse_stat_annotation(&mut self) -> Option<StatAnnotation> {
        let (word, stat_span) = self.peek_word()?;
        if word != "stat" {
            return None;
        }
        self.at += 1;
        let (kind, kind_span) = match self.peek_word() {
            Some((word, span)) => match StatKind::from_word(word) {
                Some(kind) => {
                    self.at += 1;
                    (kind, span)
                }
                None => {
                    self.errors.push(
                        Diagnostic::error(span, format!("'{word}' is not a statistic kind"))
                            .with_help("the kinds are 'counter', 'gauge', 'max' and 'min'"),
                    );
                    self.at += 1;
                    (StatKind::Counter, span)
                }
            },
            // No kind word: `stat` alone is the short spelling of a counter.
            None => (StatKind::Counter, stat_span),
        };
        let (help, help_span) = match self.tokens.get(self.at) {
            Some(Token {
                kind: Kind::String(value),
                span,
            }) => {
                let value = value.clone();
                let span = *span;
                self.at += 1;
                (Some(value), span)
            }
            _ => (None, kind_span),
        };
        Some(StatAnnotation {
            kind,
            help,
            help_span,
        })
    }

    fn parse_acl(&mut self) -> Option<Item> {
        let (_, start) = self.take_word().expect("peeked acl");
        let (name, name_span) = match self.take_word() {
            Some(value) => value,
            None => {
                self.expected("ACL name after 'acl'");
                self.recover_top_level();
                return None;
            }
        };
        if self.expect(Kind::LBrace, "'{' after ACL name").is_none() {
            self.recover_top_level();
            return None;
        }
        let mut entries = Vec::new();
        loop {
            if self.at >= self.tokens.len() {
                self.expected("'}' closing the ACL body");
                return None;
            }
            if self.check(&Kind::RBrace) {
                break;
            }
            let Some(entry) = self.parse_acl_entry() else {
                self.recover_statement();
                if self.check(&Kind::RBrace) {
                    break;
                }
                continue;
            };
            entries.push(entry);
        }
        let end = self
            .expect(Kind::RBrace, "'}' closing the ACL body")
            .unwrap_or(name_span.end);
        Some(Item::Acl {
            name,
            name_span,
            entries,
            span: Span::new(start.start, end),
        })
    }

    fn parse_acl_entry(&mut self) -> Option<AclEntry> {
        let start = self.current_span().start;
        let negate = self.check(&Kind::Bang);
        if negate {
            self.at += 1;
        }
        let (address, address_span) = match self.take_string() {
            Some(value) => value,
            None => {
                self.expected("a quoted IP address in the ACL body");
                return None;
            }
        };
        let mut prefix = None;
        let mut prefix_span = address_span;
        if self.check(&Kind::Slash) {
            self.at += 1;
            let (digits, span) = match self.take_word() {
                Some(value) => value,
                None => {
                    self.expected("a prefix length after '/'");
                    return None;
                }
            };
            prefix_span = span;
            match digits.parse::<u32>() {
                Ok(bits) => prefix = Some(bits),
                Err(_) => {
                    self.errors.push(Diagnostic::error(
                        span,
                        format!("'{digits}' is not a prefix length"),
                    ));
                    return None;
                }
            }
        }
        let end = self
            .expect(Kind::Semicolon, "';' after an ACL entry")
            .unwrap_or(prefix_span.end);
        Some(AclEntry {
            negate,
            address,
            address_span,
            prefix,
            prefix_span,
            span: Span::new(start, end),
        })
    }

    fn parse_import(&mut self) {
        let _ = self.take_word().expect("peeked import");
        let Some((module, span)) = self.take_word() else {
            self.expected("module name after 'import'");
            self.recover_statement();
            return;
        };
        if !matches!(
            module.as_str(),
            "std" | "digest" | "str" | "urlplus" | "headerplus" | "cookieplus" | "uri"
        ) {
            let help = match module.as_str() {
                "file" => "certificate management owns ACME challenge answering; guest policy has no filesystem access",
                "accounting" => "accounting and metrics belong to the Varnish VCL that forks this tenant",
                "directors" => "backends and directors belong to the Varnish VCL that forks this tenant",
                _ => "use the always-available std/digest APIs, or a Rust guest for another module",
            };
            self.errors.push(
                Diagnostic::error(span, format!("unsupported VCL module '{module}'"))
                    .with_help(help),
            );
        }
        self.expect(Kind::Semicolon, "';' after import");
    }

    fn parse_sub(&mut self) -> Option<Sub> {
        if !self.expect_word("sub") {
            self.recover_top_level();
            return None;
        }
        let (name, name_span) = match self.take_word() {
            Some(value) => value,
            None => {
                self.expected("subroutine name");
                self.recover_top_level();
                return None;
            }
        };
        if self
            .expect(Kind::LBrace, "'{' after subroutine name")
            .is_none()
        {
            self.recover_top_level();
            return None;
        }
        let mut statements = Vec::new();
        while self.at < self.tokens.len() && !self.check(&Kind::RBrace) {
            let before = self.at;
            if let Some(statement) = self.parse_statement() {
                statements.push(statement);
            } else {
                self.recover_statement();
            }
            if self.at == before {
                self.at += 1;
            }
        }
        self.expect(Kind::RBrace, "'}' after subroutine body");
        Some(Sub {
            name,
            name_span,
            statements,
            included: false,
        })
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        let (keyword, start) = self.take_word()?;
        match keyword.as_str() {
            "var" => self.parse_declare(start),
            "static" => {
                self.errors.push(
                    Diagnostic::error(start, "statics are declared at the top level")
                        .with_help("use 'static var NAME: TYPE;' outside every subroutine"),
                );
                None
            }
            "set" => self.parse_set(start),
            "unset" => self.parse_unset(start),
            "if" => self.parse_if(start),
            "return" => self.parse_return(start),
            "std.log" => self.parse_log(start),
            // The one `std` function that is a statement rather than a value.
            // It takes a HEADER, so the type checker reads its first argument
            // as a variable name rather than as a string.
            "std.collect" => self.parse_builtin_call("std.collect".to_string(), start),
            "synthetic" => self.parse_synthetic(start),
            "hash_data" => self.parse_hash_data(start),
            "elsif" | "elseif" | "elif" | "else" => {
                self.errors.push(Diagnostic::error(
                    start,
                    format!("'{keyword}' has no preceding if statement"),
                ));
                None
            }
            "call" => self.parse_call(start),
            keyword if crate::typecheck::is_builtin_module_call(keyword) => {
                self.parse_builtin_call(keyword.to_string(), start)
            }
            "new" => {
                self.errors.push(
                    Diagnostic::error(start, "VCL objects are not supported")
                        .with_help("certificate management owns ACME challenge answering; guest policy has no filesystem access"),
                );
                None
            }
            _ => {
                let help = unsupported_module_call_help(&keyword);
                let mut diagnostic =
                    Diagnostic::error(start, format!("unsupported statement '{keyword}'"));
                if let Some(help) = help {
                    diagnostic = diagnostic.with_help(help);
                }
                self.errors
                    .push(Diagnostic::error(diagnostic.span, diagnostic.message));
                if let (Some(last), Some(help)) = (self.errors.last_mut(), diagnostic.help) {
                    last.help = Some(help);
                }
                None
            }
        }
    }

    fn parse_declaration_name(&mut self) -> Option<(String, Span)> {
        let (name, span) = match self.take_word() {
            Some(value) => value,
            None => {
                self.expected("variable name");
                return None;
            }
        };
        if name.contains('.') {
            self.errors.push(Diagnostic::error(
                span,
                "a declared variable name cannot contain '.'",
            ));
            return None;
        }
        Some((name, span))
    }

    fn parse_type_name(&mut self) -> Option<TypeName> {
        let (name, span) = match self.take_word() {
            Some(value) => value,
            None => {
                self.expected("variable type INT, BOOL, DURATION, TIME, or STRING");
                return None;
            }
        };
        match name.to_ascii_uppercase().as_str() {
            "INT" => Some(TypeName::Integer),
            "BOOL" => Some(TypeName::Boolean),
            "DURATION" => Some(TypeName::Duration),
            "TIME" => Some(TypeName::Time),
            "STRING" => Some(TypeName::String),
            _ => {
                self.errors.push(Diagnostic::error(
                    span,
                    format!(
                        "unknown variable type '{name}'; expected INT, BOOL, DURATION, TIME, or STRING"
                    ),
                ));
                None
            }
        }
    }

    fn parse_declare(&mut self, start: Span) -> Option<Statement> {
        let (name, name_span) = self.parse_declaration_name()?;
        self.expect(Kind::Colon, "':' after variable name")?;
        let value_type = self.parse_type_name()?;
        let init = if self.check(&Kind::Equal) {
            self.at += 1;
            Some(self.parse_expr()?)
        } else {
            None
        };
        let end = self.expect(Kind::Semicolon, "';' after variable declaration");
        let fallback = init.as_ref().map_or(name_span.end, |expr| expr.span.end);
        Some(Statement::Declare {
            name,
            name_span,
            value_type,
            init,
            span: Span::new(start.start, end.unwrap_or(fallback)),
        })
    }

    fn parse_call(&mut self, start: Span) -> Option<Statement> {
        let (sub, sub_span) = match self.take_word() {
            Some(value) => value,
            None => {
                self.expected("subroutine name after 'call'");
                return None;
            }
        };
        let end = self.expect(Kind::Semicolon, "';' after call statement");
        Some(Statement::Call {
            sub,
            sub_span,
            span: Span::new(start.start, end.unwrap_or(sub_span.end)),
        })
    }

    fn parse_builtin_call(&mut self, function: String, start: Span) -> Option<Statement> {
        // `parse_primary` already owns VCL's positional-then-named call
        // grammar. Reuse it after putting back the function token would be
        // awkward, so this is the same small argument loop with statement
        // punctuation instead of an expression result.
        self.expect(Kind::LParen, "'(' after builtin function")?;
        let mut arguments = Vec::new();
        if !self.check(&Kind::RParen) {
            loop {
                let named = self
                    .peek_word()
                    .map(|(name, span)| (name.to_string(), span));
                let (name, name_span) = if let Some((name, name_span)) = named {
                    if self
                        .tokens
                        .get(self.at + 1)
                        .is_some_and(|token| matches!(token.kind, Kind::Equal))
                    {
                        self.at += 2;
                        (Some(name), Some(name_span))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };
                arguments.push(CallArgument {
                    name,
                    name_span,
                    value: self.parse_expr()?,
                });
                if !self.check(&Kind::Comma) {
                    break;
                }
                self.at += 1;
            }
        }
        let end = self.expect(Kind::RParen, "')' after builtin arguments")?;
        let semi = self.expect(Kind::Semicolon, "';' after builtin function");
        Some(Statement::BuiltinCall {
            function,
            arguments,
            span: Span::new(start.start, semi.unwrap_or(end)),
        })
    }

    fn parse_unset(&mut self, start: Span) -> Option<Statement> {
        let (target, target_span) = match self.take_word() {
            Some(value) => value,
            None => {
                self.expected("variable after 'unset'");
                return None;
            }
        };
        let end = self.expect(Kind::Semicolon, "';' after unset statement");
        Some(Statement::Unset {
            target,
            target_span,
            span: Span::new(start.start, end.unwrap_or(target_span.end)),
        })
    }

    fn parse_set(&mut self, start: Span) -> Option<Statement> {
        let (target, target_span) = match self.take_word() {
            Some(value) => value,
            None => {
                self.expected("variable after 'set'");
                return None;
            }
        };
        let op = self.parse_set_op();
        let value = self.parse_expr()?;
        let end = self.expect(Kind::Semicolon, "';' after set statement");
        let value_end = value.span.end;
        Some(Statement::Set {
            target,
            target_span,
            op,
            value,
            span: Span::new(start.start, end.unwrap_or(value_end)),
        })
    }

    /// `=`, or `+=` / `-=` spelled as two adjacent tokens: the lexer has no
    /// compound operators, and `a + =` with a space is not one.
    fn parse_set_op(&mut self) -> SetOp {
        let compound = match (self.tokens.get(self.at), self.tokens.get(self.at + 1)) {
            (Some(first), Some(second))
                if matches!(second.kind, Kind::Equal) && first.span.end == second.span.start =>
            {
                if matches!(first.kind, Kind::Plus) {
                    Some(SetOp::Add)
                } else if matches!(first.kind, Kind::Minus) {
                    Some(SetOp::Subtract)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(op) = compound {
            self.at += 2;
            return op;
        }
        self.expect(Kind::Equal, "'=' in set statement");
        SetOp::Assign
    }

    fn parse_if(&mut self, start: Span) -> Option<Statement> {
        let condition = self.parse_parenthesized_condition("if")?;
        let (body, mut end) = self.parse_statement_block("if condition")?;
        let mut branches = vec![(condition, body)];
        let mut otherwise = Vec::new();

        loop {
            let Some((keyword, _keyword_span)) = self.peek_word() else {
                break;
            };
            let keyword = keyword.to_string();
            if matches!(keyword.as_str(), "elsif" | "elseif" | "elif") {
                self.at += 1;
                let condition = self.parse_parenthesized_condition(&keyword)?;
                let (body, body_end) = self.parse_statement_block("conditional")?;
                branches.push((condition, body));
                end = body_end;
                continue;
            }
            if keyword == "else" {
                self.at += 1;
                // `else if` is the spelling most VCL in the wild uses; the
                // three contracted keywords above are the same statement.
                if self.peek_word().is_some_and(|(word, _)| word == "if") {
                    self.at += 1;
                    let condition = self.parse_parenthesized_condition("if")?;
                    let (body, body_end) = self.parse_statement_block("if condition")?;
                    branches.push((condition, body));
                    end = body_end;
                    continue;
                }
                let (body, body_end) = self.parse_statement_block("else")?;
                otherwise = body;
                end = body_end;
            }
            break;
        }

        Some(Statement::If {
            branches,
            otherwise,
            span: Span::new(start.start, end),
        })
    }

    fn parse_parenthesized_condition(&mut self, keyword: &str) -> Option<Expr> {
        self.expect(Kind::LParen, &format!("'(' after {keyword}"));
        let condition = self.parse_expr()?;
        self.expect(Kind::RParen, "')' after condition");
        Some(condition)
    }

    fn parse_statement_block(&mut self, description: &str) -> Option<(Vec<Statement>, usize)> {
        self.expect(Kind::LBrace, &format!("'{{' after {description}"))?;
        self.nested(Self::parse_block_body)
    }

    fn parse_block_body(&mut self) -> Option<(Vec<Statement>, usize)> {
        let mut statements = Vec::new();
        while self.at < self.tokens.len() && !self.check(&Kind::RBrace) {
            let before = self.at;
            if let Some(statement) = self.parse_statement() {
                statements.push(statement);
            } else {
                self.recover_statement();
            }
            if self.at == before {
                self.at += 1;
            }
        }
        let end = self.expect(Kind::RBrace, "'}' after conditional body")?;
        Some((statements, end))
    }

    fn parse_log(&mut self, start: Span) -> Option<Statement> {
        self.expect(Kind::LParen, "'(' after std.log");
        let value = self.parse_expr()?;
        self.expect(Kind::RParen, "')' after std.log argument");
        let end = self.expect(Kind::Semicolon, "';' after std.log");
        let value_end = value.span.end;
        Some(Statement::Log {
            value,
            span: Span::new(start.start, end.unwrap_or(value_end)),
        })
    }

    fn parse_synthetic(&mut self, start: Span) -> Option<Statement> {
        self.expect(Kind::LParen, "'(' after synthetic");
        let value = self.parse_expr()?;
        self.expect(Kind::RParen, "')' after synthetic argument");
        let end = self.expect(Kind::Semicolon, "';' after synthetic");
        let value_end = value.span.end;
        Some(Statement::Synthetic {
            value,
            span: Span::new(start.start, end.unwrap_or(value_end)),
        })
    }

    fn parse_hash_data(&mut self, start: Span) -> Option<Statement> {
        self.expect(Kind::LParen, "'(' after hash_data");
        let value = self.parse_expr()?;
        self.expect(Kind::RParen, "')' after hash_data argument");
        let end = self.expect(Kind::Semicolon, "';' after hash_data");
        let value_end = value.span.end;
        Some(Statement::HashData {
            value,
            span: Span::new(start.start, end.unwrap_or(value_end)),
        })
    }

    /// `(status [, "reason"])` after `synth` or `error`.
    fn parse_status_reason(&mut self, action: &str) -> Option<(u16, String)> {
        self.expect(Kind::LParen, &format!("'(' after {action}"));
        let (raw_status, status_span) = self.take_word()?;
        let status = raw_status
            .parse::<u16>()
            .ok()
            .filter(|n| (100..=999).contains(n));
        let Some(status) = status else {
            self.errors.push(Diagnostic::error(
                status_span,
                format!("{action} status must be an integer from 100 through 999"),
            ));
            return None;
        };
        let reason = if self.check(&Kind::Comma) {
            self.at += 1;
            let (text, span) = self.take_string()?;
            // The host drops a reason it would refuse (src/vcl/abi.hpp's
            // MAX_VALUE, or a byte that ends the status line), so refuse it
            // here rather than send Varnish's default reason instead.
            if text.len() > SYNTH_REASON_LIMIT {
                self.errors.push(Diagnostic::error(
                    span,
                    format!("{action} reason is longer than {SYNTH_REASON_LIMIT} bytes"),
                ));
                return None;
            }
            if let Some(byte) = text.bytes().find(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
                self.errors.push(Diagnostic::error(
                    span,
                    format!("{action} reason cannot contain the byte 0x{byte:02x}"),
                ));
                return None;
            }
            text
        } else {
            String::new()
        };
        self.expect(Kind::RParen, &format!("')' after {action} arguments"));
        Some((status, reason))
    }

    fn parse_return(&mut self, start: Span) -> Option<Statement> {
        let action = if self.check(&Kind::Semicolon) {
            ReturnAction::Bare
        } else {
            self.expect(Kind::LParen, "'(' after return");
            let (name, span) = self.take_word()?;
            let action = match name.as_str() {
                "hash" => ReturnAction::Hash,
                "lookup" => ReturnAction::Lookup,
                "fetch" => ReturnAction::Fetch,
                "miss" => ReturnAction::Miss,
                "pass" => ReturnAction::Pass,
                "abandon" => ReturnAction::Abandon,
                "deliver" => ReturnAction::Deliver,
                "fail" => ReturnAction::Fail,
                "synth" => {
                    let (status, reason) = self.parse_status_reason("synth")?;
                    ReturnAction::Synth { status, reason }
                }
                "error" => {
                    let (status, reason) = self.parse_status_reason("error")?;
                    ReturnAction::Error { status, reason }
                }
                // Varnish's remaining return actions. Naming them here keeps
                // the diagnostic about the action the user wrote; the fallback
                // below would report an unknown *subroutine* instead.
                "vcl" => {
                    // Consume the label syntax so the following tokens do not
                    // cascade into unrelated parse errors.
                    if self.check(&Kind::LParen) {
                        self.at += 1;
                        while self.at < self.tokens.len() && !self.check(&Kind::RParen) {
                            self.at += 1;
                        }
                        self.expect(Kind::RParen, "')' after VCL label");
                    }
                    self.errors.push(
                        Diagnostic::error(span, "return (vcl(...)) is not supported")
                            .with_help("VCL labels are routing, and routing belongs to the Varnish VCL that forks this tenant"),
                    );
                    return None;
                }
                "restart" | "retry" | "pipe" | "purge" | "connect" | "hit" | "upgrade"
                | "none" | "ok" => {
                    let help = match name.as_str() {
                        "purge" => "purging belongs to the Varnish VCL that forks this tenant",
                        "restart" | "retry" | "pipe" | "connect" => {
                            "restarts, retries and piping are host-controlled"
                        }
                        _ => "the actions are hash, lookup, miss, fetch, pass, deliver, \
                              abandon, synth, error and fail, each in the subroutines \
                              Varnish allows it",
                    };
                    self.errors.push(
                        Diagnostic::error(span, format!("return ({name}) is not supported"))
                            .with_help(help),
                    );
                    return None;
                }
                _ => ReturnAction::Sub(name, span),
            };
            self.expect(Kind::RParen, "')' after return action");
            action
        };
        let end = self.expect(Kind::Semicolon, "';' after return");
        Some(Statement::Return {
            action,
            span: Span::new(start.start, end.unwrap_or(start.end)),
        })
    }

    fn parse_expr(&mut self) -> Option<Expr> {
        self.nested(Self::parse_or)
    }

    fn parse_or(&mut self) -> Option<Expr> {
        self.chain(Self::parse_or_chain)
    }

    fn parse_or_chain(&mut self) -> Option<Expr> {
        let mut expr = self.parse_and()?;
        while self.check(&Kind::OrOr) {
            self.at += 1;
            self.charge_level()?;
            let right = self.parse_and()?;
            let span = Span::new(expr.span.start, right.span.end);
            expr = Expr {
                kind: ExprKind::Binary {
                    op: BinaryOp::Or,
                    left: Box::new(expr),
                    right: Box::new(right),
                },
                span,
            };
        }
        Some(expr)
    }

    fn parse_and(&mut self) -> Option<Expr> {
        self.chain(Self::parse_and_chain)
    }

    fn parse_and_chain(&mut self) -> Option<Expr> {
        let mut expr = self.parse_equality()?;
        while self.check(&Kind::AndAnd) {
            self.at += 1;
            self.charge_level()?;
            let right = self.parse_equality()?;
            let span = Span::new(expr.span.start, right.span.end);
            expr = Expr {
                kind: ExprKind::Binary {
                    op: BinaryOp::And,
                    left: Box::new(expr),
                    right: Box::new(right),
                },
                span,
            };
        }
        Some(expr)
    }

    fn parse_equality(&mut self) -> Option<Expr> {
        self.chain(Self::parse_equality_chain)
    }

    fn parse_equality_chain(&mut self) -> Option<Expr> {
        let mut expr = self.parse_ordering()?;
        while self.check(&Kind::EqualEqual)
            || self.check(&Kind::BangEqual)
            || self.check(&Kind::Tilde)
            || self.check(&Kind::BangTilde)
        {
            let op = if self.check(&Kind::EqualEqual) {
                BinaryOp::Equal
            } else if self.check(&Kind::BangEqual) {
                BinaryOp::NotEqual
            } else if self.check(&Kind::Tilde) {
                BinaryOp::Match
            } else {
                BinaryOp::NotMatch
            };
            self.at += 1;
            self.charge_level()?;
            let right = self.parse_ordering()?;
            let span = Span::new(expr.span.start, right.span.end);
            expr = Expr {
                kind: ExprKind::Binary {
                    op,
                    left: Box::new(expr),
                    right: Box::new(right),
                },
                span,
            };
        }
        Some(expr)
    }

    fn parse_ordering(&mut self) -> Option<Expr> {
        self.chain(Self::parse_ordering_chain)
    }

    fn parse_ordering_chain(&mut self) -> Option<Expr> {
        let mut expr = self.parse_additive()?;
        while self.check(&Kind::Less)
            || self.check(&Kind::LessEqual)
            || self.check(&Kind::Greater)
            || self.check(&Kind::GreaterEqual)
        {
            let op = if self.check(&Kind::Less) {
                BinaryOp::Less
            } else if self.check(&Kind::LessEqual) {
                BinaryOp::LessEqual
            } else if self.check(&Kind::Greater) {
                BinaryOp::Greater
            } else {
                BinaryOp::GreaterEqual
            };
            self.at += 1;
            self.charge_level()?;
            let right = self.parse_additive()?;
            let span = Span::new(expr.span.start, right.span.end);
            expr = Expr {
                kind: ExprKind::Binary {
                    op,
                    left: Box::new(expr),
                    right: Box::new(right),
                },
                span,
            };
        }
        Some(expr)
    }

    fn parse_additive(&mut self) -> Option<Expr> {
        self.chain(Self::parse_additive_chain)
    }

    /// `+` and `-`, left-associative.
    ///
    /// A run of `+` becomes one [`ExprKind::AddChain`]: string building is
    /// the shape that gets long in a real policy, and folding the run flat is
    /// what lets it stay legal while every other flat chain is charged a
    /// nesting level per operator. `-` keeps the left-deep `Binary` shape and
    /// pays per operator.
    fn parse_additive_chain(&mut self) -> Option<Expr> {
        let mut expr = self.parse_multiplicative()?;
        loop {
            if self.check(&Kind::Plus) {
                self.charge_level()?;
                let mut operands = vec![expr];
                while self.check(&Kind::Plus) {
                    self.at += 1;
                    if operands.len() >= MAX_CHAIN_OPERANDS {
                        self.errors.push(
                            Diagnostic::error(
                                self.current_span(),
                                format!(
                                    "a '+' chain may not join more than {MAX_CHAIN_OPERANDS} values"
                                ),
                            )
                            .with_help("split the policy into smaller statements"),
                        );
                        return None;
                    }
                    operands.push(self.parse_multiplicative()?);
                }
                let span = Span::new(
                    operands.first().map_or(0, |first| first.span.start),
                    operands.last().map_or(0, |last| last.span.end),
                );
                expr = Expr {
                    kind: ExprKind::AddChain(operands),
                    span,
                };
            } else if self.check(&Kind::Minus) {
                self.at += 1;
                self.charge_level()?;
                let right = self.parse_multiplicative()?;
                let span = Span::new(expr.span.start, right.span.end);
                expr = Expr {
                    kind: ExprKind::Binary {
                        op: BinaryOp::Subtract,
                        left: Box::new(expr),
                        right: Box::new(right),
                    },
                    span,
                };
            } else {
                break;
            }
        }
        Some(expr)
    }

    fn parse_multiplicative(&mut self) -> Option<Expr> {
        self.chain(Self::parse_multiplicative_chain)
    }

    fn parse_multiplicative_chain(&mut self) -> Option<Expr> {
        let mut expr = self.parse_unary()?;
        while self.check(&Kind::Star) || self.check(&Kind::Slash) || self.check(&Kind::Percent) {
            let op = if self.check(&Kind::Star) {
                BinaryOp::Multiply
            } else if self.check(&Kind::Slash) {
                BinaryOp::Divide
            } else {
                BinaryOp::Modulo
            };
            self.at += 1;
            self.charge_level()?;
            let right = self.parse_unary()?;
            let span = Span::new(expr.span.start, right.span.end);
            expr = Expr {
                kind: ExprKind::Binary {
                    op,
                    left: Box::new(expr),
                    right: Box::new(right),
                },
                span,
            };
        }
        Some(expr)
    }

    fn parse_unary(&mut self) -> Option<Expr> {
        if self.check(&Kind::Bang) {
            let start = self.tokens[self.at].span;
            self.at += 1;
            let operand = self.nested(Self::parse_unary)?;
            return Some(Expr {
                span: Span::new(start.start, operand.span.end),
                kind: ExprKind::Not(Box::new(operand)),
            });
        }
        if self.check(&Kind::Minus) {
            let start = self.tokens[self.at].span;
            self.at += 1;
            if let Some((word, span)) = self.peek_word() {
                if word == "9223372036854775808" {
                    self.at += 1;
                    return Some(Expr {
                        span: Span::new(start.start, span.end),
                        kind: ExprKind::Literal(Literal::Integer(i64::MIN)),
                    });
                }
            }
            let operand = self.nested(Self::parse_unary)?;
            return Some(Expr {
                span: Span::new(start.start, operand.span.end),
                kind: ExprKind::Negate(Box::new(operand)),
            });
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        if self.check(&Kind::LParen) {
            let start = self.tokens[self.at].span;
            self.at += 1;
            let mut expr = self.parse_expr()?;
            if let Some(end) = self.expect(Kind::RParen, "')' after expression") {
                expr.span = Span::new(start.start, end);
            }
            return Some(expr);
        }
        if let Some(Token {
            kind: Kind::String(value),
            span,
        }) = self.tokens.get(self.at)
        {
            self.at += 1;
            return Some(Expr {
                kind: ExprKind::Literal(Literal::String(value.clone())),
                span: *span,
            });
        }
        let Some((word, span)) = self.take_word() else {
            self.expected("an expression");
            return None;
        };
        if self.check(&Kind::LParen) {
            self.at += 1;
            let mut arguments = Vec::new();
            if !self.check(&Kind::RParen) {
                loop {
                    let named = self
                        .peek_word()
                        .map(|(name, span)| (name.to_string(), span));
                    let (name, name_span) = if let Some((name, name_span)) = named {
                        if !self
                            .tokens
                            .get(self.at + 1)
                            .is_some_and(|token| matches!(token.kind, Kind::Equal))
                        {
                            (None, None)
                        } else {
                            self.at += 2;
                            (Some(name), Some(name_span))
                        }
                    } else {
                        (None, None)
                    };
                    let value = self.parse_expr()?;
                    arguments.push(CallArgument {
                        name,
                        name_span,
                        value,
                    });
                    if !self.check(&Kind::Comma) {
                        break;
                    }
                    self.at += 1;
                }
            }
            let end = self.expect(Kind::RParen, "')' after function arguments");
            return Some(Expr {
                kind: ExprKind::Call {
                    function: word,
                    arguments,
                },
                span: Span::new(span.start, end.unwrap_or(span.end)),
            });
        }
        if word == "true" || word == "false" {
            return Some(Expr {
                kind: ExprKind::Bool(word == "true"),
                span,
            });
        }
        if let Ok(value) = word.parse::<i64>() {
            return Some(Expr {
                kind: ExprKind::Literal(Literal::Integer(value)),
                span,
            });
        }
        if let Some(value) = parse_duration(&word) {
            return Some(Expr {
                kind: ExprKind::Literal(Literal::Duration(value)),
                span,
            });
        }
        if word.contains('.') && word.parse::<f64>().is_ok() {
            return Some(Expr {
                kind: ExprKind::Literal(Literal::Real(word)),
                span,
            });
        }
        // Nothing that starts with a digit is a variable name, so a word that
        // reached here is a number the literal forms above could not take —
        // out of range, or a unit that is not one. Say so, rather than let it
        // reach the type checker as an "unknown VCL variable".
        if word.starts_with(|character: char| character.is_ascii_digit()) {
            let units = DURATION_UNITS
                .iter()
                .map(|(suffix, _)| *suffix)
                .collect::<Vec<_>>()
                .join(", ");
            self.errors.push(
                Diagnostic::error(span, format!("'{word}' is not a number that can be spelled here"))
                    .with_help(format!(
                        "an INT fits in 64 bits and a duration is a number and one of {units}"
                    )),
            );
            return None;
        }
        Some(Expr {
            kind: ExprKind::Variable(word),
            span,
        })
    }

    fn take_word(&mut self) -> Option<(String, Span)> {
        match self.tokens.get(self.at) {
            Some(Token {
                kind: Kind::Word(word),
                span,
            }) => {
                self.at += 1;
                Some((word.clone(), *span))
            }
            _ => None,
        }
    }

    fn take_string(&mut self) -> Option<(String, Span)> {
        match self.tokens.get(self.at) {
            Some(Token {
                kind: Kind::String(value),
                span,
            }) => {
                self.at += 1;
                Some((value.clone(), *span))
            }
            _ => {
                self.expected("string literal");
                None
            }
        }
    }

    fn peek_word(&self) -> Option<(&str, Span)> {
        match self.tokens.get(self.at) {
            Some(Token {
                kind: Kind::Word(word),
                span,
            }) => Some((word, *span)),
            _ => None,
        }
    }

    fn expect_word(&mut self, expected: &str) -> bool {
        match self.tokens.get(self.at) {
            Some(Token {
                kind: Kind::Word(word),
                ..
            }) if word == expected => {
                self.at += 1;
                true
            }
            _ => {
                self.expected(&format!("'{expected}'"));
                false
            }
        }
    }

    fn expect(&mut self, expected: Kind, description: &str) -> Option<usize> {
        if self.check(&expected) {
            let end = self.tokens[self.at].span.end;
            self.at += 1;
            Some(end)
        } else {
            self.expected(description);
            None
        }
    }

    fn check(&self, expected: &Kind) -> bool {
        self.tokens.get(self.at).is_some_and(|token| {
            std::mem::discriminant(&token.kind) == std::mem::discriminant(expected)
        })
    }

    fn expected(&mut self, expected: &str) {
        self.errors.push(Diagnostic::error(
            self.current_span(),
            format!("expected {expected}"),
        ));
    }

    fn current_span(&self) -> Span {
        self.tokens.get(self.at).map_or_else(
            || Span::new(self.source.len(), self.source.len()),
            |token| token.span,
        )
    }

    /// Run `parse` one nesting level deeper, or diagnose and give up.
    ///
    /// The bound is a compiler limit, so exceeding it is a normal diagnostic
    /// with a span — never a stack overflow. See [`MAX_NESTING`].
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Option<T>) -> Option<T> {
        if self.depth >= MAX_NESTING {
            self.too_deep();
            return None;
        }
        self.depth += 1;
        let parsed = f(self);
        self.depth -= 1;
        parsed
    }

    /// Run one precedence level's loop and restore the nesting counter after
    /// it, whatever the loop charged.
    fn chain(&mut self, f: impl FnOnce(&mut Self) -> Option<Expr>) -> Option<Expr> {
        let entry = self.depth;
        let parsed = f(self);
        self.depth = entry;
        parsed
    }

    /// Charge one nesting level for a left-deep node a precedence loop is
    /// about to build, and leave it charged for the rest of that loop.
    ///
    /// [`Self::nested`] unwinds as soon as its callee returns, which bounds
    /// `((((x))))` but not `a - b - c - …`: the second shape is built by a
    /// loop that returns the counter to its entry value each time round while
    /// the tree it is building grows one level deeper per iteration, and every
    /// later stage recurses over that tree. Raising the counter inside the
    /// loop makes the flat shape cost what the nested one does;
    /// [`Self::chain`] restores it.
    fn charge_level(&mut self) -> Option<()> {
        if self.depth >= MAX_NESTING {
            self.too_deep();
            return None;
        }
        self.depth += 1;
        Some(())
    }

    fn too_deep(&mut self) {
        self.errors.push(
            Diagnostic::error(
                self.current_span(),
                format!("expressions and blocks may not nest more than {MAX_NESTING} deep"),
            )
            .with_help("split the policy into smaller statements"),
        );
    }

    fn recover_statement(&mut self) {
        while self.at < self.tokens.len() {
            if self.check(&Kind::Semicolon) {
                self.at += 1;
                break;
            }
            if self.check(&Kind::RBrace) {
                break;
            }
            self.at += 1;
        }
    }

    fn recover_top_level(&mut self) {
        while self.at < self.tokens.len() {
            if matches!(&self.tokens[self.at].kind, Kind::Word(word) if word == "sub" || word == "static" || word == "var")
            {
                break;
            }
            self.at += 1;
        }
    }
}

fn unsupported_module_call_help(function: &str) -> Option<&'static str> {
    // Varnish's bare action statements. A `ban(...)`, `error 503;` or
    // `restart;` is the same decision as the matching `return (...)` form, so
    // it gets the same answer rather than a bare "unsupported statement".
    if let Some(help) = match function {
        "ban" => Some("bans and purges belong to the Varnish VCL that forks this tenant"),
        "restart" | "retry" | "pipe" => Some("restarts, retries and piping are host-controlled"),
        "purge" => Some("purging belongs to the Varnish VCL that forks this tenant"),
        "error" | "fail" => Some("write return (synth(...)), return (error(...)) or return (fail)"),
        "rollback" | "std.rollback" => {
            Some("a request's headers are not snapshotted, so there is nothing to roll back")
        }
        "esi" => Some("response bodies are immutable, so there is no ESI processor"),
        _ => None,
    } {
        return Some(help);
    }
    let module = function.split_once('.')?.0;
    match module {
        // Imports for the builtin VMOD namespaces are accepted before every
        // individual function lands.  Keep their interim rejection useful:
        // otherwise a migration corpus sees an unexplained parser failure
        // merely because the import itself stopped being the diagnostic.
        "urlplus" | "headerplus" | "cookieplus" => Some(
            "this builtin VMOD function is not implemented yet; see docs/plans/vcl-vmods.md",
        ),
        "accounting" => Some("accounting and metrics belong to the Varnish VCL that forks this tenant"),
        "file" => Some("certificate management owns ACME challenge answering; guest policy has no filesystem access"),
        _ => None,
    }
}

/// VCL's duration literals, in nanoseconds per unit.
///
/// The set and the scale factors are Varnish's (`VNUM_duration_unit` in
/// `lib/libvarnish/vnum.c`), a year being 365 days. `ms` has to be tried
/// before `s` because it ends in one.
const DURATION_UNITS: [(&str, u64); 7] = [
    ("ms", 1_000_000),
    ("s", 1_000_000_000),
    ("m", 60_000_000_000),
    ("h", 3_600_000_000_000),
    ("d", 86_400_000_000_000),
    ("w", 604_800_000_000_000),
    ("y", 31_536_000_000_000_000),
];

fn parse_duration(word: &str) -> Option<u64> {
    for (suffix, multiplier) in DURATION_UNITS {
        let Some(number) = word.strip_suffix(suffix) else {
            continue;
        };
        if number.is_empty() {
            return None;
        }
        // Whole counts stay exact; Varnish's duration is a REAL, so `1.5s`
        // and `0.5h` are ordinary literals and only those go through f64.
        if let Ok(whole) = number.parse::<u64>() {
            return whole.checked_mul(multiplier);
        }
        let fraction = number.parse::<f64>().ok()?;
        if !fraction.is_finite() || fraction < 0.0 {
            return None;
        }
        let nanoseconds = (fraction * multiplier as f64).round();
        if nanoseconds > u64::MAX as f64 {
            return None;
        }
        return Some(nanoseconds as u64);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file with no version marker is usually a library someone tried to
    /// compile on its own. That is one mistake, so it is one diagnostic: the
    /// version, semicolon and `sub` checks that used to follow said nothing
    /// the first line had not already.
    #[test]
    fn a_missing_version_marker_is_one_diagnostic() {
        let source = "sub vcl_recv { set req.http.X = \"1\"; }";
        let error = parse(source, &crate::lexer::lex(source).unwrap()).unwrap_err();
        assert_eq!(error.diagnostics.len(), 1, "{error}");
        assert!(
            error
                .to_string()
                .contains("a VCL policy must begin with a version marker"),
            "{error}"
        );
    }

    /// Every duration unit Varnish spells, and the fractional form, land on
    /// the same nanosecond count `VNUM_duration_unit` would produce.
    #[test]
    fn duration_literals_match_varnishs_units() {
        for (literal, nanoseconds) in [
            ("1ms", 1_000_000),
            ("1s", 1_000_000_000),
            ("1m", 60_000_000_000),
            ("1h", 3_600_000_000_000),
            ("1d", 86_400_000_000_000),
            ("1w", 604_800_000_000_000),
            ("1y", 31_536_000_000_000_000),
            ("1.5s", 1_500_000_000),
            ("0.5h", 1_800_000_000_000),
            ("2.25d", 194_400_000_000_000),
        ] {
            assert_eq!(parse_duration(literal), Some(nanoseconds), "{literal}");
        }
        for literal in ["1", "s", "1sec", "1x", "99999999999y", "-1s", "1.5"] {
            assert_eq!(parse_duration(literal), None, "{literal}");
        }
    }

    fn subs(program: &Program) -> impl Iterator<Item = &Sub> {
        program.items.iter().filter_map(|item| match item {
            Item::Acl { .. } => None,
            Item::Sub(sub) => Some(sub),
            Item::Static { .. } | Item::Global { .. } | Item::Include { .. } => None,
        })
    }

    fn sub(program: &Program, index: usize) -> &Sub {
        subs(program).nth(index).expect("sub exists")
    }

    #[test]
    fn varnish_return_actions_name_the_action_not_a_subroutine() {
        for (action, help) in [
            ("restart", "host-controlled"),
            ("retry", "host-controlled"),
            ("pipe", "host-controlled"),
            ("purge", "purging belongs to the Varnish VCL"),
            ("hit", "the actions are"),
        ] {
            let source = format!("vcl 4.1; sub vcl_recv {{ return ({action}); }}");
            let error = parse(&source, &crate::lexer::lex(&source).unwrap())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("return ({action}) is not supported")),
                "{error}"
            );
            assert!(error.contains(help), "{error}");
        }
    }

    #[test]
    fn parses_var_static_call_and_sub_return() {
        let source = concat!(
            "vcl 4.1; static var count: int = 1; ",
            "sub helper { var text: String = \"x\"; return; } ",
            "sub gate { return (hash); } ",
            "sub vcl_recv { var ok: BOOL = true; var wait: duration; ",
            "call helper; return (gate); }"
        );
        let ast = parse(source, &crate::lexer::lex(source).unwrap()).unwrap();
        assert!(matches!(
            &ast.items[0],
            Item::Static {
                value_type: TypeName::Integer,
                ..
            }
        ));
        let Item::Sub(recv) = ast.items.last().unwrap() else {
            panic!("expected recv sub");
        };
        assert!(matches!(
            recv.statements[0],
            Statement::Declare {
                value_type: TypeName::Boolean,
                ..
            }
        ));
        assert!(matches!(
            recv.statements[1],
            Statement::Declare {
                value_type: TypeName::Duration,
                ..
            }
        ));
        assert!(matches!(recv.statements[2], Statement::Call { .. }));
        assert!(matches!(
            recv.statements[3],
            Statement::Return {
                action: ReturnAction::Sub(_, _),
                ..
            }
        ));
    }
    use crate::lexer;

    #[test]
    fn parses_basic_policy() {
        let source = "vcl 4.1; sub vcl_recv { set req.http.X = \"yes\"; return (pass); }";
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        assert_eq!(subs(&ast).count(), 1);
        assert_eq!(sub(&ast, 0).statements.len(), 2);
    }

    #[test]
    fn builtin_module_imports_are_no_ops_but_other_modules_are_rejected() {
        let source = concat!(
            "vcl 4.1; import digest; import std; import urlplus; import headerplus; import cookieplus; ",
            "sub vcl_recv { set req.http.X = digest.hash_sha256(\"x\"); }"
        );
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        assert_eq!(subs(&ast).count(), 1);

        let source = "vcl 4.1; import directors; sub vcl_recv {}";
        let error = parse(source, &lexer::lex(source).unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unsupported VCL module 'directors'"),
            "{error}"
        );
    }

    #[test]
    fn long_strings_are_expression_literals() {
        let source = "vcl 4.1; sub vcl_recv { std.log({\"line one\nline two\"}); }";
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        let Statement::Log { value, .. } = &sub(&ast, 0).statements[0] else {
            panic!("expected log statement");
        };
        assert!(matches!(
            &value.kind,
            ExprKind::Literal(Literal::String(value)) if value == "line one\nline two"
        ));
    }

    #[test]
    fn ownership_rejections_name_the_varnish_vcl_owner() {
        for declaration in ["backend origin {}", "director pool {}"] {
            let source = format!("vcl 4.1; {declaration} sub vcl_recv {{}}");
            let error = parse(&source, &lexer::lex(&source).unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains("backends and directors belong to the Varnish VCL"), "{error}");
        }

        // hash_data() is a statement of its own; the type checker confines
        // it to vcl_hash.
        let source = "vcl 4.1; sub vcl_hash { hash_data(req.url); }";
        assert!(parse(source, &lexer::lex(source).unwrap()).is_ok());

        // A `probe` used to be reported as "expected 'sub'", which says
        // nothing about where health checks actually live.
        let source = "vcl 4.1; probe healthy { .url = \"/healthz\"; } sub vcl_recv {}";
        let error = parse(source, &lexer::lex(source).unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("probe declarations are not supported"),
            "{error}"
        );
        assert!(error.contains("health checks belong to the Varnish VCL"), "{error}");
    }

    /// Varnish's bare action statements get the same answer their
    /// `return (...)` spellings do. A migrating author writing `restart;`
    /// used to be told only that the statement was unsupported.
    #[test]
    fn action_statements_name_what_to_write_instead() {
        for (statement, needle) in [
            ("ban(\"req.url ~ /x\");", "bans and purges belong"),
            ("restart;", "host-controlled"),
            ("error 503;", "return (synth("),
            ("rollback;", "nothing to roll back"),
        ] {
            let source = format!("vcl 4.1; sub vcl_recv {{ {statement} }}");
            let error = parse(&source, &lexer::lex(&source).unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{statement}: {error}");
        }
    }

    #[test]
    fn real_literals_name_the_v1_integer_alternative() {
        let source = "vcl 4.1; sub vcl_recv { set req.http.X = 1.5; }";
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        let Statement::Set { value, .. } = &sub(&ast, 0).statements[0] else {
            panic!("expected set statement");
        };
        assert!(
            matches!(value.kind, ExprKind::Literal(Literal::Real(ref value)) if value == "1.5")
        );
    }

    #[test]
    fn parses_real_literals_for_std_syntax_to_type_check() {
        let source = "vcl 4.1; sub vcl_recv { if (std.syntax(4.1)) { return (hash); } }";
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        let Statement::If { branches, .. } = &sub(&ast, 0).statements[0] else {
            panic!("expected if statement");
        };
        let ExprKind::Call {
            function,
            arguments,
        } = &branches[0].0.kind
        else {
            panic!("expected std.syntax call");
        };
        assert_eq!(function, "std.syntax");
        assert!(
            matches!(arguments[0].value.kind, ExprKind::Literal(Literal::Real(ref value)) if value == "4.1")
        );
    }

    #[test]
    fn real_literals_are_left_for_the_type_checker_to_reject() {
        let source = "vcl 4.1; sub vcl_recv { set req.http.X = 1.5; }";
        let error = crate::compile(source, crate::CompileOptions::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("REAL literals are not supported"), "{error}");
        assert!(error.contains("integer or duration arithmetic"), "{error}");
    }

    #[test]
    fn reports_more_than_one_syntax_error() {
        let source = "vcl 9; sub vcl_recv { nope; wat; }";
        let err = parse(source, &lexer::lex(source).unwrap()).unwrap_err();
        assert!(err.diagnostics.len() >= 3);
    }

    #[test]
    fn rejects_a_synth_reason_that_would_end_the_status_line() {
        for action in ["synth", "error"] {
            let source = format!("vcl 4.1; sub vcl_recv {{ return ({action}(403, {{\"No\r\n\"}})); }}");
            let error = parse(&source, &lexer::lex(&source).unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains("reason cannot contain the byte 0x0d"), "{error}");
        }
        let long = "x".repeat(SYNTH_REASON_LIMIT + 1);
        let source = format!("vcl 4.1; sub vcl_recv {{ return (synth(403, \"{long}\")); }}");
        let error = parse(&source, &lexer::lex(&source).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("reason is longer than"), "{error}");
    }

    #[test]
    fn rejects_a_synth_status_outside_three_digits() {
        for status in ["99", "1000"] {
            let source = format!("vcl 4.1; sub vcl_recv {{ return (synth({status}, \"x\")); }}");
            let error = parse(&source, &lexer::lex(&source).unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains("from 100 through 999"), "{error}");
        }
        // The custom-status idiom: vcl_synth turns 750 into a redirect.
        let source = "vcl 4.1; sub vcl_recv { return (synth(750, \"/elsewhere\")); }";
        assert!(parse(source, &lexer::lex(source).unwrap()).is_ok());
    }

    #[test]
    fn parses_nested_boolean_conditionals_and_elsif_spellings() {
        let source = concat!(
            "vcl 4.1; sub vcl_recv { ",
            "if (req.method == \"GET\" && !false) { set req.http.X = req.url; } ",
            "elseif (req.method != \"POST\") { return (pass); } ",
            "else { return (hash); } }"
        );
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        let Statement::If {
            branches,
            otherwise,
            ..
        } = &sub(&ast, 0).statements[0]
        else {
            panic!("expected conditional statement");
        };
        assert_eq!(branches.len(), 2);
        assert_eq!(otherwise.len(), 1);
    }

    #[test]
    fn arithmetic_precedence_feeds_ordered_comparisons() {
        let source = concat!(
            "vcl 4.1; sub vcl_backend_response { ",
            "if (beresp.status + 2 * 3 >= 506) { set beresp.ttl = 1m - 15s; } }"
        );
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        let Statement::If { branches, .. } = &sub(&ast, 0).statements[0] else {
            panic!("expected conditional");
        };
        let ExprKind::Binary { op, left, .. } = &branches[0].0.kind else {
            panic!("expected ordered comparison");
        };
        assert_eq!(*op, BinaryOp::GreaterEqual);
        let ExprKind::AddChain(operands) = &left.kind else {
            panic!("expected a '+' run");
        };
        assert_eq!(operands.len(), 2);
        assert!(matches!(
            operands[1].kind,
            ExprKind::Binary {
                op: BinaryOp::Multiply,
                ..
            }
        ));
    }

    #[test]
    fn parses_the_full_signed_integer_range() {
        let source = concat!(
            "vcl 4.1; sub vcl_backend_response { ",
            "if (-9223372036854775808 < 0) { return (deliver); } }"
        );
        let ast = parse(source, &lexer::lex(source).unwrap()).unwrap();
        let Statement::If { branches, .. } = &sub(&ast, 0).statements[0] else {
            panic!("expected conditional");
        };
        let ExprKind::Binary { left, .. } = &branches[0].0.kind else {
            panic!("expected comparison");
        };
        assert!(matches!(
            left.kind,
            ExprKind::Literal(Literal::Integer(i64::MIN))
        ));
    }

    #[test]
    fn deep_nesting_is_a_diagnostic_rather_than_a_stack_overflow() {
        for source in [
            format!(
                "vcl 4.1; sub vcl_recv {{ set req.http.X = {}1{}; }}",
                "(".repeat(5_000),
                ")".repeat(5_000)
            ),
            format!(
                "vcl 4.1; sub vcl_recv {{ set req.http.X = {}\"x\"; }}",
                "!".repeat(5_000)
            ),
            format!(
                "vcl 4.1; sub vcl_recv {{ {} return (pass); {} }}",
                "if (true) {".repeat(5_000),
                "}".repeat(5_000)
            ),
        ] {
            let error = parse(&source, &lexer::lex(&source).unwrap())
                .expect_err("deeply nested source must be rejected")
                .to_string();
            assert!(error.contains("may not nest more than"), "{error}");
        }
    }

    /// A flat operator chain builds the same left-deep tree a nested
    /// expression does, one level per operator, so it has to be charged the
    /// same way. Before this was true, `1-1-1-…` at a few thousand terms —
    /// well inside `MAX_SOURCE_BYTES` — overflowed the stack in the type
    /// checker and took the process with it.
    #[test]
    fn flat_operator_chains_are_charged_like_nested_ones() {
        for tail in ["- 1", "|| true", "== 1", "* 1"] {
            let source = format!(
                "vcl 4.1; sub vcl_recv {{ if (1 {}) {{ return (pass); }} }}",
                format!("{tail} ").repeat(10_000)
            );
            let error = parse(&source, &lexer::lex(&source).unwrap())
                .expect_err("a flat chain must be rejected")
                .to_string();
            assert!(error.contains("may not nest more than"), "{error}");
        }
    }

    /// The one chain that is folded flat rather than charged per operator,
    /// because building a long string out of many pieces is a shape people
    /// actually write. It is bounded by [`MAX_CHAIN_OPERANDS`] instead.
    #[test]
    fn a_long_string_concatenation_compiles_and_is_one_flat_run() {
        let source = format!(
            "vcl 4.1; sub vcl_recv {{ set req.http.X = \"a\"{}; }}",
            " + \"a\"".repeat(511)
        );
        let ast = parse(&source, &lexer::lex(&source).unwrap()).expect("512 terms must compile");
        let Statement::Set { value, .. } = &sub(&ast, 0).statements[0] else {
            panic!("expected an assignment");
        };
        let ExprKind::AddChain(operands) = &value.kind else {
            panic!("expected a '+' run");
        };
        assert_eq!(operands.len(), 512);

        let source = format!(
            "vcl 4.1; sub vcl_recv {{ set req.http.X = \"a\"{}; }}",
            " + \"a\"".repeat(10_000)
        );
        let error = parse(&source, &lexer::lex(&source).unwrap())
            .expect_err("an unbounded '+' run must be rejected")
            .to_string();
        assert!(error.contains("may not join more than"), "{error}");
    }

    #[test]
    fn corrupted_token_streams_never_panic() {
        const ALPHABET: &[u8] = b"vclsub{}();=,._- 0123456789\"#\n";
        let mut random = 0xd1b5_4a32_d192_ed03u64;
        for _ in 0..1_000 {
            let mut source = String::new();
            let length = (random & 63) as usize;
            for _ in 0..length {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                source.push(ALPHABET[(random as usize) % ALPHABET.len()] as char);
            }
            if let Ok(tokens) = lexer::lex(&source) {
                let _ = parse(&source, &tokens);
            }
        }
    }
}
