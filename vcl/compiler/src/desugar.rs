//! Lower the language-shaped typed tree into the ABI-shaped tree consumed by IR lowering.

use std::collections::BTreeMap;

use crate::ast::BinaryOp;
use crate::backend::BackendError;
use crate::resolver::SubId;
use crate::typecheck::{
    TypedExpr, TypedExprKind, TypedProgram, TypedStatement, TypedSub, TypedUserSub, VmodAction,
};
use crate::types::{LocalId, Phase, ValueType, MAX_BLOCK_DEPTH};
use crate::vars::Lowering;
use crate::vmod::Module;
use crate::{Diagnostic, Diagnostics, Span};

/// The budget one hook's inlined body may spend.
///
/// Charged in statements *and* expression nodes, because inlining deep-clones
/// the callee's expression trees at every call site: counting statements
/// alone lets one large expression in a sub called four thousand times
/// multiply the tree by four thousand while the counter reads 4 096.
///
/// Four times the old statement ceiling, because an ordinary statement costs
/// itself plus three or four expression nodes: a policy that was legal when
/// only statements were counted is still legal, and the shape this now
/// refuses is the one where the expressions, not the statements, are what
/// grew.
const MAX_INLINED_NODES: usize = 16_384;

pub(crate) fn desugar(source: &str, checked: TypedProgram) -> Result<TypedProgram, Diagnostics> {
    let TypedProgram {
        subs,
        user_subs,
        statics,
        globals,
        acls,
        patterns,
        warnings,
    } = checked;

    let mut warnings = warnings;
    let mut desugared = Vec::with_capacity(subs.len());
    for sub in subs {
        let sub = expand_sub(source, sub, &user_subs, &mut warnings)?;
        if let Some((second, module)) = second_header_commit(&sub.statements) {
            return Err(Diagnostics::single(
                source,
                Diagnostic::error(
                    second,
                    format!(
                        "{} commits the header map a second time in {}",
                        module.write_call(),
                        sub.phase.vcl_name()
                    ),
                )
                .with_help(
                    "the host's header commit is once per phase per map, as it is for a C or \
                     Rust guest; stage every change and write once. headerplus.write() and \
                     cookieplus.setcookie_write() are the same commit, so one phase may run \
                     only one of them",
                ),
            ));
        }
        desugared.push(sub);
    }
    let program = TypedProgram {
        subs: desugared,
        user_subs: BTreeMap::new(),
        statics,
        globals,
        acls,
        patterns,
        warnings,
    };
    verify(&program).map_err(|error| Diagnostics::single(source, error.into_diagnostic()))?;
    Ok(program)
}

/// The span of a `headerplus.write()` that could run after another one.
///
/// Exact rather than a count: a sequence sums its statements' writes and a
/// conditional takes the largest of its branches, so `write()` in each arm of
/// an if/else is one write, not two. There are no loops, so that is the whole
/// analysis.
///
/// The rule is the host's, not VCL's. `headerplus.write()` lowers onto the
/// generic header commit, which is once per phase per side for every guest
/// language; catching it here is the difference between a diagnostic on the
/// second `write()` and an unexplained EBREAK at run time.
fn second_header_commit(statements: &[TypedStatement]) -> Option<(Span, Module)> {
    fn walk(statements: &[TypedStatement], seen: &mut bool) -> Option<(Span, Module)> {
        for statement in statements {
            match statement {
                TypedStatement::Vmod {
                    module,
                    action: VmodAction::Write { .. },
                    span,
                } if matches!(module, Module::Headerplus | Module::Setcookie) => {
                    if *seen {
                        return Some((*span, *module));
                    }
                    *seen = true;
                }
                TypedStatement::If {
                    branches,
                    otherwise,
                    ..
                } => {
                    // Every branch starts from what ran before the `if` and
                    // at most one of them runs, so the join has seen a write
                    // when any branch performed one.
                    let mut joined = *seen;
                    for body in branches
                        .iter()
                        .map(|(_, body)| body.as_slice())
                        .chain(core::iter::once(otherwise.as_slice()))
                    {
                        let mut branch = *seen;
                        if let Some(span) = walk(body, &mut branch) {
                            return Some(span);
                        }
                        joined |= branch;
                    }
                    *seen = joined;
                }
                TypedStatement::Inlined { body, .. } => {
                    if let Some(span) = walk(body, seen) {
                        return Some(span);
                    }
                }
                // Everything else is a leaf holding no nested body, plus
                // the vmod statements the arm above did not take -- a
                // transform, or a `write()` on a module that commits
                // something other than the header list. A new statement kind
                // that can nest a body has to be added above.
                TypedStatement::Vmod { .. }
                | TypedStatement::Declare { .. }
                | TypedStatement::SetLocal { .. }
                | TypedStatement::SetStatic { .. }
                | TypedStatement::SetGlobal { .. }
                | TypedStatement::Call { .. }
                | TypedStatement::SetHeader { .. }
                | TypedStatement::UnsetHeader { .. }
                | TypedStatement::SetUrl { .. }
                | TypedStatement::SetVar { .. }
                | TypedStatement::SetBody { .. }
                | TypedStatement::HashData { .. }
                | TypedStatement::SetCacheDuration { .. }
                | TypedStatement::SetTtl { .. }
                | TypedStatement::SetStaleWhileRevalidate { .. }
                | TypedStatement::SetStaleIfError { .. }
                | TypedStatement::SetUncacheable { .. }
                | TypedStatement::Collect { .. }
                | TypedStatement::Log { .. }
                | TypedStatement::Synthetic { .. }
                | TypedStatement::Return { .. } => {}
            }
        }
        None
    }

    let mut seen = false;
    walk(statements, &mut seen)
}

fn expand_sub(
    source: &str,
    sub: TypedSub,
    user_subs: &BTreeMap<(Phase, SubId), TypedUserSub>,
    warnings: &mut Vec<Diagnostic>,
) -> Result<TypedSub, Diagnostics> {
    let mut expander = Expander {
        source,
        phase: sub.phase,
        user_subs,
        locals: sub.locals,
        inlined_statements: 0,
        inline_counts: BTreeMap::new(),
        stack: Vec::new(),
        depth: 0,
        warnings: Vec::new(),
    };
    let statements = expander.block(sub.statements, false)?;
    warnings.append(&mut expander.warnings);
    Ok(TypedSub {
        phase: sub.phase,
        statements,
        locals: expander.locals,
    })
}

struct Expander<'a> {
    source: &'a str,
    phase: Phase,
    user_subs: &'a BTreeMap<(Phase, SubId), TypedUserSub>,
    locals: Vec<ValueType>,
    inlined_statements: usize,
    inline_counts: BTreeMap<String, usize>,
    stack: Vec<(String, Span)>,
    depth: usize,
    warnings: Vec<Diagnostic>,
}

impl Expander<'_> {
    fn block(
        &mut self,
        statements: Vec<TypedStatement>,
        contributed: bool,
    ) -> Result<Vec<TypedStatement>, Diagnostics> {
        if self.depth >= MAX_BLOCK_DEPTH {
            let span = statements.first().map(statement_span).unwrap_or_default();
            return Err(self.error(
                Diagnostic::error(
                    span,
                    format!(
                        "blocks and user-subroutine calls may not nest more than {MAX_BLOCK_DEPTH} deep"
                    ),
                )
                .with_help("flatten the nesting or shorten the chain of 'call' statements"),
            ));
        }
        self.depth += 1;
        let mut result = Vec::with_capacity(statements.len());
        for statement in statements {
            if contributed {
                let charge = 1 + expression_nodes(&statement);
                self.inlined_statements += charge;
                if let Some((name, _)) = self.stack.last() {
                    *self.inline_counts.entry(name.clone()).or_default() += charge;
                }
                if self.inlined_statements > MAX_INLINED_NODES {
                    let most = self
                        .inline_counts
                        .iter()
                        .max_by_key(|(name, count)| (*count, std::cmp::Reverse(*name)))
                        .map(|(name, count)| format!("; sub {name} contributes the most ({count})"))
                        .unwrap_or_default();
                    self.depth -= 1;
                    return Err(self.error(
                        Diagnostic::error(
                            statement_span(&statement),
                            format!(
                                "inlined hook exceeds the limit of {MAX_INLINED_NODES} statements and expression nodes{most}"
                            ),
                        )
                        .with_help("split or reduce repeated user-subroutine calls"),
                    ));
                }
            }
            result.push(self.statement(statement)?);
        }
        self.depth -= 1;
        Ok(result)
    }

    fn statement(&mut self, statement: TypedStatement) -> Result<TypedStatement, Diagnostics> {
        Ok(match statement {
            TypedStatement::Call {
                id,
                sub,
                deciding,
                span,
            } => {
                let Some(callee) = self.user_subs.get(&(self.phase, id)) else {
                    return Err(self.error(Diagnostic::error(
                        span,
                        format!(
                            "typed subroutine {sub} is unavailable in {}",
                            self.phase.vcl_name()
                        ),
                    )));
                };
                let base = self.locals.len() as u32;
                self.locals.extend(callee.locals.iter().copied());
                let mut body = callee.statements.clone();
                shift_locals(&mut body, base);
                self.stack.push((sub.clone(), span));
                let body = self.block(body, true)?;
                self.stack.pop();
                TypedStatement::Inlined {
                    sub,
                    body,
                    deciding,
                    span,
                }
            }
            TypedStatement::If {
                branches,
                otherwise,
                span,
            } => {
                let mut expanded = Vec::with_capacity(branches.len());
                for (condition, body) in branches {
                    expanded.push((condition, self.block(body, !self.stack.is_empty())?));
                }
                let otherwise = self.block(otherwise, !self.stack.is_empty())?;
                TypedStatement::If {
                    branches: expanded,
                    otherwise,
                    span,
                }
            }
            TypedStatement::Inlined { span, .. } => {
                return Err(self.error(Diagnostic::error(
                    span,
                    "type checker produced an already-inlined subroutine",
                )))
            }
            TypedStatement::SetCacheDuration {
                lowering,
                target,
                target_span,
                value,
                span,
            } => {
                let (statement, warning) =
                    fold_cache_duration(lowering, &target, target_span, value, span)
                        .map_err(|diagnostic| self.error(diagnostic))?;
                self.warnings.extend(warning);
                statement
            }
            other @ (TypedStatement::Declare { .. }
            | TypedStatement::SetLocal { .. }
            | TypedStatement::SetStatic { .. }
            | TypedStatement::SetGlobal { .. }
            | TypedStatement::SetHeader { .. }
            | TypedStatement::UnsetHeader { .. }
            | TypedStatement::SetUrl { .. }
            | TypedStatement::SetVar { .. }
            | TypedStatement::SetBody { .. }
            | TypedStatement::HashData { .. }
            | TypedStatement::SetTtl { .. }
            | TypedStatement::SetStaleWhileRevalidate { .. }
            | TypedStatement::SetStaleIfError { .. }
            | TypedStatement::SetUncacheable { .. }
            | TypedStatement::Vmod { .. }
            | TypedStatement::Collect { .. }
            | TypedStatement::Log { .. }
            | TypedStatement::Synthetic { .. }
            | TypedStatement::Return { .. }) => other,
        })
    }

    fn error(&self, mut diagnostic: Diagnostic) -> Diagnostics {
        for (name, span) in self.stack.iter().rev() {
            diagnostic = diagnostic.with_note(*span, format!("while inlining sub {name}"));
        }
        Diagnostics::single(self.source, diagnostic)
    }
}

fn shift_locals(statements: &mut [TypedStatement], amount: u32) {
    fn expression(expr: &mut TypedExpr, amount: u32) {
        match &mut expr.kind {
            TypedExprKind::Local(local) => local.0 += amount,
            TypedExprKind::Digest { arguments, .. } => {
                for argument in arguments {
                    expression(argument, amount);
                }
            }
            TypedExprKind::Regsub {
                subject,
                pattern,
                replacement,
                ..
            } => {
                expression(subject, amount);
                expression(pattern, amount);
                expression(replacement, amount);
            }
            TypedExprKind::Concat(parts) => {
                for part in parts {
                    expression(part, amount);
                }
            }
            TypedExprKind::Binary { left, right, .. }
            | TypedExprKind::Extreme { left, right, .. } => {
                expression(left, amount);
                expression(right, amount);
            }
            TypedExprKind::AclMatch { address, .. } => expression(address, amount),
            TypedExprKind::ToString { value, .. }
            | TypedExprKind::StringCase { value, .. }
            | TypedExprKind::Querysort { value }
            | TypedExprKind::Not(value)
            | TypedExprKind::Negate(value) => expression(value, amount),
            TypedExprKind::Strstr { haystack, needle } => {
                expression(haystack, amount);
                expression(needle, amount);
            }
            TypedExprKind::StringPredicate { value, affix, .. } => {
                expression(value, amount);
                expression(affix, amount);
            }
            TypedExprKind::ParseInteger { value, fallback }
            | TypedExprKind::ParseDuration { value, fallback }
            | TypedExprKind::ParseTime { value, fallback } => {
                expression(value, amount);
                expression(fallback, amount);
            }
            TypedExprKind::Fnmatch {
                subject,
                pattern,
                pathname,
                noescape,
                period,
            } => {
                expression(subject, amount);
                expression(pattern, amount);
                expression(pathname, amount);
                expression(noescape, amount);
                expression(period, amount);
            }
            TypedExprKind::StrTest {
                subject,
                other,
                separators,
                ..
            } => {
                expression(subject, amount);
                expression(other, amount);
                expression(separators, amount);
            }
            TypedExprKind::StrEdit {
                subject,
                count,
                offset,
                ..
            } => {
                expression(subject, amount);
                expression(count, amount);
                expression(offset, amount);
            }
            TypedExprKind::StrSplit {
                subject,
                index,
                separators,
            } => {
                expression(subject, amount);
                expression(index, amount);
                expression(separators, amount);
            }
            TypedExprKind::VmodRead {
                arguments, default, ..
            } => {
                for argument in arguments {
                    expression(argument, amount);
                }
                expression(default, amount);
            }
            TypedExprKind::VmodCount { arguments, .. } => {
                for argument in arguments {
                    expression(argument, amount);
                }
            }
            TypedExprKind::String(_)
            | TypedExprKind::Integer(_)
            | TypedExprKind::Duration(_)
            | TypedExprKind::Boolean(_)
            | TypedExprKind::Static(_)
            | TypedExprKind::Global(_)
            | TypedExprKind::Read { .. }
            | TypedExprKind::HeaderPresent { .. } => {}
        }
    }

    for statement in statements {
        match statement {
            TypedStatement::Declare { local, init, .. } => {
                local.0 += amount;
                if let Some(init) = init {
                    expression(init, amount);
                }
            }
            TypedStatement::SetLocal { local, value, .. } => {
                local.0 += amount;
                expression(value, amount);
            }
            TypedStatement::SetStatic { value, .. }
            | TypedStatement::SetGlobal { value, .. }
            | TypedStatement::SetHeader { value, .. }
            | TypedStatement::SetUrl { value, .. }
            | TypedStatement::SetVar { value, .. }
            | TypedStatement::SetBody { value, .. }
            | TypedStatement::HashData { value, .. }
            | TypedStatement::SetCacheDuration { value, .. }
            | TypedStatement::Collect {
                separator: value, ..
            }
            | TypedStatement::Log { value, .. }
            | TypedStatement::Synthetic { value, .. } => expression(value, amount),
            TypedStatement::Vmod { action, .. } => {
                if let VmodAction::Transform { arguments, .. } = action {
                    for argument in arguments {
                        expression(argument, amount);
                    }
                }
            }
            TypedStatement::Inlined { body, .. } => shift_locals(body, amount),
            TypedStatement::If {
                branches,
                otherwise,
                ..
            } => {
                for (condition, body) in branches {
                    expression(condition, amount);
                    shift_locals(body, amount);
                }
                shift_locals(otherwise, amount);
            }
            TypedStatement::Call { .. }
            | TypedStatement::UnsetHeader { .. }
            | TypedStatement::SetTtl { .. }
            | TypedStatement::SetStaleWhileRevalidate { .. }
            | TypedStatement::SetStaleIfError { .. }
            | TypedStatement::SetUncacheable { .. }
            | TypedStatement::Return { .. } => {}
        }
    }
}

pub(crate) fn verify(program: &TypedProgram) -> Result<(), BackendError> {
    if !program.user_subs.is_empty() {
        return Err(BackendError::without_span(
            "desugar verifier",
            "language-shaped subroutines survived desugaring",
        ));
    }
    for sub in &program.subs {
        verify_block(&sub.statements, sub.locals.len(), program.statics.len())?;
    }
    Ok(())
}

fn verify_block(
    statements: &[TypedStatement],
    locals: usize,
    statics: usize,
) -> Result<(), BackendError> {
    fn expression(expr: &TypedExpr, locals: usize, statics: usize) -> Result<(), BackendError> {
        let fail = |message| BackendError::at("desugar verifier", expr.span, message);
        match &expr.kind {
            TypedExprKind::Local(LocalId(id)) if *id as usize >= locals => {
                return Err(fail(format!("expression uses out-of-range local {id}")))
            }
            TypedExprKind::Static(id) if id.0 as usize >= statics => {
                return Err(fail(format!(
                    "expression uses out-of-range static {}",
                    id.0
                )))
            }
            TypedExprKind::Digest { arguments, .. } => {
                for value in arguments {
                    expression(value, locals, statics)?;
                }
            }
            TypedExprKind::Regsub {
                subject,
                pattern,
                replacement,
                ..
            } => {
                expression(subject, locals, statics)?;
                expression(pattern, locals, statics)?;
                expression(replacement, locals, statics)?;
            }
            TypedExprKind::Concat(parts) => {
                for part in parts {
                    expression(part, locals, statics)?;
                }
            }
            TypedExprKind::Binary { left, right, .. }
            | TypedExprKind::Extreme { left, right, .. } => {
                expression(left, locals, statics)?;
                expression(right, locals, statics)?;
            }
            TypedExprKind::AclMatch { address, .. } => expression(address, locals, statics)?,
            TypedExprKind::ToString { value, .. }
            | TypedExprKind::StringCase { value, .. }
            | TypedExprKind::Querysort { value }
            | TypedExprKind::Not(value)
            | TypedExprKind::Negate(value) => expression(value, locals, statics)?,
            TypedExprKind::Strstr { haystack, needle } => {
                expression(haystack, locals, statics)?;
                expression(needle, locals, statics)?;
            }
            TypedExprKind::StringPredicate { value, affix, .. } => {
                expression(value, locals, statics)?;
                expression(affix, locals, statics)?;
            }
            TypedExprKind::ParseInteger { value, fallback }
            | TypedExprKind::ParseDuration { value, fallback }
            | TypedExprKind::ParseTime { value, fallback } => {
                expression(value, locals, statics)?;
                expression(fallback, locals, statics)?;
            }
            TypedExprKind::Fnmatch {
                subject,
                pattern,
                pathname,
                noescape,
                period,
            } => {
                expression(subject, locals, statics)?;
                expression(pattern, locals, statics)?;
                expression(pathname, locals, statics)?;
                expression(noescape, locals, statics)?;
                expression(period, locals, statics)?;
            }
            TypedExprKind::StrTest {
                subject,
                other,
                separators,
                ..
            } => {
                expression(subject, locals, statics)?;
                expression(other, locals, statics)?;
                expression(separators, locals, statics)?;
            }
            TypedExprKind::StrEdit {
                subject,
                count,
                offset,
                ..
            } => {
                expression(subject, locals, statics)?;
                expression(count, locals, statics)?;
                expression(offset, locals, statics)?;
            }
            TypedExprKind::StrSplit {
                subject,
                index,
                separators,
            } => {
                expression(subject, locals, statics)?;
                expression(index, locals, statics)?;
                expression(separators, locals, statics)?;
            }
            TypedExprKind::VmodRead {
                arguments, default, ..
            } => {
                for argument in arguments {
                    expression(argument, locals, statics)?;
                }
                expression(default, locals, statics)?;
            }
            TypedExprKind::VmodCount { arguments, .. } => {
                for argument in arguments {
                    expression(argument, locals, statics)?;
                }
            }
            TypedExprKind::String(_)
            | TypedExprKind::Integer(_)
            | TypedExprKind::Duration(_)
            | TypedExprKind::Boolean(_)
            | TypedExprKind::Local(_)
            | TypedExprKind::Static(_)
            | TypedExprKind::Global(_)
            | TypedExprKind::Read { .. }
            | TypedExprKind::HeaderPresent { .. } => {}
        }
        Ok(())
    }

    for statement in statements {
        let span = statement_span(statement);
        match statement {
            TypedStatement::Call { .. } => {
                return Err(BackendError::at(
                    "desugar verifier",
                    span,
                    "symbolic call survived desugaring",
                ))
            }
            // A cache duration the folder could not evaluate: the value is
            // an ordinary expression from here on, verified like any other.
            TypedStatement::SetCacheDuration { value, .. } => expression(value, locals, statics)?,
            TypedStatement::Declare { local, init, .. } => {
                if local.0 as usize >= locals {
                    return Err(BackendError::at(
                        "desugar verifier",
                        span,
                        "declaration uses an out-of-range local",
                    ));
                }
                if let Some(value) = init {
                    expression(value, locals, statics)?;
                }
            }
            TypedStatement::SetLocal { local, value, .. } => {
                if local.0 as usize >= locals {
                    return Err(BackendError::at(
                        "desugar verifier",
                        span,
                        "assignment uses an out-of-range local",
                    ));
                }
                expression(value, locals, statics)?;
            }
            TypedStatement::SetStatic {
                static_id, value, ..
            } => {
                if static_id.0 as usize >= statics {
                    return Err(BackendError::at(
                        "desugar verifier",
                        span,
                        "assignment uses an out-of-range static",
                    ));
                }
                expression(value, locals, statics)?;
            }
            TypedStatement::SetGlobal { value, .. }
            | TypedStatement::SetHeader { value, .. }
            | TypedStatement::SetUrl { value, .. }
            | TypedStatement::SetVar { value, .. }
            | TypedStatement::SetBody { value, .. }
            | TypedStatement::HashData { value, .. }
            | TypedStatement::Collect {
                separator: value, ..
            }
            | TypedStatement::Log { value, .. }
            | TypedStatement::Synthetic { value, .. } => expression(value, locals, statics)?,
            TypedStatement::Vmod { action, .. } => {
                if let VmodAction::Transform { arguments, .. } = action {
                    for argument in arguments {
                        expression(argument, locals, statics)?;
                    }
                }
            }
            TypedStatement::If {
                branches,
                otherwise,
                ..
            } => {
                for (condition, body) in branches {
                    expression(condition, locals, statics)?;
                    verify_block(body, locals, statics)?;
                }
                verify_block(otherwise, locals, statics)?;
            }
            TypedStatement::Inlined { body, .. } => {
                verify_block(body, locals, statics)?;
            }
            TypedStatement::UnsetHeader { .. }
            | TypedStatement::SetTtl { .. }
            | TypedStatement::SetStaleWhileRevalidate { .. }
            | TypedStatement::SetStaleIfError { .. }
            | TypedStatement::SetUncacheable { .. }
            | TypedStatement::Return { .. } => {}
        }
    }
    Ok(())
}

/// How many expression nodes one statement carries, not counting the bodies
/// it nests — those are walked, and charged, in their own right.
fn expression_nodes(statement: &TypedStatement) -> usize {
    let mut pending = crate::typecheck::statement_expressions(statement);
    let mut nodes = 0;
    while let Some(expression) = pending.pop() {
        nodes += 1;
        pending.extend(crate::typecheck::operands(expression));
    }
    nodes
}

fn statement_span(statement: &TypedStatement) -> Span {
    match statement {
        TypedStatement::Declare { span, .. }
        | TypedStatement::SetLocal { span, .. }
        | TypedStatement::SetStatic { span, .. }
        | TypedStatement::SetGlobal { span, .. }
        | TypedStatement::Inlined { span, .. }
        | TypedStatement::Call { span, .. }
        | TypedStatement::SetHeader { span, .. }
        | TypedStatement::UnsetHeader { span, .. }
        | TypedStatement::SetUrl { span, .. }
        | TypedStatement::SetVar { span, .. }
        | TypedStatement::SetBody { span, .. }
        | TypedStatement::HashData { span, .. }
        | TypedStatement::SetCacheDuration { span, .. }
        | TypedStatement::SetTtl { span, .. }
        | TypedStatement::SetStaleWhileRevalidate { span, .. }
        | TypedStatement::SetStaleIfError { span, .. }
        | TypedStatement::SetUncacheable { span }
        | TypedStatement::Vmod { span, .. }
        | TypedStatement::Collect { span, .. }
        | TypedStatement::Log { span, .. }
        | TypedStatement::Synthetic { span, .. }
        | TypedStatement::If { span, .. }
        | TypedStatement::Return { span, .. } => *span,
    }
}

/// Fold `set beresp.ttl|grace|keep = <duration>` down to the whole seconds
/// the scripting ABI speaks, or leave the assignment standing when the value
/// is only known at runtime.
///
/// The folded form is exact: a negative, absurd, or sub-second constant is a
/// compile error, because the compiler can see it. The unfolded form cannot
/// be, so it carries one runtime rule — the nanoseconds it computes are
/// truncated toward zero at the assignment — and one compile-time guard
/// against the mistake that rule would otherwise hide: every duration
/// *literal* in the expression must already be whole seconds.
fn fold_cache_duration(
    lowering: Lowering,
    target: &str,
    target_span: Span,
    value: TypedExpr,
    span: Span,
) -> Result<(TypedStatement, Option<Diagnostic>), Diagnostic> {
    let Some(nanoseconds) = evaluate_duration(&value)? else {
        let warning =
            sub_second_literal(&value).map(|(literal, at)| truncation_warning(target, literal, at));
        return Ok((
            TypedStatement::SetCacheDuration {
                lowering,
                target: target.to_string(),
                target_span,
                value,
                span,
            },
            warning,
        ));
    };
    const MAX_DURATION_NS: i128 = 365 * 86_400 * 1_000_000_000;
    if nanoseconds < 0 {
        return Err(Diagnostic::error(
            value.span,
            format!("{target} cannot be negative"),
        ));
    }
    if nanoseconds > MAX_DURATION_NS {
        return Err(Diagnostic::error(
            target_span,
            format!("{target} exceeds the scripting ABI maximum of 365 days"),
        ));
    }
    // The ABI carries cache durations in whole seconds and `max-age` is
    // `delta-seconds`, so a fraction has nowhere to go. Truncating toward zero
    // and saying so beats refusing a policy that otherwise compiles unchanged
    // — Varnish's own `0.1s` in a health include means `0s` here whichever way
    // this goes.
    let warning = (nanoseconds % 1_000_000_000 != 0)
        .then(|| truncation_warning(target, nanoseconds, value.span));
    let seconds =
        u64::try_from(nanoseconds / 1_000_000_000).expect("validated cache duration fits u64");
    let statement = match lowering {
        Lowering::Ttl => TypedStatement::SetTtl { seconds, span },
        Lowering::StaleWhileRevalidate => TypedStatement::SetStaleWhileRevalidate { seconds, span },
        Lowering::StaleIfError => TypedStatement::SetStaleIfError { seconds, span },
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
            return Err(Diagnostic::error(
                target_span,
                "non-duration variable reached cache-duration desugaring",
            ))
        }
    };
    Ok((statement, warning))
}

fn truncation_warning(target: &str, nanoseconds: i128, span: Span) -> Diagnostic {
    let seconds = nanoseconds / 1_000_000_000;
    Diagnostic::warning(
        span,
        format!("{target} is truncated to {seconds}s: the scripting ABI carries cache durations in whole seconds"),
    )
    .with_help("Cache-Control max-age is delta-seconds, so a fraction has nowhere to go")
}

/// The first sub-second duration literal in a cache assignment the compiler
/// could not fold, and where it is.
///
/// The runtime truncates the same way the folded form does, so this is only
/// about being able to say so at compile time.
fn sub_second_literal(expression: &TypedExpr) -> Option<(i128, Span)> {
    if let TypedExprKind::Duration(nanoseconds) = &expression.kind {
        if nanoseconds % 1_000_000_000 != 0 {
            return Some((i128::from(*nanoseconds), expression.span));
        }
    }
    // Through [`crate::typecheck::operands`] rather than the two operator
    // kinds arithmetic folds, so a literal in any other position -- the
    // fallback of `std.duration()`, say -- is found by construction.
    crate::typecheck::operands(expression)
        .into_iter()
        .find_map(sub_second_literal)
}

/// The constant value of a cache-duration expression in nanoseconds, or
/// `None` when it is only known at runtime.
///
/// `Err` stays reserved for an expression that cannot be a duration at all,
/// and for constant arithmetic that overflows or divides by zero — the cases
/// no runtime lowering would rescue.
fn evaluate_duration(expression: &TypedExpr) -> Result<Option<i128>, Diagnostic> {
    let error = |message: &str| Diagnostic::error(expression.span, message);
    match &expression.kind {
        TypedExprKind::AclMatch { .. } => Err(error("an acl match is not a duration")),
        TypedExprKind::Duration(value) => Ok(Some(i128::from(*value))),
        TypedExprKind::Integer(value) => Ok(Some(i128::from(*value))),
        TypedExprKind::Binary { op, left, right } => {
            let left_value = evaluate_duration(left)?;
            let right_value = evaluate_duration(right)?;
            let (Some(left_value), Some(right_value)) = (left_value, right_value) else {
                // One side is a runtime value, so the whole expression is —
                // but the operator still has to be one arithmetic can use.
                return match op {
                    BinaryOp::Add
                    | BinaryOp::Subtract
                    | BinaryOp::Multiply
                    | BinaryOp::Divide
                    | BinaryOp::Modulo => Ok(None),
                    BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::Greater
                    | BinaryOp::GreaterEqual
                    | BinaryOp::Match
                    | BinaryOp::NotMatch
                    | BinaryOp::And
                    | BinaryOp::Or => Err(error("cache duration is not a duration expression")),
                };
            };
            match op {
                BinaryOp::Add => left_value
                    .checked_add(right_value)
                    .map(Some)
                    .ok_or_else(|| error("duration expression overflows")),
                BinaryOp::Subtract => left_value
                    .checked_sub(right_value)
                    .map(Some)
                    .ok_or_else(|| error("duration expression overflows")),
                BinaryOp::Multiply => left_value
                    .checked_mul(right_value)
                    .map(Some)
                    .ok_or_else(|| error("duration expression overflows")),
                BinaryOp::Divide => {
                    if right_value == 0 {
                        Err(error("duration expression divides by zero"))
                    } else {
                        left_value
                            .checked_div(right_value)
                            .map(Some)
                            .ok_or_else(|| error("duration expression overflows"))
                    }
                }
                BinaryOp::Modulo
                | BinaryOp::Equal
                | BinaryOp::NotEqual
                | BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::Greater
                | BinaryOp::GreaterEqual
                | BinaryOp::Match
                | BinaryOp::NotMatch
                | BinaryOp::And
                | BinaryOp::Or => Err(error("cache duration is not a duration expression")),
            }
        }
        TypedExprKind::Negate(operand) => match evaluate_duration(operand)? {
            Some(value) => value
                .checked_neg()
                .map(Some)
                .ok_or_else(|| error("duration expression overflows")),
            None => Ok(None),
        },
        // Scalars the host, a local, or a vmod produces: known only when the
        // phase runs, and lowered as an expression.
        TypedExprKind::Read { .. }
        | TypedExprKind::Local(_)
        | TypedExprKind::Static(_)
        | TypedExprKind::Global(_)
        | TypedExprKind::ParseDuration { .. }
        | TypedExprKind::ParseInteger { .. }
        | TypedExprKind::VmodRead { .. }
        | TypedExprKind::VmodCount { .. }
        | TypedExprKind::Extreme { .. } => Ok(None),
        TypedExprKind::HeaderPresent { .. }
        | TypedExprKind::Digest { .. }
        | TypedExprKind::Regsub { .. }
        | TypedExprKind::ParseTime { .. }
        | TypedExprKind::String(_)
        | TypedExprKind::Boolean(_)
        | TypedExprKind::Not(_)
        | TypedExprKind::Concat(_)
        | TypedExprKind::ToString { .. }
        | TypedExprKind::StringCase { .. }
        | TypedExprKind::Strstr { .. }
        | TypedExprKind::StringPredicate { .. }
        | TypedExprKind::Fnmatch { .. }
        | TypedExprKind::StrTest { .. }
        | TypedExprKind::StrEdit { .. }
        | TypedExprKind::StrSplit { .. }
        | TypedExprKind::Querysort { .. } => {
            Err(error("cache duration is not a duration expression"))
        }
    }
}
