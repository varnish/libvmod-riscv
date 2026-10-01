//! Name, hook, static, and user-subroutine resolution.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast;
use crate::types::{AclId, Phase};
use crate::{Diagnostic, Diagnostics, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SubId(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserSubKind {
    Plain,
    Deciding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedProgram {
    pub hooks: Vec<ResolvedHook>,
    pub subs: BTreeMap<SubId, ResolvedUserSub>,
    pub sub_names: BTreeMap<String, SubId>,
    pub statics: Vec<ResolvedStatic>,
    pub globals: Vec<ResolvedGlobal>,
    pub acls: Vec<ResolvedAcl>,
    pub acl_names: BTreeMap<String, AclId>,
    /// The declared syntax level, times ten. See [`ast::Program::syntax`].
    pub syntax: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedHook {
    pub id: SubId,
    pub phase: Phase,
    pub name_span: Span,
    pub statements: Vec<ast::Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedUserSub {
    pub id: SubId,
    pub name: String,
    pub name_span: Span,
    pub kind: UserSubKind,
    pub statements: Vec<ast::Statement>,
    pub included: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedStatic {
    pub name: String,
    pub name_span: Span,
    pub value_type: ast::TypeName,
    pub init: Option<ast::Expr>,
    pub stat: Option<ast::StatAnnotation>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedGlobal {
    pub name: String,
    pub name_span: Span,
    pub value_type: ast::TypeName,
    pub init: Option<ast::Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedAcl {
    pub name: String,
    pub name_span: Span,
    /// The packed entry table `vcl_rt::acl_match` scans, sorted by
    /// prefix length so the first hit is the most specific one.
    pub table: Vec<u8>,
    pub span: Span,
}

/// Pack an ACL body into the runtime's entry table.
///
/// Every address is widened to 128 bits, an IPv4 prefix raised by the 96 bits
/// of the mapping, and the host bits cleared, so a match is one masked compare
/// per entry regardless of family.
fn encode_acl(
    name: &str,
    name_span: Span,
    entries: &[ast::AclEntry],
    errors: &mut Vec<Diagnostic>,
) -> Vec<u8> {
    if entries.is_empty() {
        errors.push(Diagnostic::error(
            name_span,
            format!("acl {name} has no entries"),
        ));
        return Vec::new();
    }

    let mut encoded: Vec<(u8, [u8; 16], bool, Span)> = Vec::new();
    for entry in entries {
        let Ok(address) = entry.address.parse::<std::net::IpAddr>() else {
            errors.push(
                Diagnostic::error(
                    entry.address_span,
                    format!("'{}' is not an IP address", entry.address),
                )
                .with_help("ACL entries are literal addresses; the compiler resolves no names"),
            );
            continue;
        };
        let (octets, width) = match address {
            std::net::IpAddr::V4(v4) => (vcl_rt::v4_mapped(v4.octets()), 32u32),
            std::net::IpAddr::V6(v6) => (v6.octets(), 128u32),
        };
        let declared = entry.prefix.unwrap_or(width);
        if declared > width {
            errors.push(Diagnostic::error(
                entry.prefix_span,
                format!(
                    "/{declared} is wider than the {width} bits of {}",
                    entry.address
                ),
            ));
            continue;
        }
        let bits = (declared + 128 - width) as u8;
        let network = u128::from_be_bytes(octets) & vcl_rt::prefix_mask(bits);
        if let Some((_, _, _, first)) = encoded.iter().find(|(other, address, _, _)| {
            *other == bits && u128::from_be_bytes(*address) == network
        }) {
            errors.push(
                Diagnostic::error(entry.span, format!("acl {name} repeats {}", entry.address))
                    .with_note(*first, "the first entry for this network is here"),
            );
            continue;
        }
        encoded.push((bits, network.to_be_bytes(), entry.negate, entry.span));
    }

    encoded.sort_by(|left, right| right.0.cmp(&left.0));
    let mut table = Vec::with_capacity(encoded.len() * vcl_rt::ACL_ENTRY_SIZE);
    for (bits, network, negate, _) in encoded {
        table.extend_from_slice(&network);
        table.push(bits);
        table.push(if negate {
            vcl_rt::ACL_NEGATE
        } else {
            0
        });
        table.extend_from_slice(&[0, 0]);
    }
    table
}

pub(crate) fn resolve(source: &str, program: ast::Program) -> Result<ResolvedProgram, Diagnostics> {
    let syntax = program.syntax;
    let mut errors = Vec::new();
    // Subs, statics and request globals share one declaration namespace, as
    // the include contract says they do: a library's definitions join the
    // program's, and a collision across files — of any kind — is an error
    // rather than a silent shadow. A global and a static are both read as
    // `var.NAME`, so one name for both could only ever mean one of them.
    let mut declarations = BTreeMap::<String, (Span, &'static str)>::new();
    let mut statics = Vec::new();
    let mut globals = Vec::new();
    let mut acls: Vec<ResolvedAcl> = Vec::new();
    let mut raw_subs = Vec::new();

    for item in program.items {
        match item {
            ast::Item::Static {
                name,
                name_span,
                value_type,
                init,
                stat,
                span,
            } => {
                if let Some((previous, kind)) = declarations.get(&name) {
                    errors.push(
                        Diagnostic::error(name_span, format!("duplicate declaration of {name}"))
                            .with_note(*previous, format!("the first declaration is the {kind}")),
                    );
                    continue;
                }
                declarations.insert(name.clone(), (name_span, "static"));
                statics.push(ResolvedStatic {
                    name,
                    name_span,
                    value_type,
                    init,
                    stat,
                    span,
                });
            }
            ast::Item::Global {
                name,
                name_span,
                value_type,
                init,
                span,
            } => {
                if let Some((previous, kind)) = declarations.get(&name) {
                    errors.push(
                        Diagnostic::error(name_span, format!("duplicate declaration of {name}"))
                            .with_note(*previous, format!("the first declaration is the {kind}")),
                    );
                    continue;
                }
                declarations.insert(name.clone(), (name_span, "request global"));
                globals.push(ResolvedGlobal {
                    name,
                    name_span,
                    value_type,
                    init,
                    span,
                });
            }
            ast::Item::Sub(sub) => {
                if let Some((previous, kind)) = declarations.get(&sub.name) {
                    errors.push(
                        Diagnostic::error(
                            sub.name_span,
                            format!("duplicate declaration of {}", sub.name),
                        )
                        .with_note(*previous, format!("the first declaration is the {kind}")),
                    );
                    continue;
                }
                declarations.insert(sub.name.clone(), (sub.name_span, "sub"));
                raw_subs.push(sub);
            }
            ast::Item::Acl {
                name,
                name_span,
                entries,
                span,
            } => {
                if let Some((previous, kind)) = declarations.get(&name) {
                    errors.push(
                        Diagnostic::error(name_span, format!("duplicate declaration of {name}"))
                            .with_note(*previous, format!("the first declaration is the {kind}")),
                    );
                    continue;
                }
                declarations.insert(name.clone(), (name_span, "acl"));
                let table = encode_acl(&name, name_span, &entries, &mut errors);
                acls.push(ResolvedAcl {
                    name,
                    name_span,
                    table,
                    span,
                });
            }
            ast::Item::Include { .. } => unreachable!("includes are expanded before resolution"),
        }
    }

    let acl_names: BTreeMap<_, _> = acls
        .iter()
        .enumerate()
        .map(|(index, acl)| (acl.name.clone(), AclId(index as u32)))
        .collect();
    let sub_names: BTreeMap<_, _> = raw_subs
        .iter()
        .enumerate()
        .map(|(index, sub)| (sub.name.clone(), SubId(index as u32)))
        .collect();
    let mut hooks = Vec::new();
    let mut subs = BTreeMap::new();
    for sub in raw_subs {
        let id = sub_names[&sub.name];
        if let Some(phase) = Phase::from_vcl_name(&sub.name) {
            hooks.push(ResolvedHook {
                id,
                phase,
                name_span: sub.name_span,
                statements: sub.statements,
            });
        } else if is_unsupported_hook(&sub.name) {
            errors.push(unsupported_hook(&sub.name, sub.name_span));
        } else if is_reserved(&sub.name) {
            errors.push(Diagnostic::error(
                sub.name_span,
                format!(
                    "'{}' is reserved and cannot name a user subroutine",
                    sub.name
                ),
            ));
        } else {
            let kind = if contains_deciding_return(&sub.statements) {
                if let Some(span) = first_bare_return(&sub.statements) {
                    errors.push(Diagnostic::error(
                        span,
                        format!("deciding sub {} cannot return without an action", sub.name),
                    ));
                }
                if !block_terminates(&sub.statements) {
                    errors.push(
                        Diagnostic::error(
                            sub.name_span,
                            format!("deciding sub {} has a path that falls through", sub.name),
                        )
                        .with_help("end every path with return (ACTION) or return (SUB)"),
                    );
                }
                UserSubKind::Deciding
            } else {
                UserSubKind::Plain
            };
            subs.insert(
                id,
                ResolvedUserSub {
                    id,
                    name: sub.name,
                    name_span: sub.name_span,
                    kind,
                    statements: sub.statements,
                    included: sub.included,
                },
            );
        }
    }

    let hook_ids: BTreeSet<_> = hooks.iter().map(|hook| hook.id).collect();
    let user_ids: BTreeSet<_> = subs.keys().copied().collect();
    let mut graph = BTreeMap::<SubId, Vec<(SubId, Span)>>::new();
    for hook in &hooks {
        validate_edges(
            hook.id,
            &hook.statements,
            &sub_names,
            &subs,
            &hook_ids,
            &user_ids,
            &mut graph,
            &mut errors,
        );
    }
    for sub in subs.values() {
        validate_edges(
            sub.id,
            &sub.statements,
            &sub_names,
            &subs,
            &hook_ids,
            &user_ids,
            &mut graph,
            &mut errors,
        );
    }

    if let Some(cycle) = find_cycle(&graph) {
        let names = cycle
            .iter()
            .map(|id| name_for(*id, &sub_names))
            .collect::<Vec<_>>()
            .join(" -> ");
        let span = subs
            .get(&cycle[0])
            .map_or(Span::default(), |sub| sub.name_span);
        errors.push(Diagnostic::error(
            span,
            format!("recursive VCL subroutine cycle: {names}"),
        ));
    }

    let mut reachable = BTreeSet::new();
    let mut pending: Vec<_> = hooks.iter().map(|hook| hook.id).collect();
    while let Some(id) = pending.pop() {
        for (callee, _) in graph.get(&id).into_iter().flatten() {
            if reachable.insert(*callee) {
                pending.push(*callee);
            }
        }
    }
    for sub in subs.values() {
        if !sub.included && !reachable.contains(&sub.id) {
            let mut diagnostic =
                Diagnostic::error(sub.name_span, format!("sub {} is never called", sub.name));
            // Hook names are case-sensitive, so `sub VCL_recv` is a legal user
            // sub that nothing calls rather than a hook. That is exactly the
            // mistake worth naming: the policy looks like it has a vcl_recv.
            if Phase::from_vcl_name(&sub.name.to_ascii_lowercase()).is_some() {
                diagnostic = diagnostic.with_help(format!(
                    "hook names are lower case; '{}' would be the hook",
                    sub.name.to_ascii_lowercase()
                ));
            }
            errors.push(diagnostic);
        }
    }

    if errors.is_empty() {
        Ok(ResolvedProgram {
            hooks,
            subs,
            sub_names,
            statics,
            globals,
            acls,
            acl_names,
            syntax,
        })
    } else {
        Err(Diagnostics::new(source, errors))
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_edges(
    caller: SubId,
    statements: &[ast::Statement],
    names: &BTreeMap<String, SubId>,
    subs: &BTreeMap<SubId, ResolvedUserSub>,
    hook_ids: &BTreeSet<SubId>,
    user_ids: &BTreeSet<SubId>,
    graph: &mut BTreeMap<SubId, Vec<(SubId, Span)>>,
    errors: &mut Vec<Diagnostic>,
) {
    #[derive(Clone, Copy)]
    enum EdgeForm {
        Call,
        Return,
    }

    walk_statements(statements, &mut |statement| {
        let (name, span, form) = match statement {
            ast::Statement::Call { sub, sub_span, .. } => (sub, *sub_span, EdgeForm::Call),
            ast::Statement::Return {
                action: ast::ReturnAction::Sub(sub, span),
                ..
            } => (sub, *span, EdgeForm::Return),
            ast::Statement::Declare { .. }
            | ast::Statement::BuiltinCall { .. }
            | ast::Statement::Set { .. }
            | ast::Statement::Unset { .. }
            | ast::Statement::If { .. }
            | ast::Statement::Log { .. }
            | ast::Statement::Synthetic { .. }
            | ast::Statement::HashData { .. }
            | ast::Statement::Return { .. } => return,
        };
        let Some(callee) = names.get(name).copied() else {
            errors.push(Diagnostic::error(
                span,
                format!("unknown subroutine '{name}'"),
            ));
            return;
        };
        if hook_ids.contains(&callee) {
            errors.push(Diagnostic::error(
                span,
                format!("hooks are invoked by the VMOD, not by VCL: {name}"),
            ));
            return;
        }
        if !user_ids.contains(&callee) {
            errors.push(Diagnostic::error(
                span,
                format!("subroutine '{name}' is unavailable"),
            ));
            return;
        }
        match (form, subs[&callee].kind) {
            (EdgeForm::Call, UserSubKind::Deciding) => errors.push(
                Diagnostic::error(span, format!("call of deciding sub {name} is not allowed"))
                    .with_help(format!("use 'return ({name});'")),
            ),
            (EdgeForm::Return, UserSubKind::Plain) => errors.push(
                Diagnostic::error(span, format!("plain sub {name} does not return an action"))
                    .with_help(format!("use 'call {name};'")),
            ),
            _ => {}
        }
        graph.entry(caller).or_default().push((callee, span));
    });
}

fn walk_statements(statements: &[ast::Statement], visit: &mut impl FnMut(&ast::Statement)) {
    for statement in statements {
        visit(statement);
        if let ast::Statement::If {
            branches,
            otherwise,
            ..
        } = statement
        {
            for (_, body) in branches {
                walk_statements(body, visit);
            }
            walk_statements(otherwise, visit);
        }
    }
}

fn contains_deciding_return(statements: &[ast::Statement]) -> bool {
    let mut found = false;
    walk_statements(statements, &mut |statement| {
        if matches!(
            statement,
            ast::Statement::Return {
                action: ast::ReturnAction::Hash
                    | ast::ReturnAction::Fetch
                    | ast::ReturnAction::Pass
                    | ast::ReturnAction::Abandon
                    | ast::ReturnAction::Deliver
                    | ast::ReturnAction::Synth { .. }
                    | ast::ReturnAction::Sub(_, _),
                ..
            }
        ) {
            found = true;
        }
    });
    found
}

fn first_bare_return(statements: &[ast::Statement]) -> Option<Span> {
    let mut result = None;
    walk_statements(statements, &mut |statement| {
        if result.is_none() {
            if let ast::Statement::Return {
                action: ast::ReturnAction::Bare,
                span,
            } = statement
            {
                result = Some(*span);
            }
        }
    });
    result
}

fn block_terminates(statements: &[ast::Statement]) -> bool {
    statements.last().is_some_and(statement_terminates)
}

fn statement_terminates(statement: &ast::Statement) -> bool {
    match statement {
        ast::Statement::Return {
            action: ast::ReturnAction::Bare,
            ..
        } => false,
        ast::Statement::Return { .. } => true,
        ast::Statement::If {
            branches,
            otherwise,
            ..
        } => {
            !otherwise.is_empty()
                && branches.iter().all(|(_, body)| block_terminates(body))
                && block_terminates(otherwise)
        }
        ast::Statement::Declare { .. }
        | ast::Statement::Call { .. }
        | ast::Statement::BuiltinCall { .. }
        | ast::Statement::Set { .. }
        | ast::Statement::Unset { .. }
        | ast::Statement::Log { .. }
        | ast::Statement::Synthetic { .. }
        | ast::Statement::HashData { .. } => false,
    }
}

/// Depth-first search for a `call` cycle, iteratively.
///
/// A chain of subroutines is as long as the file allows, so the walk keeps its
/// own stack: recursing once per edge overflows the thread stack and aborts the
/// process before the cycle check can report anything. `work` is that stack —
/// its node column is the current path, so a callee already on it closes a
/// cycle.
fn find_cycle(graph: &BTreeMap<SubId, Vec<(SubId, Span)>>) -> Option<Vec<SubId>> {
    let mut done = BTreeSet::new();
    for root in graph.keys().copied() {
        if done.contains(&root) {
            continue;
        }
        let mut work = vec![(root, 0usize)];
        while let Some((id, edge)) = work.last_mut() {
            let id = *id;
            let next = graph.get(&id).and_then(|edges| edges.get(*edge)).copied();
            let Some((callee, _)) = next else {
                done.insert(id);
                work.pop();
                continue;
            };
            *edge += 1;
            if let Some(at) = work.iter().position(|(entry, _)| *entry == callee) {
                let mut cycle: Vec<SubId> = work[at..].iter().map(|(id, _)| *id).collect();
                cycle.push(callee);
                return Some(cycle);
            }
            if !done.contains(&callee) {
                work.push((callee, 0));
            }
        }
    }
    None
}

fn name_for(id: SubId, names: &BTreeMap<String, SubId>) -> String {
    names
        .iter()
        .find_map(|(name, candidate)| (*candidate == id).then(|| name.clone()))
        .unwrap_or_else(|| format!("sub#{}", id.0))
}

fn is_reserved(name: &str) -> bool {
    matches!(
        name,
        "var"
            | "static"
            | "hash"
            | "lookup"
            | "fetch"
            | "miss"
            | "pass"
            | "abandon"
            | "deliver"
            | "synth"
            | "error"
            | "fail"
            | "restart"
            | "retry"
            | "pipe"
            | "purge"
    )
}

/// `vcl_` names a hook, never a user subroutine — that is Varnish's rule too.
///
/// Anything with the prefix that is not one of the phases is therefore an
/// error here rather than an ordinary sub that turns out to be uncalled, which
/// is what a mistyped hook name used to be reported as.
fn is_unsupported_hook(name: &str) -> bool {
    name.starts_with("vcl_")
}

/// The Varnish hooks a tenant has no phase for. A name in this list is a
/// real hook the tenant cannot reach; anything else with the prefix is a typo.
fn is_varnish_hook(name: &str) -> bool {
    matches!(
        name,
        "vcl_purge" | "vcl_pipe" | "vcl_connect" | "vcl_init" | "vcl_fini"
    )
}

const HOOKS: &str = "vcl_recv, vcl_hash, vcl_hit, vcl_miss, vcl_pass, vcl_deliver, vcl_synth, \
                     vcl_backend_fetch, vcl_backend_response and vcl_backend_error";

fn unsupported_hook(name: &str, span: Span) -> Diagnostic {
    let message = if is_varnish_hook(name) {
        format!("sub {name} is not a hook a tenant policy can define")
    } else {
        format!("sub {name} is not a VCL hook, and the 'vcl_' prefix names hooks only")
    };
    Diagnostic::error(span, message).with_help(match name {
        "vcl_purge" => {
            "purging belongs to the Varnish VCL that forks this tenant".to_string()
        }
        "vcl_pipe" | "vcl_connect" => {
            "piping and tunnelling are host-controlled".to_string()
        }
        "vcl_init" | "vcl_fini" => {
            "a tenant has no per-VCL state; backends and directors belong to the Varnish \
             VCL that forks this tenant"
                .to_string()
        }
        _ => format!("the hooks are {HOOKS}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every Varnish hook Carapace has no phase for is refused by name, with
    /// the owner of the decision in the help. A hook missing from the list
    /// would instead be reported as an uncalled subroutine, which says nothing
    /// about why it is uncalled.
    #[test]
    fn every_varnish_hook_without_a_phase_is_refused_by_name() {
        for hook in ["vcl_purge", "vcl_pipe", "vcl_connect", "vcl_init", "vcl_fini"] {
            let source = format!("vcl 4.1; sub {hook} {{ }} sub vcl_recv {{ return (hash); }}");
            let error = resolved(&source).unwrap_err().to_string();
            assert!(
                error.contains(&format!("sub {hook} is not a hook a tenant policy can define")),
                "{hook}: {error}"
            );
        }
    }

    /// A `vcl_` name that is not a hook at all — `vcl_backend_request`, which
    /// is what the *host* phase is called, is the likely one — is a hook typo,
    /// not a user subroutine nothing calls.
    #[test]
    fn an_unknown_vcl_prefixed_sub_is_a_hook_typo() {
        let error =
            resolved("vcl 4.1; sub vcl_backend_request { } sub vcl_recv { return (hash); }")
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("sub vcl_backend_request is not a VCL hook"),
            "{error}"
        );
        assert!(error.contains("the hooks are vcl_recv"), "{error}");
    }

    /// Hook names are case-sensitive, so `VCL_recv` is a legal user sub that
    /// nothing calls. The diagnostic has to say which of the two it is.
    #[test]
    fn a_miscased_hook_name_is_reported_as_the_case_mistake_it_is() {
        let error = resolved("vcl 4.1; sub VCL_recv { } sub vcl_recv { return (hash); }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("sub VCL_recv is never called"), "{error}");
        assert!(error.contains("'vcl_recv' would be the hook"), "{error}");
    }
    use crate::{lexer, parser};

    fn resolved(source: &str) -> Result<ResolvedProgram, Diagnostics> {
        resolve(source, parser::parse(source, &lexer::lex(source)?)?)
    }

    /// A long `call` chain must not recurse the cycle search off the stack.
    #[test]
    fn deep_call_chain_is_a_diagnostic_rather_than_a_stack_overflow() {
        let mut source = String::from("vcl 4.1; ");
        for index in 0..2_000 {
            source.push_str(&format!("sub s{index} {{ call s{}; }} ", index + 1));
        }
        source.push_str("sub s2000 { call s0; } sub vcl_recv { call s0; }");
        let error = resolved(&source).unwrap_err().to_string();
        assert!(error.contains("s0 -> s1 -> s2"), "{error}");
    }

    #[test]
    fn resolves_plain_and_deciding_subs() {
        let program = resolved("vcl 4.1; sub helper { return; } sub gate { return (hash); } sub vcl_recv { call helper; return (gate); }").unwrap();
        assert_eq!(program.subs.len(), 2);
        assert!(program
            .subs
            .values()
            .any(|sub| sub.kind == UserSubKind::Plain));
        assert!(program
            .subs
            .values()
            .any(|sub| sub.kind == UserSubKind::Deciding));
    }

    #[test]
    fn owns_duplicate_and_unsupported_hook_diagnostics() {
        let error = resolved("vcl 4.1; sub vcl_purge {} sub vcl_recv {} sub vcl_recv {}")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a hook a tenant policy can define"), "{error}");
        assert!(
            error.contains("duplicate declaration of vcl_recv"),
            "{error}"
        );
    }

    #[test]
    fn a_static_and_a_sub_cannot_share_a_name() {
        let error = resolved(
            "vcl 4.1; static var helper: INT; sub helper { return; } sub vcl_recv { return (hash); }",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicate declaration of helper"), "{error}");
        assert!(
            error.contains("the first declaration is the static"),
            "{error}"
        );

        let error = resolved(
            "vcl 4.1; sub helper { return; } static var helper: INT; sub vcl_recv { return (hash); }",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("the first declaration is the sub"),
            "{error}"
        );
    }
}
