use crate::ast::{self, BinaryOp, ExprKind, Literal, ReturnAction};
use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::ast::SetOp;
use crate::resolver::{ResolvedProgram, ResolvedUserSub, SubId, UserSubKind};
use crate::types::{
    global_slot_size, stat_name_ok, AclId, GlobalId, LocalId, Phase, StatKind, StatSpec, StaticId,
    StringConversion, ValueType, MAX_BLOCK_DEPTH, MAX_GLOBAL_STRING, MAX_REQUEST_GLOBALS,
    MAX_STATS, MAX_STAT_HELP, MAX_STAT_NAME,
};
use crate::vars::{self, HostVar, Lowering, WriteConstraint};
use crate::vmod::{Module, RecordSet, RegexSelect};
use crate::{CompileOptions, Diagnostic, Diagnostics, Span};
use vcl_rt::OpCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypedStatic {
    pub name: String,
    pub value_type: ValueType,
    pub initial: i64,
    /// The Varnish counter this static is. Every static has one: the
    /// annotation is required, and only metadata — it reaches
    /// `.carapace.stats` and changes nothing the static compiles to.
    pub stat: Option<StatSpec>,
}

/// A request global: one slot of the region the host copies in and out at
/// every phase boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypedGlobal {
    pub name: String,
    pub value_type: ValueType,
    /// What the slot holds when the client instance is created.
    pub initial: GlobalInit,
}

/// A request global's initialiser, which lands in the published image as
/// bytes: the host applies it without running guest code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GlobalInit {
    Scalar(i64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypedProgram {
    pub subs: Vec<TypedSub>,
    pub user_subs: BTreeMap<(Phase, SubId), TypedUserSub>,
    pub statics: Vec<TypedStatic>,
    pub globals: Vec<TypedGlobal>,
    /// Packed ACL entry tables, indexed by [`AclId`].
    pub acls: Vec<Vec<u8>>,
    /// Every regular-expression literal the policy spells, deduplicated, in
    /// first-use order. Published as `.carapace.regex` so the engine compiles
    /// the set once at warm rather than a thread compiling it per phase.
    pub patterns: Vec<String>,
    /// Things the policy does that compile, but not to what a Varnish author
    /// would expect. Carried out to [`crate::Compiled::warnings`], never
    /// fatal.
    pub warnings: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypedUserSub {
    pub id: SubId,
    pub name: String,
    pub statements: Vec<TypedStatement>,
    pub locals: Vec<ValueType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypedSub {
    pub phase: Phase,
    pub statements: Vec<TypedStatement>,
    pub locals: Vec<ValueType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypedStatement {
    Declare {
        local: LocalId,
        value_type: ValueType,
        init: Option<TypedExpr>,
        span: Span,
    },
    SetLocal {
        local: LocalId,
        value: TypedExpr,
        span: Span,
    },
    SetStatic {
        static_id: StaticId,
        value: TypedExpr,
        span: Span,
    },
    SetGlobal {
        global: GlobalId,
        value: TypedExpr,
        span: Span,
    },
    Inlined {
        sub: String,
        body: Vec<TypedStatement>,
        deciding: bool,
        span: Span,
    },
    Call {
        id: SubId,
        sub: String,
        deciding: bool,
        span: Span,
    },
    SetHeader {
        response: bool,
        name: String,
        value: TypedExpr,
        span: Span,
    },
    UnsetHeader {
        response: bool,
        name: String,
        span: Span,
    },
    SetUrl {
        value: TypedExpr,
        span: Span,
    },
    /// A write through the generic host variable call.
    SetVar {
        var: HostVar,
        value: TypedExpr,
        span: Span,
    },
    /// `set resp.body` in vcl_synth, `set beresp.body` in vcl_backend_error.
    SetBody {
        value: TypedExpr,
        span: Span,
    },
    /// `hash_data()` in vcl_hash.
    HashData {
        value: TypedExpr,
        span: Span,
    },
    /// A typed cache-duration assignment. Desugaring owns evaluating this
    /// constant expression and selecting the concrete ABI operation.
    SetCacheDuration {
        lowering: Lowering,
        target: String,
        target_span: Span,
        value: TypedExpr,
        span: Span,
    },
    SetTtl {
        seconds: u64,
        span: Span,
    },
    SetStaleWhileRevalidate {
        seconds: u64,
        span: Span,
    },
    SetStaleIfError {
        seconds: u64,
        span: Span,
    },
    SetUncacheable {
        span: Span,
    },
    /// `std.collect(hdr, sep)`: replace every header of one name with a
    /// single header holding their values joined.
    Collect {
        response: bool,
        name: String,
        separator: TypedExpr,
        span: Span,
    },
    /// A `cookieplus`, `urlplus` or `headerplus` statement.
    ///
    /// One variant for all three, because the compiler treats them as one
    /// mechanism; see [`crate::vmod`].
    Vmod {
        module: Module,
        action: VmodAction,
        span: Span,
    },
    Log {
        value: TypedExpr,
        span: Span,
    },
    Synthetic {
        value: TypedExpr,
        span: Span,
    },
    If {
        branches: Vec<(TypedExpr, Vec<TypedStatement>)>,
        otherwise: Vec<TypedStatement>,
        span: Span,
    },
    Return {
        action: TypedReturnAction,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypedExpr {
    pub kind: TypedExprKind,
    pub value_type: ValueType,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypedExprKind {
    String(String),
    Integer(i64),
    Duration(u64),
    Boolean(bool),
    Local(LocalId),
    Static(StaticId),
    Global(GlobalId),
    Read {
        lowering: Lowering,
        name: Option<String>,
    },
    HeaderPresent {
        response: bool,
        name: String,
    },
    Digest {
        function: DigestFunction,
        arguments: Vec<TypedExpr>,
    },
    Regsub {
        subject: Box<TypedExpr>,
        pattern: Box<TypedExpr>,
        replacement: Box<TypedExpr>,
        all: bool,
    },
    AclMatch {
        address: Box<TypedExpr>,
        acl: AclId,
        negated: bool,
    },
    /// A flat `+` run over two or more string operands, in source order.
    Concat(Vec<TypedExpr>),
    ToString {
        value: Box<TypedExpr>,
        conversion: StringConversion,
    },
    StringCase {
        value: Box<TypedExpr>,
        upper: bool,
    },
    Strstr {
        haystack: Box<TypedExpr>,
        needle: Box<TypedExpr>,
    },
    StringPredicate {
        value: Box<TypedExpr>,
        affix: Box<TypedExpr>,
        prefix: bool,
    },
    ParseInteger {
        value: Box<TypedExpr>,
        fallback: Box<TypedExpr>,
    },
    ParseDuration {
        value: Box<TypedExpr>,
        fallback: Box<TypedExpr>,
    },
    ParseTime {
        value: Box<TypedExpr>,
        fallback: Box<TypedExpr>,
    },
    Fnmatch {
        pattern: Box<TypedExpr>,
        subject: Box<TypedExpr>,
        pathname: Box<TypedExpr>,
        noescape: Box<TypedExpr>,
        period: Box<TypedExpr>,
    },
    Querysort {
        value: Box<TypedExpr>,
    },
    /// A `str` call whose result is an integer.  `other` and `separators`
    /// are the empty string for the operations that take neither.
    StrTest {
        op: vcl_rt::StrTest,
        subject: Box<TypedExpr>,
        other: Box<TypedExpr>,
        separators: Box<TypedExpr>,
    },
    /// `str.substr` and `str.reverse`: a string built from one subject and
    /// two integers, which `reverse` leaves at zero.
    StrEdit {
        op: vcl_rt::StrEdit,
        subject: Box<TypedExpr>,
        count: Box<TypedExpr>,
        offset: Box<TypedExpr>,
    },
    /// `str.split(S, N, SEP)`.
    StrSplit {
        subject: Box<TypedExpr>,
        index: Box<TypedExpr>,
        separators: Box<TypedExpr>,
    },
    /// A vmod read producing a string, with the VCL `default` argument the
    /// runtime falls back to when the value is absent.
    VmodRead {
        module: Module,
        code: i64,
        arguments: Vec<TypedExpr>,
        default: Box<TypedExpr>,
        /// A `_regex` form's project/match step; its bitmaps become the call's
        /// one runtime argument.
        regex: Option<RegexSelect>,
    },
    /// A vmod read producing an integer.
    VmodCount {
        module: Module,
        code: i64,
        arguments: Vec<TypedExpr>,
        regex: Option<RegexSelect>,
    },
    Not(Box<TypedExpr>),
    Negate(Box<TypedExpr>),
    Binary {
        op: BinaryOp,
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
    },
    /// `std.max` / `std.min` over two INTs.
    Extreme {
        max: bool,
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestFunction {
    HashSha256,
    HmacSha256,
    VerifyHmacSha256,
}

/// The request-cookie operations supported by the first cookieplus slice.
/// State is owned by the generated hook, never by the runtime image, so a VM
/// What a vmod statement does to its module's per-hook state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VmodAction {
    /// Seed the state from the module's source: `init()`, `reset()`, and the
    /// implicit seeding the hook prologue performs.
    Reseed {
        /// headerplus: the header map the phase writes.
        response: bool,
        /// `setcookie_parse(header)`: the header the state is seeded from
        /// instead of the module's own source.
        source: Option<String>,
    },
    /// Mutate the state through a runtime routine.
    Transform {
        code: i64,
        arguments: Vec<TypedExpr>,
        regex: Option<RegexSelect>,
    },
    /// Store the state back through the host.
    Write {
        /// The operation that renders the state, unused by headerplus.
        code: i64,
        response: bool,
        /// `setcookie_write([header])`: the header the rendered state is
        /// committed to.
        header: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypedReturnAction {
    /// The hook ended without a return: the Varnish VCL around the tenant
    /// carries on, which is where Varnish's built-in VCL runs.
    Next,
    Hash,
    Lookup,
    Fetch,
    Miss,
    Pass,
    Abandon,
    Deliver,
    Fail,
    Synth {
        status: u16,
        reason: String,
    },
    Error {
        status: u16,
        reason: String,
    },
    Leave,
}

pub(crate) fn check(
    source: &str,
    program: ResolvedProgram,
    options: &CompileOptions,
) -> Result<TypedProgram, Diagnostics> {
    debug_assert!(vars::VARIABLES
        .iter()
        .all(|spec| !spec.readable.is_empty() || !spec.writable.is_empty()));
    let mut errors = Vec::new();
    let collected = Collector::default();
    let mut statics = Vec::new();
    let mut static_names = BTreeMap::new();
    for declaration in program.statics.iter() {
        let value_type = ValueType::from(declaration.value_type);
        // A static without `stat` is refused, but still declared, so a use
        // of the name is not also reported as undeclared.
        let Some(annotation) = declaration.stat.as_ref() else {
            errors.push(static_refused(declaration.span));
            let id = StaticId(statics.len() as u32);
            static_names.insert(declaration.name.clone(), (value_type, id));
            statics.push(TypedStatic {
                name: declaration.name.clone(),
                value_type,
                initial: 0,
                stat: None,
            });
            continue;
        };
        if value_type == ValueType::String {
            errors.push(Diagnostic::error(
                declaration.name_span,
                "a static cannot have type STRING because strings live in the per-phase arena",
            ));
            let id = StaticId(statics.len() as u32);
            static_names.insert(declaration.name.clone(), (value_type, id));
            statics.push(TypedStatic {
                name: declaration.name.clone(),
                value_type,
                initial: 0,
                stat: None,
            });
            continue;
        }
        let initial = match declaration.init.as_ref() {
            None => 0,
            Some(expr) => match static_literal(expr, value_type) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(error);
                    0
                }
            },
        };
        let stat = check_stat(declaration, annotation, value_type, &mut errors);
        if stat.is_some() && statics.iter().filter(|s: &&TypedStatic| s.stat.is_some()).count() == MAX_STATS {
            errors.push(Diagnostic::error(
                declaration.name_span,
                format!("a policy declares at most {MAX_STATS} statistics"),
            ));
        }
        let id = StaticId(statics.len() as u32);
        static_names.insert(declaration.name.clone(), (value_type, id));
        statics.push(TypedStatic {
            name: declaration.name.clone(),
            value_type,
            initial,
            stat,
        });
    }

    let (globals, global_names) = check_globals(&program, &mut errors);

    let reachable = reachable_user_subs(&program);
    let shared = Shared {
        syntax: program.syntax,
        options,
        subs: &program.subs,
        sub_names: &program.sub_names,
        statics: &static_names,
        globals: &global_names,
        acls: &program.acl_names,
        collected: &collected,
    };
    let mut subs = Vec::new();
    for sub in program.hooks.iter() {
        let phase = sub.phase;
        let mut checker = Checker::new(phase, shared);
        let mut statements = checker.check_block(sub.statements.clone(), false);
        if !matches!(statements.last(), Some(TypedStatement::Return { .. })) {
            statements.push(TypedStatement::Return {
                action: TypedReturnAction::Next,
                span: sub.name_span,
            });
        }
        errors.append(&mut checker.errors);
        subs.push(TypedSub {
            phase,
            statements,
            locals: checker.locals,
        });
    }

    let mut user_subs = BTreeMap::new();
    for &(phase, id) in reachable.keys() {
        let sub = &program.subs[&id];
        let mut checker = Checker::new(phase, shared);
        checker.current_user_kind = Some(sub.kind);
        let statements = checker.check_block(sub.statements.clone(), false);
        if !checker.errors.is_empty() {
            let notes = call_path(phase, id, &reachable);
            for error in &mut checker.errors {
                error.notes.extend(notes.iter().cloned());
            }
        }
        errors.append(&mut checker.errors);
        user_subs.insert(
            (phase, id),
            TypedUserSub {
                id,
                name: sub.name.clone(),
                statements,
                locals: checker.locals,
            },
        );
    }
    if errors.is_empty() {
        Ok(TypedProgram {
            subs,
            user_subs,
            statics,
            globals,
            acls: program.acls.iter().map(|acl| acl.table.clone()).collect(),
            patterns: collected.patterns.into_vec(),
            warnings: collected.warnings.into_vec(),
        })
    } else {
        Err(Diagnostics::new(source, errors))
    }
}

/// The calls one block makes, in source order, nested blocks included.
///
/// Nested blocks are walked with an explicit stack, for the reason given on
/// [`reachable_user_subs`].
fn block_calls(statements: &[ast::Statement]) -> Vec<(&str, Span)> {
    let mut calls = Vec::new();
    let mut blocks = vec![statements.iter()];
    while let Some(block) = blocks.last_mut() {
        let Some(statement) = block.next() else {
            blocks.pop();
            continue;
        };
        match statement {
            ast::Statement::Call { sub, sub_span, .. }
            | ast::Statement::Return {
                action: ReturnAction::Sub(sub, sub_span),
                ..
            } => calls.push((sub.as_str(), *sub_span)),
            ast::Statement::If {
                branches,
                otherwise,
                ..
            } => {
                // Pushed in reverse so they pop back in source order.
                blocks.push(otherwise.iter());
                for (_, body) in branches.iter().rev() {
                    blocks.push(body.iter());
                }
            }
            ast::Statement::Declare { .. }
            | ast::Statement::Set { .. }
            | ast::Statement::Unset { .. }
            | ast::Statement::Log { .. }
            | ast::Statement::Synthetic { .. }
            | ast::Statement::HashData { .. }
            | ast::Statement::BuiltinCall { .. }
            | ast::Statement::Return { .. } => {}
        }
    }
    calls
}

/// The call that first reached a subroutine: one edge, not a whole path.
struct ReachedBy<'a> {
    span: Span,
    caller: &'a str,
    parent: Option<SubId>,
}

/// Every user subroutine each hook can reach, and the call that reached it.
///
/// The call graph is acyclic but its depth is bounded only by the size of the
/// configuration, and `desugar` enforces [`MAX_BLOCK_DEPTH`] over call chains
/// only after this runs. A candidate deep enough to exceed that limit has to
/// be *rejected*, so this walk may not fall over first: it keeps its own
/// stack rather than recursing, and it records one edge per subroutine rather
/// than a copy of the path that reached it. Storing paths costs O(n^2) in the
/// length of a call chain, which is a heap exhaustion in the same place a
/// recursive walk is a stack overflow. [`call_path`] rebuilds a path from the
/// edges, and only a subroutine that actually failed needs one.
fn reachable_user_subs(program: &ResolvedProgram) -> BTreeMap<(Phase, SubId), ReachedBy<'_>> {
    struct Frame<'a> {
        sub: Option<SubId>,
        caller: &'a str,
        calls: std::vec::IntoIter<(&'a str, Span)>,
    }

    let mut found = BTreeMap::new();
    for hook in &program.hooks {
        let phase = hook.phase;
        let mut stack = vec![Frame {
            sub: None,
            caller: phase.vcl_name(),
            calls: block_calls(&hook.statements).into_iter(),
        }];
        while let Some(frame) = stack.last_mut() {
            let Some((name, span)) = frame.calls.next() else {
                stack.pop();
                continue;
            };
            let Some(id) = program.sub_names.get(name).copied() else {
                continue;
            };
            if found.contains_key(&(phase, id)) {
                continue;
            }
            let reached = ReachedBy {
                span,
                caller: frame.caller,
                parent: frame.sub,
            };
            found.insert((phase, id), reached);
            if let Some(sub) = program.subs.get(&id) {
                stack.push(Frame {
                    sub: Some(id),
                    caller: &sub.name,
                    calls: block_calls(&sub.statements).into_iter(),
                });
            }
        }
    }
    found
}

/// The chain of calls reaching `id`, outermost first, rebuilt from the edges.
fn call_path(
    phase: Phase,
    id: SubId,
    reached: &BTreeMap<(Phase, SubId), ReachedBy<'_>>,
) -> Vec<(Span, String)> {
    let mut path = Vec::new();
    let mut cursor = Some(id);
    while let Some(current) = cursor {
        let Some(edge) = reached.get(&(phase, current)) else {
            break;
        };
        path.push((edge.span, format!("called from {}", edge.caller)));
        cursor = edge.parent;
    }
    path.reverse();
    path
}

/// Every regular-expression literal one policy spells, collected as the type
/// checker validates it.
///
/// One choke point, [`check_pattern`], sees all of them: `~`, `!~`, `regsub`,
/// `regsuball` and the vmod `_regex` forms all require a literal. The table
/// goes into the ELF, so the engine — which is the tenant-scoped unit — owns
/// the compiled patterns instead of a worker thread's shared cache.
#[derive(Default)]
pub(crate) struct PatternTable {
    patterns: RefCell<Vec<String>>,
}

/// The two things every phase's checker adds to and the checked program
/// carries out: the regular-expression literals the policy spells, and what
/// the compiler has to say about a policy it will nonetheless build.
///
/// One borrow rather than two, because the deeper free functions take
/// `&TypeEnv` and not `&mut Checker`, and a checker is built per phase.
#[derive(Default)]
pub(crate) struct Collector {
    patterns: PatternTable,
    warnings: WarningSink,
}

/// Warnings collected while checking one policy.
///
/// Shared by every phase's checker rather than owned per checker, so the
/// deeper free functions — which take `&TypeEnv` and not `&mut Checker` —
/// can add to it.
#[derive(Default)]
pub(crate) struct WarningSink {
    warnings: RefCell<Vec<Diagnostic>>,
}

impl WarningSink {
    fn push(&self, warning: Diagnostic) {
        self.warnings.borrow_mut().push(warning);
    }

    fn into_vec(self) -> Vec<Diagnostic> {
        self.warnings.into_inner()
    }
}

/// How many distinct patterns one policy may spell.
///
/// The engine compiles every one of them at `warm`, so this is what bounds
/// that work. Nothing a person writes comes close; a generated policy that
/// does is refused with the number rather than making every VM start slow.
const MAX_POLICY_PATTERNS: usize = 256;

impl PatternTable {
    fn record(&self, pattern: &str) -> Result<(), String> {
        let mut patterns = self.patterns.borrow_mut();
        if patterns.iter().any(|known| known == pattern) {
            return Ok(());
        }
        if patterns.len() >= MAX_POLICY_PATTERNS {
            return Err(format!(
                "a policy may spell at most {MAX_POLICY_PATTERNS} distinct patterns"
            ));
        }
        patterns.push(pattern.to_string());
        Ok(())
    }

    fn into_vec(self) -> Vec<String> {
        self.patterns.into_inner()
    }
}

struct Checker<'a> {
    phase: Phase,
    /// The declared syntax level, times ten; `std.syntax` compares against it.
    syntax: u32,
    options: &'a CompileOptions,
    subs: &'a BTreeMap<SubId, ResolvedUserSub>,
    sub_names: &'a BTreeMap<String, SubId>,
    statics: &'a BTreeMap<String, (ValueType, StaticId)>,
    globals: &'a BTreeMap<String, (ValueType, GlobalId)>,
    acls: &'a BTreeMap<String, AclId>,
    collected: &'a Collector,
    scopes: Vec<BTreeMap<String, (ValueType, LocalId)>>,
    locals: Vec<ValueType>,
    current_user_kind: Option<UserSubKind>,
    depth: usize,
    errors: Vec<Diagnostic>,
}

/// What every phase's checker reads, and none of them changes.
///
/// One value rather than six parameters: the three `Checker::new` call sites
/// pass the same tables, so a seventh has one place to be added rather than
/// four.
#[derive(Clone, Copy)]
struct Shared<'a> {
    syntax: u32,
    options: &'a CompileOptions,
    subs: &'a BTreeMap<SubId, ResolvedUserSub>,
    sub_names: &'a BTreeMap<String, SubId>,
    statics: &'a BTreeMap<String, (ValueType, StaticId)>,
    globals: &'a BTreeMap<String, (ValueType, GlobalId)>,
    acls: &'a BTreeMap<String, AclId>,
    collected: &'a Collector,
}

impl<'a> Checker<'a> {
    fn new(phase: Phase, shared: Shared<'a>) -> Self {
        Self {
            phase,
            syntax: shared.syntax,
            options: shared.options,
            subs: shared.subs,
            sub_names: shared.sub_names,
            statics: shared.statics,
            globals: shared.globals,
            acls: shared.acls,
            collected: shared.collected,
            scopes: vec![BTreeMap::new()],
            locals: Vec::new(),
            current_user_kind: None,
            depth: 0,
            errors: Vec::new(),
        }
    }

    fn env(&self) -> TypeEnv<'_> {
        TypeEnv {
            scopes: &self.scopes,
            statics: self.statics,
            globals: self.globals,
            acls: self.acls,
            collected: self.collected,
            syntax: self.syntax,
        }
    }

    fn check_block(&mut self, source: Vec<ast::Statement>, nested: bool) -> Vec<TypedStatement> {
        if self.depth >= MAX_BLOCK_DEPTH {
            if let Some(statement) = source.first() {
                self.errors.push(
                    Diagnostic::error(
                        statement_span(statement),
                        format!(
                            "blocks and user-subroutine calls may not nest more than \
                             {MAX_BLOCK_DEPTH} deep"
                        ),
                    )
                    .with_help("flatten the nesting or shorten the chain of 'call' statements"),
                );
            }
            return Vec::new();
        }
        self.depth += 1;
        if nested {
            self.scopes.push(BTreeMap::new());
        }
        let mut statements = Vec::new();
        for statement in source {
            match self.check_statement(statement) {
                Ok(statement) => statements.push(statement),
                Err(error) => self.errors.push(error),
            }
        }
        if nested {
            self.scopes.pop();
        }
        self.depth -= 1;
        statements
    }

    fn inline(
        &mut self,
        name: &str,
        span: Span,
        deciding: bool,
    ) -> Result<TypedStatement, Diagnostic> {
        let id = self
            .sub_names
            .get(name)
            .copied()
            .ok_or_else(|| Diagnostic::error(span, format!("unknown subroutine '{name}'")))?;
        let sub = self
            .subs
            .get(&id)
            .ok_or_else(|| Diagnostic::error(span, format!("'{name}' is not a user subroutine")))?;
        debug_assert_eq!(sub.kind == UserSubKind::Deciding, deciding);
        Ok(TypedStatement::Call {
            id,
            sub: sub.name.clone(),
            deciding,
            span,
        })
    }

    fn storage(&self, full_name: &str) -> Option<Storage> {
        let name = full_name.strip_prefix("var.")?;
        for scope in self.scopes.iter().rev() {
            if let Some((value_type, id)) = scope.get(name) {
                return Some(Storage::Local(*value_type, *id));
            }
        }
        // Innermost local, then request global, then static (R12). A local
        // may shadow neither, so the order never changes what a name means;
        // it only fixes where the lookup stops.
        if let Some((value_type, id)) = self.globals.get(name) {
            return Some(Storage::Global(*value_type, *id));
        }
        self.statics
            .get(name)
            .map(|(value_type, id)| Storage::Static(*value_type, *id))
    }

    fn check_statement(&mut self, statement: ast::Statement) -> Result<TypedStatement, Diagnostic> {
        match statement {
            ast::Statement::Declare { name, name_span, value_type, init, span } => {
                if self.statics.contains_key(&name)
                    || self.globals.contains_key(&name)
                    || self.scopes.iter().any(|scope| scope.contains_key(&name))
                {
                    return Err(Diagnostic::error(
                        name_span,
                        format!("var.{name} is already visible in this scope"),
                    ));
                }
                let value_type = ValueType::from(value_type);
                let init = init
                    .map(|expr| check_expr(self.phase, expr, &self.env()))
                    .transpose()?;
                if let Some(value) = &init {
                    require_type(&format!("var.{name}"), value_type, value)?;
                }
                let local = LocalId(self.locals.len() as u32);
                self.locals.push(value_type);
                self.scopes.last_mut().expect("scope exists").insert(name, (value_type, local));
                Ok(TypedStatement::Declare { local, value_type, init, span })
            }
            ast::Statement::Call { sub, sub_span, span } => self.inline(&sub, sub_span, false).map(|mut typed| {
                if let TypedStatement::Call { span: typed_span, .. } = &mut typed { *typed_span = span; }
                typed
            }),
            ast::Statement::BuiltinCall { function, arguments, span } if function == "std.collect" => {
                check_collect(self.phase, arguments, span, self.options, &self.env())
            }
            ast::Statement::BuiltinCall { function, arguments, span } => {
                check_vmod_statement(self.phase, &function, arguments, span, &self.env())
            }
            ast::Statement::Set { target, target_span, op, value, span } if target.starts_with("var.") => {
                let Some(storage) = self.storage(&target) else {
                    return Err(undeclared_storage(&target, target_span));
                };
                let value = check_expr(self.phase, value, &self.env())?;
                let value = match op {
                    SetOp::Assign => value,
                    SetOp::Add | SetOp::Subtract => {
                        compound_assignment(&target, target_span, storage, op, value)?
                    }
                };
                require_type(&target, storage.value_type(), &value)?;
                Ok(match storage {
                    Storage::Local(_, local) => TypedStatement::SetLocal { local, value, span },
                    Storage::Static(_, static_id) => TypedStatement::SetStatic { static_id, value, span },
                    Storage::Global(_, global) => TypedStatement::SetGlobal { global, value, span },
                })
            }
            ast::Statement::Set { target, target_span, op, .. } if op != SetOp::Assign => {
                Err(Diagnostic::error(
                    target_span,
                    format!(
                        "'{}' applies to an INT variable, and {target} is not one",
                        op.spelling()
                    ),
                ))
            }
            ast::Statement::Unset { target, target_span, .. } if target.starts_with("var.") => {
                Err(Diagnostic::error(
                    target_span,
                    format!("unset {target} is not allowed; locals die with the phase and request globals with the request"),
                ))
            }
            ast::Statement::If { branches, otherwise, span } => {
                let mut typed_branches = Vec::with_capacity(branches.len());
                for (condition, body) in branches {
                    let condition = check_expr(self.phase, condition, &self.env())?;
                    let condition_type = condition.value_type;
                    let condition_span = condition.span;
                    let Some(condition) = coerce_boolean(condition) else {
                        return Err(Diagnostic::error(condition_span, format!(
                            "if condition expects BOOL, found {}", type_name(condition_type))));
                    };
                    typed_branches.push((condition, self.check_block(body, true)));
                }
                let otherwise = self.check_block(otherwise, true);
                Ok(TypedStatement::If { branches: typed_branches, otherwise, span })
            }
            ast::Statement::Return { action: ReturnAction::Bare, span }
                if self.current_user_kind == Some(UserSubKind::Plain) =>
            {
                Ok(TypedStatement::Return { action: TypedReturnAction::Leave, span })
            }
            ast::Statement::Return { action: ReturnAction::Sub(name, name_span), span } => {
                self.inline(&name, name_span, true).map(|mut typed| {
                    if let TypedStatement::Call { span: typed_span, .. } = &mut typed { *typed_span = span; }
                    typed
                })
            }
            other @ (ast::Statement::Set { .. }
            | ast::Statement::Unset { .. }
            | ast::Statement::Log { .. }
            | ast::Statement::Synthetic { .. }
            | ast::Statement::HashData { .. }
            | ast::Statement::Return { .. }) => {
                check_host_statement(self.phase, other, self.options, &self.env())
            }
        }
    }
}

#[derive(Clone, Copy)]
struct TypeEnv<'a> {
    scopes: &'a [BTreeMap<String, (ValueType, LocalId)>],
    statics: &'a BTreeMap<String, (ValueType, StaticId)>,
    globals: &'a BTreeMap<String, (ValueType, GlobalId)>,
    acls: &'a BTreeMap<String, AclId>,
    collected: &'a Collector,
    /// The declared syntax level, times ten. See [`ast::Program::syntax`].
    syntax: u32,
}

impl TypeEnv<'_> {
    /// The refusal an unknown name gets.
    ///
    /// Locals and statics are declared bare (`var n: INT;`) and read through
    /// the `var.` namespace, which is the one mistake worth naming: a bare
    /// `n` is otherwise indistinguishable from a misspelt VCL variable.
    fn unknown_variable(&self, name: &str, span: Span) -> Diagnostic {
        let declared = self.scopes.iter().any(|scope| scope.contains_key(name))
            || self.statics.contains_key(name)
            || self.globals.contains_key(name);
        if declared {
            unknown_variable(name, span).with_help(format!(
                "'{name}' is declared in this policy; locals, request globals and \
                 statics are read through the 'var.' namespace, so write 'var.{name}'"
            ))
        } else {
            unknown_variable(name, span)
        }
    }
}

#[derive(Clone, Copy)]
enum Storage {
    Local(ValueType, LocalId),
    Static(ValueType, StaticId),
    Global(ValueType, GlobalId),
}

impl Storage {
    fn value_type(self) -> ValueType {
        match self {
            Self::Local(value_type, _)
            | Self::Static(value_type, _)
            | Self::Global(value_type, _) => value_type,
        }
    }
}

/// Check a `stat` annotation and resolve it to what the ELF row carries.
///
/// Returns `None` when the annotation is rejected — the static itself still
/// exists and still compiles; only the exported statistic is dropped, and the
/// diagnostic that dropped it fails the compile anyway.
fn check_stat(
    declaration: &crate::resolver::ResolvedStatic,
    annotation: &ast::StatAnnotation,
    value_type: ValueType,
    errors: &mut Vec<Diagnostic>,
) -> Option<StatSpec> {
    // `INT` only. `BOOL` and `TIME` are not quantities; `DURATION` is one and
    // is the named extension, waiting on `scalar_metric` learning `divisor`.
    let refusal = match value_type {
        ValueType::Integer => None,
        // A quantity, and the obvious extension — it would set a divisor and
        // name the family `_seconds` — but `divisor` is documented as
        // ignored by every kind but a histogram, so it is not free.
        ValueType::Duration => Some((
            "a DURATION static cannot be a statistic yet",
            "store nanoseconds in an INT static and annotate that",
        )),
        ValueType::Boolean => Some((
            "a BOOL static cannot be a statistic",
            "a statistic is a quantity, so it must be INT",
        )),
        ValueType::Time => Some((
            "a TIME static cannot be a statistic",
            "a statistic is a quantity, so it must be INT",
        )),
        // Already refused at the type: a static cannot be either of these.
        ValueType::String | ValueType::Ip => Some((
            "this static cannot be a statistic",
            "a statistic is a quantity, so it must be INT",
        )),
    };
    if let Some((what, help)) = refusal {
        errors.push(Diagnostic::error(declaration.name_span, what).with_help(help));
        return None;
    }

    // A min accumulator needs a sentinel start, and the host primes the word
    // to `i64::MAX` after `main` so the sentinel stays out of the language.
    // An initialiser would be overwritten, so it is refused rather than
    // silently ignored.
    if annotation.kind == StatKind::Min {
        if let Some(init) = declaration.init.as_ref() {
            errors.push(
                Diagnostic::error(init.span, "a 'min' statistic cannot have an initializer")
                    .with_help("the host primes a 'min' word to its sentinel after main() runs"),
            );
            return None;
        }
    }

    // The name reaches a Varnish counter name, so it is held to a safe
    // grammar and to a length. `__` is Carapace's separator between a tenant
    // and a name, refused here too so a policy moves between the two
    // unchanged.
    if declaration.name.contains("__") {
        errors.push(
            Diagnostic::error(
                declaration.name_span,
                "a statistic name may not contain '__'",
            )
            .with_help("'__' is reserved as the separator between a tenant and a name"),
        );
        return None;
    }
    if !stat_name_ok(&declaration.name) {
        errors.push(Diagnostic::error(
            declaration.name_span,
            "a statistic name must match [a-z][a-z0-9_]*, not ending in '_'",
        ));
        return None;
    }
    if declaration.name.len() > MAX_STAT_NAME {
        errors.push(Diagnostic::error(
            declaration.name_span,
            format!("a statistic name is at most {MAX_STAT_NAME} bytes"),
        ));
        return None;
    }

    let help = match annotation.help.as_ref() {
        Some(help) => {
            if help.len() > MAX_STAT_HELP {
                errors.push(Diagnostic::error(
                    annotation.help_span,
                    format!("a statistic description is at most {MAX_STAT_HELP} bytes"),
                ));
                return None;
            }
            if help.as_bytes().contains(&0) {
                errors.push(Diagnostic::error(
                    annotation.help_span,
                    "a statistic description contains a NUL byte",
                ));
                return None;
            }
            help.clone()
        }
        // Derived from the declaration and nothing else. Never the source
        // path: two programs of one tenant declaring one name from different
        // files would then disagree about the help.
        None => format!(
            "VCL-declared {} {}",
            annotation.kind.word(),
            declaration.name
        ),
    };

    Some(StatSpec {
        kind: annotation.kind,
        help,
    })
}

/// The refusal a `static var` without `stat` gets.
///
/// Varnish runs each request in a fresh fork of the VM, so a plain static
/// could only ever hold its initialiser: a write would vanish with the
/// request. A statistic is the exception, because the host folds what the
/// request did to it into a Varnish counter before the fork goes away.
fn static_refused(span: Span) -> Diagnostic {
    Diagnostic::error(
        span,
        "static variables are not supported: every request runs in a fresh VM fork, so nothing \
         persists between requests",
    )
    .with_help(
        "use a request global ('var NAME: TYPE;' at the top level) instead, or annotate it \
         with 'stat' to count into a Varnish counter",
    )
}

/// `set var.x += e` and `-=`: the read, add and store that `set var.x =
/// var.x + e` already is. INT only.
fn compound_assignment(
    target: &str,
    target_span: Span,
    storage: Storage,
    op: SetOp,
    value: TypedExpr,
) -> Result<TypedExpr, Diagnostic> {
    let value_type = storage.value_type();
    if value_type != ValueType::Integer {
        return Err(Diagnostic::error(
            target_span,
            format!(
                "'{}' applies to an INT, and {target} is {}",
                op.spelling(),
                type_name(value_type)
            ),
        ));
    }
    require_type(target, ValueType::Integer, &value)?;
    let current = TypedExpr {
        kind: match storage {
            Storage::Local(_, local) => TypedExprKind::Local(local),
            Storage::Static(_, id) => TypedExprKind::Static(id),
            Storage::Global(_, id) => TypedExprKind::Global(id),
        },
        value_type,
        span: target_span,
    };
    let span = Span::new(target_span.start, value.span.end);
    Ok(TypedExpr {
        kind: TypedExprKind::Binary {
            op: if op == SetOp::Add {
                BinaryOp::Add
            } else {
                BinaryOp::Subtract
            },
            left: Box::new(current),
            right: Box::new(value),
        },
        value_type,
        span,
    })
}

/// Type the request globals and hold their region to its bound (R11).
///
/// A global whose declaration is refused is still given an id, typed as
/// declared, so its uses report nothing further: the one diagnostic that
/// refused it fails the compile anyway.
fn check_globals(
    program: &ResolvedProgram,
    errors: &mut Vec<Diagnostic>,
) -> (Vec<TypedGlobal>, BTreeMap<String, (ValueType, GlobalId)>) {
    let mut globals = Vec::new();
    let mut names = BTreeMap::new();
    let mut region = 0u64;
    for declaration in &program.globals {
        let value_type = ValueType::from(declaration.value_type);
        if value_type == ValueType::Time {
            errors.push(
                Diagnostic::error(
                    declaration.name_span,
                    "a request global cannot have type TIME",
                )
                .with_help(
                    "read 'now' in the phase that needs it, or keep a DURATION in the global",
                ),
            );
        }
        let initial = match (declaration.init.as_ref(), value_type) {
            (None, ValueType::String) => GlobalInit::String(String::new()),
            (None, _) => GlobalInit::Scalar(0),
            (Some(expr), ValueType::String) => match &expr.kind {
                ExprKind::Literal(Literal::String(value)) => {
                    if value.len() as u64 > MAX_GLOBAL_STRING {
                        errors.push(Diagnostic::error(
                            expr.span,
                            format!(
                                "a STRING request global holds at most {MAX_GLOBAL_STRING} bytes"
                            ),
                        ));
                    }
                    GlobalInit::String(value.clone())
                }
                ExprKind::Literal(_) | ExprKind::Bool(_) => {
                    errors.push(Diagnostic::error(
                        expr.span,
                        "request global initialiser expects STRING",
                    ));
                    GlobalInit::String(String::new())
                }
                ExprKind::Variable(_)
                | ExprKind::Call { .. }
                | ExprKind::Not(_)
                | ExprKind::Negate(_)
                | ExprKind::Binary { .. }
                | ExprKind::AddChain(_) => {
                    errors.push(global_initialiser_not_literal(expr.span));
                    GlobalInit::String(String::new())
                }
            },
            (Some(expr), _) => match static_literal(expr, value_type) {
                Ok(value) => GlobalInit::Scalar(value),
                Err(mut error) => {
                    // The same literal rules as a static, with the reason
                    // restated for this storage class.
                    if error
                        .message
                        .starts_with("a static initialiser must be a literal")
                    {
                        error = global_initialiser_not_literal(expr.span);
                    } else if let Some(rest) = error.message.strip_prefix("static initialiser") {
                        error.message = format!("request global initialiser{rest}");
                    }
                    errors.push(error);
                    GlobalInit::Scalar(0)
                }
            },
        };
        region += global_slot_size(value_type);
        let id = GlobalId(globals.len() as u32);
        names.insert(declaration.name.clone(), (value_type, id));
        globals.push(TypedGlobal {
            name: declaration.name.clone(),
            value_type,
            initial,
        });
    }
    if region > MAX_REQUEST_GLOBALS {
        let mut diagnostic = Diagnostic::error(
            program.globals[0].name_span,
            format!(
                "request globals take {region} bytes, over the {MAX_REQUEST_GLOBALS}-byte region \
                 the host copies at every phase boundary"
            ),
        )
        .with_help(format!(
            "a STRING global takes {} bytes and any other type 8; declare fewer",
            global_slot_size(ValueType::String)
        ));
        for declaration in program.globals.iter().skip(1) {
            diagnostic = diagnostic.with_note(declaration.name_span, "also declared here");
        }
        errors.push(diagnostic);
    }
    (globals, names)
}

fn global_initialiser_not_literal(span: Span) -> Diagnostic {
    Diagnostic::error(
        span,
        "a request global's initialiser must be a literal: it is applied before any phase runs",
    )
    .with_help("assign it with 'set var.NAME = ...;' at the top of vcl_recv")
}

fn static_literal(expression: &ast::Expr, expected: ValueType) -> Result<i64, Diagnostic> {
    let value = match &expression.kind {
        ExprKind::Literal(Literal::Integer(value)) if expected == ValueType::Integer => *value,
        ExprKind::Literal(Literal::Duration(value)) if expected == ValueType::Duration => {
            i64::try_from(*value).map_err(|_| {
                Diagnostic::error(
                    expression.span,
                    "duration literal exceeds the signed 64-bit VCL range",
                )
            })?
        }
        ExprKind::Negate(value) if expected == ValueType::Integer => {
            let ExprKind::Literal(Literal::Integer(value)) = value.kind else {
                return Err(Diagnostic::error(
                    expression.span,
                    "a static initialiser must be a literal because it runs before any request exists",
                ));
            };
            value.checked_neg().ok_or_else(|| {
                Diagnostic::error(
                    expression.span,
                    "integer literal is outside the signed 64-bit VCL range",
                )
            })?
        }
        ExprKind::Negate(value) if expected == ValueType::Duration => {
            let ExprKind::Literal(Literal::Duration(value)) = value.kind else {
                return Err(Diagnostic::error(
                    expression.span,
                    "a static initialiser must be a literal because it runs before any request exists",
                ));
            };
            -i64::try_from(value).map_err(|_| {
                Diagnostic::error(
                    expression.span,
                    "duration literal exceeds the signed 64-bit VCL range",
                )
            })?
        }
        ExprKind::Bool(value) if expected == ValueType::Boolean => i64::from(*value),
        ExprKind::Literal(_) | ExprKind::Bool(_) => {
            return Err(Diagnostic::error(
                expression.span,
                format!("static initialiser expects {}", type_name(expected)),
            ))
        }
        ExprKind::Variable(_)
        | ExprKind::Call { .. }
        | ExprKind::Not(_)
        | ExprKind::Negate(_)
        | ExprKind::Binary { .. }
        | ExprKind::AddChain(_) => {
            return Err(Diagnostic::error(
                expression.span,
                "a static initialiser must be a literal because it runs before any request exists",
            ))
        }
    };
    Ok(value)
}

fn require_type(name: &str, expected: ValueType, value: &TypedExpr) -> Result<(), Diagnostic> {
    if value.value_type == expected {
        Ok(())
    } else {
        Err(Diagnostic::error(
            value.span,
            format!(
                "{name} expects {}, found {}",
                type_name(expected),
                type_name(value.value_type)
            ),
        ))
    }
}

fn statement_span(statement: &ast::Statement) -> Span {
    match statement {
        ast::Statement::Declare { span, .. }
        | ast::Statement::Call { span, .. }
        | ast::Statement::BuiltinCall { span, .. }
        | ast::Statement::Set { span, .. }
        | ast::Statement::Unset { span, .. }
        | ast::Statement::If { span, .. }
        | ast::Statement::Log { span, .. }
        | ast::Statement::Synthetic { span, .. }
        | ast::Statement::HashData { span, .. }
        | ast::Statement::Return { span, .. } => *span,
    }
}

fn undeclared_storage(name: &str, span: Span) -> Diagnostic {
    let bare = name.strip_prefix("var.").unwrap_or(name);
    Diagnostic::error(span, format!("{name} is not declared"))
        .with_help(format!("declare 'var {bare}: TYPE;' before this line"))
}

/// The refusal a read of a variable this phase does not own gets.
///
/// The common one in migrated VCL is the client request read from a backend
/// subroutine, or the other way round: Varnish's backend side has its own
/// copy, `bereq`, and the client side never sees it.
fn not_readable(name: &str, phase: Phase, span: Span) -> Diagnostic {
    let help = if phase.is_backend() && name.starts_with("req.") {
        let equivalent = name.replacen("req.", "bereq.", 1);
        format!(
            "{} runs on the backend request; read {equivalent} instead",
            phase.vcl_name()
        )
    } else if !phase.is_backend() && name.starts_with("bereq.") {
        let equivalent = name.replacen("bereq.", "req.", 1);
        format!(
            "{} runs on the client request; read {equivalent} instead",
            phase.vcl_name()
        )
    } else {
        "move this expression to the VCL sub that owns the variable".to_string()
    };
    Diagnostic::error(
        span,
        format!("{name} is not readable in {}", phase.vcl_name()),
    )
    .with_help(help)
}

/// The refusal a write to a variable this phase does not own gets.
///
/// "Move it to the owning sub" is only useful advice when a sub owns it. For
/// a variable no phase may write, it is a wrong answer that sends a migrating
/// author looking for a sub that does not exist, so those name what to write
/// instead.
fn not_writable(target: &str, phase: Phase, target_span: Span) -> Diagnostic {
    let owned_somewhere = vars::resolve(target).is_some_and(|(spec, _)| !spec.writable.is_empty());
    let help = if phase.is_backend() && target.starts_with("req.") {
        "the backend side writes its own copy of the request, bereq"
    } else if target == "req.backend_hint" || target == "bereq.backend" {
        "backends and directors belong to the Varnish VCL that forks this tenant"
    } else if let Some(help) = absent_variable_help(target) {
        help
    } else if owned_somewhere {
        "move this assignment to the VCL sub that owns the variable"
    } else {
        "no VCL sub may write this variable"
    };
    Diagnostic::error(
        target_span,
        format!("{target} is not writable in {}", phase.vcl_name()),
    )
    .with_help(help)
}

/// The identity rules a header write answers to, whatever spells it.
///
/// `set req.http.X` and `std.collect(req.http.X)` reach the same map through
/// the same syscall, so they are refused by the same rules. One owner is what
/// stops a second spelling from quietly acquiring a header the first one may
/// not touch.
fn check_header_identity(
    phase: Phase,
    spec: &vars::VariableSpec,
    header: &str,
    target_span: Span,
    options: &CompileOptions,
) -> Result<(), Diagnostic> {
    if vars::is_framing_header(header) {
        return Err(Diagnostic::error(
            target_span,
            format!("{header} is a framing or hop-by-hop header and cannot be set"),
        )
        .with_help("framing belongs to Varnish"));
    }
    if spec.write_constraint != WriteConstraint::ClientRequestHeader {
        return Ok(());
    }
    if header.eq_ignore_ascii_case("Host") {
        return Err(Diagnostic::error(
            target_span,
            "req.http.Host picked this tenant and cannot be changed",
        )
        .with_help(
            "the Varnish VCL that forks this tenant routes by Host; rewrite the origin's \
             Host as bereq.http.Host in vcl_backend_fetch",
        ));
    }
    if phase == Phase::Recv && options.forbids_recv_header(header) {
        return Err(Diagnostic::error(
            target_span,
            format!("req.http.{header} is a hash input and cannot be set in vcl_recv"),
        )
        .with_help("remove the assignment; the header is part of the cache key"));
    }
    Ok(())
}

/// A URL or method write: a literal that could never be one is refused
/// here, as the host refuses the same bytes at run time.
fn check_request_line(value: &TypedExpr, target: &str) -> Result<(), Diagnostic> {
    if let TypedExprKind::String(text) = &value.kind {
        if text.is_empty() || text.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(Diagnostic::error(
                value.span,
                format!("{target} cannot be empty or contain spaces or control characters"),
            ));
        }
    }
    Ok(())
}

/// `std.collect(hdr [, sep])`.
///
/// The first argument is a `HEADER`, not a `STRING`: it names the header to
/// collapse rather than reading one. That is the whole reason this does not
/// go through [`check_call`] -- everything else in `FUNCTIONS` type checks
/// its arguments as values.
fn check_collect(
    phase: Phase,
    arguments: Vec<ast::CallArgument>,
    span: Span,
    options: &CompileOptions,
    env: &TypeEnv<'_>,
) -> Result<TypedStatement, Diagnostic> {
    let mut bound = bind_arguments("std.collect", COLLECT_PARAMS, arguments, span)?.into_iter();
    let target = bound.next().expect("std.collect binds two parameters");
    let separator = bound.next().expect("std.collect binds two parameters");

    let ExprKind::Variable(name) = &target.kind else {
        return Err(
            Diagnostic::error(target.span, "std.collect expects a header")
                .with_help("name the header to collapse, such as std.collect(req.http.Cookie)"),
        );
    };
    let Some((spec, suffix)) = vars::resolve(name) else {
        return Err(env.unknown_variable(name, target.span));
    };
    let (Some(header), Lowering::RequestHeader | Lowering::ResponseHeader) =
        (suffix, spec.lowering)
    else {
        return Err(Diagnostic::error(
            target.span,
            format!("{name} is not a header, so std.collect cannot collapse it"),
        ));
    };
    if !spec.writable.contains(&phase) {
        return Err(not_writable(name, phase, target.span));
    }
    check_header_identity(phase, spec, header, target.span, options)?;

    Ok(TypedStatement::Collect {
        response: spec.lowering == Lowering::ResponseHeader,
        name: header.to_string(),
        separator: coerce_string(check_expr(phase, separator, env)?),
        span,
    })
}

fn check_host_statement(
    phase: Phase,
    statement: ast::Statement,
    options: &CompileOptions,
    env: &TypeEnv<'_>,
) -> Result<TypedStatement, Diagnostic> {
    match statement {
        ast::Statement::Set {
            target,
            target_span,
            value,
            span,
            ..
        } => {
            let Some((spec, suffix)) = vars::resolve(&target) else {
                return Err(env.unknown_variable(&target, target_span));
            };
            if !spec.writable.contains(&phase) {
                return Err(not_writable(&target, phase, target_span));
            }
            match spec.write_constraint {
                WriteConstraint::Header | WriteConstraint::ClientRequestHeader => {
                    let header = suffix.expect("header constraint belongs to a header family");
                    check_header_identity(phase, spec, header, target_span, options)?;
                }
                WriteConstraint::TrueOnly => {
                    if !matches!(value.kind, ast::ExprKind::Bool(true)) {
                        return Err(Diagnostic::error(
                            value.span,
                            format!("{target} may only be set to true"),
                        )
                        .with_help(
                            "omit the assignment when the response should remain cacheable",
                        ));
                    }
                    debug_assert_eq!(spec.lowering, Lowering::Uncacheable);
                    return Ok(TypedStatement::SetUncacheable { span });
                }
                WriteConstraint::None => {}
            }
            let mut value = check_expr(phase, value, env)?;
            if spec.value_type == ValueType::String {
                value = coerce_string(value);
            } else if value.value_type != spec.value_type {
                return Err(Diagnostic::error(
                    value.span,
                    format!(
                        "{target} expects {}, found {}",
                        type_name(spec.value_type),
                        type_name(value.value_type)
                    ),
                ));
            }
            match spec.lowering {
                Lowering::RequestHeader | Lowering::ResponseHeader => {
                    check_header_value(&value)?;
                    Ok(TypedStatement::SetHeader {
                        response: spec.lowering == Lowering::ResponseHeader,
                        name: suffix.expect("header family has suffix").to_string(),
                        value,
                        span,
                    })
                }
                Lowering::RequestUrl => {
                    check_request_line(&value, &target)?;
                    Ok(TypedStatement::SetUrl { value, span })
                }
                Lowering::RequestMethod => {
                    check_request_line(&value, &target)?;
                    Ok(TypedStatement::SetVar {
                        var: HostVar::Method,
                        value,
                        span,
                    })
                }
                Lowering::Host(var) => {
                    if spec.value_type == ValueType::String {
                        check_header_value(&value)?;
                    }
                    Ok(TypedStatement::SetVar { var, value, span })
                }
                Lowering::Body => Ok(TypedStatement::SetBody { value, span }),
                Lowering::Ttl | Lowering::StaleWhileRevalidate | Lowering::StaleIfError => {
                    note_stale_cap(&target, spec.lowering, &value, options, env);
                    Ok(TypedStatement::SetCacheDuration {
                        lowering: spec.lowering,
                        target,
                        target_span,
                        value,
                        span,
                    })
                }
                Lowering::Now
                | Lowering::ClientIp
                | Lowering::Uncacheable
                | Lowering::CacheHit => {
                    unreachable!("{target} has no writable phase")
                }
            }
        }
        ast::Statement::Unset {
            target,
            target_span,
            span,
        } => {
            let Some((spec, suffix)) = vars::resolve(&target) else {
                return Err(env.unknown_variable(&target, target_span));
            };
            let Some(name) = suffix else {
                return Err(Diagnostic::error(
                    target_span,
                    "unset is supported only for HTTP header variables",
                ));
            };
            if !matches!(
                spec.lowering,
                Lowering::RequestHeader | Lowering::ResponseHeader
            ) {
                return Err(Diagnostic::error(
                    target_span,
                    "unset is supported only for HTTP header variables",
                ));
            }
            match spec.write_constraint {
                WriteConstraint::Header | WriteConstraint::ClientRequestHeader => {
                    if vars::is_framing_header(name) {
                        return Err(Diagnostic::error(
                            target_span,
                            format!("{name} is a framing or hop-by-hop header and cannot be unset"),
                        ));
                    }
                    if spec.write_constraint == WriteConstraint::ClientRequestHeader
                        && name.eq_ignore_ascii_case("Host")
                    {
                        return Err(Diagnostic::error(
                            target_span,
                            "req.http.Host picked this tenant and cannot be unset",
                        ));
                    }
                    if spec.write_constraint == WriteConstraint::ClientRequestHeader
                        && phase == Phase::Recv
                        && options.forbids_recv_header(name)
                    {
                        return Err(Diagnostic::error(
                            target_span,
                            format!("{target} is a hash input and cannot be unset in vcl_recv"),
                        ));
                    }
                }
                WriteConstraint::None | WriteConstraint::TrueOnly => {}
            }
            if !spec.writable.contains(&phase) {
                return Err(Diagnostic::error(
                    target_span,
                    format!("{target} is not writable in {}", phase.vcl_name()),
                ));
            }
            Ok(TypedStatement::UnsetHeader {
                response: spec.lowering == Lowering::ResponseHeader,
                name: name.to_string(),
                span,
            })
        }
        ast::Statement::If { .. } => unreachable!("Checker owns lexical block scopes"),
        ast::Statement::Log { value, span } => Ok(TypedStatement::Log {
            value: coerce_string(check_expr(phase, value, env)?),
            span,
        }),
        ast::Statement::Synthetic { value, span } => {
            if !matches!(phase, Phase::Synth | Phase::BackendError) {
                return Err(Diagnostic::error(
                    span,
                    "synthetic() is only valid in vcl_synth and vcl_backend_error",
                ));
            }
            Ok(TypedStatement::Synthetic {
                value: coerce_string(check_expr(phase, value, env)?),
                span,
            })
        }
        ast::Statement::HashData { value, span } => {
            if phase != Phase::Hash {
                return Err(Diagnostic::error(
                    span,
                    "hash_data() is only valid in vcl_hash",
                ));
            }
            Ok(TypedStatement::HashData {
                value: coerce_string(check_expr(phase, value, env)?),
                span,
            })
        }
        ast::Statement::Return { action, span } => {
            let action = check_return_action(phase, action, span)?;
            Ok(TypedStatement::Return { action, span })
        }
        ast::Statement::Declare { .. }
        | ast::Statement::Call { .. }
        | ast::Statement::BuiltinCall { .. } => {
            unreachable!("Checker owns declarations and calls")
        }
    }
}

fn check_expr(
    phase: Phase,
    expression: ast::Expr,
    env: &TypeEnv<'_>,
) -> Result<TypedExpr, Diagnostic> {
    let span = expression.span;
    let (kind, value_type) = match expression.kind {
        ExprKind::Literal(Literal::String(value)) => {
            (TypedExprKind::String(value), ValueType::String)
        }
        ExprKind::Literal(Literal::Integer(value)) => {
            (TypedExprKind::Integer(value), ValueType::Integer)
        }
        ExprKind::Literal(Literal::Duration(value)) => {
            if value > i64::MAX as u64 {
                return Err(Diagnostic::error(
                    span,
                    "duration literal exceeds the signed 64-bit VCL range",
                ));
            }
            (TypedExprKind::Duration(value), ValueType::Duration)
        }
        ExprKind::Literal(Literal::Real(_)) => {
            return Err(
                Diagnostic::error(span, "REAL literals are not supported in VCL v1")
                    .with_help("use integer or duration arithmetic"),
            );
        }
        ExprKind::Bool(value) => (TypedExprKind::Boolean(value), ValueType::Boolean),
        ExprKind::Variable(name) => {
            if let Some(local_name) = name.strip_prefix("var.") {
                for scope in env.scopes.iter().rev() {
                    if let Some((value_type, local)) = scope.get(local_name) {
                        return Ok(TypedExpr {
                            kind: TypedExprKind::Local(*local),
                            value_type: *value_type,
                            span,
                        });
                    }
                }
                if let Some((value_type, global)) = env.globals.get(local_name) {
                    return Ok(TypedExpr {
                        kind: TypedExprKind::Global(*global),
                        value_type: *value_type,
                        span,
                    });
                }
                if let Some((value_type, static_id)) = env.statics.get(local_name) {
                    return Ok(TypedExpr {
                        kind: TypedExprKind::Static(*static_id),
                        value_type: *value_type,
                        span,
                    });
                }
                return Err(undeclared_storage(&name, span));
            }
            let Some((spec, suffix)) = vars::resolve(&name) else {
                return Err(env.unknown_variable(&name, span));
            };
            if !spec.readable.contains(&phase) {
                return Err(not_readable(&name, phase, span));
            }
            (
                TypedExprKind::Read {
                    lowering: spec.lowering,
                    name: suffix.map(str::to_string),
                },
                spec.value_type,
            )
        }
        ExprKind::Call {
            function,
            arguments,
        } => check_call(phase, &function, arguments, span, env)?,
        ExprKind::Not(operand) => {
            let operand = check_expr(phase, *operand, env)?;
            let operand_type = operand.value_type;
            let operand_span = operand.span;
            let Some(operand) = coerce_boolean(operand) else {
                return Err(Diagnostic::error(
                    operand_span,
                    format!("'!' expects BOOL, found {}", type_name(operand_type)),
                ));
            };
            (TypedExprKind::Not(Box::new(operand)), ValueType::Boolean)
        }
        ExprKind::Negate(operand) => {
            let operand = check_expr(phase, *operand, env)?;
            if !matches!(operand.value_type, ValueType::Integer | ValueType::Duration) {
                return Err(Diagnostic::error(
                    operand.span,
                    format!(
                        "unary '-' expects INT or DURATION, found {}",
                        type_name(operand.value_type)
                    ),
                ));
            }
            let value_type = operand.value_type;
            (TypedExprKind::Negate(Box::new(operand)), value_type)
        }
        ExprKind::AddChain(operands) => {
            // `+` is left-associative and turns to string concatenation the
            // moment either side is a string, and stays there: `1 + 2 + "a"`
            // is `"3a"`, not `"12a"`. Walking the run left to right is what
            // reproduces that without rebuilding the left-deep tree the
            // parser deliberately did not build.
            let mut operands = operands.into_iter();
            let mut accumulated = match operands.next() {
                Some(first) => AddAccumulator::Value(check_expr(phase, first, env)?),
                None => return Err(Diagnostic::error(span, "'+' requires two operands")),
            };
            for operand in operands {
                let right = check_expr(phase, operand, env)?;
                accumulated = match accumulated {
                    AddAccumulator::Strings(mut parts) => {
                        parts.push(coerce_string(right));
                        AddAccumulator::Strings(parts)
                    }
                    AddAccumulator::Value(left) => {
                        if left.value_type == ValueType::String
                            || right.value_type == ValueType::String
                        {
                            AddAccumulator::Strings(vec![coerce_string(left), coerce_string(right)])
                        } else {
                            let joined = Span::new(left.span.start, right.span.end);
                            let value_type = additive_type(
                                BinaryOp::Add,
                                left.value_type,
                                right.value_type,
                                joined,
                            )?;
                            AddAccumulator::Value(TypedExpr {
                                kind: TypedExprKind::Binary {
                                    op: BinaryOp::Add,
                                    left: Box::new(left),
                                    right: Box::new(right),
                                },
                                value_type,
                                span: joined,
                            })
                        }
                    }
                };
            }
            match accumulated {
                AddAccumulator::Value(value) => return Ok(value),
                AddAccumulator::Strings(parts) => (TypedExprKind::Concat(parts), ValueType::String),
            }
        }
        ExprKind::Binary { op, left, right } => {
            if matches!(op, BinaryOp::Match | BinaryOp::NotMatch) {
                if let ExprKind::Variable(name) = &right.kind {
                    if let Some(acl) = env.acls.get(name).copied() {
                        let address = check_expr(phase, *left, env)?;
                        if address.value_type != ValueType::Ip {
                            return Err(Diagnostic::error(
                                address.span,
                                format!(
                                    "acl {name} matches an IP, found {}",
                                    type_name(address.value_type)
                                ),
                            ));
                        }
                        return Ok(TypedExpr {
                            kind: TypedExprKind::AclMatch {
                                address: Box::new(address),
                                acl,
                                negated: op == BinaryOp::NotMatch,
                            },
                            value_type: ValueType::Boolean,
                            span,
                        });
                    }
                }
            }
            let mut left = check_expr(phase, *left, env)?;
            let mut right = check_expr(phase, *right, env)?;
            let result_type = match op {
                BinaryOp::Add | BinaryOp::Subtract => {
                    if op == BinaryOp::Add
                        && (left.value_type == ValueType::String
                            || right.value_type == ValueType::String)
                    {
                        left = coerce_string(left);
                        right = coerce_string(right);
                        return Ok(TypedExpr {
                            kind: TypedExprKind::Concat(vec![left, right]),
                            value_type: ValueType::String,
                            span,
                        });
                    }
                    additive_type(op, left.value_type, right.value_type, span)?
                }
                BinaryOp::Multiply => match (left.value_type, right.value_type) {
                    (ValueType::Integer, ValueType::Integer) => ValueType::Integer,
                    (ValueType::Duration, ValueType::Integer)
                    | (ValueType::Integer, ValueType::Duration) => ValueType::Duration,
                    _ => {
                        return Err(Diagnostic::error(
                            span,
                            "'*' requires INT * INT, DURATION * INT, or INT * DURATION",
                        ));
                    }
                },
                BinaryOp::Divide => match (left.value_type, right.value_type) {
                    (ValueType::Integer, ValueType::Integer) => ValueType::Integer,
                    (ValueType::Duration, ValueType::Integer) => ValueType::Duration,
                    (ValueType::Duration, ValueType::Duration) => ValueType::Integer,
                    _ => {
                        return Err(Diagnostic::error(
                            span,
                            "'/' requires INT / INT, DURATION / INT, or DURATION / DURATION",
                        ));
                    }
                },
                BinaryOp::Modulo => {
                    if left.value_type != ValueType::Integer
                        || right.value_type != ValueType::Integer
                    {
                        return Err(Diagnostic::error(span, "'%' requires INT operands"));
                    }
                    ValueType::Integer
                }
                BinaryOp::Equal | BinaryOp::NotEqual => {
                    if left.value_type != right.value_type {
                        return Err(Diagnostic::error(
                            span,
                            format!(
                                "cannot compare {} with {}",
                                type_name(left.value_type),
                                type_name(right.value_type)
                            ),
                        ));
                    }
                    ValueType::Boolean
                }
                BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::Greater
                | BinaryOp::GreaterEqual => {
                    if left.value_type != right.value_type
                        || !matches!(
                            left.value_type,
                            ValueType::Integer | ValueType::Duration | ValueType::Time
                        )
                    {
                        return Err(Diagnostic::error(
                            span,
                            format!(
                                "'{}' requires matching INT or DURATION operands",
                                binary_name(op)
                            ),
                        ));
                    }
                    ValueType::Boolean
                }
                BinaryOp::Match | BinaryOp::NotMatch => {
                    if left.value_type == ValueType::Ip {
                        return Err(Diagnostic::error(
                            span,
                            "an IP matches an acl, not a regular expression",
                        ));
                    }
                    if left.value_type != ValueType::String || right.value_type != ValueType::String
                    {
                        return Err(Diagnostic::error(
                            span,
                            "'~' and '!~' require STRING operands",
                        ));
                    }
                    let TypedExprKind::String(pattern) = &right.kind else {
                        return Err(Diagnostic::error(
                            right.span,
                            "the right operand of '~' and '!~' must be a literal pattern",
                        ));
                    };
                    check_pattern(pattern, right.span, env)?;
                    ValueType::Boolean
                }
                BinaryOp::And | BinaryOp::Or => {
                    let left_type = left.value_type;
                    let left_span = left.span;
                    let Some(coerced_left) = coerce_boolean(left) else {
                        return Err(Diagnostic::error(
                            left_span,
                            format!(
                                "'&&' and '||' require BOOL operands, found {}",
                                type_name(left_type)
                            ),
                        ));
                    };
                    let right_type = right.value_type;
                    let right_span = right.span;
                    let Some(coerced_right) = coerce_boolean(right) else {
                        return Err(Diagnostic::error(
                            right_span,
                            format!(
                                "'&&' and '||' require BOOL operands, found {}",
                                type_name(right_type)
                            ),
                        ));
                    };
                    left = coerced_left;
                    right = coerced_right;
                    ValueType::Boolean
                }
            };
            (
                TypedExprKind::Binary {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                },
                result_type,
            )
        }
    };
    Ok(TypedExpr {
        kind,
        value_type,
        span,
    })
}

/// How a [`FunctionSpec`] row reaches the IR.
///
/// `UriDecode` is a [`vcl_rt::StrEdit`] under the skin -- one
/// subject and one integer -- and has a variant of its own only because
/// `strict` is a BOOL where the `StrEdit` rows bind an INT.
#[derive(Clone, Copy)]
enum BuiltinLowering {
    Digest(DigestFunction),
    StringCase { upper: bool },
    Regsub { all: bool },
    Strstr,
    StringPredicate { prefix: bool },
    ParseInteger,
    ParseDuration,
    ParseTime,
    Fnmatch,
    Querysort,
    Syntax,
    StrTest(vcl_rt::StrTest),
    StrEdit(vcl_rt::StrEdit),
    StrSplit,
    UriDecode,
    Extreme { max: bool },
}

#[derive(Clone, Copy)]
struct FunctionSpec {
    name: &'static str,
    params: &'static [ParameterSpec],
    result: ValueType,
    lower: BuiltinLowering,
}

#[derive(Clone, Copy)]
struct ParameterSpec {
    name: &'static str,
    default: Option<DefaultArgument>,
    enum_values: &'static [&'static str],
}

#[derive(Clone, Copy)]
enum DefaultArgument {
    Integer(i64),
    Duration(u64),
    Boolean(bool),
    String(&'static str),
    Enum(&'static str),
}

const REQUIRED: Option<DefaultArgument> = None;
const NO_PARAMS: &[ParameterSpec] = &[];
const INTEGER_ZERO: Option<DefaultArgument> = Some(DefaultArgument::Integer(0));
const DURATION_ZERO: Option<DefaultArgument> = Some(DefaultArgument::Duration(0));
const BOOLEAN_FALSE: Option<DefaultArgument> = Some(DefaultArgument::Boolean(false));
const BOOLEAN_TRUE: Option<DefaultArgument> = Some(DefaultArgument::Boolean(true));

const ONE_STRING: &[ParameterSpec] = &[ParameterSpec {
    name: "value",
    default: REQUIRED,
    enum_values: &[],
}];
const TWO_STRINGS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "suffix",
        default: REQUIRED,
        enum_values: &[],
    },
];
const TWO_INTEGERS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "a",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "b",
        default: REQUIRED,
        enum_values: &[],
    },
];
const THREE_STRINGS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "pattern",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "replacement",
        default: REQUIRED,
        enum_values: &[],
    },
];
const INTEGER_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "fallback",
        default: INTEGER_ZERO,
        enum_values: &[],
    },
];
const DURATION_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "fallback",
        default: DURATION_ZERO,
        enum_values: &[],
    },
];
const TIME_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "fallback",
        default: REQUIRED,
        enum_values: &[],
    },
];
// ── str ─────────────────────────────────────────────────────────────────
//
// Parameter names are the enterprise `.vcc` spellings, so a named argument
// that works in Varnish works here.
const STR_ONE: &[ParameterSpec] = &[ParameterSpec {
    name: "s",
    default: REQUIRED,
    enum_values: &[],
}];
const STR_TWO: &[ParameterSpec] = &[
    ParameterSpec {
        name: "s1",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "s2",
        default: REQUIRED,
        enum_values: &[],
    },
];
const STR_TOKEN_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "str1",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "str2",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "separators",
        default: Some(DefaultArgument::String(" ,")),
        enum_values: &[],
    },
];
const STR_SUBSTR_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "s",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "n",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "offset",
        default: INTEGER_ZERO,
        enum_values: &[],
    },
];
const STR_SPLIT_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "s",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "n",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "sep",
        default: Some(DefaultArgument::String(" \t")),
        enum_values: &[],
    },
];
const COLLECT_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "hdr",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "sep",
        // Varnish's own default, and what `http_CollectHdrSep` falls back to
        // for an empty one.
        default: Some(DefaultArgument::String(", ")),
        enum_values: &[],
    },
];
const FNMATCH_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "pattern",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "subject",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "pathname",
        default: Some(DefaultArgument::Boolean(true)),
        enum_values: &[],
    },
    ParameterSpec {
        name: "noescape",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "period",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const SYNTAX_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "version",
    default: REQUIRED,
    enum_values: &[],
}];
// ---------------------------------------------------------------------------
// vmod calls
//
// `cookieplus`, `urlplus` and `headerplus` are one table.  A row is a VCL
// signature, the runtime operation it selects, and a rule per parameter
// saying where the bound value goes: a runtime string argument, a read's
// fallback, or a field of the `OpCode` word the runtime takes in a2.
//
// Everything downstream is generic over that: one IR op triple, one emitter
// triple, one interpreter arm triple.  The previous shape -- a `match` per
// module that decoded its parameters, a second `match` that rebuilt an
// operation enum from them, and a third that truncated the argument vector --
// had to be written three times and was wrong in all three: the packing of a
// range argument differed between the emitter and the interpreter, and
// `query_get` handed its `position` to the runtime as the `default`.
// ---------------------------------------------------------------------------

/// Where one bound parameter goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bind {
    /// A runtime string argument.  Two of them are joined with a NUL, which
    /// is the split the runtime's `name_and_value` undoes.
    Argument,
    /// The value a read falls back to when the routine reports the value
    /// absent, the way an absent header reads as `""`.
    Default,
    /// A literal that sets one `OpCode` flag bit when it is true: a `BOOL`
    /// that is `true`, or an `ENUM` that is not its first value.
    Flag(u8),
    /// An `INT` literal that becomes `OpCode::first`.
    First,
    /// An `INT` literal that becomes `OpCode::second`.
    Second,
    /// An `ENUM` literal whose index lands at `shift` in `OpCode::extra`.
    Extra(u8),
    /// `headerplus.init(scope)`: an `ENUM` naming a header map, checked
    /// against the map the phase can write rather than encoded.
    Scope,
    /// A regex literal matched host-side against the record *name*.
    ///
    /// The pattern never becomes a runtime argument: it crosses once through
    /// `regex_match_list` and what reaches the routine is the bitmap. The
    /// compiler prefixes `(?i)` for `headerplus`, whose name patterns the
    /// vmod compiles with `VRE_CASELESS`; urlplus and cookieplus compile
    /// theirs plain, so a header name matches case-insensitively and a cookie
    /// or query name does not.
    NamePattern,
    /// A regex literal matched against the record *value*, case-sensitively
    /// in every module, as the vmods compile it.
    ValuePattern,
    /// A `BOOL` literal that sets one bit of `OpCode::extra`.
    ///
    /// `setcookie_add`'s `secure` and `httponly` are flags like every other
    /// [`Bind::Flag`]; they live in `extra` only because `flag` has no bit
    /// left.
    ExtraFlag(u8),
    /// `setcookie_add`'s `ttl`: a `DURATION` that becomes *two* runtime
    /// arguments, the ttl and `now`, both as decimal nanoseconds.
    ///
    /// The `Expires` the vmod writes is `now + ttl`, and the guest cannot
    /// read a clock, so the clock crosses with the call. Both are arguments
    /// rather than fields of the operation word because neither is a literal
    /// small enough to ride in one.
    Expiry,
    /// A `HEADER`, naming a header rather than reading one.
    ///
    /// It never becomes a runtime argument in the ordinary way: the name is
    /// known when the script is compiled, and it is what `setcookie_write`
    /// commits to and what `setcookie_parse` seeds from.
    Header,
}

/// What a vmod call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A statement that mutates the module's state.
    Transform(u8),
    /// An expression producing a string.
    Read(u8),
    /// An expression producing an integer.
    Count(u8),
    /// `init(scope)` and `reset()`: re-seed the state from its source.
    Reseed,
    /// `write()`: store the state back through the host.  The operation is
    /// the read that renders the state, and is unused by `headerplus`.
    Write(u8),
}

struct VmodSpec {
    name: &'static str,
    module: Module,
    shape: Shape,
    params: &'static [ParameterSpec],
    /// One entry per parameter, in order.  A unit test holds the two in step.
    binds: &'static [Bind],
    /// The phases the call is legal in.  Empty means every phase the module
    /// itself allows.
    phases: &'static [Phase],
    /// The help line on a phase rejection, which is where a call that a
    /// declarative knob owns names that knob.
    phase_help: &'static str,
    /// `OpCode` flags the row sets unconditionally.  This is what lets a
    /// function that is another with one argument fixed -- `toupper` is
    /// `tolower` -- be a row rather than an operation of its own.
    flags: u8,
    /// For a `_regex` form: the sub-list its patterns are matched against.
    ///
    /// `Some` is what turns the call into the project/match/apply triple; a
    /// row that binds a pattern without naming a set, or names one without
    /// binding a pattern, is caught by `vmod_rows_agree_with_their_binds`.
    select: Option<RecordSet>,
}

/// The phases whose writable header map is the request's.
const REQUEST_PHASES: &[Phase] = &[
    Phase::Recv,
    Phase::Hash,
    Phase::Hit,
    Phase::Miss,
    Phase::Pass,
    Phase::BackendRequest,
];
/// The phases whose writable header map is the response's.
const RESPONSE_PHASES: &[Phase] = &[
    Phase::BackendResponse,
    Phase::BackendError,
    Phase::Deliver,
    Phase::Synth,
];
const HEADER_PHASES: &[Phase] = Phase::ALL;

/// Every phase the module allows, which for `uri` is every phase there is:
/// its state is parsed from strings the guest already holds.
const NO_PHASES: &[Phase] = &[];
const NO_BINDS: &[Bind] = &[];
const ONE_NAME: &[ParameterSpec] = &[ParameterSpec {
    name: "name",
    default: REQUIRED,
    enum_values: &[],
}];
const NAME_BIND: &[Bind] = &[Bind::Argument];

const SLASH_ENUM: &[&str] = &["FROM_INPUT", "TRUE", "FALSE"];
const PART_ENUM: &[&str] = &["ALL", "URL", "QUERY"];

/// `OpCode::extra` shifts, matching `vcl_rt::url_extra`.
const EXTRA_LEADING: u8 = 0;
const EXTRA_TRAILING: u8 = 2;
const EXTRA_PART: u8 = 4;

const COOKIE_GET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "default",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "occurrence",
        default: Some(DefaultArgument::Enum("FIRST")),
        enum_values: &["FIRST", "LAST"],
    },
];
const COOKIE_ADD_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    // `keep = 1`, as the vmod has it: with keep mode real, a default of
    // false would make `keep("a"); add("b", ...)` drop the cookie it just
    // added, which is not what any policy writes that pair to mean.
    ParameterSpec {
        name: "keep",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "override",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const COOKIE_DELETE_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "delete_keep",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const COOKIE_PARSE_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "cookies",
    default: REQUIRED,
    enum_values: &[],
}];

const SETCOOKIE_GET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "default",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
];
const SETCOOKIE_GET_BINDS: &[Bind] = &[Bind::Argument, Bind::Default];
/// `setcookie_add(name, value, ttl, domain, path, secure, httponly, extra,
/// keep, override)`.
///
/// The one call whose arguments do not fit the two strings the routine ABI
/// carries, which is why the joined argument has seven fields; see
/// `vcl_rt::setcookie_field`, whose order this must match.
const SETCOOKIE_ADD_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "ttl",
        default: DURATION_ZERO,
        enum_values: &[],
    },
    ParameterSpec {
        name: "domain",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "path",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "secure",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "httponly",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "extra",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "keep",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "override",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
];
const SETCOOKIE_ADD_BINDS: &[Bind] = &[
    Bind::Argument,
    Bind::Argument,
    Bind::Expiry,
    Bind::Argument,
    Bind::Argument,
    Bind::ExtraFlag(0),
    Bind::ExtraFlag(1),
    Bind::Argument,
    Bind::Flag(vcl_rt::flag::KEEP),
    Bind::Flag(vcl_rt::flag::OVERRIDE),
];
/// `setcookie_write([header])`, whose target defaults to `Set-Cookie`.
const SETCOOKIE_WRITE_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "header",
    default: Some(DefaultArgument::String("Set-Cookie")),
    enum_values: &[],
}];
const SETCOOKIE_PARSE_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "header",
    default: REQUIRED,
    enum_values: &[],
}];
const HEADER_BIND: &[Bind] = &[Bind::Header];

const URL_RENDER_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "sort_query",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "leading_slash",
        default: Some(DefaultArgument::Enum("FROM_INPUT")),
        enum_values: SLASH_ENUM,
    },
    ParameterSpec {
        name: "trailing_slash",
        default: Some(DefaultArgument::Enum("FROM_INPUT")),
        enum_values: SLASH_ENUM,
    },
    ParameterSpec {
        name: "query_keep_equal_sign",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const URL_RENDER_BINDS: &[Bind] = &[
    Bind::Flag(vcl_rt::flag::SORT_QUERY),
    Bind::Extra(EXTRA_LEADING),
    Bind::Extra(EXTRA_TRAILING),
    Bind::Flag(vcl_rt::flag::KEEP_EQUAL_SIGN),
];
const URL_QUERY_RENDER_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "sort_query",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "query_keep_equal_sign",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const URL_QUERY_RENDER_BINDS: &[Bind] = &[
    Bind::Flag(vcl_rt::flag::SORT_QUERY),
    Bind::Flag(vcl_rt::flag::KEEP_EQUAL_SIGN),
];
const URL_GET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "start_range",
        default: Some(DefaultArgument::Integer(0)),
        enum_values: &[],
    },
    ParameterSpec {
        name: "end_range",
        default: Some(DefaultArgument::Integer(-1)),
        enum_values: &[],
    },
    ParameterSpec {
        name: "leading_slash",
        default: Some(DefaultArgument::Enum("FROM_INPUT")),
        enum_values: SLASH_ENUM,
    },
    ParameterSpec {
        name: "trailing_slash",
        default: Some(DefaultArgument::Enum("FROM_INPUT")),
        enum_values: SLASH_ENUM,
    },
];
const URL_GET_BINDS: &[Bind] = &[
    Bind::First,
    Bind::Second,
    Bind::Extra(EXTRA_LEADING),
    Bind::Extra(EXTRA_TRAILING),
];
const URL_QUERY_GET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "default",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "position",
        default: Some(DefaultArgument::Integer(-1)),
        enum_values: &[],
    },
];
const URL_QUERY_GET_BINDS: &[Bind] = &[Bind::Argument, Bind::Default, Bind::First];
const URL_QUERY_ADD_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "value",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "keep",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "position",
        default: Some(DefaultArgument::Integer(-1)),
        enum_values: &[],
    },
];
const URL_QUERY_ADD_BINDS: &[Bind] = &[
    Bind::Argument,
    Bind::Argument,
    Bind::Flag(vcl_rt::flag::KEEP),
    Bind::First,
];
const URL_QUERY_SET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "value",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "keep",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "all",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const URL_QUERY_SET_BINDS: &[Bind] = &[
    Bind::Argument,
    Bind::Argument,
    Bind::Flag(vcl_rt::flag::KEEP),
    Bind::Flag(vcl_rt::flag::ALL),
];
const URL_ADD_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "keep",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
    ParameterSpec {
        name: "position",
        default: Some(DefaultArgument::Integer(-1)),
        enum_values: &[],
    },
];
const URL_ADD_BINDS: &[Bind] = &[
    Bind::Argument,
    Bind::Flag(vcl_rt::flag::KEEP),
    Bind::First,
];
const DELETE_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "delete_keep",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const DELETE_BINDS: &[Bind] = &[
    Bind::Argument,
    Bind::Flag(vcl_rt::flag::DELETE_KEEP),
];
const URL_RANGE_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "start_range",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "end_range",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "delete_keep",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const URL_RANGE_BINDS: &[Bind] = &[
    Bind::First,
    Bind::Second,
    Bind::Flag(vcl_rt::flag::DELETE_KEEP),
];
const URL_CASE_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "convert",
    default: Some(DefaultArgument::Enum("ALL")),
    enum_values: PART_ENUM,
}];
const URL_CASE_BINDS: &[Bind] = &[Bind::Extra(EXTRA_PART)];

const HEADER_SCOPE_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "scope",
    default: REQUIRED,
    enum_values: &["req", "bereq", "beresp", "resp"],
}];
const HEADER_SET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "value",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "keep",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
];
const HEADER_SET_BINDS: &[Bind] = &[
    Bind::Argument,
    Bind::Argument,
    Bind::Flag(vcl_rt::flag::KEEP),
];
const HEADER_GET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "default",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "occurrence",
        default: Some(DefaultArgument::Integer(-1)),
        enum_values: &[],
    },
];
const HEADER_GET_BINDS: &[Bind] = &[Bind::Argument, Bind::Default, Bind::First];

/// `url_as_string(leading_slash, trailing_slash)`: `url_get`'s two slash
/// arguments without its range.
const URL_PATH_RENDER_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "leading_slash",
        default: Some(DefaultArgument::Enum("FROM_INPUT")),
        enum_values: SLASH_ENUM,
    },
    ParameterSpec {
        name: "trailing_slash",
        default: Some(DefaultArgument::Enum("FROM_INPUT")),
        enum_values: SLASH_ENUM,
    },
];
const URL_PATH_RENDER_BINDS: &[Bind] = &[Bind::Extra(EXTRA_LEADING), Bind::Extra(EXTRA_TRAILING)];

// ── the `_regex` forms ──────────────────────────────────────────────────────
//
// Every one of them binds its pattern with `Bind::NamePattern` or
// `Bind::ValuePattern` and names a `RecordSet`; the two together are what
// turn the call into the project/match/apply triple. None of them binds a
// runtime string argument, because the bitmap *is* the argument.
const ONE_PATTERN: &[ParameterSpec] = &[ParameterSpec {
    name: "regex",
    default: REQUIRED,
    enum_values: &[],
}];
const ONE_PATTERN_BIND: &[Bind] = &[Bind::NamePattern];
const PATTERN_DELETE_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "regex",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "delete_keep",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const PATTERN_DELETE_BINDS: &[Bind] = &[
    Bind::NamePattern,
    Bind::Flag(vcl_rt::flag::DELETE_KEEP),
];
const PATTERN_GET_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "regex",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "default",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
];
const PATTERN_GET_BINDS: &[Bind] = &[Bind::NamePattern, Bind::Default];
/// `headerplus.get_regex(name_re, value_re, default)`.
///
/// The vmod's `value_re` is optional; VCL v1 has no absent argument, so the
/// default is the empty pattern -- which matches every value, making the
/// second bitmap's AND a no-op, exactly as an absent `value_re` does.
const HEADER_GET_REGEX_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name_re",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "value_re",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "default",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
];
const HEADER_GET_REGEX_BINDS: &[Bind] = &[Bind::NamePattern, Bind::ValuePattern, Bind::Default];
const HEADER_NAME_REGEX_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "name_re",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "value_re",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
];
const HEADER_NAME_REGEX_BINDS: &[Bind] = &[Bind::NamePattern, Bind::ValuePattern];

// ── uri ─────────────────────────────────────────────────────────────────────
//
// Every `uri` function has at most one boolean, and it is always the same
// bit of `OpCode::extra`: `decode` on a read, `encode` on a set, `norm` on a
// parse.  `flag` has no bit left, which is why it lives in `extra`.
const URI_OPTION: Bind = Bind::ExtraFlag(0);
const URI_OPTION_BIND: &[Bind] = &[URI_OPTION];
/// `parse(input, norm)`.  `input` defaults to the empty string, which the
/// routine reads as "the request's own Host and URL", the way an omitted
/// `input` does in the vmod.
const URI_PARSE_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "input",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "norm",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const URI_AS_STRING_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "fmt",
        default: Some(DefaultArgument::String("%S%A%P%Q%F")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "decode",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const URI_DECODE_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "decode",
    default: BOOLEAN_FALSE,
    enum_values: &[],
}];
/// `set_scheme(new)` and `set_port(new)`, the two components the vmod gives
/// no `encode` parameter because neither has an escapable character.
const URI_SET_PARAMS: &[ParameterSpec] = &[ParameterSpec {
    name: "new",
    default: Some(DefaultArgument::String("")),
    enum_values: &[],
}];
const URI_SET_BINDS: &[Bind] = &[Bind::Argument];
const URI_SET_ENCODE_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "new",
        default: Some(DefaultArgument::String("")),
        enum_values: &[],
    },
    ParameterSpec {
        name: "encode",
        default: BOOLEAN_FALSE,
        enum_values: &[],
    },
];
const URI_SET_ENCODE_BINDS: &[Bind] = &[Bind::Argument, URI_OPTION];
/// `uri.decode(in, strict)`.
const URI_DECODE_STRAND_PARAMS: &[ParameterSpec] = &[
    ParameterSpec {
        name: "in",
        default: REQUIRED,
        enum_values: &[],
    },
    ParameterSpec {
        name: "strict",
        default: BOOLEAN_TRUE,
        enum_values: &[],
    },
];

const URL_WRITE_HELP: &str = "urlplus.write replaces the request URL, which the client \
     subroutines up to vcl_pass and vcl_backend_fetch may do";

const VMODS: &[VmodSpec] = &[
    // ── cookieplus ──────────────────────────────────────────────────────
    VmodSpec {
        name: "cookieplus.get",
        module: Module::Cookieplus,
        shape: Shape::Read(vcl_rt::CookieRead::Get as u8),
        params: COOKIE_GET_PARAMS,
        binds: &[
            Bind::Argument,
            Bind::Default,
            Bind::Flag(vcl_rt::flag::LAST),
        ],
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.as_string",
        module: Module::Cookieplus,
        shape: Shape::Read(vcl_rt::CookieRead::AsString as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.count",
        module: Module::Cookieplus,
        shape: Shape::Count(0),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.add",
        module: Module::Cookieplus,
        shape: Shape::Transform(vcl_rt::CookieOp::Add as u8),
        params: COOKIE_ADD_PARAMS,
        binds: &[
            Bind::Argument,
            Bind::Argument,
            Bind::Flag(vcl_rt::flag::KEEP),
            Bind::Flag(vcl_rt::flag::OVERRIDE),
        ],
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.delete",
        module: Module::Cookieplus,
        shape: Shape::Transform(vcl_rt::CookieOp::Delete as u8),
        params: COOKIE_DELETE_PARAMS,
        binds: DELETE_BINDS,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.keep",
        module: Module::Cookieplus,
        shape: Shape::Transform(vcl_rt::CookieOp::Keep as u8),
        params: ONE_NAME,
        binds: NAME_BIND,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.parse",
        module: Module::Cookieplus,
        shape: Shape::Transform(vcl_rt::CookieOp::Parse as u8),
        params: COOKIE_PARSE_PARAMS,
        binds: NAME_BIND,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.reset",
        module: Module::Cookieplus,
        shape: Shape::Reseed,
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.write",
        module: Module::Cookieplus,
        shape: Shape::Write(vcl_rt::CookieRead::AsString as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.get_regex",
        module: Module::Cookieplus,
        shape: Shape::Read(vcl_rt::CookieRead::GetRegex as u8),
        params: PATTERN_GET_PARAMS,
        binds: PATTERN_GET_BINDS,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "cookieplus.delete_regex",
        module: Module::Cookieplus,
        shape: Shape::Transform(vcl_rt::CookieOp::DeleteRegex as u8),
        params: PATTERN_DELETE_PARAMS,
        binds: PATTERN_DELETE_BINDS,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "cookieplus.keep_regex",
        module: Module::Cookieplus,
        shape: Shape::Transform(vcl_rt::CookieOp::KeepRegex as u8),
        params: ONE_PATTERN,
        binds: ONE_PATTERN_BIND,
        phases: REQUEST_PHASES,
        phase_help: COOKIE_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    // ── cookieplus, the Set-Cookie half ─────────────────────────────────
    VmodSpec {
        name: "cookieplus.setcookie_get",
        module: Module::Setcookie,
        shape: Shape::Read(vcl_rt::SetcookieRead::Get as u8),
        params: SETCOOKIE_GET_PARAMS,
        binds: SETCOOKIE_GET_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.setcookie_get_regex",
        module: Module::Setcookie,
        shape: Shape::Read(vcl_rt::SetcookieRead::GetRegex as u8),
        params: PATTERN_GET_PARAMS,
        binds: PATTERN_GET_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "cookieplus.setcookie_count",
        module: Module::Setcookie,
        shape: Shape::Count(0),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.setcookie_add",
        module: Module::Setcookie,
        shape: Shape::Transform(vcl_rt::SetcookieOp::Add as u8),
        params: SETCOOKIE_ADD_PARAMS,
        binds: SETCOOKIE_ADD_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.setcookie_delete",
        module: Module::Setcookie,
        shape: Shape::Transform(vcl_rt::SetcookieOp::Delete as u8),
        params: COOKIE_DELETE_PARAMS,
        binds: DELETE_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.setcookie_delete_regex",
        module: Module::Setcookie,
        shape: Shape::Transform(vcl_rt::SetcookieOp::DeleteRegex as u8),
        params: PATTERN_DELETE_PARAMS,
        binds: PATTERN_DELETE_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "cookieplus.setcookie_keep",
        module: Module::Setcookie,
        shape: Shape::Transform(vcl_rt::SetcookieOp::Keep as u8),
        params: ONE_NAME,
        binds: NAME_BIND,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.setcookie_keep_regex",
        module: Module::Setcookie,
        shape: Shape::Transform(vcl_rt::SetcookieOp::KeepRegex as u8),
        params: ONE_PATTERN,
        binds: ONE_PATTERN_BIND,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "cookieplus.setcookie_parse",
        module: Module::Setcookie,
        shape: Shape::Reseed,
        params: SETCOOKIE_PARSE_PARAMS,
        binds: HEADER_BIND,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.setcookie_reset",
        module: Module::Setcookie,
        shape: Shape::Reseed,
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "cookieplus.setcookie_write",
        module: Module::Setcookie,
        shape: Shape::Write(vcl_rt::SetcookieOp::Render as u8),
        params: SETCOOKIE_WRITE_PARAMS,
        binds: HEADER_BIND,
        phases: RESPONSE_PHASES,
        phase_help: SETCOOKIE_PHASE_HELP,
        flags: 0,
        select: None,
    },
    // ── urlplus ─────────────────────────────────────────────────────────
    VmodSpec {
        name: "urlplus.parse",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::Parse as u8),
        params: ONE_NAME,
        binds: NAME_BIND,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.reset",
        module: Module::Urlplus,
        shape: Shape::Reseed,
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.write",
        module: Module::Urlplus,
        shape: Shape::Write(vcl_rt::UrlRead::AsString as u8),
        params: URL_RENDER_PARAMS,
        binds: URL_RENDER_BINDS,
        phases: REQUEST_PHASES,
        phase_help: URL_WRITE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.as_string",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::AsString as u8),
        params: URL_RENDER_PARAMS,
        binds: URL_RENDER_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_as_string",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::QueryAsString as u8),
        params: URL_QUERY_RENDER_PARAMS,
        binds: URL_QUERY_RENDER_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.url_get",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::UrlGet as u8),
        params: URL_GET_PARAMS,
        binds: URL_GET_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.get_basename",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::Basename as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.get_filename",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::Filename as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.get_extension",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::Extension as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.get_dirname",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::Dirname as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_get",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::QueryGet as u8),
        params: URL_QUERY_GET_PARAMS,
        binds: URL_QUERY_GET_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_count",
        module: Module::Urlplus,
        shape: Shape::Count(vcl_rt::URL_COUNT_QUERIES),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.url_count",
        module: Module::Urlplus,
        shape: Shape::Count(vcl_rt::URL_COUNT_SEGMENTS),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_add",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::QueryAdd as u8),
        params: URL_QUERY_ADD_PARAMS,
        binds: URL_QUERY_ADD_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_set",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::QuerySet as u8),
        params: URL_QUERY_SET_PARAMS,
        binds: URL_QUERY_SET_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_delete",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::QueryDelete as u8),
        params: DELETE_PARAMS,
        binds: DELETE_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_keep",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::QueryKeep as u8),
        params: ONE_NAME,
        binds: NAME_BIND,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.url_add",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::UrlAdd as u8),
        params: URL_ADD_PARAMS,
        binds: URL_ADD_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.url_delete",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::UrlDelete as u8),
        params: DELETE_PARAMS,
        binds: DELETE_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.url_keep",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::UrlKeep as u8),
        params: ONE_NAME,
        binds: NAME_BIND,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.url_delete_range",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::UrlDeleteRange as u8),
        params: URL_RANGE_PARAMS,
        binds: URL_RANGE_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.tolower",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::CaseMap as u8),
        params: URL_CASE_PARAMS,
        binds: URL_CASE_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.toupper",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::CaseMap as u8),
        params: URL_CASE_PARAMS,
        binds: URL_CASE_BINDS,
        phases: &[],
        phase_help: "",
        flags: vcl_rt::flag::UPPER,
        select: None,
    },
    VmodSpec {
        name: "urlplus.url_as_string",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::UrlAsString as u8),
        params: URL_PATH_RENDER_PARAMS,
        binds: URL_PATH_RENDER_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "urlplus.query_get_regex",
        module: Module::Urlplus,
        shape: Shape::Read(vcl_rt::UrlRead::QueryGetRegex as u8),
        params: PATTERN_GET_PARAMS,
        binds: PATTERN_GET_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: Some(RecordSet::Queries),
    },
    VmodSpec {
        name: "urlplus.query_delete_regex",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::QueryDeleteRegex as u8),
        params: PATTERN_DELETE_PARAMS,
        binds: PATTERN_DELETE_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: Some(RecordSet::Queries),
    },
    VmodSpec {
        name: "urlplus.query_keep_regex",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::QueryKeepRegex as u8),
        params: ONE_PATTERN,
        binds: ONE_PATTERN_BIND,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: Some(RecordSet::Queries),
    },
    VmodSpec {
        name: "urlplus.url_delete_regex",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::UrlDeleteRegex as u8),
        params: PATTERN_DELETE_PARAMS,
        binds: PATTERN_DELETE_BINDS,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: Some(RecordSet::Segments),
    },
    VmodSpec {
        name: "urlplus.url_keep_regex",
        module: Module::Urlplus,
        shape: Shape::Transform(vcl_rt::UrlOp::UrlKeepRegex as u8),
        params: ONE_PATTERN,
        binds: ONE_PATTERN_BIND,
        phases: &[],
        phase_help: "",
        flags: 0,
        select: Some(RecordSet::Segments),
    },
    // ── headerplus ──────────────────────────────────────────────────────
    VmodSpec {
        name: "headerplus.init",
        module: Module::Headerplus,
        shape: Shape::Reseed,
        params: HEADER_SCOPE_PARAMS,
        binds: &[Bind::Scope],
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.init_req",
        module: Module::Headerplus,
        shape: Shape::Reseed,
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: REQUEST_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.init_resp",
        module: Module::Headerplus,
        shape: Shape::Reseed,
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: RESPONSE_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.reset",
        module: Module::Headerplus,
        shape: Shape::Reseed,
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.write",
        module: Module::Headerplus,
        shape: Shape::Write(0),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.get",
        module: Module::Headerplus,
        shape: Shape::Read(vcl_rt::HEADER_READ_GET),
        params: HEADER_GET_PARAMS,
        binds: HEADER_GET_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.count",
        module: Module::Headerplus,
        shape: Shape::Count(vcl_rt::HEADER_COUNT_NAME),
        params: ONE_NAME,
        binds: NAME_BIND,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.keep",
        module: Module::Headerplus,
        shape: Shape::Transform(vcl_rt::HeaderOp::Keep as u8),
        params: ONE_NAME,
        binds: NAME_BIND,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.delete",
        module: Module::Headerplus,
        shape: Shape::Transform(vcl_rt::HeaderOp::Delete as u8),
        params: DELETE_PARAMS,
        binds: DELETE_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.set",
        module: Module::Headerplus,
        shape: Shape::Transform(vcl_rt::HeaderOp::Set as u8),
        params: HEADER_SET_PARAMS,
        binds: HEADER_SET_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.add",
        module: Module::Headerplus,
        shape: Shape::Transform(vcl_rt::HeaderOp::Add as u8),
        params: HEADER_SET_PARAMS,
        binds: HEADER_SET_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "headerplus.get_regex",
        module: Module::Headerplus,
        shape: Shape::Read(vcl_rt::HEADER_READ_GET_REGEX),
        params: HEADER_GET_REGEX_PARAMS,
        binds: HEADER_GET_REGEX_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "headerplus.get_name_regex",
        module: Module::Headerplus,
        shape: Shape::Read(vcl_rt::HEADER_READ_NAME_REGEX),
        params: HEADER_NAME_REGEX_PARAMS,
        binds: HEADER_NAME_REGEX_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "headerplus.count_regex",
        module: Module::Headerplus,
        shape: Shape::Count(vcl_rt::HEADER_COUNT_REGEX),
        params: ONE_PATTERN,
        binds: ONE_PATTERN_BIND,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "headerplus.keep_regex",
        module: Module::Headerplus,
        shape: Shape::Transform(vcl_rt::HeaderOp::KeepRegex as u8),
        params: ONE_PATTERN,
        binds: ONE_PATTERN_BIND,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    VmodSpec {
        name: "headerplus.delete_regex",
        module: Module::Headerplus,
        shape: Shape::Transform(vcl_rt::HeaderOp::DeleteRegex as u8),
        params: PATTERN_DELETE_PARAMS,
        binds: PATTERN_DELETE_BINDS,
        phases: HEADER_PHASES,
        phase_help: HEADER_PHASE_HELP,
        flags: 0,
        select: Some(RecordSet::Whole),
    },
    // ── uri ─────────────────────────────────────────────────────────────
    //
    // Seven components, and for five of them a `get` that may decode and a
    // `set` that may encode.  The pairs are rows rather than one row with
    // the component as an argument, so the VCL name and the runtime
    // operation stay in the one-to-one relation the rest of the table has.
    VmodSpec {
        name: "uri.parse",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::Parse as u8),
        params: URI_PARSE_PARAMS,
        binds: &[Bind::Argument, URI_OPTION],
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.reset",
        module: Module::Uri,
        shape: Shape::Reseed,
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.write",
        module: Module::Uri,
        shape: Shape::Write(vcl_rt::UriRead::AsString as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: &[Phase::BackendRequest],
        phase_help: URI_KEY_OWNED_BY_TOML,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.as_string",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::AsString as u8),
        params: URI_AS_STRING_PARAMS,
        binds: &[Bind::Argument, URI_OPTION],
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.get_scheme",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::Scheme as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.set_scheme",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::SetScheme as u8),
        params: URI_SET_PARAMS,
        binds: URI_SET_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.get_userinfo",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::Userinfo as u8),
        params: URI_DECODE_PARAMS,
        binds: URI_OPTION_BIND,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.set_userinfo",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::SetUserinfo as u8),
        params: URI_SET_ENCODE_PARAMS,
        binds: URI_SET_ENCODE_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.get_host",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::Host as u8),
        params: URI_DECODE_PARAMS,
        binds: URI_OPTION_BIND,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.set_host",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::SetHost as u8),
        params: URI_SET_ENCODE_PARAMS,
        binds: URI_SET_ENCODE_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.get_port",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::Port as u8),
        params: NO_PARAMS,
        binds: NO_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.set_port",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::SetPort as u8),
        params: URI_SET_PARAMS,
        binds: URI_SET_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.get_path",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::Path as u8),
        params: URI_DECODE_PARAMS,
        binds: URI_OPTION_BIND,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.set_path",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::SetPath as u8),
        params: URI_SET_ENCODE_PARAMS,
        binds: URI_SET_ENCODE_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.get_query",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::Query as u8),
        params: URI_DECODE_PARAMS,
        binds: URI_OPTION_BIND,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.set_query",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::SetQuery as u8),
        params: URI_SET_ENCODE_PARAMS,
        binds: URI_SET_ENCODE_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.get_fragment",
        module: Module::Uri,
        shape: Shape::Read(vcl_rt::UriRead::Fragment as u8),
        params: URI_DECODE_PARAMS,
        binds: URI_OPTION_BIND,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
    VmodSpec {
        name: "uri.set_fragment",
        module: Module::Uri,
        shape: Shape::Transform(vcl_rt::UriOp::SetFragment as u8),
        params: URI_SET_ENCODE_PARAMS,
        binds: URI_SET_ENCODE_BINDS,
        phases: NO_PHASES,
        phase_help: URI_PHASE_HELP,
        flags: 0,
        select: None,
    },
];

const COOKIE_PHASE_HELP: &str =
    "cookieplus works on req.http.Cookie, so it is available while shaping the request";
const SETCOOKIE_PHASE_HELP: &str =
    "the setcookie_* half of cookieplus works on the response's Set-Cookie headers, so it is \
     available in vcl_backend_response, vcl_deliver and vcl_synth";
const URI_PHASE_HELP: &str =
    "uri parses a URI into its RFC 3986 components; the parse itself is available in every phase";
const URI_KEY_OWNED_BY_TOML: &str = "uri.write replaces Host as well as the URL, and the client's \
     Host picked this tenant; use urlplus.write on the client side, or uri.write in vcl_backend_fetch";
const HEADER_PHASE_HELP: &str =
    "headerplus works on the header map the phase can write: req or bereq while shaping the \
     request, beresp or resp while shaping the response";

const FUNCTIONS: &[FunctionSpec] = &[
    FunctionSpec {
        name: "digest.hash_sha256",
        params: ONE_STRING,
        result: ValueType::String,
        lower: BuiltinLowering::Digest(DigestFunction::HashSha256),
    },
    FunctionSpec {
        name: "digest.hmac_sha256",
        params: TWO_STRINGS,
        result: ValueType::String,
        lower: BuiltinLowering::Digest(DigestFunction::HmacSha256),
    },
    FunctionSpec {
        name: "digest.verify_hmac_sha256",
        params: THREE_STRINGS,
        result: ValueType::Boolean,
        lower: BuiltinLowering::Digest(DigestFunction::VerifyHmacSha256),
    },
    FunctionSpec {
        name: "std.tolower",
        params: ONE_STRING,
        result: ValueType::String,
        lower: BuiltinLowering::StringCase { upper: false },
    },
    FunctionSpec {
        name: "std.toupper",
        params: ONE_STRING,
        result: ValueType::String,
        lower: BuiltinLowering::StringCase { upper: true },
    },
    FunctionSpec {
        name: "regsub",
        params: THREE_STRINGS,
        result: ValueType::String,
        lower: BuiltinLowering::Regsub { all: false },
    },
    FunctionSpec {
        name: "regsuball",
        params: THREE_STRINGS,
        result: ValueType::String,
        lower: BuiltinLowering::Regsub { all: true },
    },
    FunctionSpec {
        name: "std.strstr",
        params: TWO_STRINGS,
        result: ValueType::String,
        lower: BuiltinLowering::Strstr,
    },
    FunctionSpec {
        name: "std.prefix",
        params: TWO_STRINGS,
        result: ValueType::Boolean,
        lower: BuiltinLowering::StringPredicate { prefix: true },
    },
    FunctionSpec {
        name: "std.suffix",
        params: TWO_STRINGS,
        result: ValueType::Boolean,
        lower: BuiltinLowering::StringPredicate { prefix: false },
    },
    FunctionSpec {
        name: "std.max",
        params: TWO_INTEGERS,
        result: ValueType::Integer,
        lower: BuiltinLowering::Extreme { max: true },
    },
    FunctionSpec {
        name: "std.min",
        params: TWO_INTEGERS,
        result: ValueType::Integer,
        lower: BuiltinLowering::Extreme { max: false },
    },
    FunctionSpec {
        name: "std.integer",
        params: INTEGER_PARAMS,
        result: ValueType::Integer,
        lower: BuiltinLowering::ParseInteger,
    },
    FunctionSpec {
        name: "std.duration",
        params: DURATION_PARAMS,
        result: ValueType::Duration,
        lower: BuiltinLowering::ParseDuration,
    },
    FunctionSpec {
        name: "std.time",
        params: TIME_PARAMS,
        result: ValueType::Time,
        lower: BuiltinLowering::ParseTime,
    },
    FunctionSpec {
        name: "std.fnmatch",
        params: FNMATCH_PARAMS,
        result: ValueType::Boolean,
        lower: BuiltinLowering::Fnmatch,
    },
    FunctionSpec {
        name: "std.querysort",
        params: ONE_STRING,
        result: ValueType::String,
        lower: BuiltinLowering::Querysort,
    },
    FunctionSpec {
        name: "str.len",
        params: STR_ONE,
        result: ValueType::Integer,
        lower: BuiltinLowering::StrTest(vcl_rt::StrTest::Len),
    },
    FunctionSpec {
        name: "str.startswith",
        params: STR_TWO,
        result: ValueType::Boolean,
        lower: BuiltinLowering::StrTest(vcl_rt::StrTest::StartsWith),
    },
    FunctionSpec {
        name: "str.endswith",
        params: STR_TWO,
        result: ValueType::Boolean,
        lower: BuiltinLowering::StrTest(vcl_rt::StrTest::EndsWith),
    },
    FunctionSpec {
        name: "str.contains",
        params: STR_TWO,
        result: ValueType::Boolean,
        lower: BuiltinLowering::StrTest(vcl_rt::StrTest::Contains),
    },
    FunctionSpec {
        name: "str.token_intersect",
        params: STR_TOKEN_PARAMS,
        result: ValueType::Boolean,
        lower: BuiltinLowering::StrTest(vcl_rt::StrTest::TokenIntersect),
    },
    FunctionSpec {
        name: "str.substr",
        params: STR_SUBSTR_PARAMS,
        result: ValueType::String,
        lower: BuiltinLowering::StrEdit(vcl_rt::StrEdit::Substr),
    },
    FunctionSpec {
        name: "str.reverse",
        params: STR_ONE,
        result: ValueType::String,
        lower: BuiltinLowering::StrEdit(vcl_rt::StrEdit::Reverse),
    },
    FunctionSpec {
        name: "str.split",
        params: STR_SPLIT_PARAMS,
        result: ValueType::String,
        lower: BuiltinLowering::StrSplit,
    },
    FunctionSpec {
        name: "uri.decode",
        params: URI_DECODE_STRAND_PARAMS,
        result: ValueType::String,
        lower: BuiltinLowering::UriDecode,
    },
    FunctionSpec {
        name: "std.syntax",
        params: SYNTAX_PARAMS,
        result: ValueType::Boolean,
        lower: BuiltinLowering::Syntax,
    },
];

/// Bind a VCL call according to VCC's positional-then-named rule.  This is
/// deliberately shared by every builtin: adding a vmod function must not add
/// another subtly different spelling of optional parameters.
fn bind_arguments(
    function: &str,
    params: &[ParameterSpec],
    arguments: Vec<ast::CallArgument>,
    call_span: Span,
) -> Result<Vec<ast::Expr>, Diagnostic> {
    let found = arguments.len();
    let mut bound: Vec<Option<ast::Expr>> = vec![None; params.len()];
    let mut next_positional = 0;
    let mut saw_named = false;

    for argument in arguments {
        let parameter = match argument.name {
            Some(name) => {
                saw_named = true;
                let Some(index) = params.iter().position(|param| param.name == name) else {
                    let valid = params
                        .iter()
                        .map(|param| param.name)
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(Diagnostic::error(
                        argument.name_span.unwrap_or(argument.value.span),
                        format!("{function} has no parameter named '{name}'"),
                    )
                    .with_help(format!("valid parameters: {valid}")));
                };
                index
            }
            None => {
                if saw_named {
                    return Err(Diagnostic::error(
                        argument.value.span,
                        "a positional argument cannot follow a named argument",
                    ));
                }
                let index = next_positional;
                next_positional += 1;
                index
            }
        };
        if parameter >= params.len() {
            return Err(argument_count_error(function, params, found, call_span));
        }
        if bound[parameter].is_some() {
            return Err(Diagnostic::error(
                argument.name_span.unwrap_or(argument.value.span),
                format!(
                    "{function} parameter '{}' is specified more than once",
                    params[parameter].name
                ),
            ));
        }

        let mut value = argument.value;
        if !params[parameter].enum_values.is_empty() {
            let ExprKind::Variable(name) = &value.kind else {
                return Err(Diagnostic::error(
                    value.span,
                    format!(
                        "{} expects {} as a bare identifier",
                        params[parameter].name,
                        params[parameter].enum_values.join(" | ")
                    ),
                ));
            };
            if !params[parameter].enum_values.contains(&name.as_str()) {
                return Err(Diagnostic::error(
                    value.span,
                    format!("invalid {} value '{name}'", params[parameter].name),
                )
                .with_help(format!(
                    "valid values: {}",
                    params[parameter].enum_values.join(", ")
                )));
            }
            value.kind = ExprKind::Literal(Literal::String(name.clone()));
        }
        bound[parameter] = Some(value);
    }

    bound
        .into_iter()
        .enumerate()
        .map(|(index, value)| match value {
            Some(value) => Ok(value),
            None => match params[index].default {
                Some(DefaultArgument::Integer(value)) => Ok(ast::Expr {
                    kind: ExprKind::Literal(Literal::Integer(value)),
                    span: call_span,
                }),
                Some(DefaultArgument::Duration(value)) => Ok(ast::Expr {
                    kind: ExprKind::Literal(Literal::Duration(value)),
                    span: call_span,
                }),
                Some(DefaultArgument::Boolean(value)) => Ok(ast::Expr {
                    kind: ExprKind::Bool(value),
                    span: call_span,
                }),
                Some(DefaultArgument::String(value)) | Some(DefaultArgument::Enum(value)) => {
                    Ok(ast::Expr {
                        kind: ExprKind::Literal(Literal::String(value.to_string())),
                        span: call_span,
                    })
                }
                None => Err(argument_count_error(function, params, found, call_span)),
            },
        })
        .collect()
}

/// The header map a phase can write, which is the map `headerplus` reads and
/// commits there.
///
/// Making the scope a function of the phase rather than of an earlier
/// `init()` is what keeps M5's "the scope is a compile-time constant per
/// hook" true without carrying state across statements: `init(req)` in
/// `vcl_deliver` is a compile error naming the phase's map, exactly as
/// `set req.http.X` there already is.
fn header_scope(phase: Phase) -> (bool, &'static str) {
    match phase {
        Phase::Recv | Phase::Hash | Phase::Hit | Phase::Miss | Phase::Pass => (false, "req"),
        Phase::BackendRequest => (false, "bereq"),
        Phase::BackendResponse | Phase::BackendError => (true, "beresp"),
        Phase::Deliver | Phase::Synth => (true, "resp"),
    }
}

/// Whether a call names one of the built-in vmod modules.
pub(crate) fn is_vmod_call(function: &str) -> bool {
    function
        .split_once('.')
        .is_some_and(|(module, _)| MODULE_NAMES.contains(&module))
}

const MODULE_NAMES: &[&str] = &["cookieplus", "urlplus", "headerplus", "uri"];

/// Modules whose functions the compiler can speak about by name.
///
/// A statement that calls into one of these reaches the type checker even when
/// the function itself is unknown, so the refusal can list what the module does
/// have instead of the bare "unsupported statement" a stray word gets.
pub(crate) fn is_builtin_module_call(function: &str) -> bool {
    function
        .split_once('.')
        .is_some_and(|(module, _)| matches!(module, "std" | "str" | "digest"))
        || is_vmod_call(function)
}

/// `uri.decode` is the one function of a `VMODS` module that is not a
/// `VMODS` row: it touches no state, so it lowers like `str.substr` rather
/// than through the module's routines.
pub(crate) fn is_stateless_vmod_call(function: &str) -> bool {
    function == "uri.decode"
}

fn vmod_spec(function: &str) -> Option<&'static VmodSpec> {
    VMODS.iter().find(|spec| spec.name == function)
}

/// Everything one bound vmod call produces.
struct BoundCall {
    module: Module,
    shape: Shape,
    /// The runtime operation word.
    code: i64,
    /// The runtime string arguments, already coerced to STRING.
    arguments: Vec<TypedExpr>,
    /// A read's fallback value.
    default: TypedExpr,
    /// The header map a `headerplus` statement targets.
    response: bool,
    /// The project/match step a `_regex` form runs before its own routine.
    regex: Option<RegexSelect>,
    /// The header a `HEADER` parameter named: the state `setcookie_parse`
    /// seeds from, or the one `setcookie_write` commits to.
    header: Option<String>,
}

/// Bind, check and encode one vmod call.
///
/// This is the only place that reads a [`VmodSpec`], so the argument list, the
/// phase gate and the operation word are decided once for every function in
/// all three modules.
fn bind_vmod_call(
    phase: Phase,
    function: &str,
    arguments: Vec<ast::CallArgument>,
    span: Span,
    env: &TypeEnv<'_>,
) -> Result<BoundCall, Diagnostic> {
    let Some(spec) = vmod_spec(function) else {
        let module = function.split('.').next().unwrap_or(function);
        let mut supported: Vec<&str> = VMODS
            .iter()
            .filter(|candidate| candidate.module.vcl_name() == module)
            .map(|candidate| {
                candidate
                    .name
                    .split_once('.')
                    .map_or(candidate.name, |(_, tail)| tail)
            })
            .collect();
        // `uri.decode` is in FUNCTIONS rather than VMODS, so the list a
        // reader gets has to name it too.
        if module == "uri" {
            supported.push("decode");
        }
        supported.sort_unstable();
        return Err(
            Diagnostic::error(span, format!("unsupported {module} function '{function}'"))
                .with_help(format!("supported: {}", supported.join(", "))),
        );
    };

    let (response, scope_name) = header_scope(phase);
    if !spec.phases.is_empty() && !spec.phases.contains(&phase) {
        return Err(Diagnostic::error(
            span,
            format!("{function} is not valid in {}", phase.vcl_name()),
        )
        .with_help(spec.phase_help));
    }

    let bound = bind_arguments(function, spec.params, arguments, span)?;
    let mut code = OpCode::new(match spec.shape {
        Shape::Transform(op) | Shape::Read(op) | Shape::Count(op) | Shape::Write(op) => op,
        Shape::Reseed => 0,
    });
    code.flags = spec.flags;
    let mut runtime_arguments = Vec::new();
    let mut patterns: Vec<String> = Vec::new();
    let mut value_fields = 0u8;
    let mut default = TypedExpr {
        kind: TypedExprKind::String(String::new()),
        value_type: ValueType::String,
        span,
    };

    let mut header = None;

    for (parameter, bind) in spec
        .params
        .iter()
        .zip(spec.binds)
        .enumerate()
        .map(|(index, (parameter, bind))| ((index, parameter), *bind))
    {
        let (index, parameter) = parameter;
        let what = format!("{function} {}", parameter.name);
        // A `HEADER` names a header rather than reading one, so it is the one
        // parameter that never reaches `check_expr`.
        if bind == Bind::Header {
            header = Some(bind_header(phase, &bound[index], &what)?);
            continue;
        }
        let value = check_expr(phase, bound[index].clone(), env)?;
        match bind {
            Bind::Argument => runtime_arguments.push(coerce_string(value)),
            Bind::Default => default = coerce_string(value),
            Bind::Flag(bit) => {
                if literal_flag(&value, parameter.enum_values, &what)? {
                    code.flags |= bit;
                }
            }
            Bind::First => code.first = index_literal(&value, &what)?,
            Bind::Second => code.second = index_literal(&value, &what)?,
            Bind::Extra(shift) => {
                let selected = enum_index(&value, parameter.enum_values, &what)?;
                code.extra |= (selected & 0x3) << shift;
            }
            Bind::ExtraFlag(bit) => {
                if literal_flag(&value, parameter.enum_values, &what)? {
                    code.extra |= 1 << bit;
                }
            }
            Bind::Expiry => {
                if !matches!(value.value_type, ValueType::Duration | ValueType::Integer) {
                    return Err(Diagnostic::error(
                        value.span,
                        format!("{what} expects a DURATION"),
                    ));
                }
                let span = value.span;
                // Raw nanoseconds, not the VCL duration text: the routine
                // adds them and formats one HTTP-date from the sum.
                runtime_arguments.push(TypedExpr {
                    kind: TypedExprKind::ToString {
                        value: Box::new(value),
                        conversion: StringConversion::Integer,
                    },
                    value_type: ValueType::String,
                    span,
                });
                runtime_arguments.push(TypedExpr {
                    kind: TypedExprKind::ToString {
                        value: Box::new(TypedExpr {
                            kind: TypedExprKind::Read {
                                lowering: Lowering::Now,
                                name: None,
                            },
                            value_type: ValueType::Time,
                            span,
                        }),
                        conversion: StringConversion::Integer,
                    },
                    value_type: ValueType::String,
                    span,
                });
            }
            Bind::Header => unreachable!("a header is bound before the value is checked"),
            Bind::NamePattern | Bind::ValuePattern => {
                let TypedExprKind::String(pattern) = &value.kind else {
                    return Err(Diagnostic::error(
                        value.span,
                        format!("{what} expects a regular-expression literal"),
                    )
                    .with_help(
                        "the host compiles the pattern once when the script loads, so it \
                         cannot be built from request data",
                    ));
                };
                let pattern = if spec.module == Module::Headerplus && bind == Bind::NamePattern {
                    // The vmod compiles a header-name pattern with
                    // VRE_CASELESS; a header name is case-insensitive
                    // everywhere else in the product too.
                    format!("(?i){pattern}")
                } else {
                    pattern.clone()
                };
                // The spelling that reaches the host is the one it has to
                // have compiled at load, so that is the one recorded.
                check_pattern(&pattern, value.span, env)?;
                if matches!(bind, Bind::ValuePattern) {
                    value_fields |= 1 << patterns.len();
                }
                patterns.push(pattern);
            }
            Bind::Scope => {
                let named = enum_index(&value, parameter.enum_values, &what)?;
                let named = parameter.enum_values[named as usize];
                if named != scope_name {
                    return Err(Diagnostic::error(
                        value.span,
                        format!("{function} cannot name '{named}' in {}", phase.vcl_name()),
                    )
                    .with_help(format!(
                        "{} writes '{scope_name}'; headerplus reads and writes the map its \
                         phase can write",
                        phase.vcl_name()
                    )));
                }
            }
        }
    }

    if runtime_arguments.len() > vcl_rt::setcookie_field::COUNT {
        return Err(Diagnostic::error(
            span,
            format!("{function} passes more runtime arguments than the runtime ABI carries"),
        ));
    }

    // A `_regex` form's routine argument *is* the bitmap block, so the row
    // may not also bind a runtime string. The table is checked for this in a
    // unit test; the assertion is here for the reader.
    debug_assert!(
        spec.select.is_none() || runtime_arguments.is_empty(),
        "{function} binds both a pattern and a runtime argument"
    );
    let regex = match spec.select {
        // A module with no record projection has no `_regex` form, and the
        // table holds no row that gives it one.
        Some(set) => Some(RegexSelect {
            select: spec.module.select_code(set).ok_or_else(|| {
                Diagnostic::error(
                    span,
                    format!("{function} matches patterns against a module that has no records"),
                )
            })?,
            patterns,
            value_fields,
        }),
        None => None,
    };

    Ok(BoundCall {
        module: spec.module,
        shape: spec.shape,
        code: code.encode(),
        arguments: runtime_arguments,
        default,
        response,
        regex,
        header,
    })
}

/// A `HEADER` argument: the name of a response header the phase can write.
///
/// The string form is what the row's own default is written as; a policy that
/// spells the header out reaches the same place, and both go through
/// [`check_header_identity`] so a framing header is refused here rather than
/// by the host at run time.
fn bind_header(phase: Phase, argument: &ast::Expr, what: &str) -> Result<String, Diagnostic> {
    let name = match &argument.kind {
        ast::ExprKind::Literal(ast::Literal::String(name)) => name.clone(),
        ast::ExprKind::Variable(variable) => {
            let Some((spec, suffix)) = vars::resolve(variable) else {
                return Err(unknown_variable(variable, argument.span));
            };
            let (Some(header), Lowering::ResponseHeader) = (suffix, spec.lowering) else {
                return Err(Diagnostic::error(
                    argument.span,
                    format!("{what} expects a response header, and {variable} is not one"),
                ));
            };
            if !spec.writable.contains(&phase) {
                return Err(not_writable(variable, phase, argument.span));
            }
            header.to_string()
        }
        ast::ExprKind::Literal(_)
        | ast::ExprKind::Bool(_)
        | ast::ExprKind::Call { .. }
        | ast::ExprKind::Not(_)
        | ast::ExprKind::Negate(_)
        | ast::ExprKind::Binary { .. }
        | ast::ExprKind::AddChain(_) => {
            return Err(Diagnostic::error(
                argument.span,
                format!("{what} expects a header, such as resp.http.Set-Cookie"),
            ))
        }
    };
    // The response-map rules of `check_header_identity` reduce to this one:
    // `Host` and `variant_headers` are request-side and only in vcl_recv.
    if vars::is_framing_header(&name) {
        return Err(Diagnostic::error(
            argument.span,
            format!("{name} is a framing or hop-by-hop header and cannot be set"),
        )
        .with_help("framing is transport-owned because response bodies are immutable"));
    }
    Ok(name)
}

/// A `BOOL` literal, or a two-valued `ENUM` whose second value means true.
///
/// The `ENUM` form is what lets `cookieplus.get(..., occurrence = LAST)` and
/// `add(..., keep = true)` share one binding rule instead of each needing a
/// hand-written decoder.
fn literal_flag(
    value: &TypedExpr,
    enum_values: &'static [&'static str],
    what: &str,
) -> Result<bool, Diagnostic> {
    if !enum_values.is_empty() {
        return Ok(enum_index(value, enum_values, what)? != 0);
    }
    let TypedExprKind::Boolean(flag) = &value.kind else {
        return Err(Diagnostic::error(
            value.span,
            format!("{what} expects a BOOL literal"),
        ));
    };
    Ok(*flag)
}

/// An `INT` literal small enough to ride in the operation word.
///
/// The bound is [`vcl_rt::MAX_LIST_ITEMS`], not `i16`: an index past
/// the list capacity can never select anything, so refusing it at compile
/// time is better than encoding a number the runtime will ignore.
fn index_literal(value: &TypedExpr, what: &str) -> Result<i16, Diagnostic> {
    let TypedExprKind::Integer(number) = value.kind else {
        return Err(Diagnostic::error(
            value.span,
            format!("{what} expects an INT literal"),
        ));
    };
    let limit = vcl_rt::MAX_LIST_ITEMS as i64;
    if number < -1 || number > limit {
        return Err(Diagnostic::error(
            value.span,
            format!("{what} must be between -1 and {limit}"),
        )
        .with_help(
            "a vmod module holds a fixed number of records, so an index past it \
                    could never select one",
        ));
    }
    Ok(number as i16)
}

fn enum_index(
    value: &TypedExpr,
    values: &'static [&'static str],
    what: &str,
) -> Result<u16, Diagnostic> {
    let TypedExprKind::String(named) = &value.kind else {
        return Err(Diagnostic::error(
            value.span,
            format!("{what} expects one of {}", values.join(", ")),
        ));
    };
    values
        .iter()
        .position(|candidate| candidate == named)
        .map(|index| index as u16)
        .ok_or_else(|| {
            Diagnostic::error(value.span, format!("invalid {what} '{named}'"))
                .with_help(format!("valid values: {}", values.join(", ")))
        })
}

/// Check a vmod call in statement position.
fn check_vmod_statement(
    phase: Phase,
    function: &str,
    arguments: Vec<ast::CallArgument>,
    span: Span,
    env: &TypeEnv<'_>,
) -> Result<TypedStatement, Diagnostic> {
    if !is_vmod_call(function) || is_stateless_vmod_call(function) {
        // A `std.`/`str.`/`digest.` call in statement position, or the one
        // `uri` function that is one of them: either it is a value function
        // used as a statement, or it does not exist. `check_call` owns both
        // diagnostics, so ask it rather than repeating them.
        return Err(match check_call(phase, function, arguments, span, env) {
            Ok(_) => Diagnostic::error(
                span,
                format!("{function} returns a value and cannot stand alone as a statement"),
            )
            .with_help(format!(
                "use it in an expression, such as `set req.http.X = {function}(...)`"
            )),
            Err(diagnostic) => diagnostic,
        });
    }
    let call = bind_vmod_call(phase, function, arguments, span, env)?;
    let action = match call.shape {
        Shape::Transform(_) => VmodAction::Transform {
            code: call.code,
            arguments: call.arguments,
            regex: call.regex,
        },
        Shape::Reseed => VmodAction::Reseed {
            response: call.response,
            source: call.header,
        },
        Shape::Write(_) => VmodAction::Write {
            code: call.code,
            response: call.response,
            header: call.header,
        },
        Shape::Read(_) | Shape::Count(_) => {
            return Err(Diagnostic::error(
                span,
                format!("{function} returns a value and cannot stand alone as a statement"),
            )
            .with_help(format!(
                "use it in an expression, such as `set req.http.X = {function}(...)`"
            )))
        }
    };
    Ok(TypedStatement::Vmod {
        module: call.module,
        action,
        span,
    })
}

/// Check a vmod call in expression position.
fn check_vmod_expression(
    phase: Phase,
    function: &str,
    arguments: Vec<ast::CallArgument>,
    span: Span,
    env: &TypeEnv<'_>,
) -> Result<(TypedExprKind, ValueType), Diagnostic> {
    let call = bind_vmod_call(phase, function, arguments, span, env)?;
    match call.shape {
        Shape::Read(_) => Ok((
            TypedExprKind::VmodRead {
                module: call.module,
                code: call.code,
                arguments: call.arguments,
                default: Box::new(call.default),
                regex: call.regex,
            },
            ValueType::String,
        )),
        Shape::Count(_) => Ok((
            TypedExprKind::VmodCount {
                module: call.module,
                code: call.code,
                arguments: call.arguments,
                regex: call.regex,
            },
            ValueType::Integer,
        )),
        Shape::Transform(_) | Shape::Reseed | Shape::Write(_) => Err(Diagnostic::error(
            span,
            format!("{function} returns nothing and cannot be used as a value"),
        )
        .with_help(format!("call it as a statement: `{function}(...);`"))),
    }
}

fn argument_count_error(
    function: &str,
    params: &[ParameterSpec],
    found: usize,
    span: Span,
) -> Diagnostic {
    let required = params
        .iter()
        .filter(|param| param.default.is_none())
        .count();
    let expected = if required == params.len() {
        params.len().to_string()
    } else {
        format!("{required} or {}", params.len())
    };
    Diagnostic::error(
        span,
        format!(
            "{function} expects {expected} argument{}, found {found}",
            if params.len() == 1 { "" } else { "s" },
        ),
    )
}

fn check_call(
    phase: Phase,
    function: &str,
    arguments: Vec<ast::CallArgument>,
    span: Span,
    env: &TypeEnv<'_>,
) -> Result<(TypedExprKind, ValueType), Diagnostic> {
    if is_vmod_call(function) && !is_stateless_vmod_call(function) {
        return check_vmod_expression(phase, function, arguments, span, env);
    }
    let Some(spec) = FUNCTIONS.iter().find(|spec| spec.name == function) else {
        return if function.starts_with("digest.") {
            Err(
                Diagnostic::error(span, format!("unsupported digest function '{function}'"))
                    .with_help(
                        "use digest.hash_sha256, digest.hmac_sha256, or digest.verify_hmac_sha256",
                    ),
            )
        } else if matches!(function, "std.log" | "std.collect") {
            Err(
                Diagnostic::error(span, format!("{function} is a statement, not a value"))
                    .with_help(format!("call it on its own: `{function}(...);`")),
            )
        } else if function.starts_with("std.") {
            Err(Diagnostic::error(span, format!("unsupported std function '{function}'"))
                .with_help("supported: std.log, std.collect, std.tolower, std.toupper, std.integer, std.duration, std.time, std.fnmatch, std.querysort, std.syntax, std.strstr, std.prefix, and std.suffix"))
        } else if function.starts_with("str.") {
            Err(Diagnostic::error(span, format!("unsupported str function '{function}'"))
                .with_help("supported: str.len, str.startswith, str.endswith, str.contains, str.substr, str.reverse, str.split, and str.token_intersect"))
        } else {
            Err(Diagnostic::error(
                span,
                format!("unknown or unsupported VCL function '{function}'"),
            ))
        };
    };
    let arguments = bind_arguments(function, spec.params, arguments, span)?;
    if matches!(spec.lower, BuiltinLowering::Syntax) {
        let version = arguments
            .into_iter()
            .next()
            .expect("one std.syntax argument");
        // `std.syntax(4.1)` is a compile-time feature probe: true when the
        // file's declared level is at least the one asked for.  Varnish
        // truncates the REAL to tenths and compares it with the syntax
        // level, so `std.syntax(4.15)` still passes under `vcl 4.1;`.  V1
        // recognises the REAL spelling but never makes REAL a value type,
        // so no generated code or runtime ABI is involved.
        let ExprKind::Literal(Literal::Real(ref text)) = version.kind else {
            return Err(Diagnostic::error(
                version.span,
                "std.syntax expects a REAL literal such as 4.1",
            ));
        };
        let asked = text
            .parse::<f64>()
            .map(|level| (level * 10.0) as i64)
            .unwrap_or(i64::MAX);
        return Ok((
            TypedExprKind::Boolean(i64::from(env.syntax) >= asked),
            ValueType::Boolean,
        ));
    }
    if matches!(spec.lower, BuiltinLowering::Querysort) && phase == Phase::Recv {
        return Err(Diagnostic::error(
            span,
            "std.querysort cannot change req.url in vcl_recv because the cache key is declarative",
        )
        .with_help("sort the query string with std.querysort in the Varnish VCL that forks this tenant"));
    }
    let typed = arguments
        .into_iter()
        .map(|argument| check_expr(phase, argument, env))
        .collect::<Result<Vec<_>, _>>()?;
    let strings =
        |values: Vec<TypedExpr>| values.into_iter().map(coerce_string).collect::<Vec<_>>();
    match spec.lower {
        BuiltinLowering::Digest(digest) => Ok((
            TypedExprKind::Digest {
                function: digest,
                arguments: strings(typed),
            },
            spec.result,
        )),
        BuiltinLowering::StringCase { upper } => {
            let mut values = strings(typed);
            Ok((
                TypedExprKind::StringCase {
                    value: Box::new(values.remove(0)),
                    upper,
                },
                ValueType::String,
            ))
        }
        BuiltinLowering::Regsub { all } => {
            let mut values = strings(typed);
            let TypedExprKind::String(pattern) = &values[1].kind else {
                return Err(Diagnostic::error(
                    values[1].span,
                    "the regsub pattern must be a string literal",
                ));
            };
            check_pattern(pattern, values[1].span, env)?;
            let replacement = values.pop().expect("three values");
            let pattern = values.pop().expect("three values");
            let subject = values.pop().expect("three values");
            Ok((
                TypedExprKind::Regsub {
                    subject: Box::new(subject),
                    pattern: Box::new(pattern),
                    replacement: Box::new(replacement),
                    all,
                },
                ValueType::String,
            ))
        }
        BuiltinLowering::Strstr => {
            let mut values = strings(typed);
            let needle = values.pop().expect("two values");
            let haystack = values.pop().expect("two values");
            Ok((
                TypedExprKind::Strstr {
                    haystack: Box::new(haystack),
                    needle: Box::new(needle),
                },
                ValueType::String,
            ))
        }
        BuiltinLowering::StringPredicate { prefix } => {
            let mut values = strings(typed);
            let affix = values.pop().expect("two values");
            let value = values.pop().expect("two values");
            Ok((
                TypedExprKind::StringPredicate {
                    value: Box::new(value),
                    affix: Box::new(affix),
                    prefix,
                },
                ValueType::Boolean,
            ))
        }
        BuiltinLowering::Fnmatch => {
            let mut values = typed;
            let period = coerce_boolean(values.pop().expect("five values"))
                .ok_or_else(|| Diagnostic::error(span, "std.fnmatch period expects BOOL"))?;
            let noescape = coerce_boolean(values.pop().expect("five values"))
                .ok_or_else(|| Diagnostic::error(span, "std.fnmatch noescape expects BOOL"))?;
            let pathname = coerce_boolean(values.pop().expect("five values"))
                .ok_or_else(|| Diagnostic::error(span, "std.fnmatch pathname expects BOOL"))?;
            let subject = coerce_string(values.pop().expect("five values"));
            let pattern = coerce_string(values.pop().expect("five values"));
            Ok((
                TypedExprKind::Fnmatch {
                    pattern: Box::new(pattern),
                    subject: Box::new(subject),
                    pathname: Box::new(pathname),
                    noescape: Box::new(noescape),
                    period: Box::new(period),
                },
                ValueType::Boolean,
            ))
        }
        BuiltinLowering::Querysort => {
            let value = coerce_string(typed.into_iter().next().expect("one value"));
            Ok((
                TypedExprKind::Querysort {
                    value: Box::new(value),
                },
                ValueType::String,
            ))
        }
        BuiltinLowering::ParseInteger => {
            let mut values = typed;
            let value = coerce_string(values.remove(0));
            let fallback = if values.is_empty() {
                TypedExpr {
                    kind: TypedExprKind::Integer(0),
                    value_type: ValueType::Integer,
                    span,
                }
            } else {
                values.remove(0)
            };
            if fallback.value_type != ValueType::Integer {
                return Err(Diagnostic::error(
                    fallback.span,
                    format!(
                        "std.integer fallback expects INT, found {}",
                        type_name(fallback.value_type)
                    ),
                ));
            }
            Ok((
                TypedExprKind::ParseInteger {
                    value: Box::new(value),
                    fallback: Box::new(fallback),
                },
                ValueType::Integer,
            ))
        }
        BuiltinLowering::ParseDuration => {
            let mut values = typed;
            let value = coerce_string(values.remove(0));
            let fallback = if values.is_empty() {
                TypedExpr {
                    kind: TypedExprKind::Duration(0),
                    value_type: ValueType::Duration,
                    span,
                }
            } else {
                values.remove(0)
            };
            if fallback.value_type != ValueType::Duration {
                return Err(Diagnostic::error(
                    fallback.span,
                    format!(
                        "std.duration fallback expects DURATION, found {}",
                        type_name(fallback.value_type)
                    ),
                ));
            }
            Ok((
                TypedExprKind::ParseDuration {
                    value: Box::new(value),
                    fallback: Box::new(fallback),
                },
                ValueType::Duration,
            ))
        }
        BuiltinLowering::ParseTime => {
            let mut values = typed;
            let value = coerce_string(values.remove(0));
            let fallback = values.remove(0);
            if fallback.value_type != ValueType::Time {
                return Err(Diagnostic::error(
                    fallback.span,
                    format!(
                        "std.time fallback expects TIME, found {}",
                        type_name(fallback.value_type)
                    ),
                ));
            }
            Ok((
                TypedExprKind::ParseTime {
                    value: Box::new(value),
                    fallback: Box::new(fallback),
                },
                ValueType::Time,
            ))
        }
        BuiltinLowering::StrTest(op) => {
            let mut values = strings(typed).into_iter();
            let subject = values.next().expect("str tests bind a subject");
            let other = values.next().unwrap_or_else(|| empty_string(span));
            let separators = values.next().unwrap_or_else(|| empty_string(span));
            Ok((
                TypedExprKind::StrTest {
                    op,
                    subject: Box::new(subject),
                    other: Box::new(other),
                    separators: Box::new(separators),
                },
                spec.result,
            ))
        }
        BuiltinLowering::StrEdit(op) => {
            let mut values = typed.into_iter();
            let subject = coerce_string(values.next().expect("str edits bind a subject"));
            let count = match values.next() {
                Some(value) => integer_argument(function, "n", value)?,
                None => zero_integer(span),
            };
            let offset = match values.next() {
                Some(value) => integer_argument(function, "offset", value)?,
                None => zero_integer(span),
            };
            Ok((
                TypedExprKind::StrEdit {
                    op,
                    subject: Box::new(subject),
                    count: Box::new(count),
                    offset: Box::new(offset),
                },
                ValueType::String,
            ))
        }
        BuiltinLowering::UriDecode => {
            let mut values = typed.into_iter();
            let subject = coerce_string(values.next().expect("uri.decode binds a subject"));
            let strict = coerce_boolean(values.next().expect("uri.decode binds strict"))
                .ok_or_else(|| Diagnostic::error(span, "uri.decode strict expects BOOL"))?;
            Ok((
                TypedExprKind::StrEdit {
                    op: vcl_rt::StrEdit::UriDecode,
                    subject: Box::new(subject),
                    // The routine reads `count` as the strict flag; a BOOL
                    // is a scalar in the IR exactly as an INT is.
                    count: Box::new(strict),
                    offset: Box::new(zero_integer(span)),
                },
                ValueType::String,
            ))
        }
        BuiltinLowering::StrSplit => {
            let mut values = typed.into_iter();
            let subject = coerce_string(values.next().expect("str.split binds a subject"));
            let index = integer_argument(
                function,
                "n",
                values.next().expect("str.split binds a field number"),
            )?;
            let separators = coerce_string(values.next().expect("str.split binds a separator set"));
            Ok((
                TypedExprKind::StrSplit {
                    subject: Box::new(subject),
                    index: Box::new(index),
                    separators: Box::new(separators),
                },
                ValueType::String,
            ))
        }
        BuiltinLowering::Extreme { max } => {
            let mut values = typed.into_iter();
            let left = integer_argument(function, "a", values.next().expect("binds a"))?;
            let right = integer_argument(function, "b", values.next().expect("binds b"))?;
            Ok((
                TypedExprKind::Extreme {
                    max,
                    left: Box::new(left),
                    right: Box::new(right),
                },
                ValueType::Integer,
            ))
        }
        BuiltinLowering::Syntax => unreachable!("handled before expression type checking"),
    }
}

fn empty_string(span: Span) -> TypedExpr {
    TypedExpr {
        kind: TypedExprKind::String(String::new()),
        value_type: ValueType::String,
        span,
    }
}

fn zero_integer(span: Span) -> TypedExpr {
    TypedExpr {
        kind: TypedExprKind::Integer(0),
        value_type: ValueType::Integer,
        span,
    }
}

/// A `str` position or field number.  These are ordinary INT expressions, not
/// literals: nothing about them reaches the cache key, so there is no reason
/// to insist they be constant the way a `urlplus` segment range is.
fn integer_argument(
    function: &str,
    parameter: &str,
    value: TypedExpr,
) -> Result<TypedExpr, Diagnostic> {
    if value.value_type == ValueType::Integer {
        return Ok(value);
    }
    Err(Diagnostic::error(
        value.span,
        format!(
            "{function} {parameter} expects INT, found {}",
            type_name(value.value_type)
        ),
    ))
}

/// Every sub-expression, in evaluation order.
///
/// Exhaustive, so a new [`TypedExprKind`] has to say what it contains rather
/// than silently escaping the walks below.
/// Every expression one statement holds directly.
///
/// This and [`statement_bodies`] are the shared spine of every walk over a
/// typed body.  A pass that writes its own `match` over `TypedStatement` gets
/// to forget an arm; one that goes through these does not.
pub(crate) fn statement_expressions(statement: &TypedStatement) -> Vec<&TypedExpr> {
    match statement {
        TypedStatement::Declare { init, .. } => init.iter().collect(),
        TypedStatement::SetLocal { value, .. }
        | TypedStatement::SetStatic { value, .. }
        | TypedStatement::SetGlobal { value, .. }
        | TypedStatement::SetHeader { value, .. }
        | TypedStatement::SetUrl { value, .. }
        | TypedStatement::SetCacheDuration { value, .. }
        | TypedStatement::SetVar { value, .. }
        | TypedStatement::SetBody { value, .. }
        | TypedStatement::HashData { value, .. }
        | TypedStatement::Log { value, .. }
        | TypedStatement::Synthetic { value, .. } => vec![value],
        TypedStatement::Collect { separator, .. } => vec![separator],
        TypedStatement::Vmod { action, .. } => match action {
            VmodAction::Transform { arguments, .. } => arguments.iter().collect(),
            VmodAction::Reseed { .. } | VmodAction::Write { .. } => Vec::new(),
        },
        TypedStatement::If { branches, .. } => {
            branches.iter().map(|(condition, _)| condition).collect()
        }
        TypedStatement::Inlined { .. }
        | TypedStatement::Call { .. }
        | TypedStatement::UnsetHeader { .. }
        | TypedStatement::SetTtl { .. }
        | TypedStatement::SetStaleWhileRevalidate { .. }
        | TypedStatement::SetStaleIfError { .. }
        | TypedStatement::SetUncacheable { .. }
        | TypedStatement::Return { .. } => Vec::new(),
    }
}

/// Every nested statement body one statement holds.
pub(crate) fn statement_bodies(statement: &TypedStatement) -> Vec<&[TypedStatement]> {
    match statement {
        TypedStatement::If {
            branches,
            otherwise,
            ..
        } => branches
            .iter()
            .map(|(_, body)| body.as_slice())
            .chain(std::iter::once(otherwise.as_slice()))
            .collect(),
        TypedStatement::Inlined { body, .. } => vec![body.as_slice()],
        TypedStatement::Declare { .. }
        | TypedStatement::SetLocal { .. }
        | TypedStatement::SetStatic { .. }
        | TypedStatement::SetGlobal { .. }
        | TypedStatement::Call { .. }
        | TypedStatement::SetHeader { .. }
        | TypedStatement::UnsetHeader { .. }
        | TypedStatement::SetUrl { .. }
        | TypedStatement::SetCacheDuration { .. }
        | TypedStatement::SetTtl { .. }
        | TypedStatement::SetStaleWhileRevalidate { .. }
        | TypedStatement::SetStaleIfError { .. }
        | TypedStatement::SetUncacheable { .. }
        | TypedStatement::Collect { .. }
        | TypedStatement::Vmod { .. }
        | TypedStatement::SetVar { .. }
        | TypedStatement::SetBody { .. }
        | TypedStatement::HashData { .. }
        | TypedStatement::Log { .. }
        | TypedStatement::Synthetic { .. }
        | TypedStatement::Return { .. } => Vec::new(),
    }
}

pub(crate) fn operands(expression: &TypedExpr) -> Vec<&TypedExpr> {
    match &expression.kind {
        TypedExprKind::String(_)
        | TypedExprKind::Integer(_)
        | TypedExprKind::Duration(_)
        | TypedExprKind::Boolean(_)
        | TypedExprKind::Local(_)
        | TypedExprKind::Static(_)
        | TypedExprKind::Global(_)
        | TypedExprKind::Read { .. }
        | TypedExprKind::HeaderPresent { .. } => Vec::new(),
        TypedExprKind::Digest { arguments, .. } => arguments.iter().collect(),
        TypedExprKind::AclMatch { address, .. } => vec![address],
        TypedExprKind::Regsub {
            subject,
            pattern,
            replacement,
            ..
        } => vec![subject, pattern, replacement],
        TypedExprKind::Concat(parts) => parts.iter().collect(),
        TypedExprKind::Binary { left, right, .. } => vec![left, right],
        TypedExprKind::ToString { value, .. }
        | TypedExprKind::StringCase { value, .. }
        | TypedExprKind::Querysort { value }
        | TypedExprKind::Not(value)
        | TypedExprKind::Negate(value) => vec![value],
        TypedExprKind::Strstr { haystack, needle } => vec![haystack, needle],
        TypedExprKind::StringPredicate { value, affix, .. } => vec![value, affix],
        TypedExprKind::ParseInteger { value, fallback }
        | TypedExprKind::ParseDuration { value, fallback } => vec![value, fallback],
        TypedExprKind::ParseTime { value, fallback } => vec![value, fallback],
        TypedExprKind::Fnmatch {
            subject,
            pattern,
            pathname,
            noescape,
            period,
        } => vec![subject, pattern, pathname, noescape, period],
        TypedExprKind::StrTest {
            subject,
            other,
            separators,
            ..
        } => vec![subject, other, separators],
        TypedExprKind::StrEdit {
            subject,
            count,
            offset,
            ..
        } => vec![subject, count, offset],
        TypedExprKind::StrSplit {
            subject,
            index,
            separators,
        } => vec![subject, index, separators],
        TypedExprKind::VmodRead {
            arguments, default, ..
        } => arguments
            .iter()
            .chain(std::iter::once(default.as_ref()))
            .collect(),
        TypedExprKind::VmodCount { arguments, .. } => arguments.iter().collect(),
        TypedExprKind::Extreme { left, right, .. } => vec![left, right],
    }
}

/// What `http::HeaderValue::from_str` accepts: printable ASCII, horizontal
/// tab, and everything above 0x7f. CR, LF and NUL are exactly what it refuses.
fn is_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= 0x20 && byte != 0x7f)
}

/// Refuse a header value the transport could never carry.
///
/// A VCL string carries whatever an escape or a long literal can spell, CR and
/// LF included. The host bridge builds a `HeaderValue` from it and, when that
/// fails, warns and *skips the mutation* — the policy silently does not
/// happen. Every runtime source of a header value is already free of control
/// bytes (request headers and the URL were parsed off the wire, a digest is
/// hex, a number is rendered), so a literal is the only way one gets in, and a
/// literal is something the compiler can refuse outright.
fn check_header_value(value: &TypedExpr) -> Result<(), Diagnostic> {
    if let TypedExprKind::String(text) = &value.kind {
        if let Some(byte) = text.bytes().find(|byte| !is_header_value_byte(*byte)) {
            return Err(Diagnostic::error(
                value.span,
                format!("a header value cannot contain the byte 0x{byte:02x}"),
            )
            .with_help(
                "HTTP header values carry no control characters; \
                 use std.log or synthetic() for multi-line text",
            ));
        }
    }
    for operand in operands(value) {
        check_header_value(operand)?;
    }
    Ok(())
}

fn coerce_string(expression: TypedExpr) -> TypedExpr {
    let conversion = match expression.value_type {
        ValueType::String => return expression,
        ValueType::Integer => StringConversion::Integer,
        ValueType::Duration => StringConversion::Duration,
        ValueType::Time => StringConversion::Time,
        ValueType::Boolean => StringConversion::Boolean,
        ValueType::Ip => StringConversion::Ip,
    };
    let span = expression.span;
    TypedExpr {
        kind: TypedExprKind::ToString {
            value: Box::new(expression),
            conversion,
        },
        value_type: ValueType::String,
        span,
    }
}

/// VCL's HEADER values are truthy when the field is present. Keep that
/// distinct from STRING truthiness: an explicitly empty header is present,
/// while an absent header still compares equal to the empty string.
fn coerce_boolean(expression: TypedExpr) -> Option<TypedExpr> {
    if expression.value_type == ValueType::Boolean {
        return Some(expression);
    }
    let span = expression.span;
    if let TypedExprKind::Read {
        lowering,
        name: Some(name),
    } = &expression.kind
    {
        let response = match lowering {
            Lowering::RequestHeader => Some(false),
            Lowering::ResponseHeader => Some(true),
            Lowering::RequestUrl
            | Lowering::RequestMethod
            | Lowering::Now
            | Lowering::ClientIp
            | Lowering::Ttl
            | Lowering::StaleWhileRevalidate
            | Lowering::StaleIfError
            | Lowering::Body
            | Lowering::Host(_) => None,
            Lowering::Uncacheable | Lowering::CacheHit => None,
        };
        if let Some(response) = response {
            return Some(TypedExpr {
                kind: TypedExprKind::HeaderPresent {
                    response,
                    name: name.clone(),
                },
                value_type: ValueType::Boolean,
                span,
            });
        }
    }
    if expression.value_type != ValueType::String {
        return None;
    }
    Some(TypedExpr {
        kind: TypedExprKind::Binary {
            op: BinaryOp::NotEqual,
            left: Box::new(expression),
            right: Box::new(TypedExpr {
                kind: TypedExprKind::String(String::new()),
                value_type: ValueType::String,
                span,
            }),
        },
        value_type: ValueType::Boolean,
        span,
    })
}

/// One step through a flat `+` run.
///
/// `Value` is the arithmetic prefix; `Strings` is the flattened tail, which a
/// run enters at the first string operand and never leaves.
enum AddAccumulator {
    Value(TypedExpr),
    Strings(Vec<TypedExpr>),
}

/// Say so when a literal `beresp.grace` or `beresp.keep` will be lowered to
/// the route's cap.
///
/// `grace` and `keep` are caps, not defaults: a route that names neither caps
/// at zero and no script may raise that, so "prefer fail over stale" stays an
/// operator decision. The write is not an error — the host clamps it and
/// carries on — but a policy asking for an hour of stale-if-error on a route
/// that allows none is worth saying out loud rather than discovering from a
/// graph. Only a literal is checked; a computed window is not known here.
fn note_stale_cap(
    target: &str,
    lowering: Lowering,
    value: &TypedExpr,
    options: &CompileOptions,
    env: &TypeEnv<'_>,
) {
    let Some(cap) = options.stale_cap(lowering) else {
        return;
    };
    let TypedExprKind::Duration(nanoseconds) = value.kind else {
        return;
    };
    let seconds = nanoseconds / 1_000_000_000;
    if seconds <= u64::from(cap) {
        return;
    }
    let message = if cap == 0 {
        format!(
            "{target} has no effect here: the route names no window, so stale serving is off \
             and the {seconds}s written here becomes 0s"
        )
    } else {
        format!("{target} is capped at {cap}s by the route, not the {seconds}s written here")
    };
    env.collected
        .warnings
        .push(Diagnostic::warning(value.span, message).with_help(
            "grace and keep are caps the operator sets; a script may lower one, never raise it",
        ));
}

/// The result type of `+` or `-` over two non-string operands.
///
/// Shared by the binary arm and by [`ExprKind::AddChain`], which reproduces a
/// `+` run's left-associative meaning one operand at a time.
fn additive_type(
    op: BinaryOp,
    left: ValueType,
    right: ValueType,
    span: Span,
) -> Result<ValueType, Diagnostic> {
    match (left, right) {
        (ValueType::Integer, ValueType::Integer) | (ValueType::Duration, ValueType::Duration) => {
            Ok(left)
        }
        (ValueType::Time, ValueType::Duration) => Ok(ValueType::Time),
        (ValueType::Duration, ValueType::Time) if op == BinaryOp::Add => Ok(ValueType::Time),
        (ValueType::Time, ValueType::Time) if op == BinaryOp::Subtract => Ok(ValueType::Duration),
        _ => Err(Diagnostic::error(
            span,
            format!(
                "'{}' requires matching INT/DURATION values, TIME + DURATION, or TIME - TIME",
                binary_name(op)
            ),
        )),
    }
}

fn binary_name(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Subtract => "-",
        BinaryOp::Multiply => "*",
        BinaryOp::Divide => "/",
        BinaryOp::Modulo => "%",
        BinaryOp::Equal => "==",
        BinaryOp::NotEqual => "!=",
        BinaryOp::Less => "<",
        BinaryOp::LessEqual => "<=",
        BinaryOp::Greater => ">",
        BinaryOp::GreaterEqual => ">=",
        BinaryOp::Match => "~",
        BinaryOp::NotMatch => "!~",
        BinaryOp::And => "&&",
        BinaryOp::Or => "||",
    }
}

fn check_return_action(
    phase: Phase,
    action: ReturnAction,
    span: Span,
) -> Result<TypedReturnAction, Diagnostic> {
    use Phase::*;
    // Varnish's own table (`lib/libvcc/generate.py`), less restart, retry,
    // pipe, purge and vcl, which the parser already refused.
    let allowed: &[Phase] = match &action {
        ReturnAction::Bare => {
            return Err(Diagnostic::error(
                span,
                "a bare return is only valid in a user subroutine",
            )
            .with_help("return the normal action for this VCL hook explicitly"));
        }
        ReturnAction::Sub(_, _) => unreachable!("the checker inlines deciding subroutines"),
        ReturnAction::Hash => &[Recv],
        ReturnAction::Lookup => &[Hash],
        ReturnAction::Fetch => &[Miss, Pass, BackendRequest],
        ReturnAction::Miss => &[Hit],
        ReturnAction::Pass => &[Recv, Hit, Miss, BackendResponse],
        ReturnAction::Abandon => &[BackendRequest, BackendResponse, BackendError],
        ReturnAction::Deliver => &[Hit, Deliver, Synth, BackendResponse, BackendError],
        ReturnAction::Fail => Phase::ALL,
        ReturnAction::Synth { .. } => &[Recv, Hit, Miss, Pass, Deliver],
        ReturnAction::Error { .. } => &[BackendRequest, BackendResponse],
    };
    if !allowed.contains(&phase) {
        return Err(Diagnostic::error(
            span,
            format!(
                "return ({}) is not valid in {}",
                return_action_name(&action),
                phase.vcl_name()
            ),
        ));
    }
    Ok(match action {
        ReturnAction::Hash => TypedReturnAction::Hash,
        ReturnAction::Lookup => TypedReturnAction::Lookup,
        ReturnAction::Fetch => TypedReturnAction::Fetch,
        ReturnAction::Miss => TypedReturnAction::Miss,
        ReturnAction::Pass => TypedReturnAction::Pass,
        ReturnAction::Abandon => TypedReturnAction::Abandon,
        ReturnAction::Deliver => TypedReturnAction::Deliver,
        ReturnAction::Fail => TypedReturnAction::Fail,
        ReturnAction::Synth { status, reason } => TypedReturnAction::Synth { status, reason },
        ReturnAction::Error { status, reason } => TypedReturnAction::Error { status, reason },
        ReturnAction::Bare | ReturnAction::Sub(_, _) => unreachable!("handled above"),
    })
}

fn return_action_name(action: &ReturnAction) -> &'static str {
    match action {
        ReturnAction::Bare => "bare return",
        ReturnAction::Hash => "hash",
        ReturnAction::Lookup => "lookup",
        ReturnAction::Fetch => "fetch",
        ReturnAction::Miss => "miss",
        ReturnAction::Pass => "pass",
        ReturnAction::Abandon => "abandon",
        ReturnAction::Deliver => "deliver",
        ReturnAction::Fail => "fail",
        ReturnAction::Synth { .. } => "synth",
        ReturnAction::Error { .. } => "error",
        ReturnAction::Sub(_, _) => "subroutine",
    }
}

fn type_name(value_type: ValueType) -> &'static str {
    match value_type {
        ValueType::String => "STRING",
        ValueType::Integer => "INT",
        ValueType::Duration => "DURATION",
        ValueType::Time => "TIME",
        ValueType::Boolean => "BOOL",
        ValueType::Ip => "IP",
    }
}

/// Refuse a regular-expression literal the host could not compile.
///
/// The host builds every pattern once when the script loads and a pattern it
/// cannot build simply never matches, so a broken one has to be caught here or
/// not at all. See [`crate::regex_check`] for what "broken" is allowed to mean.
fn check_pattern(pattern: &str, span: Span, env: &TypeEnv<'_>) -> Result<(), Diagnostic> {
    crate::regex_check::validate(pattern).map_err(|reason| {
        Diagnostic::error(span, format!("invalid regular expression: {reason}")).with_help(
            "the host compiles the pattern once when the script loads, and a pattern it \
             cannot compile would match nothing at run time",
        )
    })?;
    env.collected
        .patterns
        .record(pattern)
        .map_err(|reason| Diagnostic::error(span, reason))
}

/// Why a Varnish variable Carapace knows the name of is not here, and what to
/// write instead.
///
/// A migrating author meets these one at a time, and "unknown or unsupported"
/// tells them nothing about which of the three kinds of absence they hit: a
/// decision Carapace made declaratively, a host capability that does not
/// exist, or a spelling that does exist under another name. Every row is one
/// of those three. A prefix row (`server.`) ends in `.` and matches by
/// prefix; everything else matches exactly.
const ABSENT_VARIABLES: &[(&str, &str)] = &[
    // Declarative: the answer is the Varnish VCL, not a tenant script.
    (
        "req.backend_hint",
        "backends and directors belong to the Varnish VCL that forks this tenant",
    ),
    (
        "bereq.backend",
        "backends and directors belong to the Varnish VCL that forks this tenant",
    ),
    (
        "beresp.backend",
        "backends and directors belong to the Varnish VCL that forks this tenant",
    ),
    (
        "bereq.connect_timeout",
        "timeouts belong to the Varnish VCL that forks this tenant",
    ),
    (
        "bereq.first_byte_timeout",
        "timeouts belong to the Varnish VCL that forks this tenant",
    ),
    (
        "bereq.between_bytes_timeout",
        "timeouts belong to the Varnish VCL that forks this tenant",
    ),
    (
        "bereq.last_byte_timeout",
        "timeouts belong to the Varnish VCL that forks this tenant",
    ),
    (
        "sess.timeout_idle",
        "timeouts belong to the Varnish VCL that forks this tenant",
    ),
    (
        "resp.send_timeout",
        "timeouts belong to the Varnish VCL that forks this tenant",
    ),
    (
        "req.storage",
        "storage selection belongs to the Varnish VCL that forks this tenant",
    ),
    (
        "beresp.storage",
        "storage selection belongs to the Varnish VCL that forks this tenant",
    ),
    (
        "beresp.do_esi",
        "ESI processing belongs to the Varnish VCL that forks this tenant: an include \
         may name another tenant's site",
    ),
    (
        "bereq.body",
        "request bodies are not exposed to a tenant policy",
    ),
    (
        "req.hash",
        "the digest is Varnish's; build the key with hash_data() in vcl_hash",
    ),
    (
        "server.ip",
        "the listening address is not exposed; server.hostname and server.identity are",
    ),
    (
        "local.",
        "the local socket address is not exposed",
    ),
    (
        "req.ttl",
        "Varnish's req.ttl is a lookup-side age limit, not the stored TTL; \
         set beresp.ttl in vcl_backend_response",
    ),
    ("client.port", "use client.ip; the port is not carried"),
    ("remote.port", "use remote.ip; the port is not carried"),
];

fn absent_variable_help(name: &str) -> Option<&'static str> {
    ABSENT_VARIABLES.iter().find_map(|(pattern, help)| {
        let matched = match pattern.strip_suffix('.') {
            Some(prefix) => name.starts_with(prefix) && name[prefix.len()..].starts_with('.'),
            None => name == *pattern,
        };
        matched.then_some(*help)
    })
}

fn unknown_variable(name: &str, span: Span) -> Diagnostic {
    if name.starts_with("backend.") {
        return Diagnostic::error(span, format!("{name} is not available in a tenant policy"))
            .with_help("backends and directors belong to the Varnish VCL that forks this tenant");
    }
    let diagnostic = Diagnostic::error(
        span,
        format!("unknown or unsupported VCL variable '{name}'"),
    );
    match absent_variable_help(name) {
        Some(help) => diagnostic.with_help(help),
        None => diagnostic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vmod table's two parallel arrays have to stay in step.
    ///
    /// They are parallel rather than one array of pairs because
    /// `bind_arguments` is shared with the plain `FUNCTIONS` table and takes
    /// a `&[ParameterSpec]`. This is the cheap guard that buys that.
    #[test]
    fn every_vmod_row_binds_each_of_its_parameters() {
        for spec in VMODS {
            assert_eq!(
                spec.params.len(),
                spec.binds.len(),
                "{} has {} parameters and {} binding rules",
                spec.name,
                spec.params.len(),
                spec.binds.len()
            );
            // A read's fallback is what makes it a read; a statement has none.
            let defaults = spec
                .binds
                .iter()
                .filter(|bind| matches!(bind, Bind::Default))
                .count();
            match spec.shape {
                Shape::Read(_) => assert!(defaults <= 1, "{} has {defaults} defaults", spec.name),
                Shape::Transform(_) | Shape::Count(_) | Shape::Reseed | Shape::Write(_) => {
                    assert_eq!(defaults, 0, "{} is not a read", spec.name)
                }
            }
            // The runtime ABI carries one argument register pair, and the VCL
            // arguments are joined with a NUL to fit it. `Expiry` contributes
            // two of those fields: the ttl and `now`.
            let arguments = spec
                .binds
                .iter()
                .map(|bind| match bind {
                    Bind::Argument => 1,
                    Bind::Expiry => 2,
                    Bind::Default
                    | Bind::Flag(_)
                    | Bind::First
                    | Bind::Second
                    | Bind::Extra(_)
                    | Bind::Scope
                    | Bind::NamePattern
                    | Bind::ValuePattern
                    | Bind::ExtraFlag(_)
                    | Bind::Header => 0,
                })
                .sum::<usize>();
            assert!(
                arguments <= vcl_rt::setcookie_field::COUNT,
                "{} passes {arguments} arguments",
                spec.name
            );
            // Only `setcookie_add` needs more than the pair every other row
            // fits in, and the field order the runtime decodes is its own.
            if arguments > 2 {
                assert_eq!(
                    spec.name, "cookieplus.setcookie_add",
                    "{} passes {arguments} arguments with no field layout",
                    spec.name
                );
            }
            // An `Extra` or `Scope` binding reads an enum by index, so the
            // row has to say what the valid values are.
            for (parameter, bind) in spec.params.iter().zip(spec.binds) {
                if matches!(bind, Bind::Extra(_) | Bind::Scope) {
                    assert!(
                        !parameter.enum_values.is_empty(),
                        "{} parameter '{}' is bound as an enum with no values",
                        spec.name,
                        parameter.name
                    );
                }
            }
            // A `_regex` form's routine argument *is* its bitmap block, so a
            // row that names a record set may bind no runtime string, must
            // bind at least one pattern, and may bind no more than the two
            // the fixed-stride argument carries. The converse holds too: a
            // pattern with no record set has nothing to match against.
            let patterns = spec
                .binds
                .iter()
                .filter(|bind| matches!(bind, Bind::NamePattern | Bind::ValuePattern))
                .count();
            match spec.select {
                Some(_) => {
                    assert_eq!(
                        arguments, 0,
                        "{} binds a pattern and an argument",
                        spec.name
                    );
                    assert!(
                        (1..=2).contains(&patterns),
                        "{} binds {patterns} patterns",
                        spec.name
                    );
                }
                None => assert_eq!(patterns, 0, "{} matches nothing", spec.name),
            }
            // A module answers `None` for a kind of call it does not have,
            // and every such refusal is a compiler error rather than a
            // panic. This is the table side of that: no row asks for one.
            let kind = match spec.shape {
                Shape::Count(_) => Some(crate::vmod::Routines::Count),
                Shape::Read(_) | Shape::Write(_) => Some(crate::vmod::Routines::Read),
                Shape::Transform(_) => Some(crate::vmod::Routines::Transform),
                Shape::Reseed => None,
            };
            if let Some(kind) = kind {
                assert!(
                    spec.module.routine(kind).is_some(),
                    "{} needs a {kind:?} routine its module does not have",
                    spec.name
                );
            }
            if let Some(set) = spec.select {
                assert!(
                    spec.module.select_code(set).is_some(),
                    "{} matches patterns against a module with no records",
                    spec.name
                );
            }
        }
    }

    /// The `uri` family carries its one boolean in the bit the runtime reads
    /// it from.  The bind holds a bit index and the runtime holds a mask, so
    /// nothing but this keeps the two in step.
    #[test]
    fn uri_option_bind_names_the_bit_the_runtime_reads() {
        let Bind::ExtraFlag(bit) = URI_OPTION else {
            panic!("the uri option is an extra-flag bind");
        };
        assert_eq!(1u16 << bit, vcl_rt::URI_EXTRA_OPTION);
    }

    /// A name may be in one table or the other, never both, and the router
    /// has to agree with the table the name is actually in.
    #[test]
    fn every_builtin_belongs_to_exactly_one_table() {
        for spec in FUNCTIONS {
            assert!(
                !VMODS.iter().any(|row| row.name == spec.name),
                "{} is in both tables",
                spec.name
            );
            assert!(
                !is_vmod_call(spec.name) || is_stateless_vmod_call(spec.name),
                "{} would be routed to VMODS, which does not hold it",
                spec.name
            );
        }
        for spec in VMODS {
            assert!(
                !is_stateless_vmod_call(spec.name),
                "{} would be routed to FUNCTIONS, which does not hold it",
                spec.name
            );
        }
    }

    /// No two rows may claim the same VCL name.
    #[test]
    fn vmod_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for spec in VMODS {
            assert!(seen.insert(spec.name), "{} appears twice", spec.name);
            assert!(
                is_vmod_call(spec.name),
                "{} is not recognised as a vmod call, so the parser will not \
                 route it here",
                spec.name
            );
        }
    }

    use crate::{lexer, parser};

    fn checked(source: &str) -> Result<TypedProgram, Diagnostics> {
        checked_with_options(source, &CompileOptions::default())
    }

    fn checked_with_options(
        source: &str,
        options: &CompileOptions,
    ) -> Result<TypedProgram, Diagnostics> {
        let tokens = lexer::lex(source)?;
        let ast = parser::parse(source, &tokens)?;
        let resolved = crate::resolver::resolve(source, ast)?;
        check(source, resolved, options)
    }

    fn desugared(source: &str) -> Result<TypedProgram, Diagnostics> {
        crate::desugar::desugar(source, checked(source)?)
    }

    /// Inlining re-enters a fresh body per `call`, so the chain is bounded
    /// like parser nesting is: with a diagnostic, never a stack overflow.
    #[test]
    fn deep_call_chain_is_a_diagnostic_rather_than_a_stack_overflow() {
        let mut source = String::from("vcl 4.1; ");
        for index in 0..50_000 {
            source.push_str(&format!("sub s{index} {{ call s{}; }} ", index + 1));
        }
        source.push_str("sub s50000 { set req.http.X = \"1\"; } sub vcl_recv { call s0; }");
        let typed = checked(&source).unwrap();
        let error = crate::desugar::desugar(&source, typed)
            .unwrap_err()
            .to_string();
        assert!(error.contains("may not nest more than"), "{error}");
    }

    /// The inlining budget counts what a `call` contributed, so a hook that
    /// inlines nothing is bounded by its own source instead.
    #[test]
    fn inline_budget_ignores_a_hook_that_inlines_nothing() {
        let mut source = String::from("vcl 4.1; sub vcl_recv { ");
        for index in 0..5_096 {
            source.push_str(&format!("set req.http.X-{index} = \"1\"; "));
        }
        source.push('}');
        checked(&source).expect("a hook with no calls is not an inlining budget");
    }

    /// vcl_synth is a hook of its own, run from Varnish's vcl_synth, rather
    /// than a body copied into the hooks that return synth(...).
    #[test]
    fn vcl_synth_is_its_own_hook() {
        let source = "vcl 4.1; sub vcl_synth { set resp.http.X = \"1\"; return (deliver); } \
                      sub vcl_recv { return (synth(503, \"x\")); }";
        let typed = checked(source).unwrap();
        let typed = crate::desugar::desugar(source, typed).unwrap();
        let synth = typed
            .subs
            .iter()
            .find(|sub| sub.phase == Phase::Synth)
            .expect("vcl_synth is checked");
        assert!(matches!(
            synth.statements.last(),
            Some(TypedStatement::Return {
                action: TypedReturnAction::Deliver,
                ..
            })
        ));
        let recv = typed
            .subs
            .iter()
            .find(|sub| sub.phase == Phase::Recv)
            .expect("vcl_recv is checked");
        assert!(matches!(
            recv.statements.last(),
            Some(TypedStatement::Return {
                action: TypedReturnAction::Synth { status: 503, .. },
                ..
            })
        ));
    }

    #[test]
    fn phase_table_refuses_cross_phase_write() {
        let source = "vcl 4.1; sub vcl_backend_fetch { set req.http.X = \"no\"; }";
        let error = checked(source).unwrap_err().to_string();
        assert!(error.contains("not writable in vcl_backend_fetch"), "{error}");
        assert!(error.contains("bereq"), "{error}");
    }

    #[test]
    fn function_parameters_bind_by_name_and_fill_defaults() {
        let source = concat!(
            "vcl 4.1; sub vcl_recv { ",
            "set req.http.X = std.integer(fallback = 7, value = req.http.N); return (hash); }"
        );
        let typed = checked(source).expect("named std.integer parameters are valid");
        let TypedStatement::SetHeader { value, .. } = &typed.subs[0].statements[0] else {
            panic!("expected request header assignment");
        };
        assert!(matches!(value.kind, TypedExprKind::ToString { .. }));

        let defaulted = checked(
            "vcl 4.1; sub vcl_recv { set req.http.X = std.integer(req.http.N); return (hash); }",
        )
        .expect("fallback has a default");
        assert!(matches!(
            defaulted.subs[0].statements[0],
            TypedStatement::SetHeader { .. }
        ));
    }

    #[test]
    fn function_parameter_diagnostics_name_the_binding_error() {
        for (source, expected) in [
            (
                "vcl 4.1; sub vcl_recv { set req.http.X = std.integer(nope = 1); return (hash); }",
                "has no parameter named 'nope'",
            ),
            (
                "vcl 4.1; sub vcl_recv { set req.http.X = std.integer(fallback = 1, req.http.N); return (hash); }",
                "positional argument cannot follow a named argument",
            ),
            (
                "vcl 4.1; sub vcl_recv { set req.http.X = std.integer(req.http.N, fallback = 1, fallback = 2); return (hash); }",
                "specified more than once",
            ),
        ] {
            let error = checked(source).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn esi_names_its_owner() {
        let source = "vcl 4.1; sub vcl_backend_response { set beresp.do_esi = true; }";
        let error = checked(source).unwrap_err().to_string();
        assert!(error.contains("ESI processing belongs to the Varnish VCL"), "{error}");
        checked("vcl 4.1; sub vcl_backend_response { set beresp.do_gzip = true; }")
            .expect("gzip is Varnish's work, on the tenant's say-so");
    }

    #[test]
    fn return_actions_are_checked_against_their_hook() {
        let cases = [
            (
                "vcl 4.1; sub vcl_recv { return (deliver); }",
                "return (deliver) is not valid in vcl_recv",
            ),
            (
                "vcl 4.1; sub vcl_backend_error { return (pass); }",
                "return (pass) is not valid in vcl_backend_error",
            ),
            (
                "vcl 4.1; sub vcl_hash { return (hash); }",
                "return (hash) is not valid in vcl_hash",
            ),
            (
                "vcl 4.1; sub vcl_synth { return (synth(500)); }",
                "return (synth) is not valid in vcl_synth",
            ),
            (
                "vcl 4.1; sub vcl_deliver { return (error(503)); }",
                "return (error) is not valid in vcl_deliver",
            ),
            (
                "vcl 4.1; sub vcl_deliver { return (pass); }",
                "return (pass) is not valid in vcl_deliver",
            ),
            (
                "vcl 4.1; sub vcl_recv { return; }",
                "bare return is only valid in a user subroutine",
            ),
        ];
        for (source, expected) in cases {
            let error = checked(source).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn sub_second_ttl_truncates_toward_zero_and_says_so() {
        let source = "vcl 4.1; sub vcl_backend_response { set beresp.ttl = 1500ms; }";
        let typed = desugared(source).expect("a fractional TTL compiles");
        assert!(matches!(
            typed.subs[0].statements[0],
            TypedStatement::SetTtl { seconds: 1, .. }
        ));
        assert_eq!(typed.warnings.len(), 1);
        assert!(
            typed.warnings[0].message.contains("truncated to 1s"),
            "{}",
            typed.warnings[0].message
        );
    }

    #[test]
    fn stale_windows_are_backend_response_durations() {
        let source = concat!(
            "vcl 4.1; sub vcl_backend_response { ",
            "set beresp.grace = 12s; set beresp.keep = 34s; return (deliver); }"
        );
        let typed = desugared(source).unwrap();
        assert!(matches!(
            typed.subs[0].statements[0],
            TypedStatement::SetStaleWhileRevalidate { seconds: 12, .. }
        ));
        assert!(matches!(
            typed.subs[0].statements[1],
            TypedStatement::SetStaleIfError { seconds: 34, .. }
        ));

        let wrong_phase = "vcl 4.1; sub vcl_deliver { set beresp.grace = 1s; return (deliver); }";
        let error = checked(wrong_phase).unwrap_err().to_string();
        assert!(error.contains("not writable in vcl_deliver"), "{error}");

        let fractional = "vcl 4.1; sub vcl_backend_response { set beresp.keep = 500ms; }";
        let typed = desugared(fractional).expect("a fractional stale window compiles");
        assert!(matches!(
            typed.subs[0].statements[0],
            TypedStatement::SetStaleIfError { seconds: 0, .. }
        ));
        assert!(
            typed.warnings[0]
                .message
                .contains("beresp.keep is truncated to 0s"),
            "{}",
            typed.warnings[0].message
        );
    }

    #[test]
    fn checks_arithmetic_types_and_evaluates_cache_durations() {
        let source = concat!(
            "vcl 4.1; sub vcl_backend_response { ",
            "if (beresp.status + 2 * 3 >= 506) { set beresp.ttl = 2m - 15s * 2; } ",
            "return (deliver); }"
        );
        let typed = desugared(source).unwrap();
        let TypedStatement::If { branches, .. } = &typed.subs[0].statements[0] else {
            panic!("expected conditional");
        };
        assert_eq!(branches[0].0.value_type, ValueType::Boolean);
        assert!(matches!(
            branches[0].1[0],
            TypedStatement::SetTtl { seconds: 90, .. }
        ));

        let mixed = checked(concat!(
            "vcl 4.1; sub vcl_backend_response { ",
            "if (beresp.status < 1s) {} return (deliver); }"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            mixed.contains("matching INT or DURATION operands"),
            "{mixed}"
        );

        let fractional_source = concat!(
            "vcl 4.1; sub vcl_backend_response { ",
            "set beresp.ttl = 1s / 3; return (deliver); }"
        );
        let fractional = desugared(fractional_source).expect("a folded fraction compiles");
        assert!(matches!(
            fractional.subs[0].statements[0],
            TypedStatement::SetTtl { seconds: 0, .. }
        ));
        assert!(
            fractional.warnings[0].message.contains("truncated to 0s"),
            "{}",
            fractional.warnings[0].message
        );
    }

    #[test]
    fn route_variant_header_is_not_writable_in_recv() {
        let source =
            "vcl 4.1; sub vcl_recv { set req.http.X-Variant = \"chosen\"; return (hash); }";
        let options = CompileOptions::default().with_variant_headers(["x-variant"]);
        let error = checked_with_options(source, &options)
            .unwrap_err()
            .to_string();
        assert!(error.contains("hash input"), "{error}");
    }

    #[test]
    fn header_write_constraints_live_in_the_variable_table() {
        assert_eq!(
            vars::resolve("req.http.Host").unwrap().0.write_constraint,
            WriteConstraint::ClientRequestHeader
        );
        assert_eq!(
            vars::resolve("beresp.http.Content-Length")
                .unwrap()
                .0
                .write_constraint,
            WriteConstraint::Header
        );
        assert_eq!(
            vars::resolve("beresp.uncacheable")
                .unwrap()
                .0
                .write_constraint,
            WriteConstraint::TrueOnly
        );
        assert!(!vars::is_framing_header("x-ordinary"));
    }

    #[test]
    fn framing_headers_are_rejected_at_compile_time() {
        let source = "vcl 4.1; sub vcl_deliver { set resp.http.Content-Length = \"4\"; }";
        let error = checked(source).unwrap_err().to_string();
        assert!(error.contains("framing or hop-by-hop"), "{error}");
    }

    #[test]
    fn conditions_and_reads_are_typed_and_phase_checked() {
        let valid = concat!(
            "vcl 4.1; sub vcl_recv { ",
            "if (req.method == \"GET\" && req.http.X != \"\") { ",
            "set req.http.Y = req.url; } return (hash); }"
        );
        let typed = checked(valid).unwrap();
        assert!(matches!(
            typed.subs[0].statements[0],
            TypedStatement::If { .. }
        ));

        let not_bool =
            "vcl 4.1; sub vcl_backend_response { if (beresp.status) { return (pass); } }";
        let error = checked(not_bool).unwrap_err().to_string();
        assert!(error.contains("if condition expects BOOL"), "{error}");

        let wrong_phase = "vcl 4.1; sub vcl_deliver { if (bereq.method == \"GET\") {} }";
        let error = checked(wrong_phase).unwrap_err().to_string();
        assert!(
            error.contains("bereq.method is not readable in vcl_deliver"),
            "{error}"
        );

        // The three cache-metadata variables read in `vcl_backend_response`
        // and nowhere else.
        let metadata = "vcl 4.1; sub vcl_backend_response { if (beresp.ttl == 1s) {} }";
        checked(metadata).expect("beresp.ttl is readable in vcl_backend_response");
        let deliver = "vcl 4.1; sub vcl_deliver { if (beresp.grace == 1s) {} }";
        let error = checked(deliver).unwrap_err().to_string();
        assert!(
            error.contains("beresp.grace is not readable in vcl_deliver"),
            "{error}"
        );
    }

    #[test]
    fn header_values_are_boolean_only_as_presence_tests() {
        checked(concat!(
            "vcl 4.1; sub vcl_recv { ",
            "if (req.http.Authorization && !req.http.X-Denied) { return (pass); } ",
            "return (hash); }"
        ))
        .expect("header fields are truthy when present");

        checked(concat!(
            "vcl 4.1; sub vcl_recv { ",
            "if (std.strstr(req.url, \"/api\")) { return (pass); } return (hash); }"
        ))
        .expect("non-empty STRING expressions are truthy");

        let error = checked("vcl 4.1; sub vcl_backend_response { if (beresp.status) {} }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("if condition expects BOOL"), "{error}");
    }

    #[test]
    fn digest_calls_have_a_fixed_standard_signature() {
        let source = concat!(
            "vcl 4.1; sub vcl_recv { ",
            "set req.http.Hash = digest.hash_sha256(req.url); ",
            "if (digest.verify_hmac_sha256(\"key\", req.url, req.http.Tag)) { ",
            "return (hash); } return (pass); }"
        );
        checked(source).expect("standard digest calls type-check without import");

        let error =
            checked("vcl 4.1; sub vcl_recv { set req.http.X = digest.hmac_sha256(\"key\"); }")
                .unwrap_err()
                .to_string();
        assert!(error.contains("expects 2 arguments, found 1"), "{error}");

        let error = checked(
            "vcl 4.1; sub vcl_recv { set req.http.X = digest.hash_sha256(req.url, \"x\"); }",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("expects 1 argument, found 2"), "{error}");

        let error =
            checked("vcl 4.1; sub vcl_recv { set req.http.X = digest.hash_sha512(req.url); }")
                .unwrap_err()
                .to_string();
        assert!(error.contains("unsupported digest function"), "{error}");
    }

    #[test]
    fn std_surface_concatenation_and_implicit_conversions_are_typed() {
        let source = concat!(
            "vcl 4.1; import std; sub vcl_recv { ",
            "set req.http.X = std.toupper(\"value-\" + 42 + true); ",
            "if (std.prefix(req.url, \"/api\") && std.suffix(req.url, \".m4s\")) { ",
            "set req.http.N = std.integer(req.http.N, 7); } return (hash); }"
        );
        checked(source).expect("the std compatibility surface type-checks");

        let error = checked("vcl 4.1; sub vcl_recv { set req.http.X = std.nope(req.url); }")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unsupported std function 'std.nope'"),
            "{error}"
        );
    }

    #[test]
    fn unset_and_vcl_synth_are_phase_checked() {
        let valid = concat!(
            "vcl 4.1; sub vcl_recv { unset req.http.Cookie; return (synth(403)); } ",
            "sub vcl_synth { set resp.http.X = \"yes\"; synthetic(\"blocked\"); return (deliver); }"
        );
        checked(valid).expect("header unset and folded synth type-check");

        let error = checked("vcl 4.1; sub vcl_recv { synthetic(\"no\"); }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("only valid in vcl_synth"), "{error}");

        let error = checked("vcl 4.1; sub vcl_backend_fetch { unset req.http.X; }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not writable in vcl_backend_fetch"), "{error}");

        let error = checked("vcl 4.1; sub vcl_deliver { synthetic(\"orphan\"); }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("only valid in vcl_synth"), "{error}");
        checked("vcl 4.1; sub vcl_backend_error { synthetic(\"down\"); return (deliver); }")
            .expect("vcl_backend_error writes a synthetic body");
    }

    #[test]
    fn every_table_row_has_a_phase_owner() {
        assert!(vars::VARIABLES
            .iter()
            .all(|spec| { !spec.readable.is_empty() || !spec.writable.is_empty() }));
    }

    #[test]
    fn variable_table_is_the_exhaustive_phase_permission_matrix() {
        fn source_for(phase: Phase, statement: &str) -> String {
            let action = match phase {
                Phase::Recv => "hash",
                Phase::Hash => "lookup",
                Phase::Miss | Phase::Pass | Phase::BackendRequest => "fetch",
                Phase::Hit
                | Phase::Deliver
                | Phase::Synth
                | Phase::BackendResponse
                | Phase::BackendError => "deliver",
            };
            format!(
                "vcl 4.1; sub {} {{ {statement} return ({action}); }}",
                phase.vcl_name()
            )
        }

        for spec in vars::VARIABLES {
            let variable = spec.pattern.replace('*', "X-Parity");
            for &phase in Phase::ALL {
                let probe = match spec.value_type {
                    ValueType::String => format!("if ({variable} == \"\") {{}}"),
                    ValueType::Integer => format!("if ({variable} == 0) {{}}"),
                    ValueType::Duration => format!("if ({variable} == 0s) {{}}"),
                    ValueType::Time => format!("if ({variable} == now) {{}}"),
                    ValueType::Boolean => format!("if ({variable} == false) {{}}"),
                    ValueType::Ip => format!("std.log({variable});"),
                };
                let source = source_for(phase, &probe);
                assert_eq!(
                    checked(&source).is_ok(),
                    spec.readable.contains(&phase),
                    "read permission drift for {variable} in {}",
                    phase.vcl_name()
                );

                let value = match spec.value_type {
                    ValueType::String => "\"parity\"",
                    ValueType::Integer => "1",
                    ValueType::Duration => "1s",
                    ValueType::Time => "now",
                    ValueType::Boolean => "true",
                    ValueType::Ip => "client.ip",
                };
                let source = source_for(phase, &format!("set {variable} = {value};"));
                assert_eq!(
                    checked(&source).is_ok(),
                    spec.writable.contains(&phase),
                    "write permission drift for {variable} in {}",
                    phase.vcl_name()
                );
            }
        }
    }
}
