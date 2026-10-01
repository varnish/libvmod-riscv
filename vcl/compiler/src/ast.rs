use crate::types::StatKind;
use crate::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Program {
    pub items: Vec<Item>,
    /// The declared syntax level, times ten: `vcl 4.1;` is 41. Varnish
    /// compares `std.syntax`'s REAL argument the same way, and an included
    /// library carries the main file's level because it may not declare one.
    pub syntax: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    Sub(Sub),
    Include {
        path: String,
        span: Span,
    },
    Static {
        name: String,
        name_span: Span,
        value_type: TypeName,
        init: Option<Expr>,
        /// The `stat` annotation. A static needs one: it is what the host
        /// folds into a Varnish counter at the end of every phase.
        stat: Option<StatAnnotation>,
        span: Span,
    },
    /// A top-level `var NAME: TYPE [= LITERAL];`: a request global, living
    /// for one request and copied from the client phases into the backend
    /// phases (`docs/plans/vcl-request-globals.md`).
    Global {
        name: String,
        name_span: Span,
        value_type: TypeName,
        init: Option<Expr>,
        span: Span,
    },
    Acl {
        name: String,
        name_span: Span,
        entries: Vec<AclEntry>,
        span: Span,
    },
}

/// `=`, `+=` or `-=` in a `set` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetOp {
    Assign,
    Add,
    Subtract,
}

impl SetOp {
    pub(crate) fn spelling(self) -> &'static str {
        match self {
            Self::Assign => "=",
            Self::Add => "+=",
            Self::Subtract => "-=",
        }
    }
}

/// `stat [KIND] [STRING]` on a `static var`, as written.
///
/// The kind word is optional and defaults to `counter`; so is the
/// description, which the type checker replaces with a derived default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatAnnotation {
    pub kind: StatKind,
    pub help: Option<String>,
    /// The description literal, or — with no description — the last word the
    /// annotation spelled. Where a diagnostic about the description points,
    /// and where the declaration ends when it has no `;`.
    pub help_span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AclEntry {
    pub negate: bool,
    pub address: String,
    pub address_span: Span,
    pub prefix: Option<u32>,
    pub prefix_span: Span,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeName {
    Integer,
    Boolean,
    Duration,
    Time,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sub {
    pub name: String,
    pub name_span: Span,
    pub statements: Vec<Statement>,
    pub included: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Statement {
    Declare {
        name: String,
        name_span: Span,
        value_type: TypeName,
        init: Option<Expr>,
        span: Span,
    },
    Call {
        sub: String,
        sub_span: Span,
        span: Span,
    },
    /// A builtin call used as a statement (rather than as an expression).
    /// VMODs such as cookieplus deliberately expose mutating operations in
    /// this form.
    BuiltinCall {
        function: String,
        arguments: Vec<CallArgument>,
        span: Span,
    },
    Set {
        target: String,
        target_span: Span,
        op: SetOp,
        value: Expr,
        span: Span,
    },
    Unset {
        target: String,
        target_span: Span,
        span: Span,
    },
    If {
        branches: Vec<(Expr, Vec<Statement>)>,
        otherwise: Vec<Statement>,
        span: Span,
    },
    Log {
        value: Expr,
        span: Span,
    },
    Synthetic {
        value: Expr,
        span: Span,
    },
    /// `hash_data(expr)`, vcl_hash only.
    HashData {
        value: Expr,
        span: Span,
    },
    Return {
        action: ReturnAction,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExprKind {
    Literal(Literal),
    Bool(bool),
    Variable(String),
    Call {
        function: String,
        arguments: Vec<CallArgument>,
    },
    Not(Box<Expr>),
    Negate(Box<Expr>),
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// One flat run of `+`, in source order, with at least two operands.
    ///
    /// `+` is left-associative, so a run of it is a left-deep `Binary` tree
    /// as far as the language is concerned; keeping it flat is what lets the
    /// parser charge the whole run one nesting level and the type checker
    /// walk a long string-building expression without recursing once per
    /// term. The type checker reproduces the left-associative meaning
    /// operand by operand.
    AddChain(Vec<Expr>),
}

/// One argument at a call site.  VCL permits the tail of a call to be named
/// (`fnmatch(value, pathname = true)`); retaining the name in the AST lets the
/// type checker bind it against the function declaration rather than making
/// every builtin hand-roll its own argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallArgument {
    pub name: Option<String>,
    pub name_span: Option<Span>,
    pub value: Expr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Match,
    NotMatch,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Literal {
    String(String),
    Integer(i64),
    Duration(u64),
    /// A VCL REAL literal.  V1 deliberately has no REAL value type: this
    /// syntax is retained solely so `std.syntax(4.1)` can be folded by the
    /// type checker, matching Varnish's feature-probe idiom.
    Real(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReturnAction {
    Bare,
    Hash,
    Lookup,
    Fetch,
    Miss,
    Pass,
    Abandon,
    Deliver,
    Fail,
    Synth { status: u16, reason: String },
    /// `error(status, reason)`, which hands a backend fetch to
    /// vcl_backend_error.
    Error { status: u16, reason: String },
    Sub(String, Span),
}
