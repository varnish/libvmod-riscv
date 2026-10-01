//! Human-readable virtual-register IR dumps.

use std::fmt::Write as _;

use crate::ir::{Op, Program};
use crate::typecheck::TypedProgram;

pub(crate) fn write_typed_stage(output: &mut String, stage: &str, program: &TypedProgram) {
    writeln!(output, "== {stage} ==").expect("write to String");
    writeln!(output, "{program:#?}").expect("write to String");
}

pub(crate) fn write_ir_stage(output: &mut String, stage: &str, program: &Program) {
    writeln!(output, "== {stage} ==").expect("write to String");
    writeln!(output, "functions: {}", program.functions.len()).expect("write to String");
    for function in &program.functions {
        writeln!(
            output,
            "\nfn {}  phase={:?} values={} ops={}",
            function.hook(),
            function.phase,
            function.value_count,
            function.ops.len()
        )
        .expect("write to String");
        for (index, op) in function.ops.iter().enumerate() {
            write!(output, "  {index:04}  {:<13}", op.opcode().name()).expect("write to String");
            match op {
                Op::ConstInt {
                    dst, value, span, ..
                } => write!(
                    output,
                    "v{}:scalar = {value:<20} ; bytes {}..{}",
                    dst.0, span.start, span.end
                ),
                Op::ConstString {
                    dst, value, span, ..
                } => write!(
                    output,
                    "v{}:string = {value:?} ; bytes {}..{}",
                    dst.0, span.start, span.end
                ),
                Op::LoadLocal {
                    dst, slot, span, ..
                } => write!(
                    output,
                    "v{} = load.local {} ; bytes {}..{}",
                    dst.0, slot.0, span.start, span.end
                ),
                Op::StoreLocal { slot, value, span } => write!(
                    output,
                    "store.local {}, v{} ; bytes {}..{}",
                    slot.0, value.0, span.start, span.end
                ),
                Op::LoadStatic {
                    dst,
                    static_id,
                    span,
                    ..
                } => write!(
                    output,
                    "v{} = load.static {} ; bytes {}..{}",
                    dst.0,
                    program
                        .statics
                        .get(static_id.0 as usize)
                        .map_or("<invalid>", |static_| static_.name.as_str()),
                    span.start,
                    span.end
                ),
                Op::StoreStatic {
                    static_id,
                    value,
                    span,
                } => write!(
                    output,
                    "store.static {}, v{} ; bytes {}..{}",
                    program
                        .statics
                        .get(static_id.0 as usize)
                        .map_or("<invalid>", |static_| static_.name.as_str()),
                    value.0,
                    span.start,
                    span.end
                ),
                Op::LoadGlobal {
                    dst, global, span, ..
                } => write!(
                    output,
                    "v{} = load.global {} ; bytes {}..{}",
                    dst.0,
                    program
                        .globals
                        .get(global.0 as usize)
                        .map_or("<invalid>", |global| global.name.as_str()),
                    span.start,
                    span.end
                ),
                Op::StoreGlobal {
                    global,
                    value,
                    span,
                } => write!(
                    output,
                    "store.global {}, v{} ; bytes {}..{}",
                    program
                        .globals
                        .get(global.0 as usize)
                        .map_or("<invalid>", |global| global.name.as_str()),
                    value.0,
                    span.start,
                    span.end
                ),
                Op::ReadString {
                    dst,
                    syscall,
                    args,
                    span,
                }
                | Op::ReadScalar {
                    dst,
                    syscall,
                    args,
                    span,
                } => write!(
                    output,
                    "v{} = {} #{} ({}) ; bytes {}..{}",
                    dst.0,
                    syscall.name(),
                    syscall.number(),
                    values(args),
                    span.start,
                    span.end
                ),
                Op::StringConcat {
                    dst,
                    left,
                    right,
                    span,
                } => write!(
                    output,
                    "v{} = concat(v{}, v{}) ; bytes {}..{}",
                    dst.0, left.0, right.0, span.start, span.end
                ),
                Op::StringConvert {
                    dst,
                    value,
                    conversion,
                    span,
                } => write!(
                    output,
                    "v{} = to_string.{conversion:?}(v{}) ; bytes {}..{}",
                    dst.0, value.0, span.start, span.end
                ),
                Op::StringCase {
                    dst,
                    value,
                    kind,
                    span,
                } => write!(
                    output,
                    "v{} = {kind:?}(v{}) ; bytes {}..{}",
                    dst.0, value.0, span.start, span.end
                ),
                Op::StringFind {
                    dst,
                    haystack,
                    needle,
                    span,
                } => write!(
                    output,
                    "v{} = strstr(v{}, v{}) ; bytes {}..{}",
                    dst.0, haystack.0, needle.0, span.start, span.end
                ),
                Op::StringPredicate {
                    dst,
                    value,
                    affix,
                    kind,
                    span,
                } => write!(
                    output,
                    "v{} = {kind:?}(v{}, v{}) ; bytes {}..{}",
                    dst.0, value.0, affix.0, span.start, span.end
                ),
                Op::ParseScalar {
                    dst,
                    value,
                    fallback,
                    duration,
                    time,
                    span,
                } => write!(
                    output,
                    "v{} = parse_{}(v{}, v{}) ; bytes {}..{}",
                    dst.0,
                    if *time {
                        "time"
                    } else if *duration {
                        "duration"
                    } else {
                        "integer"
                    },
                    value.0,
                    fallback.0,
                    span.start,
                    span.end
                ),
                Op::Fnmatch {
                    dst,
                    pattern,
                    subject,
                    pathname,
                    noescape,
                    period,
                    span,
                } => write!(
                    output,
                    "v{} = fnmatch(v{}, v{}, v{}, v{}, v{}) ; bytes {}..{}",
                    dst.0,
                    pattern.0,
                    subject.0,
                    pathname.0,
                    noescape.0,
                    period.0,
                    span.start,
                    span.end
                ),
                Op::Querysort { dst, value, span } => write!(
                    output,
                    "v{} = querysort(v{}) ; bytes {}..{}",
                    dst.0, value.0, span.start, span.end
                ),
                Op::StrTest {
                    dst,
                    op,
                    subject,
                    other,
                    separators,
                    span,
                } => write!(
                    output,
                    "v{} = str_{op:?}(v{}, v{}, v{}) ; bytes {}..{}",
                    dst.0, subject.0, other.0, separators.0, span.start, span.end
                ),
                Op::StrEdit {
                    dst,
                    op,
                    subject,
                    count,
                    offset,
                    span,
                } => write!(
                    output,
                    "v{} = str_{op:?}(v{}, v{}, v{}) ; bytes {}..{}",
                    dst.0, subject.0, count.0, offset.0, span.start, span.end
                ),
                Op::StrSplit {
                    dst,
                    subject,
                    index,
                    separators,
                    span,
                } => write!(
                    output,
                    "v{} = str_split(v{}, v{}, v{}) ; bytes {}..{}",
                    dst.0, subject.0, index.0, separators.0, span.start, span.end
                ),
                Op::ModuleInit {
                    dst,
                    module,
                    response,
                    source,
                    span,
                } => write!(
                    output,
                    "v{} = {}_init(response={response}{}) ; bytes {}..{}",
                    dst.0,
                    module.vcl_name(),
                    source
                        .as_deref()
                        .map(|name| format!(", source={name}"))
                        .unwrap_or_default(),
                    span.start,
                    span.end
                ),
                Op::RegexMatchList {
                    dst,
                    module,
                    select,
                    state,
                    patterns,
                    value_fields,
                    span,
                } => write!(
                    output,
                    "v{} = {}_match_list(v{}, select={}, {}) ; bytes {}..{}",
                    dst.0,
                    module.vcl_name(),
                    state.0,
                    select,
                    patterns
                        .iter()
                        .enumerate()
                        .map(|(slot, pattern)| format!(
                            "v{}:{}",
                            pattern.0,
                            if value_fields & (1 << slot) != 0 {
                                "value"
                            } else {
                                "name"
                            }
                        ))
                        .collect::<Vec<_>>()
                        .join(", "),
                    span.start,
                    span.end
                ),
                Op::ModuleRead {
                    dst,
                    module,
                    code,
                    state,
                    arguments,
                    default,
                    span,
                } => write!(
                    output,
                    "v{} = {}_read(v{}, {}, {}, default=v{}) ; bytes {}..{}",
                    dst.0,
                    module.vcl_name(),
                    state.0,
                    opcode(*code),
                    values(arguments),
                    default.0,
                    span.start,
                    span.end
                ),
                Op::ModuleCount {
                    dst,
                    module,
                    code,
                    state,
                    arguments,
                    span,
                } => write!(
                    output,
                    "v{} = {}_count(v{}, {}, {}) ; bytes {}..{}",
                    dst.0,
                    module.vcl_name(),
                    state.0,
                    opcode(*code),
                    values(arguments),
                    span.start,
                    span.end
                ),
                Op::ModuleTransform {
                    dst,
                    module,
                    code,
                    state,
                    arguments,
                    span,
                } => write!(
                    output,
                    "v{} = {}_transform(v{}, {}, {}) ; bytes {}..{}",
                    dst.0,
                    module.vcl_name(),
                    state.0,
                    opcode(*code),
                    values(arguments),
                    span.start,
                    span.end
                ),
                Op::Collect {
                    name,
                    separator,
                    response,
                    span,
                } => write!(
                    output,
                    "collect(v{}, v{}, response={response}) ; bytes {}..{}",
                    name.0, separator.0, span.start, span.end
                ),
                Op::HeaderCommit {
                    state,
                    response,
                    span,
                } => write!(
                    output,
                    "headerplus_commit(v{}, response={response}) ; bytes {}..{}",
                    state.0, span.start, span.end
                ),
                Op::ReadNow { dst, span } => write!(
                    output,
                    "v{} = now ; bytes {}..{}",
                    dst.0, span.start, span.end
                ),
                Op::ReadClientIp { dst, span } => write!(
                    output,
                    "v{} = client.ip ; bytes {}..{}",
                    dst.0, span.start, span.end
                ),
                Op::AclMatch {
                    dst,
                    address,
                    acl,
                    span,
                } => write!(
                    output,
                    "v{} = acl_match(v{}, acl{}) ; bytes {}..{}",
                    dst.0, address.0, acl.0, span.start, span.end
                ),
                Op::Not { dst, value, span } => write!(
                    output,
                    "v{} = !v{} ; bytes {}..{}",
                    dst.0, value.0, span.start, span.end
                ),
                Op::ScalarBinary {
                    dst,
                    kind,
                    left,
                    right,
                    span,
                } => write!(
                    output,
                    "v{} = v{} {kind:?} v{} ; bytes {}..{}",
                    dst.0, left.0, right.0, span.start, span.end
                ),
                Op::Compare {
                    dst,
                    kind,
                    left,
                    right,
                    span,
                } => write!(
                    output,
                    "v{} = v{} {kind:?} v{} ; bytes {}..{}",
                    dst.0, left.0, right.0, span.start, span.end
                ),
                Op::BoolSlot { dst, value, span } => write!(
                    output,
                    "v{} = bool_slot {value} ; bytes {}..{}",
                    dst.0, span.start, span.end
                ),
                Op::BoolStore {
                    target,
                    value,
                    span,
                } => write!(
                    output,
                    "v{} <- bool_store {value} ; bytes {}..{}",
                    target.0, span.start, span.end
                ),
                Op::Host {
                    syscall,
                    args,
                    span,
                } => write!(
                    output,
                    "{} #{} ({})             ; bytes {}..{}",
                    syscall.name(),
                    syscall.number(),
                    values(args),
                    span.start,
                    span.end
                ),
                Op::Label { label, span } => {
                    write!(output, "l{}: ; bytes {}..{}", label.0, span.start, span.end)
                }
                Op::Jump { target, span } => {
                    write!(output, "l{} ; bytes {}..{}", target.0, span.start, span.end)
                }
                Op::BranchZero {
                    value,
                    target,
                    span,
                } => write!(
                    output,
                    "v{}, l{} ; bytes {}..{}",
                    value.0, target.0, span.start, span.end
                ),
                Op::ReturnAction { action, args, span } => write!(
                    output,
                    "{action:?} abi={} ({})       ; bytes {}..{}",
                    action.abi_value(),
                    values(args),
                    span.start,
                    span.end
                ),
            }
            .expect("write to String");
            output.push('\n');
        }
    }
    output.push('\n');
}

/// Render an operation word the way the runtime decodes it.
///
/// The dump is a debugging surface, so it shows the fields rather than the
/// packed integer: a wrong `first` is the sort of thing this is read to find.
fn opcode(code: i64) -> String {
    let decoded = vcl_rt::OpCode::decode(code);
    format!(
        "op={} flags={:#04x} first={} second={} extra={:#06x}",
        decoded.op, decoded.flags, decoded.first, decoded.second, decoded.extra
    )
}

fn values(values: &[crate::ir::ValueId]) -> String {
    values
        .iter()
        .map(|value| format!("v{}", value.0))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use crate::{dump_ir, CompileOptions};

    /// Regenerate with:
    /// `printf '%s' 'vcl 4.1; sub vcl_recv { return (hash); }' | cargo run -q -p vcl-compiler --bin dump_ir -- -O0 -`
    #[test]
    fn basic_pipeline_dump_matches_the_reviewable_snapshot() {
        let source = "vcl 4.1; sub vcl_recv { return (hash); }";
        let actual = dump_ir(
            source,
            CompileOptions {
                optimization: crate::OptimizationLevel::None,
                ..CompileOptions::default()
            },
        )
        .unwrap();
        assert_eq!(actual, include_str!("../tests/snapshots/basic.dump"));
    }

    const SOURCE: &str = r#"vcl 4.1;
sub vcl_recv {
    set req.http.same = "same";
    return (hash);
}
"#;

    #[test]
    fn verbose_ir_names_each_optimization_stage() {
        let output = dump_ir(SOURCE, CompileOptions::default()).unwrap();
        assert!(output.contains("== lowered (O0) =="));
        assert!(output.contains("== after coalesce-constants =="));
        assert!(output.contains("== after dead-values =="));
        assert!(output.contains("req_set_header #543 (v0, v0)"));
    }

    #[test]
    fn coalescing_reduces_the_generated_elf() {
        let optimized = crate::compile(SOURCE, CompileOptions::default()).unwrap();
        let options = CompileOptions {
            optimization: crate::OptimizationLevel::None,
            ..CompileOptions::default()
        };
        let unoptimized = crate::compile(SOURCE, options).unwrap();
        // The fixed, page-aligned runtime segment is shared by both images;
        // a small policy reduction can therefore land in the same output
        // page.  Optimisation must never make the final image larger.
        assert!(optimized.elf.len() <= unoptimized.elf.len());
    }

    #[test]
    fn regex_is_one_existing_abi_call_with_pattern_first() {
        let output = dump_ir(
            r#"vcl 4.1; sub vcl_recv { if (req.url ~ "\\.m4s$") { return (pass); } }"#,
            CompileOptions::default(),
        )
        .unwrap();
        assert!(output.contains("regex_match #552 (v1, v0)"), "{output}");
    }
}
