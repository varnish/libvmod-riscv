//! Deterministic linear-scan allocation of IR virtual values.
//!
//! Caller-saved temporaries are used only for intervals contained between host
//! calls. Values which cross a call, or do not fit in the register pool, are
//! assigned a fixed stack slot. The result is an explicit allocated program;
//! machine emission never makes allocation decisions of its own.

use std::collections::{BTreeMap, BTreeSet};

use crate::backend::BackendError;
use crate::ir::{Function, GlobalDef, Op, Program, StaticDef, ValueClass, ValueId};
use crate::riscv::ALLOCATABLE_REGISTERS;
use crate::types::Phase;

/// Largest frame a hook may claim, locals and spill slots together.
///
/// Wide stack offsets are emitted for anything past the 2 KiB SP-relative
/// immediate, so the only remaining bound is the guest's own stack. Failing to
/// compile is the diagnosable outcome; overflowing it at request time is not.
const MAX_FRAME_BYTES: u32 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    Register(u8),
    RegisterPair(u8, u8),
    Stack(u32),
    StackPair(u32),
}

impl Location {
    pub(crate) fn width(self) -> usize {
        match self {
            Self::Register(_) | Self::Stack(_) => 1,
            Self::RegisterPair(_, _) | Self::StackPair(_) => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AllocatedFunction {
    pub phase: Phase,
    pub ops: Vec<Op>,
    pub locations: BTreeMap<ValueId, Location>,
    pub frame_size: u32,
    pub local_offsets: Vec<u32>,
    pub local_classes: Vec<ValueClass>,
}

impl AllocatedFunction {
    pub(crate) fn hook(&self) -> &'static str {
        self.phase.hook()
    }

    pub(crate) fn location(&self, value: ValueId) -> Result<Location, String> {
        self.locations
            .get(&value)
            .copied()
            .ok_or_else(|| format!("register allocation has no location for v{}", value.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AllocatedProgram {
    pub functions: Vec<AllocatedFunction>,
    pub statics: Vec<StaticDef>,
    pub globals: Vec<GlobalDef>,
    pub acls: Vec<Vec<u8>>,
    /// Regular-expression literals, carried through to `.carapace.regex`.
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct Interval {
    value: ValueId,
    class: ValueClass,
    start: usize,
    end: usize,
    crosses_call: bool,
}

pub(crate) fn allocate(program: &Program) -> Result<AllocatedProgram, BackendError> {
    let functions = program
        .functions
        .iter()
        .map(|function| {
            allocate_function(function).map_err(|message| {
                let span = function.ops.first().map(Op::span).unwrap_or_default();
                let error = BackendError::at("register allocation", span, message.clone());
                if message.contains("frame") && message.contains("large")
                    || message.contains("over the") && message.contains("limit")
                {
                    error.with_help(
                        "reduce the number of locals or simultaneously live values in this hook",
                    )
                } else {
                    error
                }
            })
        })
        .collect::<Result<_, _>>()?;
    let allocated = AllocatedProgram {
        functions,
        statics: program.statics.clone(),
        globals: program.globals.clone(),
        acls: program.acls.clone(),
        patterns: program.patterns.clone(),
    };
    verify(&allocated).map_err(|message| {
        let span = program
            .functions
            .first()
            .and_then(|function| function.ops.first())
            .map(Op::span);
        BackendError::new("register allocation", span, message)
    })?;
    Ok(allocated)
}

fn verify(program: &AllocatedProgram) -> Result<(), String> {
    for function in &program.functions {
        if function.frame_size % 16 != 0 {
            return Err(format!("{} has an unaligned spill frame", function.hook()));
        }
        if function.local_offsets.len() != function.local_classes.len() {
            return Err(format!(
                "{} has mismatched local offset and class tables",
                function.hook()
            ));
        }
        let mut locals_end = 0u32;
        for (offset, class) in function.local_offsets.iter().zip(&function.local_classes) {
            let width = match class {
                ValueClass::String => 16,
                ValueClass::Scalar => 8,
            };
            verify_stack(*offset, width, function.frame_size)?;
            locals_end = locals_end.max(offset.saturating_add(width));
        }
        let mut defined = BTreeMap::new();
        for op in &function.ops {
            if let Some((value, class)) = op.definition() {
                let location = function.location(value)?;
                let valid = matches!(
                    (class, location),
                    (
                        ValueClass::Scalar,
                        Location::Register(_) | Location::Stack(_)
                    ) | (
                        ValueClass::String,
                        Location::RegisterPair(_, _) | Location::StackPair(_)
                    )
                );
                if !valid {
                    return Err(format!(
                        "{} gives v{} an incompatible location",
                        function.hook(),
                        value.0
                    ));
                }
                match location {
                    Location::Register(register) => verify_register(register)?,
                    Location::RegisterPair(pointer, length) => {
                        verify_register(pointer)?;
                        verify_register(length)?;
                        if pointer == length {
                            return Err("string register pair aliases itself".to_string());
                        }
                    }
                    Location::Stack(offset) => verify_stack(offset, 8, function.frame_size)?,
                    Location::StackPair(offset) => verify_stack(offset, 16, function.frame_size)?,
                }
                if match location {
                    Location::Stack(offset) | Location::StackPair(offset) => offset < locals_end,
                    Location::Register(_) | Location::RegisterPair(_, _) => false,
                } {
                    return Err(format!(
                        "{} gives v{} a spill slot overlapping the locals area",
                        function.hook(),
                        value.0
                    ));
                }
                defined.insert(value, class);
            }
            for value in op.uses() {
                if !defined.contains_key(&value) {
                    return Err(format!(
                        "{} allocation uses v{} before its definition",
                        function.hook(),
                        value.0
                    ));
                }
            }
        }
        if defined.len() != function.locations.len() {
            return Err(format!(
                "{} allocation contains locations for undefined values",
                function.hook()
            ));
        }
        let live = intervals(&function.ops)?;
        for (index, left) in live.iter().enumerate() {
            let left_location = function.location(left.value)?;
            if left.crosses_call
                && matches!(
                    left_location,
                    Location::Register(_) | Location::RegisterPair(_, _)
                )
            {
                return Err(format!(
                    "{} keeps v{} in a caller-saved register across a host call",
                    function.hook(),
                    left.value.0
                ));
            }
            for right in &live[index + 1..] {
                if left.start <= right.end
                    && right.start <= left.end
                    && locations_overlap(left_location, function.location(right.value)?)
                {
                    return Err(format!(
                        "{} gives overlapping live values v{} and v{} the same storage",
                        function.hook(),
                        left.value.0,
                        right.value.0
                    ));
                }
            }
        }
    }
    Ok(())
}

fn locations_overlap(left: Location, right: Location) -> bool {
    match (left, right) {
        (Location::Register(left), Location::Register(right)) => left == right,
        (Location::Register(left), Location::RegisterPair(a, b))
        | (Location::RegisterPair(a, b), Location::Register(left)) => left == a || left == b,
        (Location::RegisterPair(a, b), Location::RegisterPair(c, d)) => {
            a == c || a == d || b == c || b == d
        }
        (Location::Stack(left), Location::Stack(right)) => left == right,
        (Location::Stack(left), Location::StackPair(right))
        | (Location::StackPair(right), Location::Stack(left)) => {
            left < right + 16 && right < left + 8
        }
        (Location::StackPair(left), Location::StackPair(right)) => {
            left < right + 16 && right < left + 16
        }
        (
            Location::Register(_) | Location::RegisterPair(_, _),
            Location::Stack(_) | Location::StackPair(_),
        )
        | (
            Location::Stack(_) | Location::StackPair(_),
            Location::Register(_) | Location::RegisterPair(_, _),
        ) => false,
    }
}

fn verify_register(register: u8) -> Result<(), String> {
    if ALLOCATABLE_REGISTERS.contains(&register) {
        Ok(())
    } else {
        Err(format!("allocator selected reserved register x{register}"))
    }
}

fn verify_stack(offset: u32, width: u32, frame_size: u32) -> Result<(), String> {
    if offset % 8 == 0
        && offset
            .checked_add(width)
            .is_some_and(|end| end <= frame_size)
    {
        Ok(())
    } else {
        Err(format!(
            "spill slot {offset}..{} is outside a {frame_size}-byte frame",
            offset.saturating_add(width)
        ))
    }
}

fn allocate_function(function: &Function) -> Result<AllocatedFunction, String> {
    let intervals = intervals(&function.ops)?;
    let mut free: BTreeSet<u8> = ALLOCATABLE_REGISTERS.into_iter().collect();
    let mut active: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut free_spills: BTreeMap<usize, BTreeSet<u32>> = BTreeMap::new();
    let mut active_spills: Vec<(usize, usize, u32)> = Vec::new();
    let mut locations = BTreeMap::new();
    let mut local_offsets = Vec::with_capacity(function.locals.len());
    let mut stack_bytes = 0u32;
    for class in &function.locals {
        local_offsets.push(stack_bytes);
        stack_bytes = stack_bytes
            .checked_add(match class {
                ValueClass::Scalar => 8,
                ValueClass::String => 16,
            })
            .ok_or_else(|| "VCL locals frame is too large".to_string())?;
    }

    for interval in intervals {
        let mut still_active = Vec::with_capacity(active.len());
        for (end, registers) in active.drain(..) {
            if end < interval.start {
                free.extend(registers);
            } else {
                still_active.push((end, registers));
            }
        }
        active = still_active;
        let mut still_spilled = Vec::with_capacity(active_spills.len());
        for (end, width, offset) in active_spills.drain(..) {
            if end < interval.start {
                free_spills.entry(width).or_default().insert(offset);
            } else {
                still_spilled.push((end, width, offset));
            }
        }
        active_spills = still_spilled;

        let width = match interval.class {
            ValueClass::Scalar => 1,
            ValueClass::String => 2,
        };
        let location = if !interval.crosses_call && free.len() >= width {
            let selected: Vec<_> = free.iter().copied().take(width).collect();
            for register in &selected {
                free.remove(register);
            }
            active.push((interval.end, selected.clone()));
            active.sort_by_key(|(end, _)| *end);
            match selected.as_slice() {
                [register] => Location::Register(*register),
                [pointer, length] => Location::RegisterPair(*pointer, *length),
                _ => return Err("invalid register-class width".to_string()),
            }
        } else {
            let offset = if let Some(offset) = free_spills.entry(width).or_default().pop_first() {
                offset
            } else {
                let offset = stack_bytes;
                stack_bytes = stack_bytes
                    .checked_add((width * 8) as u32)
                    .ok_or_else(|| "VCL spill frame is too large".to_string())?;
                offset
            };
            active_spills.push((interval.end, width, offset));
            active_spills.sort_by_key(|(end, _, _)| *end);
            if width == 1 {
                Location::Stack(offset)
            } else {
                Location::StackPair(offset)
            }
        };
        locations.insert(interval.value, location);
    }

    let frame_size = align(stack_bytes, 16);
    if frame_size > MAX_FRAME_BYTES {
        return Err(format!(
            "VCL hook {} needs a {frame_size}-byte frame, over the {MAX_FRAME_BYTES}-byte limit",
            function.hook()
        ));
    }
    Ok(AllocatedFunction {
        phase: function.phase,
        ops: function.ops.clone(),
        locations,
        frame_size,
        local_offsets,
        local_classes: function.locals.clone(),
    })
}

fn intervals(ops: &[Op]) -> Result<Vec<Interval>, String> {
    let calls: Vec<_> = ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| {
            matches!(
                op,
                Op::Host { .. } | Op::ReadString { .. } | Op::ReadScalar { .. }
            )
            .then_some(index)
        })
        .collect();
    let mut definitions = BTreeMap::new();
    let mut last_uses = BTreeMap::new();
    for (index, op) in ops.iter().enumerate() {
        if let Some((value, class)) = op.definition() {
            definitions.insert(value, (class, index));
        }
        for value in op.uses() {
            last_uses.insert(value, index);
        }
    }
    let mut result = Vec::with_capacity(definitions.len());
    for (value, (class, start)) in definitions {
        // Effectful producers may have an unused result (for example an arena
        // allocation whose failure is observable). They still need a
        // destination, but their interval ends at the definition.
        let end = last_uses.get(&value).copied().unwrap_or(start);
        result.push(Interval {
            value,
            class,
            start,
            end,
            crosses_call: calls.iter().any(|call| start < *call && *call < end),
        });
    }
    result.sort_by_key(|interval| (interval.start, interval.value));
    Ok(result)
}

fn align(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ActionCode, Syscall};
    use crate::Span;

    #[test]
    fn a_frame_over_the_limit_fails_to_compile() {
        let source = "heading\nreturn (hash);\n";
        let span = Span::new(8, 22);
        let locals = vec![ValueClass::String; (MAX_FRAME_BYTES as usize / 16) + 1];
        let program = Program {
            patterns: Vec::new(),
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            functions: vec![Function {
                phase: Phase::Recv,
                locals,
                value_count: 0,
                ops: vec![Op::ReturnAction {
                    action: ActionCode::Next,
                    args: vec![],
                    span,
                }],
            }],
        };
        let error = allocate(&program).unwrap_err();
        assert!(error.contains("over the"), "{error}");
        let rendered =
            crate::Diagnostics::single(source, error.into_diagnostic()).render("policy.vcl");
        assert!(
            rendered.contains("policy.vcl:2:1: error: register allocation:"),
            "{rendered}"
        );
        assert!(
            rendered.contains("help: reduce the number of locals"),
            "{rendered}"
        );
    }

    #[test]
    fn allocates_pairs_and_reuses_dead_registers() {
        let span = Span::default();
        let program = Program {
            patterns: Vec::new(),
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            functions: vec![Function {
                phase: Phase::Recv,
                locals: Vec::new(),
                value_count: 2,
                ops: vec![
                    Op::ConstString {
                        dst: ValueId(0),
                        value: "first".into(),
                        span,
                    },
                    Op::Host {
                        syscall: Syscall::Log,
                        args: vec![ValueId(0)],
                        span,
                    },
                    Op::ConstString {
                        dst: ValueId(1),
                        value: "second".into(),
                        span,
                    },
                    Op::Host {
                        syscall: Syscall::Log,
                        args: vec![ValueId(1)],
                        span,
                    },
                    Op::ReturnAction {
                        action: ActionCode::Next,
                        args: vec![],
                        span,
                    },
                ],
            }],
        };
        let allocated = allocate(&program).unwrap();
        let function = &allocated.functions[0];
        assert_eq!(function.location(ValueId(0)), function.location(ValueId(1)));
        assert_eq!(function.frame_size, 0);
    }

    #[test]
    fn spills_a_value_live_across_a_host_call() {
        let span = Span::default();
        let function = Function {
            phase: Phase::Recv,
            locals: Vec::new(),
            value_count: 2,
            ops: vec![
                Op::ConstString {
                    dst: ValueId(0),
                    value: "later".into(),
                    span,
                },
                Op::ConstString {
                    dst: ValueId(1),
                    value: "now".into(),
                    span,
                },
                Op::Host {
                    syscall: Syscall::Log,
                    args: vec![ValueId(1)],
                    span,
                },
                Op::Host {
                    syscall: Syscall::Log,
                    args: vec![ValueId(0)],
                    span,
                },
                Op::ReturnAction {
                    action: ActionCode::Next,
                    args: vec![],
                    span,
                },
            ],
        };
        let allocated = allocate(&Program {
            patterns: Vec::new(),
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            functions: vec![function],
        })
        .unwrap();
        assert!(matches!(
            allocated.functions[0].location(ValueId(0)).unwrap(),
            Location::StackPair(0)
        ));
        assert_eq!(allocated.functions[0].frame_size, 16);
    }

    #[test]
    fn reuses_spill_slots_for_non_overlapping_intervals() {
        let span = Span::default();
        let function = Function {
            phase: Phase::Recv,
            locals: Vec::new(),
            value_count: 4,
            ops: vec![
                Op::ConstString {
                    dst: ValueId(0),
                    value: "first-after".into(),
                    span,
                },
                Op::ConstString {
                    dst: ValueId(1),
                    value: "first-before".into(),
                    span,
                },
                Op::Host {
                    syscall: Syscall::Log,
                    args: vec![ValueId(1)],
                    span,
                },
                Op::Host {
                    syscall: Syscall::Log,
                    args: vec![ValueId(0)],
                    span,
                },
                Op::ConstString {
                    dst: ValueId(2),
                    value: "second-after".into(),
                    span,
                },
                Op::ConstString {
                    dst: ValueId(3),
                    value: "second-before".into(),
                    span,
                },
                Op::Host {
                    syscall: Syscall::Log,
                    args: vec![ValueId(3)],
                    span,
                },
                Op::Host {
                    syscall: Syscall::Log,
                    args: vec![ValueId(2)],
                    span,
                },
                Op::ReturnAction {
                    action: ActionCode::Next,
                    args: vec![],
                    span,
                },
            ],
        };
        let allocated = allocate(&Program {
            patterns: Vec::new(),
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            functions: vec![function],
        })
        .unwrap();
        let function = &allocated.functions[0];
        assert_eq!(function.location(ValueId(0)), function.location(ValueId(2)));
        assert_eq!(function.frame_size, 16);
    }

    #[test]
    fn verifier_rejects_storage_shared_by_overlapping_intervals() {
        let span = Span::default();
        let ops = vec![
            Op::ConstString {
                dst: ValueId(0),
                value: "name".into(),
                span,
            },
            Op::ConstString {
                dst: ValueId(1),
                value: "value".into(),
                span,
            },
            Op::Host {
                syscall: Syscall::RequestSetHeader,
                args: vec![ValueId(0), ValueId(1)],
                span,
            },
            Op::ReturnAction {
                action: ActionCode::Next,
                args: vec![],
                span,
            },
        ];
        let allocated = AllocatedProgram {
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            patterns: Vec::new(),
            functions: vec![AllocatedFunction {
                phase: Phase::Recv,
                ops,
                locations: BTreeMap::from([
                    (ValueId(0), Location::RegisterPair(5, 6)),
                    (ValueId(1), Location::RegisterPair(5, 6)),
                ]),
                frame_size: 0,
                local_offsets: Vec::new(),
                local_classes: Vec::new(),
            }],
        };
        assert!(verify(&allocated)
            .unwrap_err()
            .contains("overlapping live values"));
    }
}
