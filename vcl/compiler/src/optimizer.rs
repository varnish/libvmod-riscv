//! IR pass manager.
//!
//! The architecture intentionally does not ship a long speculative pass
//! chain. It does provide the invariant-bearing machinery now: named passes,
//! deterministic ordering, verification after every transformation, and one
//! conservative local transformations which exercise the contract.

use std::collections::{BTreeMap, BTreeSet};

use crate::backend::BackendError;
use crate::ir::{self, Op, Program, ValueId};

pub(crate) trait Pass {
    fn name(&self) -> &'static str;
    fn run(&self, program: &mut Program) -> Result<bool, BackendError>;
}

pub(crate) struct PassManager {
    passes: Vec<Box<dyn Pass>>,
    verify: bool,
}

impl PassManager {
    fn basic_passes() -> Vec<Box<dyn Pass>> {
        vec![
            Box::new(CoalesceConstants),
            Box::new(DeadStores),
            Box::new(DeadValues),
        ]
    }

    pub(crate) fn basic(verify: bool) -> Self {
        Self::basic_prefix(verify, usize::MAX)
    }

    pub(crate) fn basic_pass_names() -> Vec<&'static str> {
        Self::basic_passes()
            .into_iter()
            .map(|pass| pass.name())
            .collect()
    }

    /// Build a prefix of the normal pipeline. Differential tests use this to
    /// identify the first pass which changes observable behaviour.
    pub(crate) fn basic_prefix(verify: bool, limit: usize) -> Self {
        let mut passes = Self::basic_passes();
        passes.truncate(limit);
        Self { passes, verify }
    }

    pub(crate) fn run(&self, program: &mut Program) -> Result<(), BackendError> {
        for pass in &self.passes {
            let changed = pass.run(program)?;
            if self.verify && changed {
                ir::verify(program).map_err(|error| {
                    BackendError::new(
                        "optimizer",
                        error.span,
                        format!(
                            "IR verification after {} failed: {}",
                            pass.name(),
                            error.message
                        ),
                    )
                })?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Constant {
    Integer(i64),
    String(String),
}

/// Alias repeated constants while they are simultaneously available.
///
/// A host call clobbers the caller-saved register pool, so crossing one merely
/// to share a cheap constant can create a spill and make code larger. Clearing
/// the candidates at each call keeps this a local win: fewer materializations
/// and less register pressure, without lengthening a live interval.
struct CoalesceConstants;

impl Pass for CoalesceConstants {
    fn name(&self) -> &'static str {
        "coalesce-constants"
    }

    fn run(&self, program: &mut Program) -> Result<bool, BackendError> {
        let mut changed = false;
        for function in &mut program.functions {
            let mut function_changed = false;
            let mut available = BTreeMap::new();
            let mut aliases = BTreeMap::new();
            let mut ops = Vec::with_capacity(function.ops.len());
            for mut op in function.ops.drain(..) {
                let span = op.span();
                let duplicate = match &op {
                    Op::ConstInt { dst, value, .. } => {
                        let key = Constant::Integer(*value);
                        if let Some(existing) = available.get(&key).copied() {
                            aliases.insert(*dst, existing);
                            true
                        } else {
                            available.insert(key, *dst);
                            aliases.insert(*dst, *dst);
                            false
                        }
                    }
                    Op::ConstString { dst, value, .. } => {
                        let key = Constant::String(value.clone());
                        if let Some(existing) = available.get(&key).copied() {
                            aliases.insert(*dst, existing);
                            true
                        } else {
                            available.insert(key, *dst);
                            aliases.insert(*dst, *dst);
                            false
                        }
                    }
                    Op::ReadString { dst, .. }
                    | Op::ReadScalar { dst, .. }
                    | Op::ReadNow { dst, .. }
                    | Op::ReadClientIp { dst, .. }
                    | Op::AclMatch { dst, .. }
                    | Op::LoadLocal { dst, .. }
                    | Op::LoadStatic { dst, .. }
                    | Op::LoadGlobal { dst, .. }
                    | Op::StringConcat { dst, .. }
                    | Op::StringConvert { dst, .. }
                    | Op::StringCase { dst, .. }
                    | Op::StringFind { dst, .. }
                    | Op::StringPredicate { dst, .. }
                    | Op::ParseScalar { dst, .. }
                    | Op::Fnmatch { dst, .. }
                    | Op::Querysort { dst, .. }
                    | Op::StrTest { dst, .. }
                    | Op::StrEdit { dst, .. }
                    | Op::StrSplit { dst, .. }
                    | Op::ModuleInit { dst, .. }
                    | Op::ModuleRead { dst, .. }
                    | Op::ModuleCount { dst, .. }
                    | Op::ModuleTransform { dst, .. }
                    | Op::RegexMatchList { dst, .. }
                    | Op::Not { dst, .. }
                    | Op::ScalarBinary { dst, .. }
                    | Op::Compare { dst, .. }
                    // Aliasing a `BoolSlot` to an equal constant would let a
                    // later `BoolStore` overwrite that constant's other users.
                    // It is not a constant, so it is never a coalescing
                    // candidate; it only records itself in the alias map.
                    | Op::BoolSlot { dst, .. } => {
                        aliases.insert(*dst, *dst);
                        op.remap_values(&aliases).map_err(|message| {
                            BackendError::at("optimizer", span, message)
                        })?;
                        if matches!(
                            &op,
                            Op::ReadString { .. }
                                | Op::ReadScalar { .. }
                                | Op::ReadNow { .. }
                                | Op::ReadClientIp { .. }
                                | Op::ModuleInit { .. }
                                | Op::RegexMatchList { .. }
                        ) {
                            available.clear();
                        }
                        false
                    }
                    Op::StoreLocal { .. }
                    | Op::StoreStatic { .. }
                    | Op::StoreGlobal { .. }
                    | Op::BoolStore { .. }
                    | Op::Collect { .. }
                    | Op::HeaderCommit { .. }
                    | Op::Host { .. }
                    | Op::Label { .. }
                    | Op::Jump { .. }
                    | Op::BranchZero { .. }
                    | Op::ReturnAction { .. } => {
                        op.remap_values(&aliases).map_err(|message| {
                            BackendError::at("optimizer", span, message)
                        })?;
                        available.clear();
                        false
                    }
                };
                if duplicate {
                    function_changed = true;
                } else {
                    ops.push(op);
                }
            }
            function.ops = ops;
            if function_changed {
                let span = function.ops.first().map(Op::span).unwrap_or_default();
                function
                    .renumber_values()
                    .map_err(|message| BackendError::at("optimizer", span, message))?;
                changed = true;
            }
        }
        Ok(changed)
    }
}

struct DeadValues;

struct DeadStores;

impl Pass for DeadStores {
    fn name(&self) -> &'static str {
        "dead-stores"
    }

    fn run(&self, program: &mut Program) -> Result<bool, BackendError> {
        let mut changed = false;
        for function in &mut program.functions {
            let read: BTreeSet<_> = function
                .ops
                .iter()
                .filter_map(|op| match op {
                    Op::LoadLocal { slot, .. } => Some(*slot),
                    Op::ConstInt { .. }
                    | Op::ConstString { .. }
                    | Op::StoreLocal { .. }
                    | Op::LoadStatic { .. }
                    | Op::StoreStatic { .. }
                    | Op::LoadGlobal { .. }
                    | Op::StoreGlobal { .. }
                    | Op::ReadString { .. }
                    | Op::ReadScalar { .. }
                    | Op::ReadNow { .. }
                    | Op::ReadClientIp { .. }
                    | Op::AclMatch { .. }
                    | Op::StringConcat { .. }
                    | Op::StringConvert { .. }
                    | Op::StringCase { .. }
                    | Op::StringFind { .. }
                    | Op::StringPredicate { .. }
                    | Op::ParseScalar { .. }
                    | Op::Fnmatch { .. }
                    | Op::Querysort { .. }
                    | Op::StrTest { .. }
                    | Op::StrEdit { .. }
                    | Op::StrSplit { .. }
                    | Op::ModuleInit { .. }
                    | Op::ModuleRead { .. }
                    | Op::ModuleCount { .. }
                    | Op::ModuleTransform { .. }
                    | Op::RegexMatchList { .. }
                    | Op::Collect { .. }
                    | Op::HeaderCommit { .. }
                    | Op::Not { .. }
                    | Op::ScalarBinary { .. }
                    | Op::Compare { .. }
                    | Op::BoolSlot { .. }
                    | Op::BoolStore { .. }
                    | Op::Host { .. }
                    | Op::Label { .. }
                    | Op::Jump { .. }
                    | Op::BranchZero { .. }
                    | Op::ReturnAction { .. } => None,
                })
                .collect();
            let before = function.ops.len();
            function
                .ops
                .retain(|op| !matches!(op, Op::StoreLocal { slot, .. } if !read.contains(slot)));
            let mut local_remap = BTreeMap::new();
            let mut locals = Vec::with_capacity(read.len());
            let locals_before = function.locals.len();
            for (index, class) in std::mem::take(&mut function.locals).into_iter().enumerate() {
                let old = crate::types::LocalId(index as u32);
                if read.contains(&old) {
                    let new = crate::types::LocalId(locals.len() as u32);
                    local_remap.insert(old, new);
                    locals.push(class);
                }
            }
            for op in &mut function.ops {
                match op {
                    Op::LoadLocal { slot, .. } | Op::StoreLocal { slot, .. } => {
                        *slot = local_remap[slot];
                    }
                    Op::ConstInt { .. }
                    | Op::ConstString { .. }
                    | Op::LoadStatic { .. }
                    | Op::StoreStatic { .. }
                    | Op::LoadGlobal { .. }
                    | Op::StoreGlobal { .. }
                    | Op::ReadString { .. }
                    | Op::ReadScalar { .. }
                    | Op::ReadNow { .. }
                    | Op::ReadClientIp { .. }
                    | Op::AclMatch { .. }
                    | Op::StringConcat { .. }
                    | Op::StringConvert { .. }
                    | Op::StringCase { .. }
                    | Op::StringFind { .. }
                    | Op::StringPredicate { .. }
                    | Op::ParseScalar { .. }
                    | Op::Fnmatch { .. }
                    | Op::Querysort { .. }
                    | Op::StrTest { .. }
                    | Op::StrEdit { .. }
                    | Op::StrSplit { .. }
                    | Op::ModuleInit { .. }
                    | Op::ModuleRead { .. }
                    | Op::ModuleCount { .. }
                    | Op::ModuleTransform { .. }
                    | Op::RegexMatchList { .. }
                    | Op::Collect { .. }
                    | Op::HeaderCommit { .. }
                    | Op::Not { .. }
                    | Op::ScalarBinary { .. }
                    | Op::Compare { .. }
                    | Op::BoolSlot { .. }
                    | Op::BoolStore { .. }
                    | Op::Host { .. }
                    | Op::Label { .. }
                    | Op::Jump { .. }
                    | Op::BranchZero { .. }
                    | Op::ReturnAction { .. } => {}
                }
            }
            function.locals = locals;
            changed |= function.ops.len() != before || function.locals.len() != locals_before;
        }
        Ok(changed)
    }
}

impl Pass for DeadValues {
    fn name(&self) -> &'static str {
        "dead-values"
    }

    fn run(&self, program: &mut Program) -> Result<bool, BackendError> {
        let mut changed = false;
        for function in &mut program.functions {
            let mut live: BTreeSet<ValueId> = BTreeSet::new();
            let before = function.ops.len();
            let mut kept = Vec::with_capacity(before);
            for op in function.ops.drain(..).rev() {
                let keep = match op.definition() {
                    Some((value, _)) if op.opcode().is_pure() => live.remove(&value),
                    Some(_) | None => true,
                };
                if keep {
                    live.extend(op.uses());
                    kept.push(op);
                }
            }
            kept.reverse();
            function.ops = kept;
            if function.ops.len() == before {
                continue;
            }
            changed = true;
            let span = function.ops.first().map(Op::span).unwrap_or_default();
            function
                .renumber_values()
                .map_err(|message| BackendError::at("optimizer", span, message))?;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ActionCode, Function};
    use crate::types::Phase;
    use crate::Span;

    #[test]
    fn removes_dead_values_and_preserves_dense_ids() {
        let span = Span::default();
        let mut program = Program {
            patterns: Vec::new(),
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            functions: vec![Function {
                phase: Phase::Recv,
                locals: Vec::new(),
                value_count: 3,
                ops: vec![
                    Op::ConstInt {
                        dst: ValueId(0),
                        value: 99,
                        span,
                    },
                    Op::ConstInt {
                        dst: ValueId(1),
                        value: 403,
                        span,
                    },
                    Op::ConstString {
                        dst: ValueId(2),
                        value: "blocked".into(),
                        span,
                    },
                    Op::ReturnAction {
                        action: ActionCode::Synth,
                        args: vec![ValueId(1), ValueId(2)],
                        span,
                    },
                ],
            }],
        };
        ir::verify(&program).unwrap();
        PassManager::basic(true).run(&mut program).unwrap();
        assert_eq!(program.functions[0].value_count, 2);
        assert_eq!(program.functions[0].ops.len(), 3);
        ir::verify(&program).unwrap();
    }

    #[test]
    fn an_arena_allocating_string_survives_its_dead_store() {
        // `var.spare` is never read, so `DeadStores` drops the store — but the
        // concatenation that fed it allocates out of the per-phase read arena
        // and traps when that is exhausted. Removing it would let `-O` turn a
        // phase that fails into one that succeeds.
        let source = "vcl 4.1; sub vcl_recv { var spare: STRING = req.http.Host + \"-x\";                       return (hash); }";
        let (optimized, _unit, _warnings) =
            crate::lower_to_ir(source, &crate::CompileOptions::default()).expect("compile");
        let concats = optimized.functions[0]
            .ops
            .iter()
            .filter(|op| matches!(op, Op::StringConcat { .. }))
            .count();
        assert_eq!(concats, 1, "{:#?}", optimized.functions[0].ops);
        assert!(!optimized.functions[0]
            .ops
            .iter()
            .any(|op| matches!(op, Op::StoreLocal { .. })));
    }

    #[test]
    fn coalesces_constants_without_extending_them_across_calls() {
        let span = Span::default();
        let mut program = Program {
            patterns: Vec::new(),
            statics: Vec::new(),
            globals: Vec::new(),
            acls: Vec::new(),
            functions: vec![Function {
                phase: Phase::Recv,
                locals: Vec::new(),
                value_count: 4,
                ops: vec![
                    Op::ConstString {
                        dst: ValueId(0),
                        value: "same".into(),
                        span,
                    },
                    Op::ConstString {
                        dst: ValueId(1),
                        value: "same".into(),
                        span,
                    },
                    Op::Host {
                        syscall: crate::ir::Syscall::RequestSetHeader,
                        args: vec![ValueId(0), ValueId(1)],
                        span,
                    },
                    Op::ConstString {
                        dst: ValueId(2),
                        value: "same".into(),
                        span,
                    },
                    Op::ConstString {
                        dst: ValueId(3),
                        value: "later".into(),
                        span,
                    },
                    Op::Host {
                        syscall: crate::ir::Syscall::RequestSetHeader,
                        args: vec![ValueId(2), ValueId(3)],
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
        ir::verify(&program).unwrap();
        PassManager::basic(true).run(&mut program).unwrap();
        let function = &program.functions[0];
        assert_eq!(function.value_count, 3);
        assert_eq!(function.ops.len(), 6);
        let Op::Host { args, .. } = &function.ops[1] else {
            panic!("expected first host call");
        };
        assert_eq!(args, &[ValueId(0), ValueId(0)]);
        let Op::ConstString { dst, .. } = &function.ops[2] else {
            panic!("expected post-call constant");
        };
        assert_eq!(*dst, ValueId(1));
    }
}
