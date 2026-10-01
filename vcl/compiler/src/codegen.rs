use std::collections::BTreeMap;

use crate::backend::BackendError;
use crate::ir::{
    ActionCode, CompareKind, LabelId, LineEntry, LineTable, Op, ScalarBinaryKind, StringCaseKind,
    StringPredicateKind, Syscall, ValueClass, ValueId,
};
use crate::regalloc::{AllocatedFunction, AllocatedProgram, Location};
use crate::riscv::Reg;
use crate::runtime;
use crate::typecheck::GlobalInit;
use crate::types::{
    global_slot_size, AclId, GlobalId, LocalId, Span, StatSpec, StaticId, StringConversion,
    ValueType, MAX_GLOBAL_STRING,
};
use crate::vmod::{Module, Routines, Source};
use crate::{PhaseSet, SourceUnit};

pub(crate) const BASE_ADDRESS: u64 = 0x1_0000;
pub(crate) const BSS_ADDRESS: u64 = 0x20_0000;
const READ_ARENA_SIZE: u64 = 64 * 1024;
const NOW_ADDRESS: u64 = BSS_ADDRESS + 8;
const NOW_VALID_ADDRESS: u64 = BSS_ADDRESS + 16;
/// The 16 normalised address bytes `client.ip` reads into. Rewritten on every
/// read, and zeroed when the host declines, so a pooled VM cannot hand one
/// request the peer of the last.
const CLIENT_IP_ADDRESS: u64 = BSS_ADDRESS + 24;
const CLIENT_IP_BYTES: u64 = 16;
/// Two pointer/length pairs of emitter-local scratch.
///
/// A vmod's state seeding needs to hold a string across a call that clobbers
/// every caller-saved register, and the stack cannot serve: a spilled value's
/// `Location` is an offset from `sp`, so moving `sp` would silently redirect
/// every operand still to be loaded.
const SCRATCH_ADDRESS: u64 = BSS_ADDRESS + 40;
const SCRATCH_SLOTS: u64 = 2;
const SCRATCH_SIZE: u64 = SCRATCH_SLOTS * 16;
/// The slot a module's source string lands in while it is being parsed.
const SOURCE_SLOT: u64 = 0;
/// `headerplus.write()` holds the live snapshot and the vector it builds.
const SNAPSHOT_SLOT: u64 = 0;
const VECTOR_SLOT: u64 = 1;
/// `std.collect` holds its snapshot in [`SOURCE_SLOT`] and the joined value
/// here, because the join has no IR name to be placed under.
const COLLECTED_SLOT: u64 = 1;
/// A `_regex` vmod form holds the projected record list here while the host
/// matches it. Like the two above it, the list exists only inside one IR
/// operation, so it never gets an IR name.
const RECORDS_SLOT: u64 = 0;
const READ_ARENA_ADDRESS: u64 = SCRATCH_ADDRESS + SCRATCH_SIZE;
const LINUX_EXIT: i64 = 93;
const LINUX_CLOCK_GETTIME: i64 = 113;
const ASCII_CASE_DELTA: i32 = 32;

/// Where a vmod routine's state operand comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateOperand {
    /// An IR value the register allocator placed.
    Value(ValueId),
    /// A fixed `.bss` scratch slot, for a string that exists only inside one
    /// instruction and so never gets an IR name.
    Scratch(u64),
}

/// Where a vmod routine's string result lands: the mirror of
/// [`StateOperand`], for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringDest {
    Value(ValueId),
    Scratch(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Symbol {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticSymbol {
    pub name: String,
    pub address: u64,
    pub value_type: ValueType,
    /// The exported statistic, and where its name and help bytes were
    /// placed in the guest image. `.carapace.stats` rows point at guest
    /// strings, so the addresses are resolved here with the literals.
    pub stat: Option<StatSymbol>,
}

/// A request global's slot, for the symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

/// The request-global region `.carapace.globals` publishes: where it is, and
/// the bytes a client instance starts from. `image.len()` is the size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalRegion {
    pub address: u64,
    pub image: Vec<u8>,
}

/// A `stat`-annotated static, with its strings placed in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatSymbol {
    pub spec: StatSpec,
    /// Guest address of the NUL-terminated name.
    pub name_address: u64,
    /// Guest address of the NUL-terminated help.
    pub help_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Image {
    pub text: Vec<u8>,
    pub rodata: Vec<u8>,
    /// The pre-linked runtime's RX segment, placed at `runtime::BASE_ADDRESS`.
    pub runtime: Vec<u8>,
    /// The pre-linked runtime's constant tables. A separate read-only segment
    /// so the emulator never decodes them as instructions.
    pub runtime_rodata: Vec<u8>,
    /// Where `runtime_rodata` is linked.
    pub runtime_rodata_address: u64,
    pub symbols: Vec<Symbol>,
    pub lines: LineTable,
    /// Included library names, numbering the line table's file indexes from 1.
    pub files: Vec<String>,
    pub bss_size: u64,
    pub statics: Vec<StaticSymbol>,
    pub globals: Vec<GlobalSymbol>,
    /// `None` when the program declares no request global, so it emits no
    /// section and its bytes are those of a program before globals existed.
    pub global_region: Option<GlobalRegion>,
    pub exports: PhaseSet,
    /// Regular-expression literals for `.carapace.regex`, deduplicated and in
    /// first-use order.
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone)]
struct AddressFixup {
    instruction_offset: usize,
    literal: usize,
    register: u8,
}

#[derive(Debug, Clone, Copy)]
struct ControlFixup {
    instruction_offset: usize,
    target: LabelId,
    /// Span of the operation being emitted, so a fixup that cannot be resolved
    /// reports against that policy statement rather than the first jump in the
    /// program. Emitter-internal control flow carries none.
    span: Option<Span>,
}

#[derive(Debug, Default)]
struct Emitter {
    words: Vec<u32>,
    literals: Vec<Vec<u8>>,
    literal_index: BTreeMap<Vec<u8>, usize>,
    acls: Vec<Vec<u8>>,
    /// Address and class of each request global's slot, by [`GlobalId`].
    global_slots: Vec<(u64, ValueClass)>,
    fixups: Vec<AddressFixup>,
    line_offsets: Vec<(usize, usize)>,
    labels: BTreeMap<LabelId, usize>,
    control_fixups: Vec<ControlFixup>,
    internal_labels: u32,
    /// Span of the operation currently being emitted. Every fixup raised while
    /// it is set belongs to that operation.
    op_span: Option<Span>,
}

/// A code-generation failure, carrying the span of the operation that produced
/// it where one is known. Failures raised while finalising the image — address
/// overflow, an unpatched fixup — belong to the image, not to one operation,
/// and carry no span.
struct GenError {
    message: String,
    span: Option<Span>,
}

impl GenError {
    fn new(message: impl Into<String>, span: Option<Span>) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }

    fn at(message: impl Into<String>, span: Span) -> Self {
        Self::new(message, Some(span))
    }
}

impl From<String> for GenError {
    fn from(message: String) -> Self {
        Self {
            message,
            span: None,
        }
    }
}

pub(crate) fn generate(
    program: &AllocatedProgram,
    unit: &SourceUnit,
) -> Result<Image, BackendError> {
    generate_inner(program, unit).map_err(|GenError { message, span }| {
        let error = BackendError::new("code generation", span, message.clone());
        if message.contains("host call needs") {
            error.with_help("reduce the number or width of arguments passed by this operation")
        } else if message.contains("branch offset") {
            error.with_help(
                "reduce the size of this hook or split repeated policy into a smaller subroutine",
            )
        } else if message.contains("overlap the fixed read arena") {
            error.with_help("reduce literal data or generated policy code")
        } else {
            error
        }
    })
}

/// Emit one IR operation. The caller attaches the operation's span, so a
/// code-generation failure points at the policy statement that produced it.
fn emit_op(emitter: &mut Emitter, function: &AllocatedFunction, op: &Op) -> Result<(), String> {
    emitter.op_span = Some(op.span());
    match op {
        Op::ConstInt { dst, value, .. } => {
            emitter.emit_integer(function.location(*dst)?, *value)?
        }
        Op::ConstString { dst, value, .. } => {
            emitter.emit_string(function.location(*dst)?, value)?
        }
        Op::LoadLocal {
            dst, slot, class, ..
        } => emitter.emit_load_local(function, *dst, *slot, *class)?,
        Op::StoreLocal { slot, value, .. } => emitter.emit_store_local(function, *slot, *value)?,
        Op::LoadStatic { dst, static_id, .. } => {
            emitter.emit_load_static(function, *dst, *static_id)?
        }
        Op::StoreStatic {
            static_id, value, ..
        } => emitter.emit_store_static(function, *static_id, *value)?,
        Op::LoadGlobal {
            dst, global, class, ..
        } => emitter.emit_load_global(function, *dst, *global, *class)?,
        Op::StoreGlobal { global, value, .. } => {
            emitter.emit_store_global(function, *global, *value)?
        }
        Op::ReadString {
            dst, syscall, args, ..
        } => emitter.emit_read_string(function, *dst, *syscall, args)?,
        Op::ReadScalar {
            dst, syscall, args, ..
        } => emitter.emit_read_scalar(function, *dst, *syscall, args)?,
        Op::ReadNow { dst, .. } => emitter.emit_read_now(function, *dst)?,
        Op::ReadClientIp { dst, .. } => emitter.emit_read_client_ip(function, *dst)?,
        Op::AclMatch {
            dst, address, acl, ..
        } => emitter.emit_acl_match(function, *dst, *address, *acl)?,
        Op::StringConcat {
            dst, left, right, ..
        } => emitter.emit_string_concat(function, *dst, *left, *right)?,
        Op::StringConvert {
            dst,
            value,
            conversion,
            ..
        } => emitter.emit_string_convert(function, *dst, *value, *conversion)?,
        Op::StringCase {
            dst, value, kind, ..
        } => emitter.emit_string_case(function, *dst, *value, *kind)?,
        Op::StringFind {
            dst,
            haystack,
            needle,
            ..
        } => emitter.emit_string_find(function, *dst, *haystack, *needle)?,
        Op::StringPredicate {
            dst,
            value,
            affix,
            kind,
            ..
        } => emitter.emit_string_predicate(function, *dst, *value, *affix, *kind)?,
        Op::ParseScalar {
            dst,
            value,
            fallback,
            duration,
            time,
            ..
        } => emitter.emit_parse_scalar(function, *dst, *value, *fallback, *duration, *time)?,
        Op::Fnmatch {
            dst,
            pattern,
            subject,
            pathname,
            noescape,
            period,
            ..
        } => emitter.emit_fnmatch(
            function, *dst, *pattern, *subject, *pathname, *noescape, *period,
        )?,
        Op::Querysort { dst, value, .. } => emitter.emit_querysort(function, *dst, *value)?,
        Op::StrTest {
            dst,
            op,
            subject,
            other,
            separators,
            ..
        } => emitter.emit_str_test(function, *dst, *op, *subject, *other, *separators)?,
        Op::StrEdit {
            dst,
            op,
            subject,
            count,
            offset,
            ..
        } => emitter.emit_str_edit(function, *dst, *op, *subject, *count, *offset)?,
        Op::StrSplit {
            dst,
            subject,
            index,
            separators,
            ..
        } => emitter.emit_str_split(function, *dst, *subject, *index, *separators)?,
        Op::ModuleInit {
            dst,
            module,
            response,
            source,
            ..
        } => emitter.emit_module_init(function, *dst, *module, *response, source.as_deref())?,
        Op::ModuleRead {
            dst,
            module,
            code,
            state,
            arguments,
            default,
            ..
        } => {
            emitter.emit_module_read(function, *dst, *module, *code, *state, arguments, *default)?
        }
        Op::ModuleCount {
            dst,
            module,
            code,
            state,
            arguments,
            ..
        } => emitter.emit_module_count(function, *dst, *module, *code, *state, arguments)?,
        Op::ModuleTransform {
            dst,
            module,
            code,
            state,
            arguments,
            ..
        } => emitter.emit_module_transform(function, *dst, *module, *code, *state, arguments)?,
        Op::RegexMatchList {
            dst,
            module,
            select,
            state,
            patterns,
            value_fields,
            ..
        } => emitter.emit_regex_match_list(
            function,
            *dst,
            *module,
            *select,
            *state,
            patterns,
            *value_fields,
        )?,
        Op::Collect {
            name,
            separator,
            response,
            ..
        } => emitter.emit_collect(function, *name, *separator, *response)?,
        Op::HeaderCommit {
            state, response, ..
        } => emitter.emit_header_commit(function, *state, *response)?,
        Op::Not { dst, value, .. } => emitter.emit_not(function, *dst, *value)?,
        Op::ScalarBinary {
            dst,
            kind,
            left,
            right,
            ..
        } => emitter.emit_scalar_binary(function, *dst, *kind, *left, *right)?,
        Op::Compare {
            dst,
            kind,
            left,
            right,
            ..
        } => emitter.emit_compare(function, *dst, *kind, *left, *right)?,
        Op::BoolSlot { dst, value, .. } => {
            emitter.emit_integer(function.location(*dst)?, i64::from(*value))?
        }
        Op::BoolStore { target, value, .. } => {
            emitter.emit_integer(function.location(*target)?, i64::from(*value))?
        }
        Op::Host { syscall, args, .. } => emitter.emit_host(function, *syscall, args)?,
        Op::Label { label, .. } => emitter.emit_label(*label)?,
        Op::Jump { target, .. } => emitter.emit_jump(*target),
        Op::BranchZero { value, target, .. } => {
            emitter.emit_branch_zero(function, *value, *target)?
        }
        Op::ReturnAction { action, args, .. } => emitter.emit_action(function, *action, args)?,
    }
    Ok(())
}

fn generate_inner(program: &AllocatedProgram, unit: &SourceUnit) -> Result<Image, GenError> {
    // The request-global region follows the statics, so a static's address
    // does not depend on whether the program declares a global.
    let region_address = static_address(program.statics.len());
    let mut global_slots = Vec::with_capacity(program.globals.len());
    let mut region_size = 0u64;
    for global in &program.globals {
        global_slots.push((region_address + region_size, global.class));
        region_size += global_slot_size(global.value_type);
    }
    let mut emitter = Emitter {
        acls: program.acls.clone(),
        global_slots,
        ..Emitter::default()
    };
    let mut symbols = Vec::with_capacity(program.functions.len() + 1);

    let main_start = emitter.byte_len();
    for (index, static_) in program.statics.iter().enumerate() {
        if static_.initial != 0 {
            emitter.emit_static_initialiser(index, static_.initial)?;
        }
    }
    emitter.emit_exit()?;
    symbols.push(Symbol {
        name: "main".into(),
        offset: main_start as u64,
        size: (emitter.byte_len() - main_start) as u64,
    });

    for function in &program.functions {
        let start = emitter.byte_len();
        emitter.emit_frame_adjust(function.frame_size, false)?;
        emitter.emit_reset_read_arena()?;
        for op in &function.ops {
            if !matches!(op, Op::Label { .. }) {
                emitter
                    .line_offsets
                    .push((emitter.byte_len(), op.span().start));
            }
            emit_op(&mut emitter, function, op)
                .map_err(|message| GenError::at(message, op.span()))?;
        }
        // RETURN_ACTION stops the VM, but a real return keeps disassembly and
        // speculative/future host behaviour well-formed.
        if matches!(function.ops.last(), Some(Op::ReturnAction { .. })) {
            emitter.emit_frame_adjust(function.frame_size, true)?;
            emitter.emit_ret();
        }
        emitter.resolve_control_fixups()?;
        symbols.push(Symbol {
            name: function.hook().into(),
            offset: start as u64,
            size: (emitter.byte_len() - start) as u64,
        });
    }

    let text_len = emitter.byte_len();
    let runtime = runtime::image().map_err(|message| GenError::new(message, None))?;
    let runtime_end = runtime
        .end_address()
        .map_err(|message| GenError::new(message, None))?;
    if runtime_end > BSS_ADDRESS {
        return Err(GenError::new(
            "VCL runtime overlaps the fixed read arena",
            None,
        ));
    }
    let mut rodata = Vec::new();
    let mut literal_offsets = Vec::with_capacity(emitter.literals.len());
    for literal in &emitter.literals {
        literal_offsets.push(rodata.len());
        rodata.extend_from_slice(literal);
    }
    // A `.carapace.stats` row points at guest strings rather than carrying
    // inline lengths, so that a C guest can build one from a macro. The VCL
    // backend owes the same rows the same strings: name and help, NUL
    // terminated, beside the literals in rodata.
    let rodata_base = BASE_ADDRESS
        .checked_add(text_len as u64)
        .ok_or_else(|| "VCL text address overflow".to_string())?;
    let mut stat_symbols: Vec<Option<StatSymbol>> = Vec::with_capacity(program.statics.len());
    for static_ in &program.statics {
        let Some(spec) = static_.stat.as_ref() else {
            stat_symbols.push(None);
            continue;
        };
        let place = |rodata: &mut Vec<u8>, bytes: &[u8]| -> Result<u64, String> {
            let address = rodata_base
                .checked_add(rodata.len() as u64)
                .ok_or_else(|| "VCL statistic string address overflow".to_string())?;
            rodata.extend_from_slice(bytes);
            rodata.push(0);
            Ok(address)
        };
        let name_address = place(&mut rodata, static_.name.as_bytes())?;
        let help_address = place(&mut rodata, spec.help.as_bytes())?;
        stat_symbols.push(Some(StatSymbol {
            spec: spec.clone(),
            name_address,
            help_address,
        }));
    }
    let loaded_end = BASE_ADDRESS
        .checked_add(text_len as u64)
        .and_then(|value| value.checked_add(rodata.len() as u64))
        .ok_or_else(|| "VCL text/rodata address overflow".to_string())?;
    if loaded_end > runtime::BASE_ADDRESS {
        return Err(GenError::new(
            "generated VCL text and literals overlap the fixed runtime image",
            None,
        ));
    }
    for fixup in &emitter.fixups {
        let address = BASE_ADDRESS
            .checked_add(text_len as u64)
            .and_then(|value| value.checked_add(literal_offsets[fixup.literal] as u64))
            .ok_or_else(|| "literal address overflow".to_string())?;
        let (lui, addi) = load_address_words(fixup.register, address)?;
        let word = fixup.instruction_offset / 4;
        emitter.words[word] = lui;
        emitter.words[word + 1] = addi;
    }
    for fixup in &emitter.fixups {
        let word = fixup.instruction_offset / 4;
        if emitter.words.get(word).copied().unwrap_or_default() == 0
            || emitter.words.get(word + 1).copied().unwrap_or_default() == 0
        {
            return Err(GenError::new(
                "code generation left an address fixup unpatched",
                None,
            ));
        }
    }
    if !emitter.control_fixups.is_empty() || !emitter.labels.is_empty() {
        return Err(GenError::new(
            "code generation left a control fixup unresolved",
            None,
        ));
    }

    let text = emitter
        .words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    let lines = build_line_table(unit, emitter.line_offsets);
    let statics = program
        .statics
        .iter()
        .enumerate()
        .map(|(index, static_)| StaticSymbol {
            name: static_.name.clone(),
            address: static_address(index),
            value_type: static_.value_type,
            stat: stat_symbols[index].clone(),
        })
        .collect();
    Ok(Image {
        text,
        rodata,
        runtime: runtime.text.to_vec(),
        runtime_rodata: runtime.rodata.to_vec(),
        runtime_rodata_address: runtime.rodata_address,
        symbols,
        lines,
        files: unit.include_names(),
        bss_size: 40
            + SCRATCH_SIZE
            + READ_ARENA_SIZE
            + 8 * program.statics.len() as u64
            + region_size,
        statics,
        globals: program
            .globals
            .iter()
            .zip(&emitter.global_slots)
            .map(|(global, (address, _))| GlobalSymbol {
                name: global.name.clone(),
                address: *address,
                size: global_slot_size(global.value_type),
            })
            .collect(),
        global_region: (!program.globals.is_empty()).then(|| GlobalRegion {
            address: region_address,
            image: global_image(&program.globals),
        }),
        exports: PhaseSet::from_phases(program.functions.iter().map(|function| function.phase)),
        patterns: program.patterns.clone(),
    })
}

fn static_address(index: usize) -> u64 {
    READ_ARENA_ADDRESS + READ_ARENA_SIZE + 8 * index as u64
}

/// The bytes a client instance starts from: each slot in declaration order,
/// a scalar as its little-endian word and a `STRING` as its length followed
/// by its inline buffer, zero-padded to capacity. Nothing in it is a pointer,
/// which is what lets the host copy it anywhere.
fn global_image(globals: &[crate::ir::GlobalDef]) -> Vec<u8> {
    let mut image = Vec::new();
    for global in globals {
        let start = image.len();
        match &global.initial {
            GlobalInit::Scalar(value) => image.extend_from_slice(&value.to_le_bytes()),
            GlobalInit::String(value) => {
                image.extend_from_slice(&(value.len() as u64).to_le_bytes());
                image.extend_from_slice(value.as_bytes());
            }
        }
        image.resize(start + global_slot_size(global.value_type) as usize, 0);
    }
    image
}

impl Emitter {
    fn byte_len(&self) -> usize {
        self.words.len() * 4
    }

    fn emit_static_initialiser(&mut self, index: usize, value: i64) -> Result<(), String> {
        self.emit_li(31, static_address(index) as i64)?;
        self.emit_li(30, value)?;
        self.emit_store_to_base(30, 31, 0)
    }

    fn emit_load_local(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        slot: LocalId,
        class: ValueClass,
    ) -> Result<(), String> {
        let offset = *function
            .local_offsets
            .get(slot.0 as usize)
            .ok_or_else(|| format!("codegen has no offset for local {}", slot.0))?;
        match class {
            ValueClass::Scalar => {
                self.emit_load(10, offset)?;
                self.emit_store_scalar(function.location(dst)?, 10)
            }
            ValueClass::String => {
                self.emit_load(10, offset)?;
                self.emit_load(11, offset + 8)?;
                self.emit_store_string(function.location(dst)?, 10, 11)
            }
        }
    }

    fn emit_store_local(
        &mut self,
        function: &AllocatedFunction,
        slot: LocalId,
        value: ValueId,
    ) -> Result<(), String> {
        let offset = *function
            .local_offsets
            .get(slot.0 as usize)
            .ok_or_else(|| format!("codegen has no offset for local {}", slot.0))?;
        match function.local_classes[slot.0 as usize] {
            ValueClass::Scalar => {
                self.emit_load_scalar(function.location(value)?, 10)?;
                self.emit_store(10, offset)
            }
            ValueClass::String => {
                self.emit_load_string(function.location(value)?, 10, 11)?;
                self.emit_store(10, offset)?;
                self.emit_store(11, offset + 8)
            }
        }
    }

    fn emit_load_static(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        static_id: StaticId,
    ) -> Result<(), String> {
        self.emit_li(31, static_address(static_id.0 as usize) as i64)?;
        self.emit_load_from_base(10, 31, 0)?;
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_store_static(
        &mut self,
        function: &AllocatedFunction,
        static_id: StaticId,
        value: ValueId,
    ) -> Result<(), String> {
        self.emit_load_scalar(function.location(value)?, 10)?;
        self.emit_li(31, static_address(static_id.0 as usize) as i64)?;
        self.emit_store_to_base(10, 31, 0)
    }

    fn global_slot(&self, global: GlobalId) -> Result<(u64, ValueClass), String> {
        self.global_slots
            .get(global.0 as usize)
            .copied()
            .ok_or_else(|| format!("codegen has no slot for request global {}", global.0))
    }

    /// A scalar is one load. A `STRING` is copied out of its inline buffer
    /// into the arena, so the value cannot change under a later store.
    fn emit_load_global(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        global: GlobalId,
        class: ValueClass,
    ) -> Result<(), String> {
        let (address, _) = self.global_slot(global)?;
        self.emit_li(31, address as i64)?;
        match class {
            ValueClass::Scalar => {
                self.emit_load_from_base(10, 31, 0)?;
                self.emit_store_scalar(function.location(dst)?, 10)
            }
            ValueClass::String => {
                self.emit_load_from_base(14, 31, 0)?; // a4 = length
                self.emit_dynamic_arena_alloc(14, 15, 16, 12)?; // a2 = copy
                self.emit_store_string(function.location(dst)?, 12, 14)?;
                self.emit_li(10, (address + 8) as i64)?;
                self.emit_move(11, 14)?;
                self.emit_copy_loop(10, 11, 12)
            }
        }
    }

    /// A `STRING` store checks the capacity first and traps over it, so a
    /// store either lands whole or not at all.
    fn emit_store_global(
        &mut self,
        function: &AllocatedFunction,
        global: GlobalId,
        value: ValueId,
    ) -> Result<(), String> {
        let (address, class) = self.global_slot(global)?;
        match class {
            ValueClass::Scalar => {
                self.emit_load_scalar(function.location(value)?, 10)?;
                self.emit_li(31, address as i64)?;
                self.emit_store_to_base(10, 31, 0)
            }
            ValueClass::String => {
                self.emit_load_string(function.location(value)?, 10, 11)?;
                self.emit_li(31, MAX_GLOBAL_STRING as i64)?;
                self.words.push(bgeu(31, 11, 8)?); // bgeu cap, length, +8
                self.emit_ebreak(); // ebreak: STRING request global over capacity
                self.emit_li(31, address as i64)?;
                self.emit_store_to_base(11, 31, 0)?;
                self.emit_li(12, (address + 8) as i64)?;
                self.emit_copy_loop(10, 11, 12)
            }
        }
    }

    fn emit_integer(&mut self, location: Location, value: i64) -> Result<(), String> {
        match location {
            Location::Register(register) => self.emit_li(register, value),
            Location::Stack(offset) => {
                self.emit_li(10, value)?;
                self.emit_store(10, offset)
            }
            Location::RegisterPair(_, _) | Location::StackPair(_) => {
                Err("scalar constant was assigned a string location".to_string())
            }
        }
    }

    fn emit_string(&mut self, location: Location, value: &str) -> Result<(), String> {
        match location {
            Location::RegisterPair(pointer, length) => {
                self.emit_literal_address(pointer, value.as_bytes());
                self.emit_li(length, value.len() as i64)
            }
            Location::StackPair(offset) => {
                self.emit_literal_address(10, value.as_bytes());
                self.emit_store(10, offset)?;
                self.emit_li(11, value.len() as i64)?;
                self.emit_store(11, offset + 8)
            }
            Location::Register(_) | Location::Stack(_) => {
                Err("string constant was assigned a scalar location".to_string())
            }
        }
    }

    fn emit_reset_read_arena(&mut self) -> Result<(), String> {
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_store_to_base(0, 31, 0)?;
        self.emit_li(31, NOW_VALID_ADDRESS as i64)?;
        self.emit_store_to_base(0, 31, 0)
    }

    fn emit_dynamic_arena_alloc(
        &mut self,
        size: u8,
        cursor: u8,
        end: u8,
        pointer: u8,
    ) -> Result<(), String> {
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(cursor, 31, 0)?;
        self.words.push(add(end, cursor, size)?);
        self.emit_li(31, READ_ARENA_SIZE as i64)?;
        self.words.push(bgeu(31, end, 8)?); // bgeu cap, end, +8
        self.emit_ebreak();
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_store_to_base(end, 31, 0)?;
        self.emit_li(31, READ_ARENA_ADDRESS as i64)?;
        self.words.push(add(pointer, cursor, 31)?);
        Ok(())
    }

    fn emit_copy_loop(&mut self, source: u8, length: u8, target: u8) -> Result<(), String> {
        let again = self.internal_label()?;
        let copy = self.internal_label()?;
        let done = self.internal_label()?;
        self.emit_label(again)?;
        self.emit_jump_if_nonzero(length, copy)?;
        self.emit_jump(done);
        self.emit_label(copy)?;
        self.words.push(lbu(31, source, 0)?);
        self.words.push(sb(31, target, 0)?);
        self.words.push(addi(source, source, 1)?);
        self.words.push(addi(target, target, 1)?);
        self.words.push(addi(length, length, -1)?);
        self.emit_jump(again);
        self.emit_label(done)
    }

    fn emit_string_concat(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        left: ValueId,
        right: ValueId,
    ) -> Result<(), String> {
        self.emit_load_string(function.location(left)?, 10, 11)?;
        self.emit_load_string(function.location(right)?, 12, 13)?;
        self.words.push(add(14, 11, 13)?); // total length
        self.emit_dynamic_arena_alloc(14, 15, 16, 14)?;
        self.words.push(sub(16, 16, 15)?); // total = end - cursor
        self.emit_store_string(function.location(dst)?, 14, 16)?;
        self.emit_copy_loop(10, 11, 14)?;
        self.emit_copy_loop(12, 13, 14)
    }

    fn emit_string_case(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        value: ValueId,
        kind: StringCaseKind,
    ) -> Result<(), String> {
        // The architecture plan permits the inline fallback when each helper
        // has one source builder. These leaf loops intentionally stay here:
        // sharing machine-code bodies would add a private calling convention
        // and clobber model for a small text-size win.
        self.emit_load_string(function.location(value)?, 10, 11)?;
        self.emit_move(14, 11)?;
        self.emit_dynamic_arena_alloc(14, 15, 16, 12)?;
        self.emit_store_string(function.location(dst)?, 12, 11)?;
        let again = self.internal_label()?;
        let transform = self.internal_label()?;
        let store = self.internal_label()?;
        let done = self.internal_label()?;
        self.emit_label(again)?;
        self.emit_jump_if_nonzero(11, transform)?;
        self.emit_jump(done);
        self.emit_label(transform)?;
        self.words.push(lbu(13, 10, 0)?);
        let (low, high, delta) = match kind {
            StringCaseKind::Lower => (b'A', b'Z' + 1, ASCII_CASE_DELTA),
            StringCaseKind::Upper => (b'a', b'z' + 1, -ASCII_CASE_DELTA),
        };
        self.words.push(sltiu(14, 13, i32::from(low))?); // byte < low
        self.emit_jump_if_nonzero(14, store)?;
        self.words.push(sltiu(14, 13, i32::from(high))?); // byte < high
        let in_range = self.internal_label()?;
        self.emit_jump_if_nonzero(14, in_range)?;
        self.emit_jump(store);
        self.emit_label(in_range)?;
        self.words.push(addi(13, 13, delta)?);
        self.emit_label(store)?;
        self.words.push(sb(13, 12, 0)?);
        self.words.push(addi(10, 10, 1)?);
        self.words.push(addi(12, 12, 1)?);
        self.words.push(addi(11, 11, -1)?);
        self.emit_jump(again);
        self.emit_label(done)
    }

    fn emit_string_convert(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        value: ValueId,
        conversion: StringConversion,
    ) -> Result<(), String> {
        if conversion == StringConversion::Boolean {
            let truthy = self.internal_label()?;
            let done = self.internal_label()?;
            self.emit_load_scalar(function.location(value)?, 10)?;
            self.emit_jump_if_nonzero(10, truthy)?;
            self.emit_literal_address(11, b"false");
            self.emit_li(12, 5)?;
            self.emit_jump(done);
            self.emit_label(truthy)?;
            self.emit_literal_address(11, b"true");
            self.emit_li(12, 4)?;
            self.emit_label(done)?;
            return self.emit_store_string(function.location(dst)?, 11, 12);
        }

        if conversion == StringConversion::Ip {
            const RENDERED: i32 = 48;
            self.emit_arena_alloc(RENDERED, 12)?;
            self.emit_load_string(function.location(value)?, 10, 11)?;
            self.emit_li(13, i64::from(RENDERED))?;
            self.emit_store_string(function.location(dst)?, 12, 13)?;
            self.emit_li(13, i64::from(RENDERED))?;
            self.emit_runtime_call(vcl_rt::Routine::IpFormat)?;
            self.words.push(bge(10, 0, 8)?);
            self.emit_ebreak();
            self.emit_load_string(function.location(dst)?, 11, 12)?;
            return self.emit_store_string(function.location(dst)?, 11, 10);
        }

        if conversion == StringConversion::Time {
            // The allocation has to survive the call, and no register can
            // carry it: a0-a7 are the runtime's own arguments, t6 is this
            // emitter's scratch, and t0-t5 are the allocator's — preserved
            // across the call precisely because they may already hold a live
            // value. Park the pointer in the destination slot and reload it
            // afterwards, the way the two-call sites do.
            self.emit_arena_alloc(32, 12)?;
            self.emit_load_scalar(function.location(value)?, 10)?;
            self.emit_li(13, 32)?;
            self.emit_store_string(function.location(dst)?, 12, 13)?;
            self.emit_move(11, 12)?;
            self.emit_li(12, 32)?;
            self.emit_runtime_call(vcl_rt::Routine::TimeFormat)?;
            self.emit_load_string(function.location(dst)?, 11, 12)?;
            return self.emit_store_string(function.location(dst)?, 11, 10);
        }

        self.emit_arena_alloc(32, 15)?;
        self.emit_move(11, 15)?; // preserve the allocation start
        self.words.push(addi(12, 11, 32)?); // write pointer, backwards
        self.emit_load_scalar(function.location(value)?, 10)?;
        self.words.push(slt(13, 10, 0)?); // sign = value < 0
        let nonnegative = self.internal_label()?;
        self.words.push(bne(13, 0, 8)?);
        self.emit_jump(nonnegative);
        self.words.push(sub(10, 0, 10)?); // magnitude = -value
        self.emit_label(nonnegative)?;

        if conversion == StringConversion::Duration {
            self.emit_li(14, 500_000)?;
            self.words.push(add(10, 10, 14)?);
            self.emit_li(14, 1_000_000)?;
            self.words.push(divu(10, 10, 14)?); // ns / 1ms
            self.emit_li(14, 1000)?;
            self.words.push(remu(15, 10, 14)?); // fractional ms
            self.words.push(divu(10, 10, 14)?); // whole seconds
            self.emit_li(14, 10)?;
            for _ in 0..3 {
                self.words.push(remu(16, 15, 14)?); // remu
                self.words.push(divu(15, 15, 14)?); // divu
                self.words.push(addi(16, 16, 48)?);
                self.words.push(addi(12, 12, -1)?);
                self.words.push(sb(16, 12, 0)?);
            }
            self.words.push(addi(12, 12, -1)?);
            self.emit_li(15, i64::from(b'.'))?;
            self.words.push(sb(15, 12, 0)?);
        }

        let digits = self.internal_label()?;
        self.emit_label(digits)?;
        self.emit_li(14, 10)?;
        self.words.push(remu(15, 10, 14)?); // remu
        self.words.push(divu(10, 10, 14)?); // divu
        self.words.push(addi(15, 15, 48)?);
        self.words.push(addi(12, 12, -1)?);
        self.words.push(sb(15, 12, 0)?);
        self.emit_jump_if_nonzero(10, digits)?;
        let unsigned = self.internal_label()?;
        self.words.push(bne(13, 0, 8)?);
        self.emit_jump(unsigned);
        self.words.push(addi(12, 12, -1)?);
        self.emit_li(15, i64::from(b'-'))?;
        self.words.push(sb(15, 12, 0)?);
        self.emit_label(unsigned)?;
        self.words.push(addi(14, 11, 32)?);
        self.words.push(sub(14, 14, 12)?);
        self.emit_store_string(function.location(dst)?, 12, 14)
    }

    fn emit_string_find(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        haystack: ValueId,
        needle: ValueId,
    ) -> Result<(), String> {
        self.emit_load_string(function.location(haystack)?, 10, 11)?;
        self.emit_load_string(function.location(needle)?, 12, 13)?;
        let found = self.internal_label()?;
        let failed = self.internal_label()?;
        let outer = self.internal_label()?;
        let inner = self.internal_label()?;
        let mismatch = self.internal_label()?;
        let done = self.internal_label()?;
        self.words.push(add(11, 10, 11)?); // haystack end
        self.emit_jump_if_nonzero(13, outer)?;
        self.emit_jump(found);
        self.emit_label(outer)?;
        self.words.push(sub(14, 11, 13)?); // end - needle len
        self.words.push(sltu(14, 14, 10)?); // end-before < start
        self.emit_jump_if_nonzero(14, failed)?;
        self.emit_li(15, 0)?;
        self.emit_label(inner)?;
        self.words.push(add(16, 10, 15)?);
        self.words.push(lbu(16, 16, 0)?);
        self.words.push(add(31, 12, 15)?);
        self.words.push(lbu(31, 31, 0)?);
        self.words.push(beq(16, 31, 8)?); // equal -> continue
        self.emit_jump(mismatch);
        self.words.push(addi(15, 15, 1)?);
        self.words.push(beq(15, 13, 8)?); // complete -> found
        self.emit_jump(inner);
        self.emit_jump(found);
        self.emit_label(mismatch)?;
        self.words.push(addi(10, 10, 1)?);
        self.words.push(sub(14, 11, 13)?);
        self.words.push(sltu(14, 14, 10)?);
        self.emit_jump_if_nonzero(14, failed)?;
        self.emit_li(15, 0)?;
        self.emit_jump(inner);
        self.emit_label(found)?;
        self.words.push(sub(13, 11, 10)?); // end - match
        self.emit_store_string(function.location(dst)?, 10, 13)?;
        self.emit_jump(done);
        self.emit_label(failed)?;
        self.emit_li(10, 0)?;
        self.emit_li(13, 0)?;
        self.emit_store_string(function.location(dst)?, 10, 13)?;
        self.emit_label(done)
    }

    fn emit_string_predicate(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        value: ValueId,
        affix: ValueId,
        kind: StringPredicateKind,
    ) -> Result<(), String> {
        self.emit_load_string(function.location(value)?, 10, 11)?;
        self.emit_load_string(function.location(affix)?, 12, 13)?;
        let compare = self.internal_label()?;
        let failed = self.internal_label()?;
        let loop_label = self.internal_label()?;
        let success = self.internal_label()?;
        let done = self.internal_label()?;
        self.words.push(sltu(14, 11, 13)?); // value len < affix len
        self.emit_jump_if_nonzero(14, failed)?;
        if kind == StringPredicateKind::Suffix {
            self.words.push(sub(14, 11, 13)?);
            self.words.push(add(10, 10, 14)?);
        }
        self.emit_jump(compare);
        self.emit_label(compare)?;
        self.emit_jump_if_nonzero(13, loop_label)?;
        self.emit_jump(success);
        self.emit_label(loop_label)?;
        self.words.push(lbu(14, 10, 0)?);
        self.words.push(lbu(15, 12, 0)?);
        self.words.push(beq(14, 15, 8)?);
        self.emit_jump(failed);
        self.words.push(addi(10, 10, 1)?);
        self.words.push(addi(12, 12, 1)?);
        self.words.push(addi(13, 13, -1)?);
        self.emit_jump(compare);
        self.emit_label(success)?;
        self.emit_li(14, 1)?;
        self.emit_jump(done);
        self.emit_label(failed)?;
        self.emit_li(14, 0)?;
        self.emit_label(done)?;
        self.emit_store_scalar(function.location(dst)?, 14)
    }

    fn emit_parse_scalar(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        value: ValueId,
        fallback: ValueId,
        duration: bool,
        time: bool,
    ) -> Result<(), String> {
        self.emit_load_string(function.location(value)?, 10, 11)?;
        self.emit_load_scalar(function.location(fallback)?, 12)?;
        self.emit_runtime_call(if time {
            vcl_rt::Routine::TimeParse
        } else if duration {
            vcl_rt::Routine::DurationParse
        } else {
            vcl_rt::Routine::IntParse
        })?;
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_fnmatch(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        pattern: ValueId,
        subject: ValueId,
        pathname: ValueId,
        noescape: ValueId,
        period: ValueId,
    ) -> Result<(), String> {
        self.emit_load_string(function.location(pattern)?, 10, 11)?;
        self.emit_load_string(function.location(subject)?, 12, 13)?;
        self.emit_load_scalar(function.location(pathname)?, 14)?;
        self.emit_load_scalar(function.location(noescape)?, 15)?;
        self.emit_load_scalar(function.location(period)?, 16)?;
        self.emit_runtime_call(vcl_rt::Routine::Fnmatch)?;
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_querysort(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        value: ValueId,
    ) -> Result<(), String> {
        self.emit_load_string(function.location(value)?, 10, 11)?;
        self.emit_li(12, 0)?;
        self.emit_li(13, 0)?;
        self.emit_runtime_call(vcl_rt::Routine::Querysort)?;
        self.words.push(bge(10, 0, 8)?);
        self.emit_ebreak(); // a length the runtime could not report
        self.emit_move(14, 10)?;
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(15, 31, 0)?;
        self.words.push(add(16, 15, 14)?);
        self.emit_li(13, READ_ARENA_SIZE as i64)?;
        self.words.push(bgeu(13, 16, 8)?);
        self.emit_ebreak();
        self.emit_store_to_base(16, 31, 0)?;
        self.emit_li(31, READ_ARENA_ADDRESS as i64)?;
        self.words.push(add(12, 15, 31)?);
        self.emit_store_string(function.location(dst)?, 12, 14)?;
        self.emit_load_string(function.location(value)?, 10, 11)?;
        self.emit_load_string(function.location(dst)?, 12, 14)?;
        self.emit_move(13, 14)?;
        self.emit_runtime_call(vcl_rt::Routine::Querysort)?;
        self.emit_load_string(function.location(dst)?, 12, 14)?;
        self.words.push(beq(10, 14, 8)?);
        self.emit_ebreak();
        Ok(())
    }

    // ── str ─────────────────────────────────────────────────────────────
    //
    // The whole module is three routines in the runtime image, so all eight
    // functions reduce to loading argument registers.  a5-a6 are the output
    // pointer and capacity in both string-producing routines, which is what
    // lets one measure-then-fill sequence serve `substr`, `reverse` and
    // `split` alike.

    fn emit_str_test(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        op: vcl_rt::StrTest,
        subject: ValueId,
        other: ValueId,
        separators: ValueId,
    ) -> Result<(), String> {
        self.emit_load_string(function.location(subject)?, 11, 12)?;
        self.emit_load_string(function.location(other)?, 13, 14)?;
        self.emit_load_string(function.location(separators)?, 15, 16)?;
        self.emit_li(10, i64::from(op as u8))?;
        self.emit_runtime_call(vcl_rt::Routine::StrTest)?;
        // Only an operation word this compiler never emits is refused, so a
        // refusal here is a broken image rather than bad VCL input.
        self.words.push(bge(10, 0, 8)?);
        self.emit_ebreak();
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_str_edit(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        op: vcl_rt::StrEdit,
        subject: ValueId,
        count: ValueId,
        offset: ValueId,
    ) -> Result<(), String> {
        self.emit_str_string_call(
            function,
            dst,
            vcl_rt::Routine::StrEdit,
            |emitter| {
                emitter.emit_load_string(function.location(subject)?, 11, 12)?;
                emitter.emit_load_scalar(function.location(count)?, 13)?;
                emitter.emit_load_scalar(function.location(offset)?, 14)?;
                emitter.emit_li(10, i64::from(op as u8))
            },
        )
    }

    fn emit_str_split(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        subject: ValueId,
        index: ValueId,
        separators: ValueId,
    ) -> Result<(), String> {
        self.emit_str_string_call(
            function,
            dst,
            vcl_rt::Routine::StrSplit,
            |emitter| {
                emitter.emit_load_string(function.location(subject)?, 10, 11)?;
                emitter.emit_load_scalar(function.location(index)?, 12)?;
                emitter.emit_load_string(function.location(separators)?, 13, 14)
            },
        )
    }

    /// Size a `str` result, reserve exactly that many arena bytes, then fill
    /// them with a second call whose returned length must match.
    ///
    /// `arguments` loads a0-a4 and runs twice, because the first call
    /// clobbers them; a5-a6 are the output pair this adds.  A `str` routine
    /// has no absent case -- a `split` field that does not exist is the empty
    /// string -- so a negative return can only be an operation word the
    /// image does not know, and traps.
    fn emit_str_string_call(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        routine: vcl_rt::Routine,
        mut arguments: impl FnMut(&mut Self) -> Result<(), String>,
    ) -> Result<(), String> {
        arguments(self)?;
        self.emit_li(15, 0)?;
        self.emit_li(16, 0)?;
        self.emit_runtime_call(routine)?;
        self.words.push(bge(10, 0, 8)?);
        self.emit_ebreak();
        self.emit_move(14, 10)?;
        self.emit_dynamic_arena_alloc(14, 15, 16, 12)?;
        self.emit_store_string(function.location(dst)?, 12, 14)?;
        arguments(self)?;
        self.emit_load_string(function.location(dst)?, 15, 16)?;
        self.emit_runtime_call(routine)?;
        self.emit_load_string(function.location(dst)?, 15, 16)?;
        self.words.push(beq(10, 16, 8)?);
        self.emit_ebreak();
        Ok(())
    }

    // ── vmod module state ───────────────────────────────────────────────
    //
    // Four emitters serve all three modules.  The register assignment, the
    // measure-then-fill sequence and the arena allocation are written once;
    // what differs between `cookieplus`, `urlplus` and `headerplus` is a
    // `Routine` from the module table and an operation word the type checker
    // already encoded.

    /// Where a routine's state operand comes from.
    #[allow(dead_code)]
    fn scratch_slot_address(slot: u64) -> u64 {
        SCRATCH_ADDRESS + slot * 16
    }

    /// Save a pointer/length pair in the fixed `.bss` scratch.
    ///
    /// The stack is not available for this: a spilled value's `Location` is
    /// an offset from `sp`, so anything that moved `sp` while an operand was
    /// still to be loaded would silently read the wrong slot.  A phase is one
    /// thread and these pairs never outlive the instruction that made them,
    /// so two fixed words each are enough.
    fn emit_scratch_store(&mut self, slot: u64, pointer: u8, length: u8) -> Result<(), String> {
        self.emit_li(31, Self::scratch_slot_address(slot) as i64)?;
        self.emit_store_to_base(pointer, 31, 0)?;
        self.emit_store_to_base(length, 31, 8)
    }

    fn emit_scratch_load(&mut self, slot: u64, pointer: u8, length: u8) -> Result<(), String> {
        self.emit_li(31, Self::scratch_slot_address(slot) as i64)?;
        self.emit_load_from_base(pointer, 31, 0)?;
        self.emit_load_from_base(length, 31, 8)
    }

    /// Load the fixed argument registers every list routine takes:
    /// `(state, state_len, code, argument, argument_len, output, output_cap)`
    /// in a0-a6.
    fn emit_module_arguments(
        &mut self,
        function: &AllocatedFunction,
        code: i64,
        state: StateOperand,
        arguments: &[ValueId],
        output: Option<StringDest>,
    ) -> Result<(), String> {
        match state {
            StateOperand::Value(value) => {
                self.emit_load_string(function.location(value)?, 10, 11)?
            }
            StateOperand::Scratch(slot) => self.emit_scratch_load(slot, 10, 11)?,
        }
        self.emit_li(12, code)?;
        match arguments.first() {
            Some(argument) => self.emit_load_string(function.location(*argument)?, 13, 14)?,
            None => {
                self.emit_li(13, 0)?;
                self.emit_li(14, 0)?;
            }
        }
        match output {
            Some(dest) => self.emit_load_dest(function, dest, 15, 16)?,
            None => {
                self.emit_li(15, 0)?;
                self.emit_li(16, 0)?;
            }
        }
        Ok(())
    }

    fn emit_load_dest(
        &mut self,
        function: &AllocatedFunction,
        dest: StringDest,
        pointer: u8,
        length: u8,
    ) -> Result<(), String> {
        match dest {
            StringDest::Value(value) => {
                self.emit_load_string(function.location(value)?, pointer, length)
            }
            StringDest::Scratch(slot) => self.emit_scratch_load(slot, pointer, length),
        }
    }

    fn emit_store_dest(
        &mut self,
        function: &AllocatedFunction,
        dest: StringDest,
        pointer: u8,
        length: u8,
    ) -> Result<(), String> {
        match dest {
            StringDest::Value(value) => {
                self.emit_store_string(function.location(value)?, pointer, length)
            }
            StringDest::Scratch(slot) => self.emit_scratch_store(slot, pointer, length),
        }
    }

    /// The measure-then-fill sequence for a routine that produces a string.
    ///
    /// The sizing call reserves exactly what the filling call writes, and the
    /// two are compared.  The runtime's shared writer makes them one code
    /// path; this is the guest-side check that they stayed one.
    ///
    /// `absent` is where control goes when the routine reports the value
    /// absent.  A read jumps to its fallback; a transform has no such case
    /// and traps, because the only way it fails is exhausting the module's
    /// fixed record capacity, which is a phase failure at the VCL line.
    fn emit_module_string_call(
        &mut self,
        function: &AllocatedFunction,
        routine: vcl_rt::Routine,
        dst: StringDest,
        code: i64,
        state: StateOperand,
        arguments: &[ValueId],
        absent: Option<LabelId>,
    ) -> Result<(), String> {
        self.emit_module_arguments(function, code, state, arguments, None)?;
        self.emit_runtime_call(routine)?;
        self.words.push(bge(10, 0, 8)?);
        match absent {
            Some(label) => self.emit_jump(label),
            None => self.emit_ebreak(),
        }
        self.emit_move(14, 10)?;
        self.emit_dynamic_arena_alloc(14, 15, 16, 12)?;
        self.emit_store_dest(function, dst, 12, 14)?;
        self.emit_module_arguments(function, code, state, arguments, Some(dst))?;
        self.emit_runtime_call(routine)?;
        self.emit_load_dest(function, dst, 15, 16)?;
        self.words.push(beq(10, 16, 8)?);
        self.emit_ebreak();
        Ok(())
    }

    /// Read a string from the host into an arena block, in the two passes the
    /// host's sizing protocol wants, leaving it in scratch slot `slot`.
    ///
    /// `arguments` re-loads the syscall's own arguments before each pass and
    /// returns the register the output pointer goes in; it runs twice because
    /// the first pass clobbers them.
    fn emit_measured_read(
        &mut self,
        slot: u64,
        syscall: Syscall,
        absent_is_empty: bool,
        mut arguments: impl FnMut(&mut Self) -> Result<u8, String>,
    ) -> Result<(), String> {
        for fill in [false, true] {
            let buffer = arguments(self)?;
            if fill {
                self.emit_scratch_load(slot, buffer, buffer + 1)?;
            } else {
                self.emit_li(buffer, 0)?;
                self.emit_li(buffer + 1, 0)?;
            }
            self.emit_li(17, syscall.number() as i64)?;
            self.emit_ecall();
            if fill {
                break;
            }
            if absent_is_empty {
                // An absent header reads as the empty string, as VCL requires.
                self.words.push(bge(10, 0, 8)?);
                self.emit_li(10, 0)?;
            } else {
                self.words.push(bge(10, 0, 8)?);
                self.emit_ebreak();
            }
            self.emit_move(14, 10)?;
            self.emit_dynamic_arena_alloc(14, 15, 16, 12)?;
            self.emit_scratch_store(slot, 12, 14)?;
        }
        Ok(())
    }

    /// Load the arguments of the `headers_snapshot` sub-command, which every
    /// `headerplus` state read shares.  A vmod snapshots every name, so the
    /// name filter is empty.
    fn emit_snapshot_arguments(&mut self, response: bool) -> Result<u8, String> {
        let command = Syscall::HeadersSnapshot
            .typed_subcommand()
            .ok_or_else(|| "headers_snapshot has no sub-command".to_string())?;
        self.emit_li(10, command)?;
        self.emit_li(11, i64::from(response))?;
        self.emit_li(12, 0)?;
        self.emit_li(13, 0)?;
        Ok(14)
    }

    /// A module's runtime routine for one kind of call.
    ///
    /// The refusals are unreachable through `VMODS`, which holds no row that
    /// asks a module for a call it does not have; they are errors rather
    /// than panics because every caller is already in a `Result`.
    fn module_routine(module: Module, kind: Routines) -> Result<vcl_rt::Routine, String> {
        module
            .routine(kind)
            .ok_or_else(|| format!("{} has no {kind:?} routine", module.vcl_name()))
    }

    /// Seed a module's per-hook state from its source string.
    fn emit_module_init(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        module: Module,
        response: bool,
        source: Option<&str>,
    ) -> Result<(), String> {
        let read = module.source().ok_or_else(|| {
            format!(
                "{} is seeded in the IR, not from one host read",
                module.vcl_name()
            )
        })?;
        match read {
            Source::RequestHeader(name) => {
                let name = name.to_string();
                self.emit_measured_read(SOURCE_SLOT, Syscall::RequestGetHeader, true, |emitter| {
                    emitter.emit_literal_address(10, name.as_bytes());
                    emitter.emit_li(11, name.len() as i64)?;
                    Ok(12)
                })?;
            }
            Source::RequestUrl => {
                self.emit_measured_read(SOURCE_SLOT, Syscall::RequestGetUrl, false, |_| Ok(10))?;
            }
            Source::HeaderSnapshot => {
                self.emit_measured_read(SOURCE_SLOT, Syscall::HeadersSnapshot, false, |emitter| {
                    emitter.emit_snapshot_arguments(response)
                })?;
            }
            Source::NamedHeaderSnapshot(default) => {
                // The snapshot is the only call that sees every value of a
                // name, which is what a multi-valued Set-Cookie needs.
                let name = source.unwrap_or(default).to_string();
                let command = Syscall::HeadersSnapshot
                    .typed_subcommand()
                    .ok_or_else(|| "headers_snapshot has no sub-command".to_string())?;
                self.emit_measured_read(SOURCE_SLOT, Syscall::HeadersSnapshot, false, |emitter| {
                    emitter.emit_li(10, command)?;
                    emitter.emit_li(11, i64::from(response))?;
                    emitter.emit_literal_address(12, name.as_bytes());
                    emitter.emit_li(13, name.len() as i64)?;
                    Ok(14)
                })?;
            }
        }
        let code = vcl_rt::OpCode::new(module.parse_op()).encode();
        self.emit_module_string_call(
            function,
            Self::module_routine(module, Routines::Transform)?,
            StringDest::Value(dst),
            code,
            StateOperand::Scratch(SOURCE_SLOT),
            &[],
            None,
        )
    }

    fn emit_module_read(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        module: Module,
        code: i64,
        state: ValueId,
        arguments: &[ValueId],
        default: ValueId,
    ) -> Result<(), String> {
        let fallback = self.internal_label()?;
        let done = self.internal_label()?;
        self.emit_module_string_call(
            function,
            Self::module_routine(module, Routines::Read)?,
            StringDest::Value(dst),
            code,
            StateOperand::Value(state),
            arguments,
            Some(fallback),
        )?;
        self.emit_jump(done);
        self.emit_label(fallback)?;
        self.emit_load_string(function.location(default)?, 10, 11)?;
        self.emit_store_string(function.location(dst)?, 10, 11)?;
        self.emit_label(done)
    }

    fn emit_module_count(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        module: Module,
        code: i64,
        state: ValueId,
        arguments: &[ValueId],
    ) -> Result<(), String> {
        self.emit_module_arguments(function, code, StateOperand::Value(state), arguments, None)?;
        self.emit_runtime_call(Self::module_routine(module, Routines::Count)?)?;
        self.words.push(bge(10, 0, 8)?);
        self.emit_ebreak();
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_module_transform(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        module: Module,
        code: i64,
        state: ValueId,
        arguments: &[ValueId],
    ) -> Result<(), String> {
        self.emit_module_string_call(
            function,
            Self::module_routine(module, Routines::Transform)?,
            StringDest::Value(dst),
            code,
            StateOperand::Value(state),
            arguments,
            None,
        )
    }

    /// The match step of a `_regex` vmod form.
    ///
    /// Three straight-line steps and no loop anywhere in the compiler: the
    /// module's own read routine projects the sub-list as the packed record
    /// format the host's list sub-commands read, one `regex_match_list`
    /// crossing per pattern fills a fixed-stride bitmap, and the module's
    /// read, count or transform routine takes the bitmaps as its argument.
    /// The record list itself never leaves this instruction, so it lives in
    /// scratch rather than in a value.
    ///
    /// A negative return traps. The host distinguishes a refused match (-2)
    /// from a malformed call (-1); neither may read as "nothing matched",
    /// which for a `keep_regex` would be a silently emptied header list.
    fn emit_regex_match_list(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        module: Module,
        select: i64,
        state: ValueId,
        patterns: &[ValueId],
        value_fields: u8,
    ) -> Result<(), String> {
        if patterns.is_empty() || patterns.len() > 2 {
            return Err(format!(
                "a list-shaped regex takes one or two patterns, not {}",
                patterns.len()
            ));
        }
        let stride = vcl_rt::REGEX_BITMAP_STRIDE as i32;
        let command = Syscall::RegexMatchList
            .typed_subcommand()
            .ok_or_else(|| "regex_match_list has no sub-command".to_string())?;

        self.emit_module_string_call(
            function,
            Self::module_routine(module, Routines::Read)?,
            StringDest::Scratch(RECORDS_SLOT),
            select,
            StateOperand::Value(state),
            &[],
            None,
        )?;

        // The bitmap block is the value this operation defines, so reloading
        // it between crossings costs nothing the allocator has not already
        // paid for.
        let width = stride * patterns.len() as i32;
        self.emit_arena_alloc(width, 12)?;
        self.emit_li(13, i64::from(width))?;
        self.emit_store_string(function.location(dst)?, 12, 13)?;

        // a5 holds the five-u64 descriptor the list sub-commands share with
        // sub-command 22. Nothing below writes a5 -- the allocator hands out
        // t0-t5 only -- so one descriptor serves both crossings, and only the
        // two words that differ between slots are rewritten.
        self.emit_arena_alloc(40, 15)?;
        self.emit_li(10, 0)?;
        self.emit_store_to_base(10, 15, 0)?; // no replacement: this is a match
        self.emit_store_to_base(10, 15, 8)?;
        self.emit_li(10, i64::from(stride))?;
        self.emit_store_to_base(10, 15, 24)?; // one slot's worth of capacity

        for (slot, pattern) in patterns.iter().enumerate() {
            self.emit_load_string(function.location(dst)?, 12, 13)?;
            if slot > 0 {
                self.words.push(addi(12, 12, stride * slot as i32)?);
            }
            self.emit_store_to_base(12, 15, 16)?; // this slot's bitmap
            self.emit_li(10, i64::from(value_fields >> slot & 1))?;
            self.emit_store_to_base(10, 15, 32)?; // bit 0: match the value

            self.emit_li(10, command)?;
            self.emit_load_string(function.location(*pattern)?, 11, 12)?;
            self.emit_scratch_load(RECORDS_SLOT, 13, 14)?;
            self.emit_li(17, Syscall::RegexMatchList.number() as i64)?;
            self.emit_ecall();
            self.words.push(bge(10, 0, 8)?); // bge a0, zero, +8
            self.emit_ebreak(); // ebreak: the host declined to match
        }
        Ok(())
    }

    /// `std.collect(hdr, sep)`.
    ///
    /// The snapshot is the only call that sees every header of a name, so it
    /// is what the join reads; the store is the ordinary header setter, which
    /// replaces every value of the name with the one this leaves.  A name
    /// with no header at all skips the store entirely: collecting an absent
    /// header must not create one.
    fn emit_collect(
        &mut self,
        function: &AllocatedFunction,
        name: ValueId,
        separator: ValueId,
        response: bool,
    ) -> Result<(), String> {
        let done = self.internal_label()?;
        let command = Syscall::HeadersSnapshot
            .typed_subcommand()
            .ok_or_else(|| "headers_snapshot has no sub-command".to_string())?;
        self.emit_measured_read(SOURCE_SLOT, Syscall::HeadersSnapshot, false, |emitter| {
            emitter.emit_li(10, command)?;
            emitter.emit_li(11, i64::from(response))?;
            emitter.emit_load_string(function.location(name)?, 12, 13)?;
            Ok(14)
        })?;
        self.emit_module_string_call(
            function,
            vcl_rt::Routine::Collect,
            StringDest::Scratch(COLLECTED_SLOT),
            0,
            StateOperand::Scratch(SOURCE_SLOT),
            &[separator],
            Some(done),
        )?;
        let syscall = if response {
            Syscall::ResponseSetHeader
        } else {
            Syscall::RequestSetHeader
        };
        self.emit_load_string(function.location(name)?, 10, 11)?;
        self.emit_scratch_load(COLLECTED_SLOT, 12, 13)?;
        self.emit_li(17, syscall.number() as i64)?;
        self.emit_ecall();
        self.emit_label(done)
    }

    /// `headerplus.write()`.
    ///
    /// The runtime builds the `Vec<Header>` the *existing* generic header
    /// commit already reads, so nothing new crosses to the host: the phase
    /// gate, the framing-header refusal, the `Host`/`variant_headers`
    /// protection and the per-phase mutation ceiling apply exactly as they do
    /// to a C or Rust guest that commits a header vector by hand.
    fn emit_header_commit(
        &mut self,
        function: &AllocatedFunction,
        state: ValueId,
        response: bool,
    ) -> Result<(), String> {
        // Re-snapshot at write time rather than reusing the state's own
        // parse: a header the policy set with `set resp.http.X` between the
        // init and the write is untouched as far as headerplus is concerned,
        // and passing it through clean is what leaves it alone.
        self.emit_measured_read(SNAPSHOT_SLOT, Syscall::HeadersSnapshot, false, |emitter| {
            emitter.emit_snapshot_arguments(response)
        })?;

        // The vector holds pointers the host follows, so its block has to be
        // eight-aligned and the routine has to be told where it landed.
        for fill in [false, true] {
            self.emit_load_string(function.location(state)?, 10, 11)?;
            self.emit_scratch_load(SNAPSHOT_SLOT, 12, 13)?;
            if fill {
                self.emit_scratch_load(VECTOR_SLOT, 14, 15)?;
                self.emit_move(16, 14)?;
            } else {
                self.emit_li(14, 0)?;
                self.emit_li(15, 0)?;
                self.emit_li(16, 0)?;
            }
            self.emit_runtime_call(vcl_rt::Routine::HeaderCommit)?;
            self.words.push(bge(10, 0, 8)?);
            self.emit_ebreak();
            if fill {
                self.emit_scratch_load(VECTOR_SLOT, 15, 16)?;
                self.words.push(beq(10, 16, 8)?);
                self.emit_ebreak();
            } else {
                self.emit_move(14, 10)?;
                self.emit_align_arena()?;
                self.emit_dynamic_arena_alloc(14, 15, 16, 12)?;
                self.emit_scratch_store(VECTOR_SLOT, 12, 14)?;
            }
        }

        let syscall = if response {
            Syscall::ResponseHeadersCommit
        } else {
            Syscall::RequestHeadersCommit
        };
        let command = syscall
            .typed_subcommand()
            .ok_or_else(|| "the header commit has no sub-command".to_string())?;
        self.emit_li(10, command)?;
        self.emit_scratch_load(VECTOR_SLOT, 11, 12)?;
        self.emit_li(17, syscall.number() as i64)?;
        self.emit_ecall();
        // A refusal is the host's: a forbidden name, a framing header, or the
        // per-phase ceiling. It fails the phase at this VCL line.
        self.words.push(bge(10, 0, 8)?);
        self.emit_ebreak();
        Ok(())
    }

    /// Round the arena cursor up to eight bytes.
    ///
    /// The arena base is eight-aligned, so aligning the cursor aligns the
    /// address.  Only the header vector needs this: it is the one block the
    /// host reads as a struct rather than as bytes.
    fn emit_align_arena(&mut self) -> Result<(), String> {
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(15, 31, 0)?;
        self.words.push(addi(15, 15, 7)?);
        self.words.push(andi(15, 15, -8)?);
        self.emit_store_to_base(15, 31, 0)
    }

    /// Enter a routine through the fixed eight-byte runtime jump table.
    /// Runtime code follows the ordinary RISC-V ABI and may clobber every
    /// caller-saved register, so preserve the allocator's six registers and
    /// the hook return address around the call.
    fn emit_runtime_call(&mut self, routine: vcl_rt::Routine) -> Result<(), String> {
        const CALL_FRAME: u32 = 64;
        const SAVED: [(u8, i32); 7] = [
            (Reg::T0.number(), 0),
            (Reg::T1.number(), 8),
            (Reg::T2.number(), 16),
            (Reg::T3.number(), 24),
            (Reg::T4.number(), 32),
            (Reg::T5.number(), 40),
            (Reg::Ra.number(), 48),
        ];
        self.emit_frame_adjust(CALL_FRAME, false)?;
        for (register, offset) in SAVED {
            self.emit_store_to_base(register, Reg::Sp.number(), offset)?;
        }
        let address = runtime::BASE_ADDRESS
            .checked_add(u64::from(routine as u8) * runtime::ENTRY_SIZE)
            .ok_or_else(|| "runtime entry address overflow".to_string())?;
        // a0-a6 are runtime arguments.  Keep the jump target in t6 so a
        // seven-argument routine (such as std.fnmatch) retains a3-a6.
        self.emit_li(Reg::T6.number(), address as i64)?;
        self.words
            .push(jalr(Reg::Ra.number(), Reg::T6.number(), 0)?);
        for (register, offset) in SAVED {
            self.emit_load_from_base(register, Reg::Sp.number(), offset)?;
        }
        self.emit_frame_adjust(CALL_FRAME, true)
    }

    /// `client.ip`: fill the fixed slot, then hand out a 16-byte string.
    ///
    /// The slot is zeroed when the host has no peer to report, so an
    /// unattributable request reads as `::` rather than as whatever the
    /// previous request on this pooled VM saw.
    fn emit_read_client_ip(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
    ) -> Result<(), String> {
        self.emit_li(
            10,
            Syscall::ClientIp
                .typed_subcommand()
                .expect("client_ip is typed"),
        )?;
        self.emit_li(11, CLIENT_IP_ADDRESS as i64)?;
        self.emit_li(12, CLIENT_IP_BYTES as i64)?;
        self.emit_li(17, Syscall::ClientIp.number() as i64)?;
        self.emit_ecall();
        self.emit_li(31, CLIENT_IP_ADDRESS as i64)?;
        self.words.push(bge(10, 0, 12)?);
        self.emit_store_to_base(0, 31, 0)?;
        self.emit_store_to_base(0, 31, 8)?;
        self.emit_li(12, CLIENT_IP_BYTES as i64)?;
        self.emit_store_string(function.location(dst)?, 31, 12)
    }

    fn emit_acl_match(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        address: ValueId,
        acl: AclId,
    ) -> Result<(), String> {
        let table = self
            .acls
            .get(acl.0 as usize)
            .cloned()
            .ok_or_else(|| format!("acl {} has no table", acl.0))?;
        self.emit_load_string(function.location(address)?, 12, 13)?;
        self.emit_literal_address(10, &table);
        self.emit_li(11, table.len() as i64)?;
        self.emit_runtime_call(vcl_rt::Routine::AclMatch)?;
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_read_now(&mut self, function: &AllocatedFunction, dst: ValueId) -> Result<(), String> {
        let ready = self.internal_label()?;
        let done = self.internal_label()?;
        self.emit_li(31, NOW_VALID_ADDRESS as i64)?;
        self.emit_load_from_base(10, 31, 0)?;
        self.emit_jump_if_nonzero(10, ready)?;
        self.emit_li(10, 0)?; // CLOCK_REALTIME
        self.emit_li(11, NOW_ADDRESS as i64)?;
        self.emit_li(17, LINUX_CLOCK_GETTIME)?;
        self.emit_ecall();
        self.emit_li(31, NOW_ADDRESS as i64)?;
        self.emit_load_from_base(10, 31, 0)?;
        self.emit_load_from_base(11, 31, 8)?;
        self.emit_li(12, 1_000_000_000)?;
        self.words.push(mul(10, 10, 12)?);
        self.words.push(add(10, 10, 11)?);
        self.emit_store_to_base(10, 31, 0)?;
        self.emit_li(12, 1)?;
        self.emit_li(31, NOW_VALID_ADDRESS as i64)?;
        self.emit_store_to_base(12, 31, 0)?;
        self.emit_jump(done);
        self.emit_label(ready)?;
        self.emit_li(31, NOW_ADDRESS as i64)?;
        self.emit_load_from_base(10, 31, 0)?;
        self.emit_label(done)?;
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_read_scalar(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        syscall: Syscall,
        args: &[ValueId],
    ) -> Result<(), String> {
        if syscall == Syscall::DigestVerifyHmacSha256 {
            return self.emit_digest_verify(function, dst, args);
        }
        self.emit_arguments(function, args, 10)?;
        if syscall == Syscall::RegexMatch {
            // Captures are not part of VCL matching. Passing null/zero keeps
            // the host on its borrowed-input is_match path.
            self.emit_li(14, 0)?;
            self.emit_li(15, 0)?;
        } else if matches!(
            syscall,
            Syscall::RequestHasHeader | Syscall::ResponseHasHeader
        ) {
            // Reuse the v1 getter as a zero-copy presence probe. Do not leave
            // its output pointer and capacity dependent on prior guest calls.
            let buffer_arg = 10 + self.argument_width(function, args)? as u8;
            self.emit_li(buffer_arg, 0)?;
            self.emit_li(buffer_arg + 1, 0)?;
        }
        self.emit_li(17, syscall.number() as i64)?;
        self.emit_ecall();
        if syscall == Syscall::RegexMatch {
            // -1 is "no match"; -2 is "the host would not build or run this
            // pattern". Folding the second into `false` is what made a
            // `~`-based deny rule compile and then never fire, so it traps
            // here exactly as the list forms already do.
            self.emit_li(31, -1)?;
            self.words.push(bge(10, 31, 8)?); // bge a0, t6, +8
            self.emit_ebreak(); // ebreak: the host declined to match
        }
        if matches!(
            syscall,
            Syscall::RegexMatch | Syscall::RequestHasHeader | Syscall::ResponseHasHeader
        ) {
            // Regex returns >= 0 for a match and -1 for none. Header probes
            // return a nonnegative length (including zero for an empty field)
            // or -1 when absent. Both become canonical BOOLs here.
            self.words.push(slti(10, 10, 0)?); // slti a0, a0, 0
            self.words.push(xori(10, 10, 1)?); // xori a0, a0, 1
        }
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_read_string(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        syscall: Syscall,
        args: &[ValueId],
    ) -> Result<(), String> {
        if matches!(
            syscall,
            Syscall::DigestHashSha256 | Syscall::DigestHmacSha256
        ) {
            return self.emit_digest_string(function, dst, syscall, args);
        }
        if syscall == Syscall::Regsub {
            return self.emit_regsub_string(function, dst, args);
        }
        if !matches!(
            syscall,
            Syscall::RequestGetMethod
                | Syscall::RequestGetUrl
                | Syscall::RequestGetHeader
                | Syscall::ResponseGetHeader
                | Syscall::VarGetString
        ) {
            return Err(format!("{} is not a string getter", syscall.name()));
        }

        self.emit_arguments(function, args, 10)?;
        let buffer_arg = 10 + self.argument_width(function, args)? as u8;
        self.emit_li(buffer_arg, 0)?;
        self.emit_li(buffer_arg + 1, 0)?;
        self.emit_li(17, syscall.number() as i64)?;
        self.emit_ecall();

        // Header getters return -1 when absent; VCL observes an absent header
        // as the empty string.
        if matches!(
            syscall,
            Syscall::RequestGetHeader | Syscall::ResponseGetHeader
        ) {
            self.words.push(bge(10, 0, 8)?); // bge a0, zero, +8
            self.emit_li(10, 0)?;
        }
        self.emit_move(14, 10)?; // a4 = measured length
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(15, 31, 0)?; // a5 = arena cursor
        self.words.push(add(16, 15, 14)?); // a6 = cursor + len
        self.emit_li(13, READ_ARENA_SIZE as i64)?;
        self.words.push(bgeu(13, 16, 8)?); // bgeu cap, end, +8
        self.emit_ebreak(); // ebreak: per-phase VCL arena overflow
        self.emit_store_to_base(16, 31, 0)?;
        self.emit_li(31, READ_ARENA_ADDRESS as i64)?;
        self.words.push(add(15, 15, 31)?); // a5 = arena + cursor
        self.emit_store_string(function.location(dst)?, 15, 14)?;

        self.emit_arguments(function, args, 10)?;
        let buffer_arg = 10 + self.argument_width(function, args)? as u8;
        self.emit_move(buffer_arg, 15)?;
        self.emit_move(buffer_arg + 1, 14)?;
        self.emit_li(17, syscall.number() as i64)?;
        self.emit_ecall();
        Ok(())
    }

    fn emit_regsub_string(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        args: &[ValueId],
    ) -> Result<(), String> {
        if args.len() != 5 {
            return Err("regsub needs command, pattern, subject, replacement and all".to_string());
        }

        // a5 points at the five-u64 descriptor consumed by sub-command 22.
        self.emit_arena_alloc(40, 15)?;
        self.emit_load_string(function.location(args[3])?, 10, 11)?;
        self.emit_store_to_base(10, 15, 0)?;
        self.emit_store_to_base(11, 15, 8)?;
        self.emit_li(10, 0)?;
        self.emit_store_to_base(10, 15, 16)?;
        self.emit_store_to_base(10, 15, 24)?;
        self.emit_load_scalar(function.location(args[4])?, 10)?;
        self.emit_store_to_base(10, 15, 32)?;

        // cmd + pattern + subject occupy a0-a4; descriptor is already a5.
        self.emit_arguments(function, &args[..3], 10)?;
        self.emit_li(17, Syscall::Regsub.number() as i64)?;
        self.emit_ecall();
        self.words.push(bge(10, 0, 8)?); // bge a0, zero, +8
        self.emit_ebreak(); // ebreak: host refused a compiler-valid call

        // Allocate exactly the measured result while preserving a1-a5 for
        // the second call. a6 is the output pointer; t5 is the end cursor.
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(16, 31, 0)?; // a6 = old cursor
        self.words.push(add(30, 16, 10)?); // t5 = cursor + len
        self.emit_li(31, READ_ARENA_SIZE as i64)?;
        self.words.push(bgeu(31, 30, 8)?); // bgeu cap, end, +8
        self.emit_ebreak();
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_store_to_base(30, 31, 0)?;
        self.emit_li(31, READ_ARENA_ADDRESS as i64)?;
        self.words.push(add(16, 16, 31)?); // a6 = arena + cursor
        self.emit_store_to_base(16, 15, 16)?;
        self.emit_store_to_base(10, 15, 24)?;

        self.emit_li(
            10,
            Syscall::Regsub.typed_subcommand().expect("typed command"),
        )?;
        self.emit_li(17, Syscall::Regsub.number() as i64)?;
        self.emit_ecall();
        self.emit_load_from_base(11, 15, 24)?;
        self.words.push(beq(10, 11, 8)?); // beq written, measured, +8
        self.emit_ebreak();
        self.emit_load_from_base(16, 15, 16)?;
        self.emit_store_string(function.location(dst)?, 16, 10)
    }

    /// Run the existing typed crypto ABI and render its 32-byte result in the
    /// spelling used by vmod-digest: `0x` followed by lowercase hex.
    fn emit_digest_string(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        syscall: Syscall,
        args: &[ValueId],
    ) -> Result<(), String> {
        const RAW_LEN: i32 = 32;
        const TEXT_LEN: i32 = 66;
        const ALLOCATION: i32 = RAW_LEN + TEXT_LEN;

        let output_register = if syscall == Syscall::DigestHashSha256 {
            14 // a4 after cmd, alg, data ptr/len
        } else if syscall == Syscall::DigestHmacSha256 {
            16 // a6 after cmd, alg, key and msg
        } else {
            return Err(format!("{} is not a digest string call", syscall.name()));
        };
        self.emit_arena_alloc(ALLOCATION, output_register)?;
        self.emit_arguments(function, args, 12)?; // a2 onward; a0/a1 are cmd/algorithm
        self.emit_li(
            10,
            syscall
                .typed_subcommand()
                .expect("digest call uses typed ABI"),
        )?;
        self.emit_li(
            11,
            if syscall == Syscall::DigestHashSha256 {
                1
            } else {
                16
            },
        )?;
        self.emit_li(17, syscall.number() as i64)?;
        self.emit_ecall();
        self.emit_li(11, i64::from(RAW_LEN))?;
        self.words.push(beq(10, 11, 8)?); // beq bytes, 32, +8
        self.emit_ebreak(); // ebreak: host refused a valid compiler call

        // Reconstitute the allocation start after the syscall. The cursor now
        // points just beyond it, which avoids relying on argument registers
        // surviving a host call.
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(10, 31, 0)?;
        self.words.push(addi(10, 10, -ALLOCATION)?);
        self.emit_li(31, READ_ARENA_ADDRESS as i64)?;
        self.words.push(add(10, 10, 31)?); // a0 = raw
        self.words.push(addi(11, 10, RAW_LEN)?); // a1 = text
        self.emit_literal_address(12, b"0123456789abcdef");
        self.emit_li(13, i64::from(b'0'))?;
        self.words.push(sb(13, 11, 0)?); // sb '0', 0(a1)
        self.emit_li(13, i64::from(b'x'))?;
        self.words.push(sb(13, 11, 1)?); // sb 'x', 1(a1)
        for index in 0..RAW_LEN {
            self.words.push(lbu(13, 10, index)?); // lbu a3, n(a0)
            self.words.push(srli(14, 13, 4)?);
            self.words.push(add(14, 12, 14)?); // add a4, table, nibble
            self.words.push(lbu(14, 14, 0)?); // lbu a4, 0(a4)
            self.words.push(sb(14, 11, 2 + index * 2)?);
            self.words.push(andi(13, 13, 15)?); // andi a3, a3, 15
            self.words.push(add(13, 12, 13)?); // add a3, table, nibble
            self.words.push(lbu(13, 13, 0)?); // lbu a3, 0(a3)
            self.words.push(sb(13, 11, 3 + index * 2)?);
        }
        self.emit_li(12, i64::from(TEXT_LEN))?;
        self.emit_store_string(function.location(dst)?, 11, 12)
    }

    /// Constant-time HMAC verification. VCL supplies the conventional 64
    /// hex characters (an optional `0x` prefix is accepted); generated code
    /// decodes them and the host performs the actual comparison.
    fn emit_digest_verify(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        args: &[ValueId],
    ) -> Result<(), String> {
        let [key, message, tag] = args else {
            return Err("digest.verify_hmac_sha256 needs three arguments".to_string());
        };
        let raw = self.internal_label()?;
        let prefixed = self.internal_label()?;
        let decode = self.internal_label()?;
        let invalid = self.internal_label()?;
        let done = self.internal_label()?;

        self.emit_arena_alloc(32, 15)?; // a5 = decoded tag
        self.emit_load_string(function.location(*tag)?, 10, 11)?;
        self.emit_li(12, 64)?;
        self.emit_jump_if_equal(11, 12, raw)?;
        self.emit_li(12, 66)?;
        self.emit_jump_if_equal(11, 12, prefixed)?;
        self.emit_jump(invalid);

        self.emit_label(prefixed)?;
        self.words.push(lbu(12, 10, 0)?);
        self.emit_li(13, i64::from(b'0'))?;
        self.words.push(beq(12, 13, 8)?); // beq, skip invalid jump
        self.emit_jump(invalid);
        self.words.push(lbu(12, 10, 1)?);
        self.emit_li(13, i64::from(b'x'))?;
        self.words.push(beq(12, 13, 8)?);
        self.emit_jump(invalid);
        self.words.push(addi(10, 10, 2)?);
        self.emit_jump(decode);

        self.emit_label(raw)?;
        self.emit_label(decode)?;
        for index in 0..32i32 {
            self.words.push(lbu(12, 10, index * 2)?); // a2 = high char
            self.emit_hex_nibble(12, 11, 16, invalid)?;
            self.words.push(slli(11, 11, 4)?); // slli high, 4
            self.words.push(lbu(12, 10, index * 2 + 1)?);
            self.emit_hex_nibble(12, 13, 16, invalid)?;
            self.words.push(or(11, 11, 13)?); // or
            self.words.push(sb(11, 15, index)?); // sb
        }

        // cmd, algorithm, key ptr/len, message ptr/len, decoded tag ptr
        self.emit_li(10, 10)?;
        self.emit_li(11, 16)?;
        self.emit_arguments(function, &[*key, *message], 12)?;
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(16, 31, 0)?;
        self.words.push(addi(16, 16, -32)?);
        self.emit_li(31, READ_ARENA_ADDRESS as i64)?;
        self.words.push(add(16, 16, 31)?);
        self.emit_li(17, Syscall::DigestVerifyHmacSha256.number() as i64)?;
        self.emit_ecall();
        self.words.push(addi(10, 10, -1)?);
        self.words.push(sltiu(10, 10, 1)?); // seqz(a0 - 1)
        self.emit_jump(done);

        self.emit_label(invalid)?;
        self.emit_li(10, 0)?;
        self.emit_label(done)?;
        self.emit_store_scalar(function.location(dst)?, 10)
    }

    fn emit_hex_nibble(
        &mut self,
        character: u8,
        result: u8,
        scratch: u8,
        invalid: LabelId,
    ) -> Result<(), String> {
        let done = self.internal_label()?;
        self.words.push(addi(result, character, -i32::from(b'0'))?);
        self.words.push(sltiu(scratch, result, 10)?); // sltiu
        self.emit_jump_if_nonzero(scratch, done)?;
        self.words.push(addi(result, character, -i32::from(b'a'))?);
        self.words.push(sltiu(scratch, result, 6)?);
        let lower = self.internal_label()?;
        self.emit_jump_if_nonzero(scratch, lower)?;
        self.words.push(addi(result, character, -i32::from(b'A'))?);
        self.words.push(sltiu(scratch, result, 6)?);
        let upper = self.internal_label()?;
        self.emit_jump_if_nonzero(scratch, upper)?;
        self.emit_jump(invalid);
        self.emit_label(lower)?;
        self.words.push(addi(result, result, 10)?);
        self.emit_jump(done);
        self.emit_label(upper)?;
        self.words.push(addi(result, result, 10)?);
        self.emit_label(done)?;
        Ok(())
    }

    fn emit_arena_alloc(&mut self, size: i32, pointer: u8) -> Result<(), String> {
        if matches!(pointer, 10 | 11 | 31) {
            return Err(
                "arena allocation pointer aliases an internal scratch register".to_string(),
            );
        }
        self.emit_li(31, BSS_ADDRESS as i64)?;
        self.emit_load_from_base(pointer, 31, 0)?;
        // Every fixed-size block holds words the code reads and writes with
        // `ld`/`sd`, and follows strings of any length, so it starts on an
        // eight-byte boundary. libvmod-riscv's libriscv is built with
        // RISCV_FORCE_ALIGN_MEMORY, where a misaligned access is silently
        // aligned down rather than emulated.
        self.words.push(addi(pointer, pointer, 7)?);
        self.words.push(andi(pointer, pointer, -8)?);
        self.words.push(addi(10, pointer, size)?); // a0 = end cursor
        self.emit_li(11, READ_ARENA_SIZE as i64)?;
        self.words.push(bgeu(11, 10, 8)?); // bgeu cap, end, +8
        self.emit_ebreak();
        self.emit_store_to_base(10, 31, 0)?;
        self.emit_li(31, READ_ARENA_ADDRESS as i64)?;
        self.words.push(add(pointer, pointer, 31)?);
        Ok(())
    }

    fn emit_jump_if_equal(&mut self, left: u8, right: u8, target: LabelId) -> Result<(), String> {
        self.words.push(bne(left, right, 8)?); // bne, skip jump
        self.emit_jump(target);
        Ok(())
    }

    fn emit_jump_if_nonzero(&mut self, value: u8, target: LabelId) -> Result<(), String> {
        self.words.push(beq(value, 0, 8)?); // beqz, skip jump
        self.emit_jump(target);
        Ok(())
    }

    fn internal_label(&mut self) -> Result<LabelId, String> {
        let label = LabelId(u32::MAX - self.internal_labels);
        self.internal_labels = self
            .internal_labels
            .checked_add(1)
            .ok_or_else(|| "VCL codegen exhausted internal labels".to_string())?;
        Ok(label)
    }

    fn emit_not(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        value: ValueId,
    ) -> Result<(), String> {
        self.emit_load_scalar(function.location(value)?, 10)?;
        self.words.push(sltiu(11, 10, 1)?); // seqz a1, a0
        self.emit_store_scalar(function.location(dst)?, 11)
    }

    fn emit_scalar_binary(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        kind: ScalarBinaryKind,
        left: ValueId,
        right: ValueId,
    ) -> Result<(), String> {
        self.emit_load_scalar(function.location(left)?, 10)?;
        self.emit_load_scalar(function.location(right)?, 11)?;
        if matches!(kind, ScalarBinaryKind::Divide | ScalarBinaryKind::Modulo) {
            self.words.push(bne(11, 0, 8)?); // bne divisor, zero, +8
            self.emit_ebreak(); // ebreak: division by zero
        }
        if matches!(kind, ScalarBinaryKind::Max | ScalarBinaryKind::Min) {
            // a2 = a0, replaced by a1 unless a0 already wins. Signed, as
            // every VCL INT is.
            self.emit_move(12, 10)?;
            self.words.push(if kind == ScalarBinaryKind::Max {
                bge(10, 11, 8)? // bge a0, a1, +8: a0 is the max
            } else {
                bge(11, 10, 8)? // bge a1, a0, +8: a0 is the min
            });
            self.emit_move(12, 11)?;
            return self.emit_store_scalar(function.location(dst)?, 12);
        }
        let word = match kind {
            ScalarBinaryKind::Add => add(12, 10, 11),
            ScalarBinaryKind::Subtract => sub(12, 10, 11),
            ScalarBinaryKind::Multiply => mul(12, 10, 11),
            ScalarBinaryKind::Divide => div(12, 10, 11),
            ScalarBinaryKind::Modulo => rem(12, 10, 11),
            ScalarBinaryKind::Max | ScalarBinaryKind::Min => unreachable!("emitted above"),
        };
        self.words.push(word?);
        self.emit_store_scalar(function.location(dst)?, 12)
    }

    fn emit_compare(
        &mut self,
        function: &AllocatedFunction,
        dst: ValueId,
        kind: CompareKind,
        left: ValueId,
        right: ValueId,
    ) -> Result<(), String> {
        match (function.location(left)?, function.location(right)?) {
            (
                left @ (Location::Register(_) | Location::Stack(_)),
                right @ (Location::Register(_) | Location::Stack(_)),
            ) => {
                self.emit_load_scalar(left, 10)?;
                self.emit_load_scalar(right, 11)?;
                self.words.push(xor(12, 10, 11)?); // xor
                match kind {
                    CompareKind::Equal => {
                        self.words.push(sltiu(12, 12, 1)?); // seqz
                    }
                    CompareKind::NotEqual => {
                        self.words.push(sltu(12, 0, 12)?); // snez
                    }
                    CompareKind::Less => {
                        self.words.push(slt(12, 10, 11)?); // slt
                    }
                    CompareKind::LessEqual => {
                        self.words.push(slt(12, 11, 10)?); // right < left
                        self.words.push(xori(12, 12, 1)?); // invert
                    }
                    CompareKind::Greater => {
                        self.words.push(slt(12, 11, 10)?); // right < left
                    }
                    CompareKind::GreaterEqual => {
                        self.words.push(slt(12, 10, 11)?); // left < right
                        self.words.push(xori(12, 12, 1)?); // invert
                    }
                }
                self.emit_store_scalar(function.location(dst)?, 12)
            }
            (
                left @ (Location::RegisterPair(_, _) | Location::StackPair(_)),
                right @ (Location::RegisterPair(_, _) | Location::StackPair(_)),
            ) => self.emit_string_compare(function.location(dst)?, kind, left, right),
            _ => Err("comparison operands have different register classes".to_string()),
        }
    }

    fn emit_string_compare(
        &mut self,
        dst: Location,
        kind: CompareKind,
        left: Location,
        right: Location,
    ) -> Result<(), String> {
        if !matches!(kind, CompareKind::Equal | CompareKind::NotEqual) {
            return Err("ordered string comparisons are not supported".to_string());
        }
        self.emit_load_string(left, 10, 11)?;
        self.emit_load_string(right, 12, 13)?;
        self.emit_li(14, 0)?;
        self.words.push(bne(11, 13, 48)?); // bne lengths, end
        self.emit_li(14, 1)?;
        self.words.push(beq(11, 0, 40)?); // beq len, zero, end
        self.words.push(lbu(15, 10, 0)?); // lbu a5, 0(a0)
        self.words.push(lbu(16, 12, 0)?); // lbu a6, 0(a2)
        self.words.push(bne(15, 16, 24)?); // bne bytes, mismatch
        self.words.push(addi(10, 10, 1)?);
        self.words.push(addi(12, 12, 1)?);
        self.words.push(addi(11, 11, -1)?);
        self.words.push(bne(11, 0, -24)?); // bne len, zero, loop
        self.words.push(jal(0, 8)?); // skip mismatch
        self.emit_li(14, 0)?;
        if kind == CompareKind::NotEqual {
            self.words.push(xori(14, 14, 1)?); // xori
        }
        self.emit_store_scalar(dst, 14)
    }

    fn emit_label(&mut self, label: LabelId) -> Result<(), String> {
        if self.labels.insert(label, self.byte_len()).is_some() {
            return Err(format!("duplicate code label l{}", label.0));
        }
        Ok(())
    }

    fn emit_jump(&mut self, target: LabelId) {
        self.control_fixups.push(ControlFixup {
            instruction_offset: self.byte_len(),
            target,
            span: self.op_span,
        });
        self.words.push(0);
    }

    fn emit_branch_zero(
        &mut self,
        function: &AllocatedFunction,
        value: ValueId,
        target: LabelId,
    ) -> Result<(), String> {
        self.emit_load_scalar(function.location(value)?, 31)?;
        self.words.push(bne(31, 0, 8)?); // bne t6, zero, +8
        self.control_fixups.push(ControlFixup {
            instruction_offset: self.byte_len(),
            target,
            span: self.op_span,
        });
        self.words.push(0);
        Ok(())
    }

    fn resolve_control_fixups(&mut self) -> Result<(), GenError> {
        for fixup in &self.control_fixups {
            let target = self.labels.get(&fixup.target).copied().ok_or_else(|| {
                GenError::new(
                    format!("undefined code label l{}", fixup.target.0),
                    fixup.span,
                )
            })?;
            let offset = i32::try_from(target as i64 - fixup.instruction_offset as i64)
                .map_err(|_| GenError::new("VCL branch offset exceeds i32", fixup.span))?;
            let word = fixup.instruction_offset / 4;
            self.words[word] = jal(0, offset)?;
        }
        self.labels.clear();
        self.control_fixups.clear();
        Ok(())
    }

    fn emit_host(
        &mut self,
        function: &AllocatedFunction,
        syscall: Syscall,
        args: &[ValueId],
    ) -> Result<(), String> {
        self.emit_arguments(function, args, 10)?;
        self.emit_li(17, syscall.number() as i64)?; // a7
        self.emit_ecall(); // ecall
        Ok(())
    }

    fn emit_action(
        &mut self,
        function: &AllocatedFunction,
        action: ActionCode,
        args: &[ValueId],
    ) -> Result<(), String> {
        self.emit_li(10, action.abi_value())?;
        self.emit_arguments(function, args, 11)?;
        self.emit_li(17, Syscall::ReturnAction.number() as i64)?;
        self.emit_ecall();
        Ok(())
    }

    fn emit_arguments(
        &mut self,
        function: &AllocatedFunction,
        args: &[ValueId],
        mut target: u8,
    ) -> Result<(), String> {
        for value in args {
            let location = function.location(*value)?;
            // a7 carries the syscall number, leaving a0-a6 for operands.
            if target as usize + location.width() > 17 {
                return Err("host call needs more than a0-a6".to_string());
            }
            match location {
                Location::Register(register) => {
                    self.emit_move(target, register)?;
                    target += 1;
                }
                Location::RegisterPair(pointer, length) => {
                    self.emit_move(target, pointer)?;
                    self.emit_move(target + 1, length)?;
                    target += 2;
                }
                Location::Stack(offset) => {
                    self.emit_load(target, offset)?;
                    target += 1;
                }
                Location::StackPair(offset) => {
                    self.emit_load(target, offset)?;
                    self.emit_load(target + 1, offset + 8)?;
                    target += 2;
                }
            }
        }
        Ok(())
    }

    fn argument_width(
        &self,
        function: &AllocatedFunction,
        args: &[ValueId],
    ) -> Result<usize, String> {
        args.iter().try_fold(0usize, |width, value| {
            Ok(width + function.location(*value)?.width())
        })
    }

    fn emit_load_scalar(&mut self, location: Location, target: u8) -> Result<(), String> {
        match location {
            Location::Register(register) => self.emit_move(target, register),
            Location::Stack(offset) => self.emit_load(target, offset),
            Location::RegisterPair(_, _) | Location::StackPair(_) => {
                Err("cannot load a string location as a scalar".to_string())
            }
        }
    }

    fn emit_store_scalar(&mut self, location: Location, source: u8) -> Result<(), String> {
        match location {
            Location::Register(register) => self.emit_move(register, source),
            Location::Stack(offset) => self.emit_store(source, offset),
            Location::RegisterPair(_, _) | Location::StackPair(_) => {
                Err("cannot store a scalar in a string location".to_string())
            }
        }
    }

    fn emit_load_string(
        &mut self,
        location: Location,
        pointer: u8,
        length: u8,
    ) -> Result<(), String> {
        match location {
            Location::RegisterPair(src_pointer, src_length) => {
                self.emit_move(pointer, src_pointer)?;
                self.emit_move(length, src_length)
            }
            Location::StackPair(offset) => {
                self.emit_load(pointer, offset)?;
                self.emit_load(length, offset + 8)
            }
            Location::Register(_) | Location::Stack(_) => {
                Err("cannot load a scalar location as a string".to_string())
            }
        }
    }

    fn emit_store_string(
        &mut self,
        location: Location,
        pointer: u8,
        length: u8,
    ) -> Result<(), String> {
        match location {
            Location::RegisterPair(dst_pointer, dst_length) => {
                self.emit_move(dst_pointer, pointer)?;
                self.emit_move(dst_length, length)
            }
            Location::StackPair(offset) => {
                self.emit_store(pointer, offset)?;
                self.emit_store(length, offset + 8)
            }
            Location::Register(_) | Location::Stack(_) => {
                Err("cannot store a string in a scalar location".to_string())
            }
        }
    }

    fn emit_move(&mut self, dst: u8, src: u8) -> Result<(), String> {
        self.words.push(addi(dst, src, 0)?);
        Ok(())
    }

    fn emit_load(&mut self, dst: u8, offset: u32) -> Result<(), String> {
        if offset <= 2047 {
            self.words.push(ld(dst, 2, offset as i32)?); // ld
        } else {
            self.emit_li(31, i64::from(offset))?;
            self.words.push(add(31, 31, 2)?); // t6 = sp + offset
            self.emit_load_from_base(dst, 31, 0)?;
        }
        Ok(())
    }

    fn emit_load_from_base(&mut self, dst: u8, base: u8, offset: i32) -> Result<(), String> {
        self.words.push(ld(dst, base, offset)?);
        Ok(())
    }

    fn emit_store(&mut self, src: u8, offset: u32) -> Result<(), String> {
        if offset <= 2047 {
            self.words.push(sd(src, 2, offset as i32)?); // sd
        } else {
            if src == 31 {
                return Err("wide stack store aliases the t6 address scratch".to_string());
            }
            self.emit_li(31, i64::from(offset))?;
            self.words.push(add(31, 31, 2)?); // t6 = sp + offset
            self.emit_store_to_base(src, 31, 0)?;
        }
        Ok(())
    }

    fn emit_store_to_base(&mut self, src: u8, base: u8, offset: i32) -> Result<(), String> {
        self.words.push(sd(src, base, offset)?);
        Ok(())
    }

    fn emit_frame_adjust(&mut self, size: u32, restore: bool) -> Result<(), String> {
        if size == 0 {
            return Ok(());
        }
        let immediate = if restore {
            i64::from(size)
        } else {
            -i64::from(size)
        };
        if (-2048..=2047).contains(&immediate) {
            self.words.push(addi(2, 2, immediate as i32)?);
        } else {
            self.emit_li(31, immediate)?;
            self.words.push(add(2, 31, 2)?); // sp += t6
        }
        Ok(())
    }

    fn emit_literal_address(&mut self, register: u8, value: &[u8]) {
        let literal = match self.literal_index.get(value) {
            Some(index) => *index,
            None => {
                let index = self.literals.len();
                self.literals.push(value.to_vec());
                self.literal_index.insert(value.to_vec(), index);
                index
            }
        };
        let instruction_offset = self.byte_len();
        self.words.extend([0, 0]);
        self.fixups.push(AddressFixup {
            instruction_offset,
            literal,
            register,
        });
    }

    fn emit_li(&mut self, register: u8, value: i64) -> Result<(), String> {
        if (-2048..=2047).contains(&value) {
            self.words.push(addi(register, 0, value as i32)?);
            return Ok(());
        }
        if let Ok(value) = i32::try_from(value) {
            let hi = ((value as i64 + 0x800) >> 12) as i32;
            let lo = value.wrapping_sub(hi.wrapping_shl(12));
            // `lui` carries a 20-bit signed immediate, and rounding the high
            // part up carries the top of the i32 range out of it: every value
            // from 0x7fff_f800 on has no two-instruction form. Falling
            // through to the byte-wise path is what keeps
            // `set var.n = 2147483647;` a program rather than an
            // encoder-shaped diagnostic.
            if let (Ok(high), Ok(low)) = (lui(register, hi), addi(register, register, lo)) {
                self.words.push(high);
                self.words.push(low);
                return Ok(());
            }
        }

        // Construct the full two's-complement value a byte at a time. Starting
        // with a signed high byte preserves negative values; every later shift
        // discards the prior sign extension as it makes room for the next byte.
        let bytes = value.to_be_bytes();
        self.words
            .push(addi(register, 0, i32::from(bytes[0] as i8))?);
        for byte in &bytes[1..] {
            self.words.push(slli(register, register, 8)?); // slli rd, rd, 8
            if *byte != 0 {
                self.words.push(addi(register, register, i32::from(*byte))?);
            }
        }
        Ok(())
    }

    fn emit_ret(&mut self) {
        self.words.push(ret());
    }

    fn emit_exit(&mut self) -> Result<(), String> {
        self.emit_li(Reg::A0.number(), 0)?; // status
        self.emit_li(Reg::A7.number(), LINUX_EXIT)?;
        self.emit_ecall();
        Ok(())
    }

    fn emit_ecall(&mut self) {
        self.words.push(ecall());
    }

    fn emit_ebreak(&mut self) {
        self.words.push(ebreak());
    }
}

fn load_address_words(register: u8, address: u64) -> Result<(u32, u32), String> {
    let address = i32::try_from(address).map_err(|_| "ELF image exceeds 2 GiB".to_string())?;
    let hi = ((address as i64 + 0x800) >> 12) as i32;
    let lo = address.wrapping_sub(hi.wrapping_shl(12));
    Ok((lui(register, hi)?, addi(register, register, lo)?))
}

// Named RV64 mnemonics are the only layer allowed to spell format fields.
macro_rules! r_mnemonic {
    ($name:ident, $funct7:expr, $funct3:expr) => {
        fn $name(rd: u8, rs1: u8, rs2: u8) -> Result<u32, String> {
            encode_r($funct7, rs2, rs1, $funct3, rd, 0x33)
        }
    };
}

r_mnemonic!(add, 0, 0);
r_mnemonic!(sub, 0x20, 0);
r_mnemonic!(mul, 1, 0);
r_mnemonic!(div, 1, 4);
r_mnemonic!(divu, 1, 5);
r_mnemonic!(rem, 1, 6);
r_mnemonic!(remu, 1, 7);
r_mnemonic!(slt, 0, 2);
r_mnemonic!(sltu, 0, 3);
r_mnemonic!(xor, 0, 4);
r_mnemonic!(or, 0, 6);

macro_rules! i_mnemonic {
    ($name:ident, $funct3:expr, $opcode:expr) => {
        fn $name(rd: u8, rs1: u8, immediate: i32) -> Result<u32, String> {
            encode_i(immediate, rs1, $funct3, rd, $opcode)
        }
    };
}

i_mnemonic!(addi, 0, 0x13);
i_mnemonic!(slli, 1, 0x13);
i_mnemonic!(slti, 2, 0x13);
i_mnemonic!(sltiu, 3, 0x13);
i_mnemonic!(xori, 4, 0x13);
i_mnemonic!(srli, 5, 0x13);
i_mnemonic!(andi, 7, 0x13);
i_mnemonic!(ld, 3, 0x03);
i_mnemonic!(lbu, 4, 0x03);

fn jalr(rd: u8, rs1: u8, immediate: i32) -> Result<u32, String> {
    encode_i(immediate, rs1, 0, rd, 0x67)
}

fn sb(rs2: u8, rs1: u8, immediate: i32) -> Result<u32, String> {
    encode_s(immediate, rs2, rs1, 0, 0x23)
}

fn sd(rs2: u8, rs1: u8, immediate: i32) -> Result<u32, String> {
    encode_s(immediate, rs2, rs1, 3, 0x23)
}

macro_rules! b_mnemonic {
    ($name:ident, $funct3:expr) => {
        fn $name(rs1: u8, rs2: u8, immediate: i32) -> Result<u32, String> {
            encode_b(immediate, rs2, rs1, $funct3, 0x63)
        }
    };
}

b_mnemonic!(beq, 0);
b_mnemonic!(bne, 1);
b_mnemonic!(bge, 5);
b_mnemonic!(bgeu, 7);

fn jal(rd: u8, immediate: i32) -> Result<u32, String> {
    encode_j(immediate, rd, 0x6f)
}

fn lui(rd: u8, immediate: i32) -> Result<u32, String> {
    encode_u(immediate, rd, 0x37)
}

fn ecall() -> u32 {
    0x0000_0073
}

fn ebreak() -> u32 {
    0x0010_0073
}

fn ret() -> u32 {
    0x0000_8067
}

fn encode_i(imm: i32, rs1: u8, funct3: u8, rd: u8, opcode: u8) -> Result<u32, String> {
    if !(-2048..=2047).contains(&imm) {
        return Err(format!("I-immediate {imm} is out of range"));
    }
    check_register(rs1)?;
    check_register(rd)?;
    Ok((((imm as u32) & 0xfff) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | ((rd as u32) << 7)
        | opcode as u32)
}

fn encode_u(imm20: i32, rd: u8, opcode: u8) -> Result<u32, String> {
    if !(-524_288..=524_287).contains(&imm20) {
        return Err(format!("U-immediate {imm20} is out of range"));
    }
    check_register(rd)?;
    Ok(((imm20 as u32 & 0x000f_ffff) << 12) | ((rd as u32) << 7) | opcode as u32)
}

fn encode_s(imm: i32, rs2: u8, rs1: u8, funct3: u8, opcode: u8) -> Result<u32, String> {
    if !(-2048..=2047).contains(&imm) {
        return Err(format!("S-immediate {imm} is out of range"));
    }
    check_register(rs1)?;
    check_register(rs2)?;
    let immediate = (imm as u32) & 0xfff;
    Ok(((immediate >> 5) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | ((immediate & 0x1f) << 7)
        | opcode as u32)
}

fn encode_r(funct7: u8, rs2: u8, rs1: u8, funct3: u8, rd: u8, opcode: u8) -> Result<u32, String> {
    check_register(rs1)?;
    check_register(rs2)?;
    check_register(rd)?;
    Ok(((funct7 as u32) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | ((rd as u32) << 7)
        | opcode as u32)
}

fn encode_b(imm: i32, rs2: u8, rs1: u8, funct3: u8, opcode: u8) -> Result<u32, String> {
    if imm % 2 != 0 || !(-4096..=4094).contains(&imm) {
        return Err(format!("B-immediate {imm} is out of range or unaligned"));
    }
    check_register(rs1)?;
    check_register(rs2)?;
    let immediate = (imm as u32) & 0x1fff;
    Ok((((immediate >> 12) & 1) << 31)
        | (((immediate >> 5) & 0x3f) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | (((immediate >> 1) & 0xf) << 8)
        | (((immediate >> 11) & 1) << 7)
        | opcode as u32)
}

fn encode_j(imm: i32, rd: u8, opcode: u8) -> Result<u32, String> {
    if imm % 2 != 0 || !(-1_048_576..=1_048_574).contains(&imm) {
        return Err(format!("J-immediate {imm} is out of range or unaligned"));
    }
    check_register(rd)?;
    let immediate = (imm as u32) & 0x1f_ffff;
    Ok((((immediate >> 20) & 1) << 31)
        | (((immediate >> 1) & 0x3ff) << 21)
        | (((immediate >> 11) & 1) << 20)
        | (((immediate >> 12) & 0xff) << 12)
        | ((rd as u32) << 7)
        | opcode as u32)
}

fn check_register(register: u8) -> Result<(), String> {
    if register < 32 {
        Ok(())
    } else {
        Err(format!("invalid RISC-V register x{register}"))
    }
}

/// Map each instruction's source offset to the file it came from and that
/// file's own line number.
///
/// Spans are offsets into the whole unit — main source first, then each
/// included library — so a line counted from the start of the unit would name
/// a line the file it belongs to does not have. Both halves are needed: the
/// file index puts the fault in the library, the line puts it on the right
/// line of it.
fn build_line_table(unit: &SourceUnit, offsets: Vec<(usize, usize)>) -> LineTable {
    let newlines: Vec<_> = unit
        .text
        .bytes()
        .enumerate()
        .filter_map(|(offset, byte)| (byte == b'\n').then_some(offset))
        .collect();
    let starts: Vec<_> = unit.files.iter().map(|file| file.start).collect();
    let mut entries = Vec::with_capacity(offsets.len());
    let mut previous = None;
    for (offset, source_offset) in offsets {
        let source_offset = source_offset.min(unit.text.len());
        let file = starts
            .partition_point(|start| *start <= source_offset)
            .saturating_sub(1);
        let first = newlines.partition_point(|newline| *newline < starts[file]);
        let line =
            (newlines.partition_point(|newline| *newline < source_offset) - first) as u32 + 1;
        let file = file as u32;
        if previous == Some((file, line)) {
            continue;
        }
        entries.push(LineEntry {
            address: BASE_ADDRESS + offset as u64,
            line,
            file,
        });
        previous = Some((file, line));
    }
    LineTable { entries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Phase;

    #[test]
    fn immediate_encoders_refuse_truncation() {
        assert!(addi(1, 0, 2048).is_err());
        assert!(addi(1, 0, -2049).is_err());
        assert!(lui(1, 524_288).is_err());
        assert!(sd(1, 2, 2048).is_err());
    }

    #[test]
    fn address_materialization_rounds_low_twelve_bits() {
        let (lui, addi) = load_address_words(10, 0x1_0fff).unwrap();
        assert_eq!(lui, 0x0001_1537);
        assert_eq!(addi, 0xfff5_0513);
    }

    #[test]
    fn regex_match_passes_no_capture_buffer_and_normalizes_the_result() {
        let function = AllocatedFunction {
            phase: Phase::Recv,
            ops: Vec::new(),
            locations: [
                (ValueId(0), Location::RegisterPair(5, 6)),
                (ValueId(1), Location::RegisterPair(7, 28)),
                (ValueId(2), Location::Register(29)),
            ]
            .into_iter()
            .collect(),
            frame_size: 0,
            local_offsets: Vec::new(),
            local_classes: Vec::new(),
        };
        let mut emitter = Emitter::default();
        emitter
            .emit_read_scalar(
                &function,
                ValueId(2),
                Syscall::RegexMatch,
                &[ValueId(0), ValueId(1)],
            )
            .unwrap();
        let ecall = emitter
            .words
            .iter()
            .position(|word| *word == 0x0000_0073)
            .expect("regex call emits ecall");

        assert_eq!(
            emitter.words[ecall - 3],
            addi(14, 0, 0).unwrap(),
            "a4/capture pointer must be null"
        );
        assert_eq!(
            emitter.words[ecall - 2],
            addi(15, 0, 0).unwrap(),
            "a5/capture count must be zero"
        );
        // -2 traps before the result is normalised: the host refusing to
        // build or run a pattern must not read as "did not match".
        assert_eq!(
            emitter.words[ecall + 1],
            addi(31, 0, -1).unwrap(),
            "t6 holds the lowest result that is not a refusal"
        );
        assert_eq!(
            emitter.words[ecall + 2],
            bge(10, 31, 8).unwrap(),
            "a refusal skips into the trap"
        );
        assert_eq!(emitter.words[ecall + 3], ebreak(), "a refusal traps");
        assert_eq!(
            emitter.words[ecall + 4],
            slti(10, 10, 0).unwrap(),
            "no match becomes false"
        );
        assert_eq!(
            emitter.words[ecall + 5],
            xori(10, 10, 1).unwrap(),
            "a match becomes true"
        );
    }

    #[test]
    fn header_presence_passes_no_output_buffer_and_normalizes_the_result() {
        let function = AllocatedFunction {
            phase: Phase::Recv,
            ops: Vec::new(),
            locations: [
                (ValueId(0), Location::RegisterPair(5, 6)),
                (ValueId(1), Location::Register(7)),
            ]
            .into_iter()
            .collect(),
            frame_size: 0,
            local_offsets: Vec::new(),
            local_classes: Vec::new(),
        };
        let mut emitter = Emitter::default();
        emitter
            .emit_read_scalar(
                &function,
                ValueId(1),
                Syscall::RequestHasHeader,
                &[ValueId(0)],
            )
            .unwrap();
        let ecall = emitter
            .words
            .iter()
            .position(|word| *word == 0x0000_0073)
            .expect("header probe emits ecall");

        assert_eq!(
            emitter.words[ecall - 3],
            addi(12, 0, 0).unwrap(),
            "a2/output pointer must be null"
        );
        assert_eq!(
            emitter.words[ecall - 2],
            addi(13, 0, 0).unwrap(),
            "a3/output capacity must be zero"
        );
        assert_eq!(
            emitter.words[ecall + 1],
            slti(10, 10, 0).unwrap(),
            "an absent header becomes false"
        );
        assert_eq!(
            emitter.words[ecall + 2],
            xori(10, 10, 1).unwrap(),
            "a present header, including an empty one, becomes true"
        );
    }

    #[test]
    fn line_table_coalesces_adjacent_ops_on_the_same_source_line() {
        let unit = unit_for("vcl 4.1;\nfirst;\nsecond;\n");
        let table = build_line_table(&unit, vec![(0, 9), (12, 11), (28, 16)]);
        assert_eq!(
            table.entries,
            [
                LineEntry {
                    address: BASE_ADDRESS,
                    line: 2,
                    file: 0,
                },
                LineEntry {
                    address: BASE_ADDRESS + 28,
                    line: 3,
                    file: 0,
                },
            ]
        );
    }

    #[test]
    fn line_table_numbers_an_included_library_by_its_own_lines() {
        // Main source, then one library appended after it. An offset in the
        // library must name the library's file and the library's line, not the
        // main file's last line.
        let main = "vcl 4.1;\nsub vcl_recv { call helper; }\n";
        let library = "sub helper {\n  set req.http.X = \"1\";\n}\n";
        let mut unit = unit_for(main);
        let start = unit.text.len() + 1;
        unit.text.push('\n');
        unit.text.push_str(library);
        unit.files.push(crate::diagnostic::DiagnosticFile {
            start,
            end: start + library.len(),
            filename: Some("/bundle/lib.vcl".into()),
            include: Some("lib.vcl".into()),
            source: library.to_string(),
        });
        let in_library = start + library.find("set").expect("statement in library");
        let table = build_line_table(&unit, vec![(0, 9), (4, in_library)]);
        assert_eq!(
            table.entries,
            [
                LineEntry {
                    address: BASE_ADDRESS,
                    line: 2,
                    file: 0,
                },
                LineEntry {
                    address: BASE_ADDRESS + 4,
                    line: 2,
                    file: 1,
                },
            ]
        );
    }

    fn unit_for(source: &str) -> SourceUnit {
        SourceUnit {
            program: crate::ast::Program {
                items: Vec::new(),
                syntax: 41,
            },
            text: source.to_string(),
            files: vec![crate::diagnostic::DiagnosticFile {
                start: 0,
                end: source.len(),
                filename: None,
                include: None,
                source: source.to_string(),
            }],
        }
    }


}
