//! Deterministic ELF64 writer for the compiler's static RV64 image.

use crate::backend::BackendError;
use crate::codegen::{Image, BASE_ADDRESS, BSS_ADDRESS};
use crate::runtime;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const SECTION_HEADER_SIZE: usize = 64;
const TEXT_OFFSET: usize = 0x1000;

#[derive(Debug, Clone)]
struct Section {
    name: &'static str,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entry_size: u64,
}

pub(crate) fn build(image: &Image) -> Result<Vec<u8>, BackendError> {
    build_inner(image).map_err(|message| BackendError::without_span("ELF writer", message))
}

fn build_inner(image: &Image) -> Result<Vec<u8>, String> {
    if image.text.is_empty() {
        return Err("cannot build an ELF with empty .text".to_string());
    }
    if image.runtime.is_empty() {
        return Err("cannot build an ELF without the VCL runtime image".to_string());
    }
    if image.runtime_rodata.is_empty() {
        return Err("cannot build an ELF without the VCL runtime constants".to_string());
    }
    let rodata_offset = TEXT_OFFSET
        .checked_add(image.text.len())
        .ok_or_else(|| "VCL text file offset overflows usize".to_string())?;
    let loaded_size = image
        .text
        .len()
        .checked_add(image.rodata.len())
        .ok_or_else(|| "VCL text and rodata size overflows usize".to_string())?;
    let loaded_end = BASE_ADDRESS
        .checked_add(u64::try_from(loaded_size).map_err(|_| "VCL image is too large".to_string())?)
        .ok_or_else(|| "VCL text address overflows u64".to_string())?;
    if loaded_end > runtime::BASE_ADDRESS {
        return Err("VCL text and rodata overlap the fixed runtime image".to_string());
    }
    // Both runtime segments keep the page congruence their own linker gave
    // them: the file offset of each has to agree with its virtual address
    // modulo the page size, or the image is not loadable.
    let runtime_offset = align(TEXT_OFFSET + loaded_size, 0x1000);
    if image.runtime_rodata_address < runtime::BASE_ADDRESS + image.runtime.len() as u64 {
        return Err("VCL runtime rodata overlaps the runtime code".to_string());
    }
    let runtime_rodata_offset = runtime_offset
        .checked_add(
            usize::try_from(image.runtime_rodata_address - runtime::BASE_ADDRESS)
                .map_err(|_| "VCL runtime rodata address does not fit usize".to_string())?,
        )
        .ok_or_else(|| "VCL runtime rodata file offset overflows usize".to_string())?;
    let bss_offset = align(runtime_rodata_offset + image.runtime_rodata.len(), 8);
    debug_assert_eq!(runtime_offset % 0x1000, 0);
    debug_assert_eq!(runtime::BASE_ADDRESS % 0x1000, 0);
    debug_assert_eq!(runtime_rodata_offset % 0x1000, 0);
    debug_assert_eq!(bss_offset % 8, 0);

    let mut strtab = vec![0];
    let mut symbol_name_offsets = Vec::with_capacity(image.symbols.len());
    for symbol in &image.symbols {
        symbol_name_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(symbol.name.as_bytes());
        strtab.push(0);
    }
    let mut static_name_offsets = Vec::with_capacity(image.statics.len());
    for static_ in &image.statics {
        static_name_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(static_.name.as_bytes());
        strtab.push(0);
    }
    let mut global_name_offsets = Vec::with_capacity(image.globals.len());
    for global in &image.globals {
        global_name_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(global.name.as_bytes());
        strtab.push(0);
    }

    let mut symtab = vec![0; 24]; // required null symbol
    for (symbol, name_offset) in image.symbols.iter().zip(symbol_name_offsets) {
        push_u32(&mut symtab, name_offset);
        symtab.push((1 << 4) | 2); // STB_GLOBAL | STT_FUNC
        symtab.push(0);
        push_u16(&mut symtab, 1); // .text
        push_u64(&mut symtab, BASE_ADDRESS + symbol.offset);
        push_u64(&mut symtab, symbol.size);
    }
    for (static_, name_offset) in image.statics.iter().zip(static_name_offsets) {
        push_u32(&mut symtab, name_offset);
        symtab.push((1 << 4) | 1); // STB_GLOBAL | STT_OBJECT
        symtab.push(0);
        push_u16(&mut symtab, 5); // .bss
        push_u64(&mut symtab, static_.address);
        push_u64(&mut symtab, 8);
    }
    // Readability only, as for the statics: the host finds the region
    // through `.carapace.globals`, never through a symbol.
    for (global, name_offset) in image.globals.iter().zip(global_name_offsets) {
        push_u32(&mut symtab, name_offset);
        symtab.push((1 << 4) | 1); // STB_GLOBAL | STT_OBJECT
        symtab.push(0);
        push_u16(&mut symtab, 5); // .bss
        push_u64(&mut symtab, global.address);
        push_u64(&mut symtab, global.size);
    }

    // Each row is address, line, and the file the line belongs to: 0 for the
    // compiled unit's own source, N for the Nth name in `.carapace.files`.
    // The field was the row's zero padding, so the row size is unchanged.
    let mut line_bytes = Vec::with_capacity(image.lines.entries.len() * 16);
    for entry in &image.lines.entries {
        push_u64(&mut line_bytes, entry.address);
        push_u32(&mut line_bytes, entry.line);
        push_u32(&mut line_bytes, entry.file);
    }

    // Include names as written, NUL-terminated, in file-index order from 1.
    // The name rather than the resolved path: an absolute path would make two
    // copies of one policy tree compile to different bytes, and engine
    // identity is the hash of these bytes.
    let mut file_bytes = Vec::new();
    for name in &image.files {
        file_bytes.extend_from_slice(name.as_bytes());
        file_bytes.push(0);
    }

    let mut cursor = bss_offset;
    let symtab_offset = cursor;
    cursor += symtab.len();
    let strtab_offset = cursor;
    cursor += strtab.len();
    cursor = align(cursor, 8);
    let lines_offset = cursor;
    cursor += line_bytes.len();

    let files_offset = if file_bytes.is_empty() {
        None
    } else {
        let offset = cursor;
        cursor += file_bytes.len();
        Some(offset)
    };

    let mut static_bytes = Vec::new();
    for static_ in &image.statics {
        push_u64(&mut static_bytes, static_.address);
        push_u32(
            &mut static_bytes,
            match static_.value_type {
                crate::types::ValueType::Integer => 0,
                crate::types::ValueType::Boolean => 1,
                crate::types::ValueType::Duration => 2,
                crate::types::ValueType::Time => 3,
                crate::types::ValueType::String | crate::types::ValueType::Ip => {
                    return Err("cannot publish a STRING static".to_string())
                }
            },
        );
        push_u32(&mut static_bytes, static_.name.len() as u32);
        static_bytes.extend_from_slice(static_.name.as_bytes());
    }
    let statics_offset = if static_bytes.is_empty() {
        None
    } else {
        cursor = align(cursor, 8);
        let offset = cursor;
        cursor += static_bytes.len();
        Some(offset)
    };

    // One 32-byte row per `stat`-annotated static, in declaration order:
    // the guest address of the 8-byte word, the kind, reserved flags, and
    // the guest addresses of the NUL-terminated name and help. Fixed-size
    // rows pointing at guest strings, because that is what lets a C or Rust
    // guest emit one from a macro — the section is an ABI, not something the
    // host learned about VCL. Unallocated: the host reads it from the ELF
    // when the program loads (src/vcl/vcl_stats.cpp).
    let mut stat_bytes = Vec::new();
    for static_ in &image.statics {
        let Some(stat) = static_.stat.as_ref() else {
            continue;
        };
        push_u64(&mut stat_bytes, static_.address);
        push_u32(&mut stat_bytes, stat.spec.kind as u32);
        push_u32(&mut stat_bytes, 0); // flags: reserved
        push_u64(&mut stat_bytes, stat.name_address);
        push_u64(&mut stat_bytes, stat.help_address);
    }
    let stats_offset = if stat_bytes.is_empty() {
        None
    } else {
        cursor = align(cursor, 8);
        let offset = cursor;
        cursor += stat_bytes.len();
        Some(offset)
    };

    // Every regular-expression literal the policy spells, NUL-terminated, in
    // first-use order. The engine compiles the set once when it warms, so a
    // VCL policy never builds a pattern on a request's own thread and never
    // shares a compiled one with another tenant.
    let mut regex_bytes = Vec::new();
    for pattern in &image.patterns {
        if pattern.as_bytes().contains(&0) {
            return Err("a regular-expression literal contains a NUL byte".to_string());
        }
        regex_bytes.extend_from_slice(pattern.as_bytes());
        regex_bytes.push(0);
    }
    let regex_offset = if regex_bytes.is_empty() {
        None
    } else {
        let offset = cursor;
        cursor += regex_bytes.len();
        Some(offset)
    };

    // The request-global region: its guest address, its size, and the bytes
    // a client instance starts from. The host copies an opaque blob to and
    // from that address at every phase boundary and learns nothing about
    // what the bytes mean: the contract is the section and not the
    // language. Extend by appending behind a new
    // section name; do not reorder.
    let mut global_bytes = Vec::new();
    if let Some(region) = &image.global_region {
        push_u64(&mut global_bytes, region.address);
        push_u64(&mut global_bytes, region.image.len() as u64);
        global_bytes.extend_from_slice(&region.image);
    }
    let globals_offset = if global_bytes.is_empty() {
        None
    } else {
        cursor = align(cursor, 8);
        let offset = cursor;
        cursor += global_bytes.len();
        Some(offset)
    };

    let mut section_names = vec![
        "",
        ".text",
        ".rodata",
        ".text.rt",
        ".rodata.rt",
        ".bss",
        ".symtab",
        ".strtab",
        ".carapace.lines",
    ];
    if files_offset.is_some() {
        section_names.push(".carapace.files");
    }
    if statics_offset.is_some() {
        section_names.push(".carapace.statics");
    }
    if stats_offset.is_some() {
        section_names.push(".carapace.stats");
    }
    if regex_offset.is_some() {
        section_names.push(".carapace.regex");
    }
    if globals_offset.is_some() {
        section_names.push(".carapace.globals");
    }
    section_names.push(".shstrtab");
    let mut shstrtab = Vec::new();
    let mut section_name_offsets = Vec::new();
    for name in section_names {
        section_name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_offset = cursor;
    cursor += shstrtab.len();
    let section_headers_offset = align(cursor, 8);

    let mut sections = vec![
        Section {
            name: "",
            kind: 0,
            flags: 0,
            address: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            align: 0,
            entry_size: 0,
        },
        Section {
            name: ".text",
            kind: 1,
            flags: 0x6,
            address: BASE_ADDRESS,
            offset: TEXT_OFFSET as u64,
            size: image.text.len() as u64,
            link: 0,
            info: 0,
            align: 4,
            entry_size: 0,
        },
        Section {
            name: ".rodata",
            kind: 1,
            flags: 0x2,
            address: BASE_ADDRESS + image.text.len() as u64,
            offset: rodata_offset as u64,
            size: image.rodata.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        },
        Section {
            name: ".text.rt",
            kind: 1,
            flags: 0x6,
            address: runtime::BASE_ADDRESS,
            offset: runtime_offset as u64,
            size: image.runtime.len() as u64,
            link: 0,
            info: 0,
            align: 4,
            entry_size: 0,
        },
        Section {
            name: ".rodata.rt",
            kind: 1,
            flags: 0x2,
            address: image.runtime_rodata_address,
            offset: runtime_rodata_offset as u64,
            size: image.runtime_rodata.len() as u64,
            link: 0,
            info: 0,
            align: 8,
            entry_size: 0,
        },
        Section {
            name: ".bss",
            kind: 8,
            flags: 0x3,
            address: BSS_ADDRESS,
            offset: bss_offset as u64,
            size: image.bss_size,
            link: 0,
            info: 0,
            align: 8,
            entry_size: 0,
        },
        Section {
            name: ".symtab",
            kind: 2,
            flags: 0,
            address: 0,
            offset: symtab_offset as u64,
            size: symtab.len() as u64,
            // The index of `.strtab`, the next section. It was 6 — this
            // section itself — from before `.text.rt`/`.rodata.rt` moved it:
            // libriscv finds `.strtab` by name so hooks still resolved, but
            // objdump and gdb read the symbol names from here.
            link: 7,
            info: 1,
            align: 8,
            entry_size: 24,
        },
        Section {
            name: ".strtab",
            kind: 3,
            flags: 0,
            address: 0,
            offset: strtab_offset as u64,
            size: strtab.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        },
        Section {
            name: ".carapace.lines",
            kind: 1,
            flags: 0,
            address: 0,
            offset: lines_offset as u64,
            size: line_bytes.len() as u64,
            link: 0,
            info: 0,
            align: 8,
            entry_size: 16,
        },
        Section {
            name: ".shstrtab",
            kind: 3,
            flags: 0,
            address: 0,
            offset: shstrtab_offset as u64,
            size: shstrtab.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        },
    ];
    if let Some(files_offset) = files_offset {
        let shstr = sections.pop().expect("shstr section");
        sections.push(Section {
            name: ".carapace.files",
            kind: 3, // SHT_STRTAB: NUL-terminated names
            flags: 0,
            address: 0,
            offset: files_offset as u64,
            size: file_bytes.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        });
        sections.push(shstr);
    }
    if let Some(statics_offset) = statics_offset {
        let shstr = sections.pop().expect("shstr section");
        sections.push(Section {
            name: ".carapace.statics",
            kind: 1,
            flags: 0,
            address: 0,
            offset: statics_offset as u64,
            size: static_bytes.len() as u64,
            link: 0,
            info: 0,
            align: 8,
            entry_size: 0,
        });
        sections.push(shstr);
    }
    if let Some(stats_offset) = stats_offset {
        let shstr = sections.pop().expect("shstr section");
        sections.push(Section {
            name: ".carapace.stats",
            kind: 1, // SHT_PROGBITS: fixed-size rows
            flags: 0,
            address: 0,
            offset: stats_offset as u64,
            size: stat_bytes.len() as u64,
            link: 0,
            info: 0,
            align: 8,
            entry_size: 32,
        });
        sections.push(shstr);
    }

    if let Some(regex_offset) = regex_offset {
        let shstr = sections.pop().expect("shstr section");
        sections.push(Section {
            name: ".carapace.regex",
            kind: 3, // SHT_STRTAB: NUL-terminated patterns
            flags: 0,
            address: 0,
            offset: regex_offset as u64,
            size: regex_bytes.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        });
        sections.push(shstr);
    }

    if let Some(globals_offset) = globals_offset {
        let shstr = sections.pop().expect("shstr section");
        sections.push(Section {
            name: ".carapace.globals",
            kind: 1, // SHT_PROGBITS: address, size, initial image
            flags: 0,
            address: 0,
            offset: globals_offset as u64,
            size: global_bytes.len() as u64,
            link: 0,
            info: 0,
            align: 8,
            entry_size: 0,
        });
        sections.push(shstr);
    }

    let total_size = section_headers_offset + sections.len() * SECTION_HEADER_SIZE;
    let mut elf = Vec::with_capacity(total_size);
    write_header(
        &mut elf,
        section_headers_offset as u64,
        sections.len() as u16,
        (sections.len() - 1) as u16,
    );
    write_program_headers(
        &mut elf,
        loaded_size as u64,
        RuntimeSegments {
            text_offset: runtime_offset as u64,
            text_size: image.runtime.len() as u64,
            rodata_offset: runtime_rodata_offset as u64,
            rodata_address: image.runtime_rodata_address,
            rodata_size: image.runtime_rodata.len() as u64,
        },
        bss_offset as u64,
        image.bss_size,
    );
    resize_to(&mut elf, TEXT_OFFSET);
    elf.extend_from_slice(&image.text);
    elf.extend_from_slice(&image.rodata);
    resize_to(&mut elf, runtime_offset);
    elf.extend_from_slice(&image.runtime);
    resize_to(&mut elf, runtime_rodata_offset);
    elf.extend_from_slice(&image.runtime_rodata);
    resize_to(&mut elf, symtab_offset);
    elf.extend_from_slice(&symtab);
    resize_to(&mut elf, strtab_offset);
    elf.extend_from_slice(&strtab);
    resize_to(&mut elf, lines_offset);
    elf.extend_from_slice(&line_bytes);
    if let Some(files_offset) = files_offset {
        resize_to(&mut elf, files_offset);
        elf.extend_from_slice(&file_bytes);
    }
    if let Some(statics_offset) = statics_offset {
        resize_to(&mut elf, statics_offset);
        elf.extend_from_slice(&static_bytes);
    }
    if let Some(stats_offset) = stats_offset {
        resize_to(&mut elf, stats_offset);
        elf.extend_from_slice(&stat_bytes);
    }
    if let Some(regex_offset) = regex_offset {
        resize_to(&mut elf, regex_offset);
        elf.extend_from_slice(&regex_bytes);
    }
    if let Some(globals_offset) = globals_offset {
        resize_to(&mut elf, globals_offset);
        elf.extend_from_slice(&global_bytes);
    }
    resize_to(&mut elf, shstrtab_offset);
    elf.extend_from_slice(&shstrtab);
    resize_to(&mut elf, section_headers_offset);
    for (section, name_offset) in sections.iter().zip(section_name_offsets) {
        debug_assert_eq!(
            section.name,
            section_names_for_debug(name_offset, &shstrtab)
        );
        write_section_header(&mut elf, name_offset, section);
    }
    debug_assert_eq!(elf.len(), total_size);
    Ok(elf)
}

fn write_header(elf: &mut Vec<u8>, shoff: u64, shnum: u16, shstrndx: u16) {
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]);
    push_u16(elf, 2); // ET_EXEC
    push_u16(elf, 243); // EM_RISCV
    push_u32(elf, 1);
    push_u64(elf, BASE_ADDRESS);
    push_u64(elf, ELF_HEADER_SIZE as u64);
    push_u64(elf, shoff);
    // The policy compiler emits RV64I instructions, but the embedded runtime
    // comes from the `riscv64gc` target and uses compressed instructions.
    // EF_RISCV_RVC lets the loader enable that decoder for the complete image.
    push_u32(elf, 0x1); // EF_RISCV_RVC
    push_u16(elf, ELF_HEADER_SIZE as u16);
    push_u16(elf, PROGRAM_HEADER_SIZE as u16);
    push_u16(elf, 4);
    push_u16(elf, SECTION_HEADER_SIZE as u16);
    push_u16(elf, shnum);
    push_u16(elf, shstrndx);
    debug_assert_eq!(elf.len(), ELF_HEADER_SIZE);
}

/// Where the two pre-linked runtime segments land in the policy image.
struct RuntimeSegments {
    text_offset: u64,
    text_size: u64,
    rodata_offset: u64,
    rodata_address: u64,
    rodata_size: u64,
}

fn write_program_headers(
    elf: &mut Vec<u8>,
    loaded_size: u64,
    runtime: RuntimeSegments,
    bss_offset: u64,
    bss_size: u64,
) {
    // The generated policy's text and literals share one RX segment. libriscv
    // shrinks that segment to the `.text` section inside it, so the literals
    // are never decoded; the runtime image below cannot rely on the same
    // reduction, which is why it arrives already split.
    push_u32(elf, 1); // PT_LOAD
    push_u32(elf, 5); // R | X; literals are immutable
    push_u64(elf, TEXT_OFFSET as u64);
    push_u64(elf, BASE_ADDRESS);
    push_u64(elf, BASE_ADDRESS);
    push_u64(elf, loaded_size);
    push_u64(elf, loaded_size);
    push_u64(elf, 0x1000);

    push_u32(elf, 1); // PT_LOAD
    push_u32(elf, 5); // R | X; pre-linked runtime routines
    push_u64(elf, runtime.text_offset);
    push_u64(elf, runtime::BASE_ADDRESS);
    push_u64(elf, runtime::BASE_ADDRESS);
    push_u64(elf, runtime.text_size);
    push_u64(elf, runtime.text_size);
    push_u64(elf, 0x1000);

    push_u32(elf, 1); // PT_LOAD
    push_u32(elf, 4); // R; the runtime's constant tables, never decoded
    push_u64(elf, runtime.rodata_offset);
    push_u64(elf, runtime.rodata_address);
    push_u64(elf, runtime.rodata_address);
    push_u64(elf, runtime.rodata_size);
    push_u64(elf, runtime.rodata_size);
    push_u64(elf, 0x1000);

    push_u32(elf, 1); // PT_LOAD
    push_u32(elf, 6); // R | W
    push_u64(elf, bss_offset);
    push_u64(elf, BSS_ADDRESS);
    push_u64(elf, BSS_ADDRESS);
    push_u64(elf, 0);
    push_u64(elf, bss_size);
    push_u64(elf, 8);
    debug_assert_eq!(elf.len(), ELF_HEADER_SIZE + 4 * PROGRAM_HEADER_SIZE);
}

fn write_section_header(elf: &mut Vec<u8>, name: u32, section: &Section) {
    push_u32(elf, name);
    push_u32(elf, section.kind);
    push_u64(elf, section.flags);
    push_u64(elf, section.address);
    push_u64(elf, section.offset);
    push_u64(elf, section.size);
    push_u32(elf, section.link);
    push_u32(elf, section.info);
    push_u64(elf, section.align);
    push_u64(elf, section.entry_size);
}

fn section_names_for_debug(offset: u32, table: &[u8]) -> &str {
    let start = offset as usize;
    let end = table[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map_or(table.len(), |relative| start + relative);
    std::str::from_utf8(&table[start..end]).unwrap_or("")
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn resize_to(bytes: &mut Vec<u8>, size: usize) {
    assert!(bytes.len() <= size);
    bytes.resize(size, 0);
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::{StaticSymbol, Symbol};
    use crate::types::ValueType;

    #[test]
    fn emits_riscv_executable_with_symbol_table() {
        let image = Image {
            patterns: Vec::new(),
            text: 0x0000_8067u32.to_le_bytes().to_vec(),
            rodata: Vec::new(),
            runtime: vec![0, 0, 0, 0],
            runtime_rodata: vec![1, 2, 3, 4],
            runtime_rodata_address: runtime::BASE_ADDRESS + 0x1000,
            symbols: vec![Symbol {
                name: "main".into(),
                offset: 0,
                size: 4,
            }],
            lines: Default::default(),
            files: Vec::new(),
            bss_size: 8 + 64 * 1024,
            statics: Vec::new(),
            globals: Vec::new(),
            global_region: None,
            exports: Default::default(),
        };
        let elf = build(&image).unwrap();
        assert_eq!(&elf[..4], b"\x7fELF");
        assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), 243);
        // The runtime has its own fixed virtual address, so both page
        // alignment and ELF's file/virtual congruence are required.  The BSS
        // follows it at an eight-byte-congruent address for scalar state.
        let header = ELF_HEADER_SIZE;
        let read_u64 =
            |offset: usize| u64::from_le_bytes(elf[offset..offset + 8].try_into().unwrap());
        let runtime_header = header + PROGRAM_HEADER_SIZE;
        let runtime_offset = read_u64(runtime_header + 8);
        let runtime_address = read_u64(runtime_header + 16);
        let runtime_align = read_u64(runtime_header + 48);
        assert_eq!(runtime_address, runtime::BASE_ADDRESS);
        assert_eq!(runtime_align, 0x1000);
        assert_eq!(
            runtime_offset % runtime_align,
            runtime_address % runtime_align
        );
        let rodata_header = runtime_header + PROGRAM_HEADER_SIZE;
        let flags = u32::from_le_bytes(
            elf[rodata_header + 4..rodata_header + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(flags, 4, "the runtime's constant tables are R, never X");
        assert_eq!(read_u64(rodata_header + 16), runtime::BASE_ADDRESS + 0x1000);
        assert_eq!(
            read_u64(rodata_header + 8) % runtime_align,
            read_u64(rodata_header + 16) % runtime_align
        );
        let bss_header = rodata_header + PROGRAM_HEADER_SIZE;
        let bss_offset = read_u64(bss_header + 8);
        let bss_address = read_u64(bss_header + 16);
        let bss_align = read_u64(bss_header + 48);
        assert_eq!(bss_offset % bss_align, bss_address % bss_align);
        assert!(elf.windows(5).any(|window| window == b"main\0"));

        // `.symtab` names its string table by index, and tools read the
        // symbol names through it.
        let u16_at = |offset: usize| u16::from_le_bytes([elf[offset], elf[offset + 1]]) as usize;
        let u32_at =
            |offset: usize| u32::from_le_bytes(elf[offset..offset + 4].try_into().unwrap());
        let (shoff, shnum, shstrndx) = (read_u64(40) as usize, u16_at(60), u16_at(62));
        let section = |index: usize| shoff + index * SECTION_HEADER_SIZE;
        let names = read_u64(section(shstrndx) + 24) as usize;
        let name_of = |index: usize| {
            let start = names + u32_at(section(index)) as usize;
            let end = start + elf[start..].iter().position(|byte| *byte == 0).unwrap();
            std::str::from_utf8(&elf[start..end]).unwrap()
        };
        let symtab = (0..shnum).find(|index| name_of(*index) == ".symtab").unwrap();
        let link = u32_at(section(symtab) + 40) as usize;
        assert_eq!(name_of(link), ".strtab");
    }

    #[test]
    fn refuses_policy_bytes_that_reach_the_runtime_segment() {
        let image = Image {
            patterns: Vec::new(),
            text: vec![0; (runtime::BASE_ADDRESS - BASE_ADDRESS + 1) as usize],
            rodata: Vec::new(),
            runtime: vec![0; 4],
            runtime_rodata: vec![1, 2, 3, 4],
            runtime_rodata_address: runtime::BASE_ADDRESS + 0x1000,
            symbols: Vec::new(),
            lines: Default::default(),
            files: Vec::new(),
            bss_size: 8,
            statics: Vec::new(),
            globals: Vec::new(),
            global_region: None,
            exports: Default::default(),
        };
        let error = build(&image).unwrap_err().to_string();
        assert!(error.contains("overlap the fixed runtime image"), "{error}");
    }

    #[test]
    fn publishes_static_object_and_self_contained_metadata() {
        let address = BSS_ADDRESS + 8 + 64 * 1024;
        let image = Image {
            patterns: Vec::new(),
            text: 0x0000_8067u32.to_le_bytes().to_vec(),
            rodata: Vec::new(),
            runtime: vec![0, 0, 0, 0],
            runtime_rodata: vec![1, 2, 3, 4],
            runtime_rodata_address: runtime::BASE_ADDRESS + 0x1000,
            symbols: vec![Symbol {
                name: "main".into(),
                offset: 0,
                size: 4,
            }],
            lines: Default::default(),
            files: Vec::new(),
            bss_size: 8 + 64 * 1024 + 8,
            statics: vec![StaticSymbol {
                name: "requests".into(),
                address,
                value_type: ValueType::Integer,
                stat: None,
            }],
            globals: Vec::new(),
            global_region: None,
            exports: Default::default(),
        };
        let elf = build(&image).unwrap();
        assert!(elf
            .windows(b".carapace.statics\0".len())
            .any(|bytes| bytes == b".carapace.statics\0"));
        assert!(elf
            .windows(b"requests\0".len())
            .any(|bytes| bytes == b"requests\0"));
        let mut row = Vec::new();
        push_u64(&mut row, address);
        push_u32(&mut row, 0);
        push_u32(&mut row, 8);
        row.extend_from_slice(b"requests");
        assert!(elf.windows(row.len()).any(|bytes| bytes == row));
    }

    #[test]
    fn publishes_the_include_file_table_alongside_the_line_rows() {
        let image = Image {
            patterns: Vec::new(),
            text: 0x0000_8067u32.to_le_bytes().to_vec(),
            rodata: Vec::new(),
            runtime: vec![0, 0, 0, 0],
            runtime_rodata: vec![1, 2, 3, 4],
            runtime_rodata_address: runtime::BASE_ADDRESS + 0x1000,
            symbols: vec![Symbol {
                name: "main".into(),
                offset: 0,
                size: 4,
            }],
            lines: crate::ir::LineTable {
                entries: vec![crate::ir::LineEntry {
                    address: BASE_ADDRESS,
                    line: 3,
                    file: 1,
                }],
            },
            files: vec!["lib.vcl".into()],
            bss_size: 8 + 64 * 1024,
            statics: Vec::new(),
            globals: Vec::new(),
            global_region: None,
            exports: Default::default(),
        };
        let elf = build(&image).unwrap();
        assert!(elf
            .windows(b".carapace.files\0".len())
            .any(|bytes| bytes == b".carapace.files\0"));
        assert!(elf
            .windows(b"lib.vcl\0".len())
            .any(|bytes| bytes == b"lib.vcl\0"));
        // The row's former padding word now carries the file index.
        let mut row = Vec::new();
        push_u64(&mut row, BASE_ADDRESS);
        push_u32(&mut row, 3);
        push_u32(&mut row, 1);
        assert!(elf.windows(row.len()).any(|bytes| bytes == row));
    }
}
