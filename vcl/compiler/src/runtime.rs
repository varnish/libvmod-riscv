//! The pre-linked RV64 runtime image carried by every VCL ELF that needs it.
//!
//! `compile()` never invokes a linker.  The small checked-in ELF is produced
//! by `vcl-rt/guest`, validated here, then its two load segments are
//! copied verbatim into the policy image at their linked addresses.
//!
//! The split into an RX code segment and a separate read-only segment is not
//! cosmetic.  libriscv decodes and binary-translates an executable segment in
//! full, and the one reduction it performs -- shrinking a segment to the
//! `.text` *section* inside it -- cannot apply here, because the policy ELF
//! already has a `.text` of its own below this image.  Constant tables sharing
//! the RX segment are therefore decoded as instructions, which is both wasted
//! translation and a source of instructions the image never contains: the
//! weekday, month and digit tables alone decoded into 110 illegal opcodes and
//! 93 floating-point operations.

pub(crate) const BASE_ADDRESS: u64 = 0x10_0000;
pub(crate) const ENTRY_SIZE: u64 = 8;
pub(crate) const ROUTINE_COUNT: usize = vcl_rt::Routine::COUNT;
const VERSION_SIZE: usize = 4;

const ELF: &[u8] = include_bytes!("../../runtime/runtime.elf");

/// The two load segments of the checked-in runtime blob.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeImage {
    /// The RX segment at [`BASE_ADDRESS`]: nothing but instructions.
    pub text: &'static [u8],
    /// The read-only segment holding the runtime's constant tables.
    pub rodata: &'static [u8],
    /// Where the read-only segment is linked, always above `text`.
    pub rodata_address: u64,
}

impl RuntimeImage {
    /// The first address past the image, for the caller's overlap checks.
    pub fn end_address(&self) -> Result<u64, String> {
        self.rodata_address
            .checked_add(self.rodata.len() as u64)
            .ok_or_else(|| "runtime rodata address overflow".to_string())
    }
}

pub(crate) fn image() -> Result<RuntimeImage, String> {
    if ELF.len() < 64 || &ELF[..4] != b"\x7fELF" || ELF[4] != 2 || ELF[5] != 1 || ELF[6] != 1 {
        return Err("runtime blob is not a little-endian ELF64 image".to_string());
    }
    if read_u16(ELF, 16)? != 2
        || read_u16(ELF, 18)? != 243
        || read_u32(ELF, 20)? != 1
        || read_u64(ELF, 24)? != BASE_ADDRESS
    {
        return Err("runtime blob is not a RISC-V executable".to_string());
    }
    if read_u32(ELF, 48)? & 0x1 == 0 {
        return Err("runtime blob must declare compressed RISC-V instructions".to_string());
    }
    let program_offset = usize::try_from(read_u64(ELF, 32)?)
        .map_err(|_| "runtime program header offset does not fit usize".to_string())?;
    let entry_size = usize::from(read_u16(ELF, 54)?);
    let count = usize::from(read_u16(ELF, 56)?);
    if entry_size != 56 || count == 0 {
        return Err("runtime blob has an invalid program-header table".to_string());
    }
    validate_sections()?;

    let mut text = None;
    let mut rodata = None;
    for index in 0..count {
        let offset = program_offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| "runtime program-header table overflows usize".to_string())?,
            )
            .ok_or_else(|| "runtime program-header table overflows usize".to_string())?;
        if read_u32(ELF, offset)? != 1 {
            continue;
        }
        let flags = read_u32(ELF, offset + 4)?;
        let address = read_u64(ELF, offset + 16)?;
        let slot =
            match flags {
                // R | X, the code segment, pinned to the address the compiler
                // generates calls to.
                5 if address == BASE_ADDRESS => &mut text,
                // R, the constant tables. Kept out of the executable segment on
                // purpose; see this module's header.
                4 => &mut rodata,
                _ => return Err(
                    "runtime PT_LOAD must be RX at the fixed runtime base or read-only above it"
                        .to_string(),
                ),
            };
        if slot.is_some() {
            return Err("runtime blob has a repeated PT_LOAD segment".to_string());
        }
        let file_offset_raw = read_u64(ELF, offset + 8)?;
        let file_offset = usize::try_from(file_offset_raw)
            .map_err(|_| "runtime load offset does not fit usize".to_string())?;
        let file_size = usize::try_from(read_u64(ELF, offset + 32)?)
            .map_err(|_| "runtime load size does not fit usize".to_string())?;
        if read_u64(ELF, offset + 32)? != read_u64(ELF, offset + 40)? {
            return Err("runtime blob must not have BSS".to_string());
        }
        let alignment = read_u64(ELF, offset + 48)?;
        if alignment != 0x1000
            || file_offset_raw % alignment != address % alignment
            || address % alignment != 0
        {
            return Err(
                "runtime PT_LOAD must be page-aligned with its virtual address".to_string(),
            );
        }
        let end = file_offset
            .checked_add(file_size)
            .ok_or_else(|| "runtime load range overflows usize".to_string())?;
        let segment = ELF
            .get(file_offset..end)
            .ok_or_else(|| "runtime PT_LOAD lies outside the blob".to_string())?;
        *slot = Some((address, segment));
    }
    let Some((_, bytes)) = text else {
        return Err("runtime blob has no executable PT_LOAD segment".to_string());
    };
    let Some((rodata_address, rodata)) = rodata else {
        return Err("runtime blob has no read-only PT_LOAD segment".to_string());
    };
    if rodata_address
        < BASE_ADDRESS
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| "runtime text address overflow".to_string())?
    {
        return Err("runtime read-only segment overlaps the executable one".to_string());
    }
    let table_size = ROUTINE_COUNT
        .checked_mul(usize::try_from(ENTRY_SIZE).expect("tiny entry size"))
        .expect("tiny entry table");
    let code_start = table_size
        .checked_add(VERSION_SIZE)
        .expect("tiny runtime image header");
    if bytes.len() < code_start {
        return Err("runtime blob is shorter than its jump table and version word".to_string());
    }
    if read_u32(bytes, table_size)? != vcl_rt::IMAGE_VERSION {
        return Err("runtime blob version does not match the compiler".to_string());
    }
    for entry in 0..ROUTINE_COUNT {
        validate_jump_entry(bytes, entry, code_start)?;
    }
    Ok(RuntimeImage {
        text: bytes,
        rodata,
        rodata_address,
    })
}

/// The copied bytes must be a self-contained text image: no mutable sections,
/// BSS, or dynamic/static relocations can accompany it into the policy ELF.
fn validate_sections() -> Result<(), String> {
    let offset = usize::try_from(read_u64(ELF, 40)?)
        .map_err(|_| "runtime section-header offset does not fit usize".to_string())?;
    let entry_size = usize::from(read_u16(ELF, 58)?);
    let count = usize::from(read_u16(ELF, 60)?);
    if entry_size != 64 || count == 0 {
        return Err("runtime blob has an invalid section-header table".to_string());
    }
    for index in 0..count {
        let header = offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| "runtime section-header table overflows usize".to_string())?,
            )
            .ok_or_else(|| "runtime section-header table overflows usize".to_string())?;
        let kind = read_u32(ELF, header + 4)?;
        let flags = read_u64(ELF, header + 8)?;
        if kind == 4 || kind == 8 || kind == 9 || flags & 0x1 != 0 {
            return Err("runtime blob contains mutable, BSS, or relocation sections".to_string());
        }
    }
    Ok(())
}

/// Verify the exact instruction pair emitted by the guest linker script and
/// prove that it reaches code in this copied load image.  The compiler calls
/// only these entries, so this catches a stale blob or a linker relaxation
/// before it becomes an opaque guest fault.
fn validate_jump_entry(bytes: &[u8], entry: usize, code_start: usize) -> Result<(), String> {
    let offset = entry
        .checked_mul(usize::try_from(ENTRY_SIZE).expect("tiny entry size"))
        .ok_or_else(|| "runtime jump-table offset overflows usize".to_string())?;
    let auipc = read_u32(bytes, offset)?;
    let jalr = read_u32(bytes, offset + 4)?;
    const T0: u32 = 5;
    if auipc & 0x7f != 0x17 || (auipc >> 7) & 0x1f != T0 {
        return Err(format!("runtime jump-table entry {entry} is not auipc t0"));
    }
    if jalr & 0x7f != 0x67
        || (jalr >> 7) & 0x1f != 0
        || (jalr >> 12) & 0x7 != 0
        || (jalr >> 15) & 0x1f != T0
    {
        return Err(format!("runtime jump-table entry {entry} is not jr t0"));
    }

    let high = sign_extend(auipc & 0xffff_f000, 32);
    let low = sign_extend((jalr >> 20) & 0xfff, 12);
    let target = i64::try_from(offset)
        .map_err(|_| "runtime jump-table offset does not fit i64".to_string())?
        .checked_add(high)
        .and_then(|value| value.checked_add(low))
        .ok_or_else(|| "runtime jump-table target overflows i64".to_string())?;
    let target = usize::try_from(target)
        .map_err(|_| format!("runtime jump-table entry {entry} jumps before the image"))?;
    if target < code_start || target >= bytes.len() || target % 2 != 0 {
        return Err(format!(
            "runtime jump-table entry {entry} does not target runtime code"
        ));
    }
    Ok(())
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((i64::from(value)) << shift) >> shift
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "runtime ELF is truncated".to_string())?;
    Ok(u16::from_le_bytes(
        bytes.try_into().expect("fixed-length slice"),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "runtime ELF is truncated".to_string())?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("fixed-length slice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let bytes = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "runtime ELF is truncated".to_string())?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("fixed-length slice"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_runtime_is_a_fixed_rx_load_without_bss() {
        let image = image().expect("checked-in runtime must be usable");
        assert!(image.text.len() >= ROUTINE_COUNT * ENTRY_SIZE as usize + VERSION_SIZE);
    }

    #[test]
    fn runtime_entries_are_fixed_width_and_reach_code() {
        let image = image().expect("checked-in runtime must be usable");
        let code_start = ROUTINE_COUNT * ENTRY_SIZE as usize + VERSION_SIZE;
        for entry in 0..ROUTINE_COUNT {
            validate_jump_entry(image.text, entry, code_start)
                .expect("checked-in entry must dispatch");
        }
    }

    /// The constant tables must stay out of the segment libriscv decodes.
    /// Everything the emulator translates has to be an instruction the guest
    /// can actually reach; see this module's header for what it costs when
    /// the tables share the RX segment.
    #[test]
    fn constant_tables_live_outside_the_executable_segment() {
        let image = image().expect("checked-in runtime must be usable");
        assert!(!image.rodata.is_empty(), "the runtime has constant tables");
        assert!(image.rodata_address >= BASE_ADDRESS + image.text.len() as u64);
        assert!(image
            .rodata
            .windows(3)
            .any(|window| window == b"Sun" || window == b"Jan"));
        assert!(
            !image.text.windows(3).any(|window| window == b"Sun"),
            "weekday table leaked back into the executable segment"
        );
    }
}
