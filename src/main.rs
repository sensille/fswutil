use std::fs::File;
use anyhow::{Result, bail};
use elf::ElfStream;
use elf::endian::AnyEndian;
use std::collections::BTreeMap;

#[derive(Clone)]
enum RegisterRule {
    Uninitialized,
    Undefined,
    SameValue,
    Offset(i64),    // offset from CFA
    ValOffset(i64),
    Register(u64),
    Expression(Vec<u8>),
    ValExpression(Vec<u8>),
}
impl std::fmt::Debug for RegisterRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterRule::Uninitialized => write!(f, "-"),
            RegisterRule::Undefined => write!(f, "u"),
            RegisterRule::SameValue => write!(f, "="),
            RegisterRule::Offset(off) => write!(f, "o{}", off),
            RegisterRule::ValOffset(off) => write!(f, "vo{}", off),
            RegisterRule::Register(reg) => write!(f, "r{}", reg),
            RegisterRule::Expression(_) => write!(f, "expr"),
            RegisterRule::ValExpression(_) => write!(f, "vexpr"),
        }
    }
}

#[derive(Clone)]
enum CFARule {
    Uninitialized,
    RegOffset(usize, i64), // (register, offset)
    Expression(Vec<u8>),
}

impl std::fmt::Debug for CFARule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CFARule::Uninitialized => write!(f, "-"),
            CFARule::RegOffset(reg, off) => write!(f, "r{}+{}", reg, off),
            CFARule::Expression(_) => write!(f, "expr"),
        }
    }
}

#[derive(Clone)]
struct CFT {
    loc: u64,
    cfa: CFARule,
    rules: Vec<RegisterRule>,
    arg_size: u64,
}

impl std::fmt::Debug for CFT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "loc {:#x}, cfa {:?} rules {:?} arg_size {}",
            self.loc, self.cfa, self.rules, self.arg_size)
    }
}

#[derive(Debug)]
struct Cie {
    version: u8,
    caf: u64,   // code alignment factor
    daf: i64,   // data alignment factor
    rar: u64,   // return address register
    aug_z: bool,
    lsda_encoding: Option<u8>,
    fde_encoding: u8,
    personality: Option<(u8, u64)>,
    initial_cfa: Vec<u8>,
}

#[derive(Debug)]
struct Fde {
    initial_location: u64,
    address_range: u64,
    instructions: Vec<u8>,
}

fn read_uint(data: &[u8], dwarf64: bool, offset: &mut usize) -> Result<u64> {
    if dwarf64 {
        read_u64(data, offset)
    } else {
        read_u32(data, offset).map(|v| v as u64)
    }
}

// TODO: generics
fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8> {
    if data.len() < *offset + 1 {
        bail!("not enough data to read u8");
    }
    let val = data[*offset];
    *offset += 1;
    Ok(val)
}

fn read_u16(data: &[u8], offset: &mut usize) -> Result<u16> {
    if data.len() < *offset + 2 {
        bail!("not enough data to read u16");
    }
    let val = u16::from_le_bytes(data[*offset..*offset + 2].try_into()?);
    *offset += 2;
    Ok(val)
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32> {
    if data.len() < *offset + 4 {
        bail!("not enough data to read u32");
    }
    let val = u32::from_le_bytes(data[*offset..*offset + 4].try_into()?);
    *offset += 4;
    Ok(val)
}

fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64> {
    if data.len() < *offset + 8 {
        bail!("not enough data to read u64");
    }
    let val = u64::from_le_bytes(data[*offset..*offset + 4].try_into()?);
    *offset += 8;
    Ok(val)
}

fn read_string(data: &[u8], offset: &mut usize) -> Result<String> {
    let start = *offset;
    while *offset < data.len() && data[*offset] != 0 {
        *offset += 1;
    }
    if *offset >= data.len() {
        bail!("string not null-terminated");
    }
    let s = String::from_utf8(data[start..*offset].to_vec())?;
    *offset += 1; // skip null terminator
    Ok(s)
}

fn read_leb128_impl(data: &[u8], offset: &mut usize, sign_extend: bool) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut byte;
    loop {
        if *offset >= data.len() {
            bail!("not enough data to read LEB128");
        }
        byte = data[*offset];
        *offset += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
    }
    // sign extend if necessary
    if sign_extend {
        println!("sign extending LEB128 value: shift {} byte {:x} result {:x}", shift, byte, result);
        if shift < 64 && (byte & 0x40) != 0 {
            result |= (!0u64) << shift;
        }
    }
    Ok(result)
}

fn read_leb128_s(data: &[u8], offset: &mut usize) -> Result<i64> {
    let val = read_leb128_impl(data, offset, true)?;
    Ok(val as i64)
}

fn read_leb128_u(data: &[u8], offset: &mut usize) -> Result<u64> {
    read_leb128_impl(data, offset, false)
}

fn read_encoded_ptr(data: &[u8], encoding: u8, dwarf64: bool, offset: &mut usize)
    -> Result<u64>
{
    if encoding == 0x00 {
        // DW_EH_PE_absptr
        read_uint(data, dwarf64, offset)
    } else {
        match encoding & 0x07 {
            0x01 => read_leb128_u(data, offset), // DW_EH_PE_uleb128
            0x02 => read_u16(data, offset).map(|v| v as u64), // DW_EH_PE_udata2
            0x03 => read_u32(data, offset).map(|v| v as u64), // DW_EH_PE_udata4
            0x04 => read_u64(data, offset), // DW_EH_PE_udata8
            _ => bail!("unsupported pointer encoding: {:#x}", encoding),
        }
    }
}

// see https://www.airs.com/blog/archives/460
fn parse_eh_cie(data: &[u8], dwarf64: bool) -> Result<Cie> {
    let mut offset = 0;
    let version = read_u8(data, &mut offset)?;
    if version != 1 && version != 3 {
        bail!("unsupported eh CIE version: {}", version);
    }
    let augmentation = read_string(data, &mut offset)?;
    let caf = read_leb128_u(data, &mut offset)?;
    let daf = read_leb128_s(data, &mut offset)?;
    let rar = if version == 1 {
        read_u8(data, &mut offset)? as u64
    } else {
        read_leb128_u(data, &mut offset)?
    };
    let mut aug_z = false;
    let mut lsda_encoding = None;
    let mut fde_encoding = 0x00; // absptr
    let mut personality = None;
    if augmentation.starts_with("z") {
        // skip augmentation data for now
        let aug_data_len = read_leb128_u(data, &mut offset)? as usize;
        println!("CIE augmentation data length: {}", aug_data_len);
        aug_z = true;
        let aug_end = offset + aug_data_len;
        for c in augmentation.chars().skip(1) {
            match c {
                'L' => {
                    lsda_encoding = Some(read_u8(data, &mut offset)?);
                }
                'R' => {
                    // fde address encoding
                    fde_encoding = read_u8(data, &mut offset)?;
                }
                'S' => {
                    // signal frame indicator
                    bail!("signal frame indicator not supported yet");
                }
                'P' => {
                    let p_enc = read_u8(data, &mut offset)?;
                    let p_ptr = read_encoded_ptr(data, p_enc, dwarf64, &mut offset)?;
                    personality = Some((p_enc, p_ptr));
                }
                _ => {
                    bail!("unsupported CIE augmentation character: {}", c);
                }
            }
        }
        if offset != aug_end {
            bail!("did not consume all augmentation data");
        }
    }

    Ok(Cie {
        version,
        caf,
        daf,
        rar,
        aug_z,
        lsda_encoding,
        fde_encoding,
        personality,
        initial_cfa: data[offset..].into(),
    })
}

fn submit_row(cft: &CFT) {
    println!("CFT Row: loc = {:#x} cfa = {:?} rules = {:?}",
        cft.loc, cft.cfa, cft.rules);
}

fn execute_instructions(instructions: &[u8], cie: &Cie, cft: &mut CFT) -> Result<()> {
    println!("Executing instructions: {:x?}", instructions);
    let mut offset = 0;
    let mut cft_stack: Vec<CFT> = Vec::new();
    while offset < instructions.len() {
        let instr = read_u8(instructions, &mut offset)?;
        println!("Instruction: {:#x}", instr);
        match instr {
            0x00 => {
                // DW_CFA_nop
                println!("DW_CFA_nop");
            }
            0x01 => {
                // DW_CFA_set_loc
                submit_row(&cft);
                cft.loc = read_uint(instructions, false, &mut offset)?;
                println!("DW_CFA_set_loc to {:#x}", cft.loc);
            }
            0x02 => {
                // DW_CFA_advance_loc1
                submit_row(&cft);
                let delta = read_u8(instructions, &mut offset)? as u64;
                println!("DW_CFA_advance_loc1 by {}", delta);
                cft.loc += delta * cie.caf;
            }
            0x03 => {
                // DW_CFA_advance_loc2
                submit_row(&cft);
                let delta = read_u16(instructions, &mut offset)? as u64;
                println!("DW_CFA_advance_loc2 by {}", delta);
                cft.loc += delta * cie.caf;
            }
            0x04 => {
                // DW_CFA_advance_loc4
                submit_row(&cft);
                let delta = read_u32(instructions, &mut offset)? as u64;
                println!("DW_CFA_advance_loc4 by {}", delta);
                cft.loc += delta * cie.caf;
            }
            0x07 => {
                // DW_CFA_undefined
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_offset: register {} out of bounds", reg);
                }
                cft.rules[reg] = RegisterRule::Undefined;
                println!("DW_CFA_def_undefined: reg {}", reg);
            }
            0x0a => {
                // DW_CFA_remember_state
                cft_stack.push(cft.clone());
                println!("DW_CFA_remember_state");
            }
            0x0b => {
                // DW_CFA_restore_state
                if cft_stack.is_empty() {
                    bail!("DW_CFA_restore_state: no state to restore");
                }
                let prev_cft = cft_stack.pop().unwrap();
                *cft = prev_cft;
                println!("DW_CFA_restore_state");
            }
            0x0c => {
                // DW_CFA_def_cfa
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                let offset_val = read_leb128_u(instructions, &mut offset)?;
                if reg > cft.rules.len() {
                    bail!("DW_CFA_def_cfa: register {} out of bounds", reg);
                }
                cft.cfa = CFARule::RegOffset(reg, offset_val as i64);
                println!("DW_CFA_def_cfa: reg {}, offset {}", reg, offset_val);
            }
            0x0d => {
                // DW_CFA_def_cfa_register
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                if reg > cft.rules.len() {
                    bail!("DW_CFA_def_cfa: register {} out of bounds", reg);
                }
                if let CFARule::RegOffset(_, offset_val) = cft.cfa {
                    cft.cfa = CFARule::RegOffset(reg, offset_val);
                } else {
                    bail!("DW_CFA_def_cfa_register: CFA not set to RegOffset");
                }
                println!("DW_CFA_def_cfa_register: reg {}", reg);
            }
            0x0e => {
                // DW_CFA_def_cfa_offset
                let offset_val = read_leb128_u(instructions, &mut offset)?;
                if let CFARule::RegOffset(reg, _) = cft.cfa {
                    cft.cfa = CFARule::RegOffset(reg, offset_val as i64);
                } else {
                    bail!("DW_CFA_def_cfa_offset: CFA register not set");
                }
                println!("DW_CFA_def_cfa_offset: offset {}", offset_val);
            }
            0x0f => {
                // DW_CFA_def_cfa_expression
                let len = read_leb128_u(instructions, &mut offset)? as usize;
                if instructions.len() < offset + len {
                    bail!("DW_CFA_def_cfa_expression: not enough data for expression, need {}, have {}",
                        len, instructions.len() - offset);
                }
                cft.cfa = CFARule::Expression(instructions[offset..offset + len]
                    .into());
                offset += len;
                println!("DW_CFA_def_cfa_register: expr");
            }
            0x2e => {
                // DW_CFA_GNU_args_size
                let size = read_leb128_u(instructions, &mut offset)?;
                cft.arg_size = size;
                println!("DW_CFA_GNU_args_size: size {}", size);
            }
            0x40..=0x7f => {
                // DW_CFA_advance_loc
                submit_row(&cft);
                let delta = (instr & 0x3f) as u64;
                println!("DW_CFA_advance_loc by {}", delta);
                cft.loc += delta;
            }
            0x80..=0xbf => {
                // DW_CFA_offset
                let reg = (instr & 0x3f) as usize;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_offset: register {} out of bounds", reg);
                }
                let offset_val = read_leb128_u(instructions, &mut offset)? as i64;
                println!("DW_CFA_offset: reg {}, offset {}", reg, offset_val * cie.daf);
                cft.rules[reg] = RegisterRule::Offset(offset_val * cie.daf);
            }
            0xc0..=0xff => {
                // DW_CFA_restore
                let reg = (instr & 0x3f) as usize;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_restore: register {} out of bounds", reg);
                }
                println!("DW_CFA_restore: reg {}", reg);
            }
            _ => {
                bail!("unsupported DWARF instruction: {:#x}", instr);
            }
        }
    }

    Ok(())
}

fn execute_fde(fde: &Fde, cie: &Cie) -> Result<()> {
    println!(
        "Executing FDE: initial_location = {:#x}, address_range = {:#x}",
        fde.initial_location, fde.address_range
    );
    // For simplicity, we just print the instructions here.
    let mut cft = CFT {
        loc: fde.initial_location,
        cfa: CFARule::Uninitialized,
        rules: vec![RegisterRule::Uninitialized; 17],
        arg_size: 0,
    };
    println!("FDE Instructions: {:x?}", fde.instructions);
    execute_instructions(&cie.initial_cfa, &cie, &mut cft)?;
    execute_instructions(&fde.instructions, &cie, &mut cft)?;
    println!("End at {:x}", fde.initial_location + fde.address_range - 1);

    Ok(())
}

fn parse_debug_cie(data: &[u8], dwarf64: bool, offset: &mut usize) -> Result<()> {
    unimplemented!("debug_frame CIE parsing not implemented yet");
}

fn parse_fde(data: &[u8], dwarf64: bool, cie: &Cie) -> Result<Fde> {
    let mut offset = 0;
    let initial_location = read_encoded_ptr(data, cie.fde_encoding, dwarf64, &mut offset)?;
    let address_range = read_encoded_ptr(data, cie.fde_encoding, dwarf64, &mut offset)?;
    if cie.aug_z {
        let aug_data_len = read_leb128_u(data, &mut offset)? as usize;
        offset += aug_data_len;
    }

    Ok(Fde {
        initial_location,
        address_range,
        instructions: data[offset..].into(),
    })
}

fn main() -> Result<()> {
    let path = std::path::PathBuf::from("./ceph-osd");
    let file = File::open(path).expect("Could not open file.");
    let mut elf = ElfStream::<AnyEndian, _>::open_stream(&file)
        .expect("Could not parse ELF file.");
    let eh_hdr = *elf
        .section_header_by_name(".eh_frame")
        .expect("section table should be parseable")
        .expect("no .eh_frame section in file");

    println!(".eh_frame section header: {:#?}", &eh_hdr);

    // XXX TODO: read as stream
    let (eh, comp) = elf
        .section_data(&eh_hdr)
        .expect("could not get .eh_frame section data");

    if comp.is_some() {
        bail!(".eh_frame is compressed, cannot decompress");
    }

    println!("compression: {:?}", comp);
    println!("eh: {:x?}", &eh[..64]);

    if eh.len() < 4 {
        bail!(".eh_frame section too small");
    }
    let mut offset = 0;
    let mut dwarf64 = false;
    if eh[0..4] == [0xff, 0xff, 0xff, 0xff] {
        println!(".eh_frame section uses 64-bit DWARF format");
        dwarf64 = true;
        offset = 4;
    }
    let mut cies = BTreeMap::new();
    while offset < eh.len() {
        let frame_len = read_uint(&eh, dwarf64, &mut offset)
            .expect("could not read frame length");
        println!("frame: {:x?}", &eh[offset..offset + frame_len as usize]);
        if frame_len == 0 {
            println!("reached end of .eh_frame");
            break;
        }
        // CIE or FDE?
        let frame_end = offset + frame_len as usize;
        let id_offset = offset;
        let id = read_uint(&eh, dwarf64, &mut offset)
            .expect("could not read frame id");
        println!("frame length: {} id {}", frame_len, id);
        // on debug_frame, this is different
        if id == 0 {
            // CIE
            let cie = parse_eh_cie(&eh[offset..frame_end], dwarf64)
                .expect("could not parse CIE");
            println!("parsed eh CIE: {:?}, id_offset {}", cie, id_offset);
            cies.insert(id_offset as u64, cie);
        } else if id == 0xffffffff {
            // debug_frame CIE
            parse_debug_cie(&eh, dwarf64, &mut offset)
                .expect("could not parse debug_frame CIE");
        } else {
            // FDE
            println!("parsing eh FDE with CIE id {}, offset {}", id, offset);
            let cie_addr = offset as u64 - id;
            let cie = cies.get(&cie_addr).expect("could not find CIE for FDE");
            let fde = parse_fde(&eh[offset..frame_end], dwarf64, &cie)
                .expect("could not parse FDE");
            println!("parsed eh FDE: {:?}", fde);
            execute_fde(&fde, &cie)?;
        }
        if offset > frame_end {
            bail!("consume more than the frame");
        }
        offset = frame_end;
    }

    Ok(())
}
