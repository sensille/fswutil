use std::fs::File;
use anyhow::{Result, bail, Context};
use elf::ElfStream;
use elf::endian::AnyEndian;
use std::collections::{ BTreeMap, BTreeSet, HashMap };
use log::{debug, info, warn};
use std::io::BufRead;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use std::default::Default;

mod fsw {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/fsw.skel.rs"
    ));
}
use fsw::*;
mod syscall;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[allow(dead_code)]
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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[allow(dead_code)]
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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
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
#[allow(dead_code)]
struct Cie {
    version: u8,
    caf: u64,   // code alignment factor
    daf: i64,   // data alignment factor
    rar: u64,   // return address register
    aug_z: bool,
    lsda_encoding: Option<u8>,
    fde_encoding: u8,
    personality: Option<(u8, u64)>,
    signal_frame: bool,
    initial_cfa: Vec<u8>,
}

#[derive(Debug)]
struct Fde {
    initial_location: u64,
    address_range: u64,
    instructions: Vec<u8>,
}

#[derive(Debug)]
struct ProcessState {
    maps_by_id: HashMap<u64, Vec<ProcessMaps>>, // (obj_id, offset) -> mapping
    maps: BTreeSet<ProcessMaps>,
    entries: BTreeMap<(u64, u64), Option<u64>>,
    cft_forw: BTreeMap<u64, CFT>,
    cft_rev: BTreeMap<CFT, u64>,
    next_id: u64,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ProcessMaps {
    vm_start: u64,
    vm_end: u64,
    offset: u64,
    pathname: String,
    perms: String,
    obj_id: u64,
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
        debug!("sign extending LEB128 value: shift {} byte {:x} result {:x}",
            shift, byte, result);
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

fn read_encoded_ptr(data: &[u8], encoding: u8, pc: u64, dwarf64: bool, offset: &mut usize)
    -> Result<u64>
{
    if encoding == 0x00 {
        // DW_EH_PE_absptr
        return read_uint(data, dwarf64, offset);
    }
    let off = match encoding & 0x0f {
        0x01 => read_leb128_u(data, offset)?, // DW_EH_PE_uleb128
        0x02 => read_u16(data, offset)? as u64, // DW_EH_PE_udata2
        0x03 => read_u32(data, offset)? as u64, // DW_EH_PE_udata4
        0x04 => read_u64(data, offset)?, // DW_EH_PE_udata8
        0x09 => read_leb128_s(data, offset)? as u64, // DW_EH_PE_uleb128
        0x0a => read_u16(data, offset)? as i16 as i64 as u64, // DW_EH_PE_udata2
        0x0b => read_u32(data, offset)? as i32 as i64 as u64, // DW_EH_PE_udata4
        0x0c => read_u64(data, offset)?, // DW_EH_PE_udata8
        _ => bail!("unsupported pointer encoding: {:#x}", encoding),
    };
    if encoding & 0x70 == 0x10 {
        // PC-relative
        Ok((pc as i64 + off as i64) as u64)
    } else {
        Ok(off)
    }
}

// see https://www.airs.com/blog/archives/460
fn parse_eh_cie(data: &[u8], pc: u64, dwarf64: bool) -> Result<Cie> {
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
    let mut signal_frame = false;
    if augmentation.starts_with("z") {
        // skip augmentation data for now
        let aug_data_len = read_leb128_u(data, &mut offset)? as usize;
        debug!("CIE augmentation data length: {}", aug_data_len);
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
                    debug!("signal frame indicator found");
                    signal_frame = true;
                }
                'P' => {
                    let p_enc = read_u8(data, &mut offset)?;
                    let p_ptr = read_encoded_ptr(data, p_enc, pc, dwarf64, &mut offset)?;
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
        signal_frame,
        initial_cfa: data[offset..].into(),
    })
}

fn submit_row(state: &mut ProcessState, obj_id: u64, cft: &CFT) {
    info!("CFT Row: loc = {:#x} cfa = {:?} rules = {:?}",
        cft.loc, cft.cfa, cft.rules);
    let mut canon_cft = cft.clone();
    canon_cft.loc = 0; // ignore loc for canonicalization
    let cft_id = state.cft_rev.get(&canon_cft);
    let id = if let Some(id) = cft_id {
        *id
    } else {
        let id = state.next_id;
        state.cft_forw.insert(id, canon_cft.clone());
        state.cft_rev.insert(canon_cft, id);
        state.next_id += 1;
        id
    };
    let old = state.entries.insert((obj_id, cft.loc), Some(id));
    if let Some(Some(_)) = old {
        panic!("Warning: overwriting existing CFT entry at loc {:#x}", cft.loc);
    }
}

fn submit_end(state: &mut ProcessState, obj_id: u64, loc: u64) {
    info!("CFT End Row: loc = {:#x}", loc);
    let key = (obj_id, loc);
    let e = state.entries.get(&key);
    // don't overwrite existing (non-end) entries
    if let Some(Some(_)) = e {
        debug!("overwriting existing CFT entry at loc {:#x}", loc);
        return;
    }
    state.entries.insert(key, None);
}

fn execute_instructions(state: &mut ProcessState, obj_id: u64, dwarf64: bool, instructions: &[u8],
    cie: &Cie, cft: &mut CFT) -> Result<()>
{
    debug!("Executing instructions: {:x?}", instructions);
    let mut offset = 0;
    let mut cft_stack: Vec<CFT> = Vec::new();
    let initial = cft.clone();
    while offset < instructions.len() {
        let instr = read_u8(instructions, &mut offset)?;
        debug!("Instruction: {:#x}", instr);
        match instr {
            0x00 => {
                // DW_CFA_nop
                debug!("DW_CFA_nop");
            }
            0x01 => {
                // DW_CFA_set_loc
                submit_row(state, obj_id, &cft);
                //cft.loc = read_uint(instructions, false, &mut offset)?;
                cft.loc = read_encoded_ptr(instructions, cie.fde_encoding,
                    0, dwarf64, &mut offset)?;
                debug!("DW_CFA_set_loc to {:#x}", cft.loc);
            }
            0x02 => {
                // DW_CFA_advance_loc1
                submit_row(state, obj_id, &cft);
                let delta = read_u8(instructions, &mut offset)? as u64;
                debug!("DW_CFA_advance_loc1 by {}", delta);
                cft.loc += delta * cie.caf;
            }
            0x03 => {
                // DW_CFA_advance_loc2
                submit_row(state, obj_id, &cft);
                let delta = read_u16(instructions, &mut offset)? as u64;
                debug!("DW_CFA_advance_loc2 by {}", delta);
                cft.loc += delta * cie.caf;
            }
            0x04 => {
                // DW_CFA_advance_loc4
                submit_row(state, obj_id, &cft);
                let delta = read_u32(instructions, &mut offset)? as u64;
                debug!("DW_CFA_advance_loc4 by {}", delta);
                cft.loc += delta * cie.caf;
            }
            0x07 => {
                // DW_CFA_undefined
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_undefined: register {} out of bounds", reg);
                }
                cft.rules[reg] = RegisterRule::Undefined;
                debug!("DW_CFA_def_undefined: reg {}", reg);
            }
            0x09 => {
                // DW_CFA_register
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                let offset = read_leb128_u(instructions, &mut offset)? as u64;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_register: register {} out of bounds", reg);
                }
                cft.rules[reg] = RegisterRule::Register(offset);
                debug!("DW_CFA_register: reg {}, reg {}", reg, offset);
            }
            0x0a => {
                // DW_CFA_remember_state
                cft_stack.push(cft.clone());
                debug!("DW_CFA_remember_state");
            }
            0x0b => {
                // DW_CFA_restore_state
                if cft_stack.is_empty() {
                    bail!("DW_CFA_restore_state: no state to restore");
                }
                let mut prev_cft = cft_stack.pop().unwrap();
                prev_cft.loc = cft.loc; // keep current loc
                //prev_cft.cfa = cft.cfa.clone(); // keep current cfa
                *cft = prev_cft;
                debug!("DW_CFA_restore_state");
            }
            0x0c => {
                // DW_CFA_def_cfa
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                let offset_val = read_leb128_u(instructions, &mut offset)?;
                if reg > cft.rules.len() {
                    bail!("DW_CFA_def_cfa: register {} out of bounds", reg);
                }
                cft.cfa = CFARule::RegOffset(reg, offset_val as i64);
                debug!("DW_CFA_def_cfa: reg {}, offset {}", reg, offset_val);
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
                debug!("DW_CFA_def_cfa_register: reg {}", reg);
            }
            0x0e => {
                // DW_CFA_def_cfa_offset
                let offset_val = read_leb128_u(instructions, &mut offset)?;
                if let CFARule::RegOffset(reg, _) = cft.cfa {
                    cft.cfa = CFARule::RegOffset(reg, offset_val as i64);
                } else {
                    bail!("DW_CFA_def_cfa_offset: CFA register not set");
                }
                debug!("DW_CFA_def_cfa_offset: offset {}", offset_val);
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
                debug!("DW_CFA_def_cfa_register: expr");
            }
            0x10 => {
                // DW_CFA_expression
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                let len = read_leb128_u(instructions, &mut offset)? as usize;
                if instructions.len() < offset + len {
                    bail!("DW_CFA_expression: not enough data for expression, need {}, have {}",
                        len, instructions.len() - offset);
                }
                cft.rules[reg] = RegisterRule::Expression(instructions[offset..offset + len]
                    .into());
                offset += len;
                debug!("DW_CFA_expression: reg {}, expr", reg);
            }
            0x11 => {
                // DW_CFA_offset_extended_sf
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_offset_extended: register {} out of bounds", reg);
                }
                let offset = read_leb128_s(instructions, &mut offset)? as i64;
                debug!("DW_CFA_offset_extended_sf: reg {}, offset {}", reg, offset * cie.daf);
                cft.rules[reg] = RegisterRule::Offset(offset * cie.daf);
            }
            0x2e => {
                // DW_CFA_GNU_args_size
                let size = read_leb128_u(instructions, &mut offset)?;
                cft.arg_size = size;
                debug!("DW_CFA_GNU_args_size: size {}", size);
            }
            0x40..=0x7f => {
                // DW_CFA_advance_loc
                submit_row(state, obj_id, &cft);
                let delta = (instr & 0x3f) as u64;
                debug!("DW_CFA_advance_loc by {}", delta);
                cft.loc += delta;
            }
            0x80..=0xbf => {
                // DW_CFA_offset
                let reg = (instr & 0x3f) as usize;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_offset: register {} out of bounds", reg);
                }
                let offset_val = read_leb128_u(instructions, &mut offset)? as i64;
                debug!("DW_CFA_offset: reg {}, offset {}", reg, offset_val * cie.daf);
                cft.rules[reg] = RegisterRule::Offset(offset_val * cie.daf);
            }
            0xc0..=0xff => {
                // DW_CFA_restore
                let reg = (instr & 0x3f) as usize;
                if reg >= cft.rules.len() {
                    bail!("DW_CFA_restore: register {} out of bounds", reg);
                }
                // XXX differs between eh_frame and debug_frame
                cft.rules[reg] = initial.rules[reg].clone();
                debug!("DW_CFA_restore: reg {}", reg);
            }
            _ => {
                bail!("unsupported DWARF instruction: {:#x}", instr);
            }
        }
    }

    Ok(())
}

fn execute_fde(state: &mut ProcessState, obj_id: u64, dwarf64: bool,
    fde: &Fde, cie: &Cie) -> Result<()>
{
    info!(
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
    debug!("FDE Instructions: {:x?}", fde.instructions);
    execute_instructions(state, obj_id, dwarf64, &cie.initial_cfa, &cie, &mut cft)?;
    execute_instructions(state, obj_id, dwarf64, &fde.instructions, &cie, &mut cft)?;
    if cft.loc >= fde.initial_location + fde.address_range {
        bail!("FDE instructions advanced location beyond address range");
    }
    submit_row(state, obj_id, &cft);
    submit_end(state, obj_id, fde.initial_location + fde.address_range);
    info!("End at {:x} of range {:x} - {:x}", cft.loc,
        fde.initial_location, fde.initial_location + fde.address_range - 1);

    Ok(())
}

fn parse_debug_cie(_data: &[u8], _dwarf64: bool, _offset: &mut usize) -> Result<()> {
    unimplemented!("debug_frame CIE parsing not implemented yet");
}

fn parse_fde(data: &[u8], pc: u64, dwarf64: bool, cie: &Cie) -> Result<Fde> {
    let mut offset = 0;
    let initial_location = read_encoded_ptr(data, cie.fde_encoding, pc, dwarf64, &mut offset)?;
    let address_range = read_encoded_ptr(data, cie.fde_encoding, 0, dwarf64, &mut offset)?;
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

fn read_process_maps(pid: u32) -> Result<Vec<ProcessMaps>> {
    let mut maps = Vec::new();
    let file = File::open(format!("/proc/{}/maps", pid))?;
    for line in std::io::BufReader::new(&file).lines() {
        let line = line?;
        //println!("maps line: {}", line?);
        let toks = line.split_whitespace().collect::<Vec<&str>>();
        let mut parts = toks[0].split('-');
        let vm_start = u64::from_str_radix(parts.next().unwrap(), 16)?;
        let vm_end = u64::from_str_radix(parts.next().unwrap(), 16)?;
        let perms = toks[1].to_string();
        let offset = u64::from_str_radix(toks[2], 16)?;
        let _dev = toks[3];
        let inode = toks[4].parse::<u64>()?;
        let pathname = if toks.len() >= 5 {
            toks[5..].join(" ")
        } else {
            String::new()
        };

        info!("map: vm_start {:#x} vm_end {:#x} offset {:#x} pathname {}",
            vm_start, vm_end, offset, pathname);
        if inode == 0 {
            continue; // skip anonymous mappings
        }
        if pathname.is_empty() {
            bail!("pathname for vm_start {:x} is empty", vm_start);
        }
        maps.push(ProcessMaps {
            vm_start,
            vm_end,
            offset,
            pathname,
            perms,
            obj_id: 0,
        });
    }

    Ok(maps)
}

impl ProcessState {
    fn add_to_map_tree(&mut self, obj_id: u64, addr: u64, size: u64) -> Result<()> {
        let entry = self.maps_by_id.get(&obj_id).expect("obj_id should exist");
        let mut found = false;
        for map in entry.iter() {
            let len = map.vm_end - map.vm_start;
            if addr >= map.offset && addr + size < map.offset + len {
                debug!("Mapping addr {:#x} size {:#x} to obj_id {} offset {:#x}",
                    addr, size, obj_id, map.offset + (addr - map.vm_start));
                self.maps.insert(map.clone());
                found = true;
            }
        }
        if !found {
            bail!("no mapping found for obj_id {} addr {:#x} in {:x?}", obj_id, addr, entry);
        }
        Ok(())
    }
}

// XXX TODO
// - distinguish between expected and unexpected errors
// - collect all parsing errors
fn build_fsw(state: &mut ProcessState, obj_id: u64, pathname: &str) -> Result<()> {
    let path = std::path::PathBuf::from(&pathname);
    let file = File::open(path).context("Could not open file.")?;
    let mut elf = ElfStream::<AnyEndian, _>::open_stream(&file)
        .context("Could not parse ELF file.")?;
    let eh_hdr = *elf
        .section_header_by_name(".eh_frame")
        .context("section table should be parseable")?
        .context("no .eh_frame section in file")?;

    debug!(".eh_frame section header: {:#?}", &eh_hdr);

    // XXX TODO: read as stream
    let (eh, comp) = elf
        .section_data(&eh_hdr)
        .context("could not get .eh_frame section data")?;

    if comp.is_some() {
        bail!(".eh_frame is compressed, cannot decompress");
    }

    debug!("compression: {:?}", comp);
    debug!("eh: {:x?}", &eh[..64]);

    if eh.len() < 4 {
        bail!(".eh_frame section too small");
    }
    let mut offset = 0;
    let mut dwarf64 = false;
    if eh[0..4] == [0xff, 0xff, 0xff, 0xff] {
        debug!(".eh_frame section uses 64-bit DWARF format");
        dwarf64 = true;
        offset = 4;
    }
    let mut cies = BTreeMap::new();
    while offset < eh.len() {
        let frame_len = read_uint(&eh, dwarf64, &mut offset)
            .context("could not read frame length")?;
        debug!("frame: {:x?}", &eh[offset..offset + frame_len as usize]);
        if frame_len == 0 {
            debug!("reached end of .eh_frame");
            break;
        }
        // CIE or FDE?
        let frame_end = offset + frame_len as usize;
        let id_offset = offset;
        let id = read_uint(&eh, dwarf64, &mut offset)
            .context("could not read frame id")?;
        debug!("frame length: {} id {}", frame_len, id);
        // on debug_frame, this is different
        let pc = offset as u64 + eh_hdr.sh_addr;
        if id == 0 {
            // CIE
            let cie = parse_eh_cie(&eh[offset..frame_end], pc, dwarf64)
                .context("could not parse CIE")?;
            assert_eq!(cie.rar, 16); // x86_64 return address register
            debug!("parsed eh CIE: {:?}, id_offset {}", cie, id_offset);
            cies.insert(id_offset as u64, cie);
        } else if id == 0xffffffff {
            // debug_frame CIE
            parse_debug_cie(&eh, dwarf64, &mut offset)
                .context("could not parse debug_frame CIE")?;
        } else {
            // FDE
            debug!("parsing eh FDE with CIE id {}, offset {}", id, offset);
            let cie_addr = offset as u64 - id;
            let cie = cies.get(&cie_addr).context("could not find CIE for FDE")?;
            let fde = parse_fde(&eh[offset..frame_end], pc, dwarf64, &cie)
                .context("could not parse FDE")?;
            debug!("parsed eh FDE: {:?}", fde);
            state.add_to_map_tree(obj_id, fde.initial_location, fde.address_range)?;
            let res = execute_fde(state, obj_id, dwarf64, &fde, &cie);
            if let Err(e) = res {
                warn!("error executing FDE at offset {}: {:?}", offset, e);
            }
        }
        if offset > frame_end {
            bail!("consume more than the frame");
        }
        offset = frame_end;
    }

    /*
    // print CFT statistics
    println!("CFT Statistics:");
    println!("  Total unique CFTs: {}", fsw.cft_forw.len());
    println!("  Total CFT entries: {}", fsw.entries.len());
    */

    Ok(())
}

fn init_perf_monitor(freq: u64, sw_event: bool) -> Result<Vec<i32>> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();
    let pid = -1;
    let attr = syscall::perf_event_attr {
        _type: if sw_event {
            syscall::PERF_TYPE_SOFTWARE
        } else {
            syscall::PERF_TYPE_HARDWARE
        },
        size: std::mem::size_of::<syscall::perf_event_attr>() as u32,
        config: if sw_event {
            syscall::PERF_COUNT_SW_CPU_CLOCK
        } else {
            syscall::PERF_COUNT_HW_CPU_CYCLES
        },
        sample: syscall::sample_un { sample_freq: freq },
        flags: 1 << 10, // freq = 1
        ..Default::default()
    };
    (0..nprocs)
        .map(|cpu| {
            let fd = syscall::perf_event_open(&attr, pid, cpu as i32, -1, 0) as i32;
            if fd == -1 {
                let mut error_context = "Failed to open perf event.";
                let os_error = std::io::Error::last_os_error();
                if !sw_event && os_error.kind() == std::io::ErrorKind::NotFound {
                    error_context = "Failed to open perf event.\n\
                                    Try running the profile example with the `--sw-event` option.";
                }
                Err(libbpf_rs::Error::from(os_error)).context(error_context)
            } else {
                Ok(fd)
            }
        })
        .collect()
}

fn attach_perf_event(
    pefds: &[i32],
    prog: &libbpf_rs::ProgramMut,
) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds
        .iter()
        .map(|pefd| prog.attach_perf_event(*pefd))
        .collect()
}

fn main() -> Result<()> {
    env_logger::init();

    let pid: u32 = 3961;

    let mut state = ProcessState {
        maps_by_id: HashMap::new(),
        maps: BTreeSet::new(),
        entries: BTreeMap::new(),
        cft_forw: BTreeMap::new(),
        cft_rev: BTreeMap::new(),
        next_id: 0,
    };

    // read process maps from /proc/[pid]/maps
    let mut maps = read_process_maps(pid)?;

    // order all mappings into a btree map
    let mut objlist = BTreeMap::new();
    let mut next_id = 1u64;
    for map in maps.iter_mut() {
        let id = match objlist.get(&map.pathname) {
            Some(id) => *id,
            None => {
                let id = next_id;
                objlist.insert(map.pathname.clone(), next_id);
                println!("Object ID {}: {}", next_id, map.pathname);
                next_id += 1;
                id
            },
        };
        map.obj_id = id;
        let entry = state.maps_by_id.entry(id).or_insert_with(Vec::new);
        entry.push(map.clone());
    }

    println!("maps_by_id: {:?}", state.maps_by_id);
    // find all binaries and build unwind tables
    let mut built_maps = vec![false; next_id as usize];
    for map in maps.iter_mut() {
        if map.perms.chars().any(|c| c == 'x') {
            continue; // skip non-executable mappings
        }
        if built_maps[map.obj_id as usize] {
            continue; // already built
        }
        built_maps[map.obj_id as usize] = true;

        println!("Build fsw for {}", map.pathname);
        let fsw = build_fsw(&mut state, map.obj_id, &map.pathname);
        match fsw {
            Ok(_) => {
                println!("Successfully built FSW for {}", map.pathname);
            }
            Err(e) => {
                println!("Error building FSW for {}: {:?}", map.pathname, e);
            }
        }
    }

    println!("needed mappings ({} total):", state.maps.len());
    for map in state.maps.iter() {
        println!("  obj_id {}: {:#x}-{:#x} {:#x} {}",
            map.obj_id, map.vm_start, map.vm_end, map.offset, map.pathname);
    }

    // print CFT statistics
    println!("CFT Statistics:");
    println!("  Total unique CFTs: {}", state.cft_forw.len());
    println!("  Total CFT entries: {}", state.entries.len());



    let mut skel_builder = FswSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_object = std::mem::MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)
        .context("failed to open FSW skel")?;

    let rodata = open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .expect("`rodata` is not memory mapped");

    // Write arguments into prog
    rodata.targ_pid = pid;

    /*
    let uprobe_add = open_skel
        .progs
        .uprobe_add
        .attach_uprobe(false, pid as i32, "/usr/bin/ceph-osd", 0)
        .expect("`uprobe_add` program is not loaded");
    */

    let om_entries = 130000;
    //let om_entries = std::mem::size_of::<types::offsetmap.entries>();
    let noffsetmaps = (state.entries.len() + om_entries - 1) / om_entries;
    open_skel.maps.offsetmaps.set_max_entries(noffsetmaps as u32)?;
    open_skel.maps.mappings.set_max_entries(1)?;

    let mut skel = open_skel.load()
        .context("failed to load FSW skel")?;

    // build offsets tables
    let mut om = types::offsetmap {
        ..Default::default()
    };
    let mut offsetmap_idx = 0u32;
    let mut entry_idx = 0;
    let mut offsetmap_starts = Vec::new();
    for ((id, offset), cft_id) in state.entries.iter() {
        om.entries[entry_idx] = types::offsetmap_entry {
            obj_id_offset: *id << 48 | (*offset & 0xffffffffffff),
            cft_id: cft_id.unwrap_or(0) as u32,
        };
        if entry_idx == 0 {
            offsetmap_starts.push((*id, *offset));
        }
        entry_idx += 1;
        if entry_idx == om_entries {
            om.nentries = entry_idx as u64;
            let m_om = unsafe {
                std::slice::from_raw_parts(
                    (&om as *const types::offsetmap) as *const u8,
                    std::mem::size_of::<types::offsetmap>(),
                )
            };
            println!("Updating offsetmap idx {} with {} entries", offsetmap_idx, entry_idx);
            skel.maps.offsetmaps.update(&offsetmap_idx.to_le_bytes(), &m_om, MapFlags::ANY)?;
            entry_idx = 0;
            om = types::offsetmap { .. Default::default()  };
            offsetmap_idx += 1;
        }
    }
    if entry_idx != 0 {
        om.nentries = entry_idx as u64;
        let m_om = unsafe {
            std::slice::from_raw_parts(
                (&om as *const types::offsetmap) as *const u8,
                std::mem::size_of::<types::offsetmap>(),
            )
        };
        println!("Updating offsetmap idx {} with {} entries", offsetmap_idx, entry_idx);
        skel.maps.offsetmaps.update(&offsetmap_idx.to_le_bytes(), &m_om, MapFlags::ANY)?;
    }

    for (i, start) in offsetmap_starts.iter().enumerate() {
        println!("Offsetmap {} starts at obj_id {} addr {:#x}", i, start.0, start.1);
    }

    // build mappings table
    let pid_b = pid.to_le_bytes();
    let mut m = types::mapping {
        nmappings: state.maps.len() as u64,
        ..Default::default() };
    let mut map_idx = 0;
    for map in state.maps.iter() {
        // find offsetmap
        let mut o = match offsetmap_starts.binary_search(&(map.obj_id, map.offset)) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let mut vm_start = map.vm_start;
        let mut offset = map.offset;
        debug!("Building mappings for obj_id {} map {:#x}-{:#x} -> {:#x}",
            map.obj_id, map.vm_start, map.vm_end, map.offset);
        while vm_start < map.vm_end {
            m.mappings[map_idx] = types::map_entry {
                vma_start: vm_start,
                obj_id_offset: map.obj_id << 48 | offset,
                offsetmap_id: o as u32,
            };
            println!("Mapping idx {}: obj_id {} addr {:#x}-{:#x} offset {:#x} to offsetmap {}",
                map_idx, map.obj_id, vm_start, map.vm_end, offset, o);
            map_idx += 1;
            let Some(next) = offsetmap_starts.get(o + 1) else {
                break;
            };
            if next.0 != map.obj_id {
                break;
            }
            vm_start += next.1 - offset;
            offset = next.1;
            o += 1;
        }
    }
    let m_b = unsafe {
        std::slice::from_raw_parts(
            (&m as *const types::mapping) as *const u8,
            std::mem::size_of::<types::mapping>(),
        )
    };

    skel.maps.mappings.update(&pid_b, &m_b, MapFlags::ANY)?;

    let pefds = init_perf_monitor(7, false)
        .context("failed to initialize perf monitor")?;
    let _links = attach_perf_event(&pefds, &skel.progs.uprobe_add);

    /*
            /* Attach tracepoint handler */
        //fsw_opts.func_name = "_ZN12PrimaryLogPG7do_readEPNS_9OpContextER5OSDOp";
        fsw_opts.func_name = "_ZN12PrimaryLogPG10do_osd_opsEPNS_9OpContextERSt6vectorI5OSDOpSaIS3_EE";
        fsw_opts.retprobe = false;
        /* fsw/uretprobe expects relative offset of the function to attach
         * to. libbpf will automatically find the offset for us if we provide the
         * function name. If the function name is not specified, libbpf will try
         * to use the function offset instead.
         */
        char *probe;
        asprintf(&probe, "/proc/%d/root/usr/bin/ceph-osd", pid);
        skel->links.uprobe_add = bpf_program__attach_uprobe_opts(skel->progs.uprobe_add,
                                                                 pid /* self pid */,
                                                                 probe,
                                                                 0 /* offset for function */,
                                                                 &fsw_opts /* opts */);
        if (!skel->links.uprobe_add) {
                err = -errno;
                fprintf(stderr, "Failed to attach fsw: %d\n", err);
                goto cleanup;
        }
        */

    skel.attach()
        .context("failed to attach FSW skel")?;

    std::thread::sleep(std::time::Duration::from_secs(100));
/*
    // Do a test stack walk
    let mut stack_file = File::open("./stack.dump")?;
    let mut stack_data = Vec::new();
    stack_file.read_to_end(&mut stack_data)?;
    let regs = vec![
        0x0u64,   // rax
        0x55c897e7fd50,  // rdx
        0x55c803185790, // rcx
        0x55c897e7fd78, // rbx
        0x55c86af87200, // rsi
        0x55c8592fe000, // rdi
        0x7fb998af8030, // rbp
        0x7fb998af7a48, // rsp
        0x55c897e7fd78, // r8
        0x20,           // r9
        0x1000,         // r10
        0x55c86af87200, // r11
        0x0,            // r12
        0x55c858d260a0, // r13
        0xfffffffffffffffe, // r14
        0x55c86af87200, // r15
        0x55c802509ac0, // rip
    ];
    let mut regs = regs.into_iter().map(|v| Some(v)).collect::<Vec<Option<u64>>>();

    let map_offset = 0x55c80220d000 - 0x377000;
    let stack_start = regs[7].unwrap(); // rsp

    loop {
        let Some(rip) = regs[16] else {
            println!("Stack walk: PC is None, stopping");
            break;
        };
        let e = fsw.entries.range(..=(rip - map_offset)).rev().next();
        let Some((_, Some(cft_id))) = e else {
            println!("Stack walk: PC {:#x}, no entry found, stopping", rip - map_offset);
            break;
        };
        let cft = fsw.cft_forw.get(cft_id).unwrap();

        println!("Stack walk: PC {:#x}, found entry: {:?}", rip - map_offset, e);

        // compute CFA
        let cfa = match cft.cfa {
            CFARule::Uninitialized => {
                println!("Stack walk: CFA uninitialized, stopping");
                break;
            }
            CFARule::Expression(_) => {
                println!("Stack walk: CFA expression not supported, stopping");
                break;
            }
            CFARule::RegOffset(r, o) => {
                let reg_val = match regs[r] {
                    Some(v) => v,
                    None => {
                        println!("Stack walk: CFA register r{} is None, stopping", r);
                        break;
                    }
                };
                let cfa = (reg_val as i64 + o) as u64;
                println!("  CFA = r{} ({:#x}) + {} = {:#x}", r, reg_val, o, cfa);
                cfa
            }
        };

        let _old_regs = regs.clone();

        // unwind stack pointer
        regs[7] = Some(cfa);

        for reg in 0..regs.len() {
            match &cft.rules[reg] {
                RegisterRule::Uninitialized|RegisterRule::SameValue => {
                    // register is unchanged
                }
                RegisterRule::Undefined => {
                    regs[reg] = None;
                }
                RegisterRule::Offset(off) => {
                    let addr = (cfa as i64 + *off) as u64;
                    let val = u64::from_le_bytes(stack_data[(addr - stack_start) as usize ..
                        ((addr - stack_start) + 8) as usize].try_into().unwrap());
                    println!("  r{}: at addr {:#x} value {:#x}", reg, addr, val);
                    regs[reg] = Some(val);
                }
                // XXX use old_regs for register to register copy
                _ => {
                    panic!("unsupported register rule for stack walk: {:?}", cft.rules[reg]);
                }
            }
        }
        println!("  next PC from r16: {:x?}", regs[16]);
        println!("  regs: {:x?}", regs);
    }
*/

    Ok(())
}
