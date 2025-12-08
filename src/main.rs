use std::fs::File;
use anyhow::{Result, bail};
use elf::ElfStream;
use elf::endian::AnyEndian;
use std::collections::BTreeMap;

fn read_uint(data: &[u8], dwarf64: bool, offset: &mut usize) -> Result<u64> {
    let size = if dwarf64 { 8 } else { 4 };
    if data.len() < *offset + size {
        bail!("not enough data to read int of size {}", size);
    }
    let val = if dwarf64 {
        u64::from_le_bytes(data[*offset..*offset + 8].try_into()?)
    } else {
        u32::from_le_bytes(data[*offset..*offset + 4].try_into()?) as u64
    };
    *offset += size;

    Ok(val)
}

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
    *offset += 1;
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
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    // sign extend if necessary
    if sign_extend && shift < 64 && (byte & 0x40) != 0 {
        result |= !0 << shift;
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

#[derive(Debug)]
struct Cie {
    version: u8,
    caf: u64,   // code alignment factor
    daf: i64,   // data alignment factor
    rar: u64,   // return address register
    aug_z: bool,
    lsda_encoding: Option<u8>,
    fde_encoding: u8,
    initial_cfa: Vec<u8>,
}

// see https://www.airs.com/blog/archives/460
fn parse_eh_cie(data: &[u8]) -> Result<Cie> {
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
    if augmentation.starts_with("z") {
        // skip augmentation data for now
        let aug_data_len = read_leb128_u(data, &mut offset)? as usize;
        println!("CIE augmentation data length: {}", aug_data_len);
        offset += aug_data_len;
        aug_z = true;
    }
    let mut lsda_encoding = None;
    if augmentation.contains("L") {
        // skip LSDA encoding
        lsda_encoding = Some(read_u8(data, &mut offset)?);
    }
    let fde_encoding = None;
    if augmentation.contains("R") {
        //fde_encoding = Some(read_u8(data, &mut offset)?);
    }
    if augmentation.contains("S") {
        bail!("signal frame indicator not supported yet");
    }
    if augmentation.contains("P") {
        let _personality = read_leb128_u(data, &mut offset)?;
        bail!("personality routine not supported yet");
    }

    Ok(Cie {
        version,
        caf,
        daf,
        rar,
        aug_z,
        lsda_encoding,
        fde_encoding: fde_encoding.unwrap_or(0),
        initial_cfa: data[offset..].into(),
    })
}

struct CFT {
    loc: u64,
    cfa_offset: i64,
    regs: Vec<i64>,
}

fn execute_instructions(instructions: &[u8], cie: &Cie, cft: &mut CFT) -> Result<()> {
    println!("Executing instructions: {:x?}", instructions);
    let mut offset = 0;
    while offset < instructions.len() {
        let instr = read_u8(instructions, &mut offset)?;
        match instr {
            0x00 => {
                // DW_CFA_nop
                println!("DW_CFA_nop");
            }
            0x01 => {
                // DW_CFA_set_loc
                if cie.fde_encoding != 0 {
                    bail!("DW_CFA_set_loc with unsupported FDE encoding {}", cie.fde_encoding);
                }
                cft.loc = read_uint(instructions, false, &mut offset)?;
                println!("DW_CFA_set_loc to {:#x}", cft.loc);
            }
            0x02 => {
                // DW_CFA_advance_loc1
                let delta = read_u8(instructions, &mut offset)? as u64;
                println!("DW_CFA_advance_loc1 by {}", delta);
                cft.loc += delta;
            }
            0x03 => {
                // DW_CFA_advance_loc2
                let delta = read_u16(instructions, &mut offset)? as u64;
                println!("DW_CFA_advance_loc2 by {}", delta);
                cft.loc += delta;
            }
            0x04 => {
                // DW_CFA_advance_loc4
                let delta = read_u32(instructions, &mut offset)? as u64;
                println!("DW_CFA_advance_loc4 by {}", delta);
                cft.loc += delta;
            }
            0x0c => {
                // DW_CFA_def_cfa
                let reg = read_leb128_u(instructions, &mut offset)? as usize;
                let offset_val = read_leb128_u(instructions, &mut offset)?;
                if reg > cft.regs.len() {
                    bail!("DW_CFA_def_cfa: register {} out of bounds", reg);
                }
                cft.regs[reg] = offset_val as i64;
                println!("DW_CFA_def_cfa: reg {}, offset {}", reg, offset_val);
            }
            0x40..=0x7f => {
                // DW_CFA_advance_loc
                let delta = (instr & 0x3f) as u64;
                println!("DW_CFA_advance_loc by {}", delta);
            }
            0x80..=0xbf => {
                // DW_CFA_offset
                let reg = (instr & 0x3f) as usize;
                if reg >= cft.regs.len() {
                    bail!("DW_CFA_offset: register {} out of bounds", reg);
                }
                let offset_val = read_leb128_u(instructions, &mut offset)? as i64;
                println!("DW_CFA_offset: reg {}, offset {}", reg, offset_val);
                cft.regs[reg] = offset_val * cie.daf;
            }
            0xc0..=0xff => {
                // DW_CFA_restore
                let reg = (instr & 0x3f) as usize;
                if reg >= cft.regs.len() {
                    bail!("DW_CFA_restore: register {} out of bounds", reg);
                }
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
        cfa_offset: 0,
        regs: vec![0; 17],
    };
    println!("FDE Instructions: {:x?}", fde.instructions);
    execute_instructions(&cie.initial_cfa, &cie, &mut cft)?;
    execute_instructions(&fde.instructions, &cie, &mut cft)?;

    Ok(())
}

fn parse_debug_cie(data: &[u8], dwarf64: bool, offset: &mut usize) -> Result<()> {
    Ok(())
}

#[derive(Debug)]
struct Fde {
    initial_location: u64,
    address_range: u64,
    instructions: Vec<u8>,
}

fn parse_fde(data: &[u8], dwarf64: bool, cie: &Cie) -> Result<Fde> {
    let mut offset = 0;
    if cie.fde_encoding != 0 {
        bail!("FDE encoding {} not supported", cie.fde_encoding);
    }
    let initial_location = read_uint(data, dwarf64, &mut offset)?;
    let address_range = read_uint(data, dwarf64, &mut offset)?;
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
        // CIE or FDE?
        let frame_end = offset + frame_len as usize;
        let id_offset = offset;
        let id = read_uint(&eh, dwarf64, &mut offset)
            .expect("could not read frame id");
        // on debug_frame, this is different
        if id == 0 {
            // CIE
            let cie = parse_eh_cie(&eh[offset..frame_end])
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
        println!("frame length: {} id {}", frame_len, id);
        offset = frame_end;
    }

    Ok(())
}
