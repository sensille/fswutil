use anyhow::{Result, bail, Context};
//use log::{debug, info, warn};
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::{ MapCore, MapFlags, MapImpl, Mut, RingBufferBuilder };
use std::default::Default;
use blazesym::symbolize::source::{ Process, Source };
use blazesym::symbolize::{ Symbolizer, Symbolized, Input };
use blazesym::Pid;

#[allow(non_camel_case_types)]
pub struct mapping {
    pub nentries: u64,
    pub entries: [map_entry; 1000],
}
impl Default for mapping {
    fn default() -> Self {
        Self {
            nentries: u64::default(),
            entries: [map_entry::default(); 1000],
        }
    }
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct map_entry {
    pub vma_start: u64,
    pub offset: u64,
    pub offsetmap_id: u32,
    pub start_in_map: u32,
}

mod fsw {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/fsw.skel.rs"
    ));
}
use fsw::*;
mod syscall;

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
    let mut fds = Vec::new();
    for cpu in 0..nprocs {
        let fd = syscall::perf_event_open(&attr, pid, cpu as i32, -1, 0) as i32;
        if fd == -1 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENODEV) => continue, // CPU does not exist
                Some(libc::ENOENT) if !sw_event => return init_perf_monitor(freq, true),
                Some(x) => bail!("Failed to open perf event: error {}", x),
                None => bail!("Failed to open perf event"),
            }
        } else {
            fds.push(fd);
        }
    }

    Ok(fds)
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

fn set_expression_in_map(map: &mut MapImpl<'_, Mut>, expr_id: u32, expr: &Vec<u8>) -> Result<()> {
    if expr.len() > 255 /* XXX hardcoded */ {
        bail!("expression too long");
    }
    let mut e = types::expression {
        ninstructions: expr.len() as u8,
        instructions: [0u8; 255],
    };
    e.instructions[..expr.len()].copy_from_slice(&expr);
    let e_b = unsafe {
        std::slice::from_raw_parts(
            (&e as *const types::expression) as *const u8,
            std::mem::size_of::<types::expression>(),
        )
    };

    // XXX to_le_bytes is too specific
    map.update(&expr_id.to_le_bytes(), &e_b, MapFlags::ANY)?;

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    //let pid: u32 = 463248;
    //let pid: u32 = 3961;
    let pid: u32 = 1339584;

    let mut fsw = libfsw::Fsw::new();

    fsw.add_pid(pid)?;
    let (mut tables, entries, expressions) = fsw.build_tables()?;
    let mappings = fsw.build_mapping_for_pid(pid)?;

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

    // set map sizes
    open_skel.maps.offsetmaps.set_max_entries(tables.len()  as u32)?;
    open_skel.maps.mappings.set_max_entries(1)?;
    open_skel.maps.cfts.set_max_entries(entries.len() as u32)?;
    open_skel.maps.expressions.set_max_entries(expressions.len() as u32)?;

    let mut skel = open_skel.load()
        .context("failed to load FSW skel")?;

    // build offsets tables
    for (i, table) in tables.iter_mut().enumerate() {
        skel.maps.offsetmaps.update(&(i as u32).to_le_bytes(), &table, MapFlags::ANY)?;
    }

    // build mappings table
    skel.maps.mappings.update(&(pid as u32).to_le_bytes(), &mappings, MapFlags::ANY)?;

    // build CFT table
    for (i, table) in entries.iter().enumerate() {
        skel.maps.cfts.update(&(i as u32).to_le_bytes(), &table, MapFlags::ANY)?;
    }

    // build CFT table
    for (i, table) in expressions.iter().enumerate() {
        println!("setting expr {} len {}", i, table.len());
        skel.maps.expressions.update(&(i as u32).to_le_bytes(), &table, MapFlags::ANY)?;
    }

    let pefds = init_perf_monitor(7, false)
        .context("failed to initialize perf monitor")?;
    let _links = attach_perf_event(&pefds, &skel.progs.ustack);

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
        skel->links.ustack = bpf_program__attach_uprobe_opts(skel->progs.ustack,
                                                                 pid /* self pid */,
                                                                 probe,
                                                                 0 /* offset for function */,
                                                                 &fsw_opts /* opts */);
        if (!skel->links.ustack) {
                err = -errno;
                fprintf(stderr, "Failed to attach fsw: %d\n", err);
                goto cleanup;
        }
        */

    skel.attach()
        .context("failed to attach FSW skel")?;

    println!("FSW attached, sleeping...");

    //let symbolizers: HashMap<u64, symbolize::Symbolizer> = HashMap::new();
    let src = Source::Process(Process::new(Pid::from(pid)));
    let symbolizer = Symbolizer::new();

    #[repr(C)]
    struct StackOut {
            nframes: u32,
            frames: [u64; 64],
    }
    let mut rbb = RingBufferBuilder::new();
    rbb.add(&skel.maps.rb, |data| {
                assert_eq!(data.len(), std::mem::size_of::<StackOut>());
                let data = unsafe {
                    &*(data.as_ptr() as *const StackOut)
                };
                println!("nframes {}", data.nframes);
                for i in 0..data.nframes as usize {
                    let ip = data.frames[i];
                    //println!("frame {}: {:#x}", i, ip);
                    // translate address to mapping and offset
                    // find map
                    /*
                    let key = ProcessMaps {
                        vm_start: ip,
                        ..Default::default()
                    };
                    let map = state.maps.range(..=key).next_back();
                    let Some(map) = map else {
                        println!("  {:#x} no mapping found", ip);
                        continue;
                    };
                    */
                    /*
                    println!("  {:#x} mapped to obj_id {} offset {:#x} in {}",
                        ip, map.obj_id, map.offset + (ip - map.vm_start), map.pathname);
                    */
                    let sym = symbolizer.symbolize_single(&src, Input::AbsAddr(ip));
                    let s = match sym {
                        Ok(Symbolized::Sym(s)) => s.name.to_string(),
                        Ok(Symbolized::Unknown(r)) => r.to_string(),
                        Err(e) => {
                            println!("    symbolization error: {:?}", e);
                            continue;
                        }
                    };
                    println!("   {:#x} {}", ip, s);
                    /*
                    let symbolizer = match symbolizers.get(&map.obj_id) {
                        Some(s) => s,
                        None => {
                            let src = symbolize::source::Source::Process(Proformat!("/proc/{}/root{}",
                                    state.pid, map.pathname));
                            let symbolizer = symbolize::Symbolizer::new();
                                format!("/proc/{}/root{}", state.pid, map.pathname)
                            ).context("failed to create symbolizer")?;
                            continue;
                        }
                    };
                    */
                }
                1
        })
        .context("failed to build ring buffer")?;
    let rb = rbb.build()?;
    loop {
        rb.poll(std::time::Duration::from_secs(100))?;
    }
}
