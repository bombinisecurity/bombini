#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{
        hash_map::HashMap,
        lpm_trie::{Key, LpmTrie},
    },
    programs::LsmContext,
};

use bombini_detectors_ebpf::vmlinux::{file, linux_binprm, path, qstr};

use bombini_common::config::gtfobins::GTFOBinsKey;
use bombini_common::constants::MAX_FILENAME_SIZE;
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, MSG_GTFOBINS};

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init, util};

#[map]
static GTFOBINS_NAME_MAP: LpmTrie<GTFOBinsKey, u32> = LpmTrie::with_max_entries(128, 0);

#[map]
static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1, 0);

#[lsm]
pub fn gtfobins_detect(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_GTFOBINS, true, try_detect)
}

static MAX_PROC_DEPTH: u32 = 4;

fn try_detect(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Event::GTFOBins(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(mut proc) = proc else {
        return Err(0);
    };

    // Check if process is privileged
    if proc.creds.euid == 0 {
        // Check if sh is executing
        unsafe {
            let binprm: *const linux_binprm = ctx.arg(0);
            let file: *mut file = (*binprm).file;
            let path =
                bpf_probe_read_kernel::<path>(&(*file).f_path as *const _).map_err(|_| 0_i32)?;
            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0_i32)?;
            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.process.filename)
                .map_err(|_| 0_i32)?;
        }
        if (event.process.filename[0] == b's' && event.process.filename[1] == b'h')
            || (event.process.filename[0] == b'b'
                && event.process.filename[1] == b'a'
                && event.process.filename[2] == b's'
                && event.process.filename[3] == b'h')
            || (event.process.filename[0] == b'd'
                && event.process.filename[1] == b'a'
                && event.process.filename[2] == b's'
                && event.process.filename[3] == b'h')
            || (event.process.filename[0] == b'z'
                && event.process.filename[1] == b's'
                && event.process.filename[2] == b'h')
        {
            for _ in 0..MAX_PROC_DEPTH {
                unsafe {
                    let _ = bpf_probe_read_kernel_buf(
                        proc.filename.as_ptr(),
                        &mut event.process.filename,
                    );
                }
                let parent_proc = unsafe { PROCMON_PROC_MAP.get(&proc.ppid) };
                let Some(parent_proc) = parent_proc else {
                    return Err(0);
                };
                // Check if GTFO binary
                let lookup = Key::new((MAX_FILENAME_SIZE * 8) as u32, event.process.filename);
                if let Some(enforce) = GTFOBINS_NAME_MAP.get(&lookup) {
                    if proc.clonned {
                        // Pass parent process in event
                        util::copy_proc(parent_proc, &mut event.process);
                    } else {
                        util::copy_proc(proc, &mut event.process);
                    }
                    if *enforce != 0 {
                        return Ok(-1);
                    }
                    return Ok(0);
                } else {
                    proc = parent_proc;
                }
            }
        }
    }
    Err(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
