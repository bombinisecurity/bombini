#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_task_btf, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{lsm, map},
    maps::hash_map::HashMap,
    programs::LsmContext,
};

use bombini_detectors_ebpf::vmlinux::{file, kuid_t, linux_binprm, path, pid_t, qstr, task_struct};

use bombini_common::constants::MAX_FILENAME_SIZE;
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, MSG_GTFOBINS};

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init, util};

#[map]
static GTFOBINS_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u32> = HashMap::with_max_entries(128, 0);

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
    unsafe {
        let binprm: *const linux_binprm = ctx.arg(0);
        let cred = (*binprm).cred;
        let euid = bpf_probe_read_kernel::<kuid_t>(&(*cred).euid as *const _)
            .map_err(|_| 0i32)?
            .val;

        // Check if process is privileged
        if euid == 0 {
            // Check if sh is executing
            let file: *mut file = (*binprm).file;
            let path =
                bpf_probe_read_kernel::<path>(&(*file).f_path as *const _).map_err(|_| 0_i32)?;
            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0_i32)?;
            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.process.filename)
                .map_err(|_| 0_i32)?;
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
                let task = bpf_get_current_task_btf() as *const task_struct;
                let parent_task =
                    bpf_probe_read_kernel::<*mut task_struct>(&(*task).parent as *const _)
                        .map_err(|_| 0i32)?;
                let mut ppid = bpf_probe_read_kernel(&(*parent_task).tgid as *const pid_t)
                    .map_err(|_| 0i32)? as u32;
                for _ in 0..MAX_PROC_DEPTH {
                    let parent_proc = PROCMON_PROC_MAP.get(&ppid);
                    let Some(parent_proc) = parent_proc else {
                        return Err(0);
                    };
                    // Check if GTFO binary
                    if let Some(enforce) = GTFOBINS_NAME_MAP.get_ptr(&parent_proc.filename) {
                        util::copy_proc(parent_proc, &mut event.process);
                        if *enforce != 0 {
                            return Ok(-1);
                        }
                        return Ok(0);
                    }
                    if parent_proc.filename[0] == b's'
                        && parent_proc.filename[1] == b'u'
                        && parent_proc.filename[2] == b'd'
                        && parent_proc.filename[3] == b'o'
                    {
                        bpf_probe_read_kernel_str_bytes(
                            &parent_proc.args as *const _,
                            &mut event.process.filename,
                        )
                        .map_err(|_| 0_i32)?;
                        if let Some(enforce) = GTFOBINS_NAME_MAP.get_ptr(&event.process.filename) {
                            util::copy_proc(parent_proc, &mut event.process);
                            if *enforce != 0 {
                                return Ok(-1);
                            }
                            return Ok(0);
                        }
                    }
                    ppid = parent_proc.ppid;
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
