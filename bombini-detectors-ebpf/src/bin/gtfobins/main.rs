#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_task_btf, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{lsm, map},
    maps::{
        hash_map::{HashMap, LruHashMap},
        per_cpu_array::PerCpuArray,
    },
    programs::LsmContext,
};

use bombini_detectors_ebpf::vmlinux::{file, kuid_t, linux_binprm, path, pid_t, qstr, task_struct};

use bombini_common::constants::MAX_FILENAME_SIZE;
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, GenericEvent, MSG_GTFOBINS};

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init, util};

#[map]
static GTFOBINS_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u32> = HashMap::with_max_entries(128, 0);

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static GTFOBINS_FILENAME_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> =
    PerCpuArray::with_max_entries(1, 0);

#[lsm]
pub fn gtfobins_detect(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_GTFOBINS, true, try_detect)
}

static MAX_PROC_DEPTH: u32 = 4;

fn try_detect(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::GTFOBins(ref mut event) = generic_event.event else {
        return Err(0);
    };
    let Some(filename_ptr) = GTFOBINS_FILENAME_HEAP.get_ptr_mut(0) else {
        return Err(0);
    };

    let filename = unsafe { filename_ptr.as_mut() };

    let Some(filename) = filename else {
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
            bpf_probe_read_kernel_str_bytes(d_name.name, filename).map_err(|_| 0_i32)?;
            if (filename[0] == b's' && filename[1] == b'h')
                || (filename[0] == b'b'
                    && filename[1] == b'a'
                    && filename[2] == b's'
                    && filename[3] == b'h')
                || (filename[0] == b'd'
                    && filename[1] == b'a'
                    && filename[2] == b's'
                    && filename[3] == b'h')
                || (filename[0] == b'z' && filename[1] == b's' && filename[2] == b'h')
            {
                let task = bpf_get_current_task_btf() as *const task_struct;
                let parent_task =
                    bpf_probe_read_kernel::<*mut task_struct>(&(*task).parent as *const _)
                        .map_err(|_| 0i32)?;
                let mut ppid = bpf_probe_read_kernel(&(*parent_task).tgid as *const pid_t)
                    .map_err(|_| 0i32)? as u32;
                for _ in 0..MAX_PROC_DEPTH {
                    let parent_proc = PROCMON_PROC_MAP.get(ppid);
                    let Some(parent_proc) = parent_proc else {
                        return Err(0);
                    };
                    if parent_proc.ppid == 1 {
                        // System process uses gtfobin and spawing shell. It's valid
                        // Example networkd-dispatcher can start some shell scripts
                        return Err(0);
                    }
                    // Check if GTFO binary
                    if let Some(enforce) = GTFOBINS_NAME_MAP.get_ptr(parent_proc.filename) {
                        util::process_key_init(&mut event.process, parent_proc);
                        if *enforce != 0 {
                            return Ok(-1);
                        }
                        return Ok(0);
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
