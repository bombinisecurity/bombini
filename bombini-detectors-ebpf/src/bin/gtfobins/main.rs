#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read, bpf_probe_read_buf,
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
use bombini_common::event::process::{ProcInfo, MAX_FILENAME_SIZE};
use bombini_common::event::{Event, MSG_GTFOBINS};

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init};

#[map]
static GTFOBINS: LpmTrie<GTFOBinsKey, u32> = LpmTrie::with_max_entries(128, 0);

#[map]
static PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1024, 0);

#[lsm]
pub fn gtfobins_detect(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_GTFOBINS, try_detect) as i32
}

fn try_detect(ctx: LsmContext, event: &mut Event) -> Result<u32, u32> {
    let Event::GTFOBins(event) = event;
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };
    let parent_proc = unsafe { PROC_MAP.get(&proc.ppid) };
    let Some(parent_proc) = parent_proc else {
        return Err(0);
    };

    if parent_proc.euid == 0 || parent_proc.is_cap_set_uid {
        // Check if sh is executing
        unsafe {
            let binprm: *const linux_binprm = ctx.arg(0);
            aya_ebpf::memset(event.process.filename.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
            let file: *mut file = (*binprm).file;
            let path = bpf_probe_read::<path>(&(*file).f_path as *const _).map_err(|e| e as u32)?;
            let d_name = bpf_probe_read::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|e| e as u32)?;
            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.process.filename)
                .map_err(|e| e as u32)?;
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
            unsafe {
                let _ =
                    bpf_probe_read_buf(parent_proc.filename.as_ptr(), &mut event.process.filename);
            }
            // Check if GTFO binary
            let lookup = Key::new((MAX_FILENAME_SIZE * 8) as u32, event.process.filename);
            if GTFOBINS.get(&lookup).is_some() {
                event.process.pid = parent_proc.pid;
                event.process.tid = parent_proc.tid;
                event.process.uid = parent_proc.uid;
                event.process.euid = parent_proc.euid;
                event.process.is_suid = parent_proc.is_suid;
                event.process.is_cap_set_uid = parent_proc.is_cap_set_uid;
                unsafe {
                    let _ = bpf_probe_read_buf(parent_proc.args.as_ptr(), &mut event.process.args);
                }
                Ok(0)
            } else {
                Err(0)
            }
        } else {
            Err(0)
        }
    } else {
        Err(0)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
