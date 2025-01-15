#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::lpm_trie::{Key, LpmTrie},
    programs::TracePointContext,
};

use bombini_detectors_ebpf::vmlinux::{
    cred, file, inode, kernel_cap_t, kuid_t, mm_struct, path, qstr, task_struct, umode_t,
};

use bombini_common::config::gtfobins::{GTFOBinsKey, MAX_ARGS_SIZE, MAX_FILENAME_SIZE};
use bombini_common::event::{Event, MSG_GTFOBINS};

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init};

const S_ISUID: u16 = 0x0004000;

#[map]
static GTFOBINS: LpmTrie<GTFOBinsKey, u32> = LpmTrie::with_max_entries(128, 0);

#[tracepoint]
pub fn gtfobins_detect(ctx: TracePointContext) -> u32 {
    event_capture!(ctx, MSG_GTFOBINS, try_detect)
}

fn try_detect(_ctx: TracePointContext, event: &mut Event) -> Result<u32, u32> {
    let Event::GTFOBins(event) = event else {
        return Err(0);
    };

    let total_cmd_len = event.command.len();
    // We need to read real executable name and get arguments from stack.
    let (arg_start, arg_end) = unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        let mm =
            bpf_probe_read::<*mut mm_struct>(&(*task).mm as *const *mut _).map_err(|e| e as u32)?;
        let mut arg_start = bpf_probe_read::<u64>(&(*mm).__bindgen_anon_1.arg_start as *const _)
            .map_err(|e| e as u32)?;

        let arg_end = bpf_probe_read::<u64>(&(*mm).__bindgen_anon_1.arg_end as *const _)
            .map_err(|e| e as u32)?;
        let file = bpf_probe_read::<*mut file>(&(*mm).__bindgen_anon_1.exe_file as *const *mut _)
            .map_err(|e| e as u32)?;
        let path = bpf_probe_read::<path>(&(*file).f_path as *const _).map_err(|e| e as u32)?;
        let d_name =
            bpf_probe_read::<qstr>(&(*(path.dentry)).d_name as *const _).map_err(|e| e as u32)?;
        let inode = bpf_probe_read::<*mut inode>(&(*file).f_inode as *const *mut _)
            .map_err(|e| e as u32)?;
        let i_mode =
            bpf_probe_read::<umode_t>(&(*inode).i_mode as *const _).map_err(|e| e as u32)?;

        // Skip argv[0]
        let first_arg = bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut event.command)
            .map_err(|e| e as u32)?;
        arg_start += 1 + first_arg.len() as u64;

        aya_ebpf::memset(event.command.as_mut_ptr(), 0, total_cmd_len);
        bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.command[..MAX_FILENAME_SIZE]).map_err(|e| e as u32)?;

        // Get cred
        let cred = bpf_probe_read::<*const cred>(&(*task).cred as *const *const _)
            .map_err(|e| e as u32)?;
        let euid = bpf_probe_read::<kuid_t>(&(*cred).euid as *const _).map_err(|e| e as u32)?;
        let uid = bpf_probe_read::<kuid_t>(&(*cred).uid as *const _).map_err(|e| e as u32)?;

        event.uid = uid.val;
        event.euid = euid.val;
        let cap_e = bpf_probe_read::<kernel_cap_t>(&(*cred).cap_effective as *const _)
            .map_err(|e| e as u32)?;

        event.is_cap_set_uid = (cap_e.val & 128) != 0;
        event.is_suid = (i_mode & S_ISUID) != 0;
        (arg_start, arg_end)
    };
    let arg_size = (arg_end - arg_start) & (MAX_ARGS_SIZE - 1) as u64;
    unsafe {
        bpf_probe_read_user_buf(arg_start as *const u8, &mut event.command[MAX_FILENAME_SIZE + 1..MAX_FILENAME_SIZE + 1 + arg_size as usize])
            .map_err(|e| e as u32)?;
    } // check EUID or capability
    if event.euid == 0 || event.is_cap_set_uid {
        // Check if GTFO binary
        let lookup = Key::new((total_cmd_len * 8) as u32, event.command);
        if GTFOBINS.get(&lookup).is_some() {
            Ok(0)
        } else {
            Ok(0)
            //Err(0)
        }
    } else {
        Err(0)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
