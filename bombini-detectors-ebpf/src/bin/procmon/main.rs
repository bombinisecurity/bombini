#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_ANY,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{hash_map::HashMap, per_cpu_array::PerCpuArray},
    programs::{ProbeContext, TracePointContext},
};

use bombini_detectors_ebpf::vmlinux::{
    cred, file, inode, kernel_cap_t, kuid_t, mm_struct, path, pid_t, qstr, task_struct, umode_t,
};

use bombini_common::event::process::{ProcInfo, MAX_ARGS_SIZE, MAX_FILENAME_SIZE};

const S_ISUID: u16 = 0x0004000;

#[map]
static PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1024, 0);

#[map]
static HEAP: PerCpuArray<ProcInfo> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn execve_capture(ctx: TracePointContext) -> u32 {
    match try_capture(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_capture(_ctx: TracePointContext) -> Result<u32, u32> {
    let Some(proc_ptr) = HEAP.get_ptr_mut(0) else {
        return Err(0);
    };

    let proc = unsafe { proc_ptr.as_mut() };

    let Some(proc) = proc else {
        return Err(0);
    };

    // We need to read real executable name and get arguments from stack.
    let (arg_start, arg_end) = unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        proc.pid = bpf_probe_read::<pid_t>(&(*task).pid as *const _).map_err(|e| e as u32)? as u32;
        proc.tid = bpf_probe_read::<pid_t>(&(*task).tgid as *const _).map_err(|e| e as u32)? as u32;

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

        aya_ebpf::memset(proc.filename.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(d_name.name, &mut proc.filename).map_err(|e| e as u32)?;
        aya_ebpf::memset(proc.args.as_mut_ptr(), 0, MAX_ARGS_SIZE);

        // Skip argv[0]
        let first_arg = bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut proc.args)
            .map_err(|e| e as u32)?;

        arg_start += 1 + first_arg.len() as u64;

        // Get cred
        let cred = bpf_probe_read::<*const cred>(&(*task).cred as *const *const _)
            .map_err(|e| e as u32)?;
        let euid = bpf_probe_read::<kuid_t>(&(*cred).euid as *const _).map_err(|e| e as u32)?;
        let uid = bpf_probe_read::<kuid_t>(&(*cred).uid as *const _).map_err(|e| e as u32)?;

        proc.uid = uid.val;
        proc.euid = euid.val;
        let cap_e = bpf_probe_read::<kernel_cap_t>(&(*cred).cap_effective as *const _)
            .map_err(|e| e as u32)?;

        proc.is_cap_set_uid = (cap_e.val & 128) != 0;
        proc.is_suid = (i_mode & S_ISUID) != 0;

        (arg_start, arg_end)
    };
    let arg_size = (arg_end - arg_start) & (MAX_ARGS_SIZE - 1) as u64;
    unsafe {
        bpf_probe_read_user_buf(arg_start as *const u8, &mut proc.args[..arg_size as usize])
            .map_err(|e| e as u32)?;
    }

    PROC_MAP
        .insert(&proc.pid, proc, BPF_ANY as u64)
        .map_err(|e| e as u32)?;
    Ok(0)
}

#[kprobe]
pub fn exit_capture(_ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    PROC_MAP.remove(&pid).unwrap();
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
