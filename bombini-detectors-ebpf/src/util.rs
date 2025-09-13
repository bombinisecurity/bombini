//! Provides some common functions
use aya_ebpf::helpers::bpf_probe_read_kernel_buf;

use bombini_common::event::process::ProcInfo;

/// Copy ProcInfo from src to dst. Commonly used to
/// copy process information to ring buffer
#[inline(always)]
pub fn copy_proc(src: &ProcInfo, dst: &mut ProcInfo) {
    dst.pid = src.pid;
    dst.tid = src.tid;
    dst.ppid = src.ppid;
    dst.creds = src.creds.clone();
    dst.auid = src.auid;
    dst.cgroup = src.cgroup.clone();
    dst.ima_hash.algo = src.ima_hash.algo;
    unsafe {
        let _ = bpf_probe_read_kernel_buf(src.filename.as_ptr(), &mut dst.filename);
        let _ = bpf_probe_read_kernel_buf(src.args.as_ptr(), &mut dst.args);
        let _ = bpf_probe_read_kernel_buf(src.binary_path.as_ptr(), &mut dst.binary_path);
        if src.ima_hash.algo > 0 {
            let _ = bpf_probe_read_kernel_buf(src.ima_hash.hash.as_ptr(), &mut dst.ima_hash.hash);
        }
    }
}
