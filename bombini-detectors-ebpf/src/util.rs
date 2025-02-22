//! Provides some common functions
use aya_ebpf::helpers::bpf_probe_read_buf;

use bombini_common::event::process::ProcInfo;

/// Copy ProcInfo from src to dst. Commonly used to
/// copy process information to ring buffer
#[inline(always)]
pub fn copy_proc(src: &ProcInfo, dst: &mut ProcInfo) {
    dst.ktime = src.ktime;
    dst.pid = src.pid;
    dst.tid = src.tid;
    dst.ppid = src.ppid;
    dst.creds = src.creds.clone();
    dst.auid = src.auid;
    unsafe {
        let _ = bpf_probe_read_buf(src.filename.as_ptr(), &mut dst.filename);
        let _ = bpf_probe_read_buf(src.args.as_ptr(), &mut dst.args);
        let _ = bpf_probe_read_buf(src.binary_path.as_ptr(), &mut dst.binary_path);
    }
}
