use aya_ebpf::helpers::bpf_get_current_task;

use super::r#gen::{self, *};
use super::{CoRe, cred, css_set, mm_struct, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type task_struct = CoRe<r#gen::task_struct>;

impl task_struct {
    #[inline(always)]
    pub unsafe fn current() -> Self {
        Self::from_ptr(bpf_get_current_task() as *const _)
    }

    rust_shim_kernel_impl!(pub, task_struct, pid, pid_t);
    rust_shim_kernel_impl!(pub, task_struct, tgid, pid_t);
    rust_shim_kernel_impl!(pub, task_struct, cred, cred);
    rust_shim_kernel_impl!(pub, task_struct, parent, Self);
    rust_shim_kernel_impl!(pub, task_struct, real_parent, Self);
    rust_shim_kernel_impl!(pub, task_struct, mm, mm_struct);
    rust_shim_kernel_impl!(pub, task_struct, cgroups, css_set);
    rust_shim_kernel_impl!(pub, task_struct, comm, *mut u8);

    #[inline(always)]
    pub unsafe fn loginuid(&self) -> Option<u32> {
        if !self.is_null() && shim_task_struct_loginuid_exists(self.as_ptr_mut()) {
            return Some(shim_task_struct_loginuid(self.as_ptr_mut()));
        }
        None
    }
}
