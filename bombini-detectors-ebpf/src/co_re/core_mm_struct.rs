use super::r#gen::{self, *};
use super::{CoRe, file, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type mm_struct = CoRe<r#gen::mm_struct>;

impl mm_struct {
    rust_shim_kernel_impl!(pub, mm_struct, arg_start, u64);
    rust_shim_kernel_impl!(pub, mm_struct, arg_end, u64);
    rust_shim_kernel_impl!(pub, mm_struct, exe_file, file);
}
