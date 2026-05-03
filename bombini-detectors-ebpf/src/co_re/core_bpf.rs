use crate::rust_shim_kernel_trusted_impl;

use super::r#gen::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type bpf_prog_aux = CoRe<r#gen::bpf_prog_aux>;

impl bpf_prog_aux {
    rust_shim_kernel_impl!(pub, bpf_prog_aux, id, u32);
    rust_shim_kernel_impl!(pub, bpf_prog_aux, name, *mut u8);
    rust_shim_kernel_impl!(pub, bpf_prog_aux, attach_func_name, *const u8);
}

#[allow(non_camel_case_types)]
pub type bpf_prog = CoRe<r#gen::bpf_prog>;

impl bpf_prog {
    rust_shim_kernel_impl!(pub, prog_type, bpf_prog, r#type, u32);
    rust_shim_kernel_impl!(pub, bpf_prog, aux, bpf_prog_aux);
}

#[allow(non_camel_case_types)]
pub type bpf_map = CoRe<r#gen::bpf_map>;

impl bpf_map {
    rust_shim_kernel_trusted_impl!(pub, map_type, bpf_map, map_type, u32);
    rust_shim_kernel_trusted_impl!(pub, key_size, bpf_map, key_size, u32);
    rust_shim_kernel_trusted_impl!(pub, value_size, bpf_map, value_size, u32);
    rust_shim_kernel_trusted_impl!(pub, max_entries, bpf_map, max_entries, u32);
    rust_shim_kernel_trusted_impl!(pub, id, bpf_map, id, u32);
    rust_shim_kernel_impl!(pub, bpf_map, name, *mut u8);
}
