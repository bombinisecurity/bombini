use super::r#gen::{self, *};
use super::{CoRe, cred, file, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type linux_binprm = CoRe<r#gen::linux_binprm>;

impl linux_binprm {
    rust_shim_kernel_impl!(pub, linux_binprm, file, file);
    rust_shim_kernel_impl!(pub, linux_binprm, cred, cred);
    rust_shim_kernel_impl!(pub, linux_binprm, per_clear, u32);
}
