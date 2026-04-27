use super::r#gen::{self, *};
use super::{CoRe, rust_shim_kernel_impl, rust_shim_kernel_impl_ptr};

#[allow(non_camel_case_types)]
pub type io_kiocb = CoRe<r#gen::io_kiocb>;

impl io_kiocb {
    rust_shim_kernel_impl_ptr!(pub, cmd, io_kiocb, cmd, *const u8);
    rust_shim_kernel_impl!(pub, io_kiocb, opcode, u8);
}

#[allow(non_camel_case_types)]
pub type filename = CoRe<r#gen::filename>;

impl filename {
    rust_shim_kernel_impl!(pub, filename, name, *const i8);
}

#[allow(non_camel_case_types)]
pub type open_how = CoRe<r#gen::open_how>;

impl open_how {
    rust_shim_kernel_impl!(pub, open_how, flags, u64);
}
