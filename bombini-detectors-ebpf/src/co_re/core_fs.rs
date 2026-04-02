use super::r#gen::{self, *};
use super::{CoRe, rust_shim_kernel_impl, rust_shim_kernel_trusted_impl};

#[allow(non_camel_case_types)]
pub type qstr = CoRe<r#gen::qstr>;

impl qstr {
    rust_shim_kernel_impl!(pub, qstr, name, *const u8);
}

#[allow(non_camel_case_types)]
pub type dentry = CoRe<r#gen::dentry>;

impl dentry {
    rust_shim_kernel_impl!(pub, dentry, d_name, qstr);
}

#[allow(non_camel_case_types)]
pub type path = CoRe<r#gen::path>;

impl path {
    rust_shim_kernel_trusted_impl!(pub, dentry_trusted, path, dentry, dentry);
    rust_shim_kernel_impl!(pub, path, dentry, dentry);
}

#[allow(non_camel_case_types)]
pub type inode = CoRe<r#gen::inode>;

impl inode {
    rust_shim_kernel_impl!(pub, inode, i_mode, u16);
    rust_shim_kernel_impl!(pub, inode, i_ino, u64);
    rust_shim_kernel_impl!(pub, inode, __i_nlink, u32);

    #[inline(always)]
    pub unsafe fn i_uid(&self) -> u32 {
        shim_inode_i_uid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn i_gid(&self) -> u32 {
        shim_inode_i_gid(self.as_ptr_mut())
    }
}

#[allow(non_camel_case_types)]
pub type file = CoRe<r#gen::file>;

impl file {
    rust_shim_kernel_trusted_impl!(pub, f_inode_trusted, file, f_inode, inode);
    rust_shim_kernel_impl!(pub, file, f_path, path);
    rust_shim_kernel_impl!(pub, file, f_inode, inode);
    rust_shim_kernel_impl!(pub, file, f_flags, u32);
}
