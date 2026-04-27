use super::r#gen::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type kernfs_node = CoRe<r#gen::kernfs_node>;

impl kernfs_node {
    rust_shim_kernel_impl!(pub, kernfs_node, parent, kernfs_node);
    rust_shim_kernel_impl!(pub, kernfs_node, name, *const i8);
}
