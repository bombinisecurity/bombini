use super::r#gen::{self, *};
use super::{CoRe, kernfs_node, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type cgroup = CoRe<r#gen::cgroup>;

impl cgroup {
    rust_shim_kernel_impl!(pub, cgroup, kn, kernfs_node);
}

#[allow(non_camel_case_types)]
pub type css_set = CoRe<r#gen::css_set>;

impl css_set {
    rust_shim_kernel_impl!(pub, css_set, dfl_cgrp, cgroup);
}
