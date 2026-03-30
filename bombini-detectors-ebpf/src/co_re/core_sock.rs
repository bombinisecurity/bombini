use super::r#gen::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type in6_addr = CoRe<r#gen::in6_addr>;

impl in6_addr {
    rust_shim_kernel_impl!(pub, in6_addr, u6_addr8, *mut u8);
}

#[allow(non_camel_case_types)]
pub type sock_common = CoRe<r#gen::sock_common>;

impl sock_common {
    rust_shim_kernel_impl!(pub, sock_common, skc_family, u16);
    rust_shim_kernel_impl!(pub, sock_common, skc_addrpair, u64);
    rust_shim_kernel_impl!(pub, sock_common, skc_portpair, u32);
    rust_shim_kernel_impl!(pub, sock_common, skc_v6_daddr, in6_addr);
    rust_shim_kernel_impl!(pub, sock_common, skc_v6_rcv_saddr, in6_addr);
}

#[allow(non_camel_case_types)]
pub type sock = CoRe<r#gen::sock>;

impl sock {
    rust_shim_kernel_impl!(pub, sock, __sk_common, sock_common);
}
