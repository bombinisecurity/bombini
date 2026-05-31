use super::r#gen::{self, *};
use super::{
    CoRe, rust_shim_kernel_impl, rust_shim_kernel_trusted_impl,
    rust_shim_kernel_trusted_or_null_impl,
};

#[allow(non_camel_case_types)]
pub type in6_addr = CoRe<r#gen::in6_addr>;

impl in6_addr {
    rust_shim_kernel_impl!(pub, in6_addr, u6_addr8, *mut u8);
}

#[allow(non_camel_case_types)]
pub type in_addr = CoRe<r#gen::in_addr>;

impl in_addr {
    rust_shim_kernel_trusted_impl!(pub, s_addr, in_addr, s_addr, u32);
}

#[allow(non_camel_case_types)]
pub type sock_common = CoRe<r#gen::sock_common>;

impl sock_common {
    rust_shim_kernel_trusted_impl!(pub, skc_family, sock_common, skc_family, u16);
    rust_shim_kernel_trusted_impl!(pub, skc_addrpair, sock_common, skc_addrpair, u64);
    rust_shim_kernel_trusted_impl!(pub, skc_portpair, sock_common, skc_portpair, u32);
    rust_shim_kernel_impl!(pub, sock_common, skc_v6_daddr, in6_addr);
    rust_shim_kernel_impl!(pub, sock_common, skc_v6_rcv_saddr, in6_addr);
}

#[allow(non_camel_case_types)]
pub type sock = CoRe<r#gen::sock>;

impl sock {
    rust_shim_kernel_trusted_impl!(pub, sk_protocol, sock, sk_protocol, u16);
    //rust_shim_kernel_impl!(pub, sock, sk_protocol, u16);
    rust_shim_kernel_impl!(pub, sock, __sk_common, sock_common);
}

#[allow(non_camel_case_types)]
pub type socket = CoRe<r#gen::socket>;

impl socket {
    rust_shim_kernel_trusted_impl!(pub, r#type, socket, r#type, i16);
    rust_shim_kernel_trusted_or_null_impl!(pub, sk, socket, sk, sock);
}

#[allow(non_camel_case_types)]
pub type sockaddr_in = CoRe<r#gen::sockaddr_in>;

impl sockaddr_in {
    rust_shim_kernel_trusted_impl!(pub, sin_port, sockaddr_in, sin_port, u16);
    rust_shim_kernel_impl!(pub, sockaddr_in, sin_addr, in_addr);
}

#[allow(non_camel_case_types)]
pub type sockaddr_in6 = CoRe<r#gen::sockaddr_in6>;

impl sockaddr_in6 {
    rust_shim_kernel_trusted_impl!(pub, sin6_port, sockaddr_in6, sin6_port, u16);
    rust_shim_kernel_impl!(pub, sockaddr_in6, sin6_addr, in6_addr);
}
