//! IP filtering interface

use aya_ebpf::{
    helpers::bpf_probe_read_kernel_buf,
    macros::map,
    maps::{
        lpm_trie::{Key, LpmTrie},
        per_cpu_array::PerCpuArray,
    },
};

use bombini_common::config::network::IpFilterMask;

#[map]
static FILTER_IP4_PREFIX_MAP: PerCpuArray<Key<[u8; 4]>> = PerCpuArray::with_max_entries(1, 0);
#[map]
static FILTER_IP6_PREFIX_MAP: PerCpuArray<Key<[u8; 16]>> = PerCpuArray::with_max_entries(1, 0);

/// Holds references for filtering maps.
/// This set of maps represents a white list.
pub struct Ipv4Filter<'a> {
    prefix_src_map_v4: &'a LpmTrie<[u8; 4], u8>,
    prefix_dst_map_v4: &'a LpmTrie<[u8; 4], u8>,
}

impl<'a> Ipv4Filter<'a> {
    /// Constracts Ipv4Filter from maps references
    pub fn new(
        prefix_src_map_v4: &'a LpmTrie<[u8; 4], u8>,
        prefix_dst_map_v4: &'a LpmTrie<[u8; 4], u8>,
    ) -> Self {
        Ipv4Filter {
            prefix_src_map_v4,
            prefix_dst_map_v4,
        }
    }

    /// Check if v4 address is in IPv4 maps.
    pub fn filter(&self, mask: IpFilterMask, src: &[u8; 4], dst: &[u8; 4]) -> bool {
        if mask.intersects(
            IpFilterMask::SOURCE_IP4_INGRESS_ALLOW
                | IpFilterMask::SOURCE_IP4_EGRESS_ALLOW
                | IpFilterMask::SOURCE_IP4_EGRESS_DENY
                | IpFilterMask::SOURCE_IP4_INGRESS_DENY,
        ) {
            let Some(prefix) = FILTER_IP4_PREFIX_MAP.get_ptr_mut(0) else {
                return false;
            };
            let prefix = unsafe { prefix.as_mut() };
            let Some(prefix) = prefix else {
                return false;
            };
            prefix.data[0] = src[0];
            prefix.data[1] = src[1];
            prefix.data[2] = src[2];
            prefix.data[3] = src[3];
            prefix.prefix_len = 32_u32;
            if mask.intersects(
                IpFilterMask::SOURCE_IP4_INGRESS_ALLOW | IpFilterMask::SOURCE_IP4_EGRESS_ALLOW,
            ) && self.prefix_src_map_v4.get(&mut *prefix).is_some()
            {
                return true;
            }
            if mask.intersects(
                IpFilterMask::SOURCE_IP4_INGRESS_DENY | IpFilterMask::SOURCE_IP4_EGRESS_DENY,
            ) && self.prefix_src_map_v4.get(&mut *prefix).is_none()
            {
                return true;
            }
        }
        if mask.intersects(
            IpFilterMask::DEST_IP4_INGRESS_ALLOW
                | IpFilterMask::DEST_IP4_INGRESS_DENY
                | IpFilterMask::DEST_IP4_EGRESS_ALLOW
                | IpFilterMask::DEST_IP4_EGRESS_DENY,
        ) {
            let Some(prefix) = FILTER_IP4_PREFIX_MAP.get_ptr_mut(0) else {
                return false;
            };
            let prefix = unsafe { prefix.as_mut() };
            let Some(prefix) = prefix else {
                return false;
            };
            prefix.data[0] = dst[0];
            prefix.data[1] = dst[1];
            prefix.data[2] = dst[2];
            prefix.data[3] = dst[3];
            prefix.prefix_len = 32_u32;
            if mask.intersects(
                IpFilterMask::DEST_IP4_INGRESS_ALLOW | IpFilterMask::DEST_IP4_EGRESS_ALLOW,
            ) && self.prefix_dst_map_v4.get(&mut *prefix).is_some()
            {
                return true;
            }
            if mask.intersects(
                IpFilterMask::DEST_IP4_INGRESS_DENY | IpFilterMask::DEST_IP4_EGRESS_DENY,
            ) && self.prefix_dst_map_v4.get(&mut *prefix).is_none()
            {
                return true;
            }
        }
        false
    }
}

/// Holds references for filtering maps.
/// This set of maps represents a white list.
pub struct Ipv6Filter<'a> {
    prefix_src_map_v6: &'a LpmTrie<[u8; 16], u8>,
    prefix_dst_map_v6: &'a LpmTrie<[u8; 16], u8>,
}

impl<'a> Ipv6Filter<'a> {
    /// Constracts Ipv6Filter from maps references
    pub fn new(
        prefix_src_map_v6: &'a LpmTrie<[u8; 16], u8>,
        prefix_dst_map_v6: &'a LpmTrie<[u8; 16], u8>,
    ) -> Self {
        Ipv6Filter {
            prefix_src_map_v6,
            prefix_dst_map_v6,
        }
    }

    /// Check if v6 address is in IPv6 maps.
    pub fn filter(&self, mask: IpFilterMask, src: &[u8; 16], dst: &[u8; 16]) -> bool {
        if mask.intersects(
            IpFilterMask::SOURCE_IP6_INGRESS_ALLOW
                | IpFilterMask::SOURCE_IP6_INGRESS_DENY
                | IpFilterMask::SOURCE_IP6_EGRESS_ALLOW
                | IpFilterMask::SOURCE_IP6_EGRESS_DENY,
        ) {
            let Some(prefix) = FILTER_IP6_PREFIX_MAP.get_ptr_mut(0) else {
                return false;
            };
            let prefix = unsafe { prefix.as_mut() };
            let Some(prefix) = prefix else {
                return false;
            };
            let _ = unsafe { bpf_probe_read_kernel_buf(src as *const _, &mut prefix.data) };
            prefix.prefix_len = 16 * 8_u32;
            if mask.intersects(
                IpFilterMask::SOURCE_IP6_INGRESS_ALLOW | IpFilterMask::SOURCE_IP6_EGRESS_ALLOW,
            ) && self.prefix_src_map_v6.get(&mut *prefix).is_some()
            {
                return true;
            }
            if mask.intersects(
                IpFilterMask::SOURCE_IP6_INGRESS_DENY | IpFilterMask::SOURCE_IP6_EGRESS_DENY,
            ) && self.prefix_src_map_v6.get(&mut *prefix).is_none()
            {
                return true;
            }
        }
        if mask.intersects(
            IpFilterMask::DEST_IP6_INGRESS_ALLOW
                | IpFilterMask::DEST_IP6_INGRESS_DENY
                | IpFilterMask::DEST_IP6_EGRESS_ALLOW
                | IpFilterMask::DEST_IP6_EGRESS_DENY,
        ) {
            let Some(prefix) = FILTER_IP6_PREFIX_MAP.get_ptr_mut(0) else {
                return false;
            };
            let prefix = unsafe { prefix.as_mut() };
            let Some(prefix) = prefix else {
                return false;
            };
            let _ = unsafe { bpf_probe_read_kernel_buf(dst as *const _, &mut prefix.data) };
            prefix.prefix_len = 16 * 8_u32;
            if mask.intersects(
                IpFilterMask::DEST_IP6_INGRESS_ALLOW | IpFilterMask::DEST_IP6_EGRESS_ALLOW,
            ) && self.prefix_dst_map_v6.get(&mut *prefix).is_some()
            {
                return true;
            }
            if mask.intersects(
                IpFilterMask::DEST_IP6_INGRESS_DENY | IpFilterMask::DEST_IP6_EGRESS_DENY,
            ) && self.prefix_dst_map_v6.get(&mut *prefix).is_none()
            {
                return true;
            }
        }
        false
    }
}
