//! kernel event module

use crate::constants::{MAX_BPFNAME_SIZE, MAX_HOOKNAME_SIZE};
use crate::event::file::AccessMode;
use crate::event::process::ProcessKey;
#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// Kernel event message
#[derive(Clone, Debug)]
#[repr(C)]
pub struct KernelMsg {
    pub process: ProcessKey,
    pub parent: ProcessKey,
    pub event: KernelEventVariant,
    /// true if event is blocked by corresponding LSM hook
    pub blocked: bool,
    pub rule_idx: Option<u8>,
}

/// Should be the same as in the kernel
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[repr(u32)]
pub enum BpfMapType {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,
    BPF_MAP_TYPE_CPUMAP,
    BPF_MAP_TYPE_XSKMAP,
    BPF_MAP_TYPE_SOCKHASH,
    BPF_MAP_TYPE_CGROUP_STORAGE,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    BPF_MAP_TYPE_QUEUE,
    BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_DEVMAP_HASH,
    BPF_MAP_TYPE_STRUCT_OPS,
    BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_INODE_STORAGE,
    BPF_MAP_TYPE_TASK_STORAGE,
    BPF_MAP_TYPE_BLOOM_FILTER,
    BPF_MAP_TYPE_USER_RINGBUF,
    BPF_MAP_TYPE_CGRP_STORAGE,
    BPF_MAP_TYPE_ARENA,
    BPF_MAP_TYPE_INSN_ARRAY,
    __MAX_BPF_MAP_TYPE,
}

/// Should be the same as in the kernel
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[repr(u32)]
pub enum BpfProgType {
    BPF_PROG_TYPE_UNSPEC = 0,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
    BPF_PROG_TYPE_CGROUP_DEVICE,
    BPF_PROG_TYPE_SK_MSG,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    BPF_PROG_TYPE_LWT_SEG6LOCAL,
    BPF_PROG_TYPE_LIRC_MODE2,
    BPF_PROG_TYPE_SK_REUSEPORT,
    BPF_PROG_TYPE_FLOW_DISSECTOR,
    BPF_PROG_TYPE_CGROUP_SYSCTL,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    BPF_PROG_TYPE_CGROUP_SOCKOPT,
    BPF_PROG_TYPE_TRACING,
    BPF_PROG_TYPE_STRUCT_OPS,
    BPF_PROG_TYPE_EXT,
    BPF_PROG_TYPE_LSM,
    BPF_PROG_TYPE_SK_LOOKUP,
    BPF_PROG_TYPE_SYSCALL, /* a program that can execute syscalls */
    BPF_PROG_TYPE_NETFILTER,
    __MAX_BPF_PROG_TYPE,
}

/// Bpf map event info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct BpfMapAccess {
    pub id: u32,
    pub name: [u8; MAX_BPFNAME_SIZE],
    pub map_type: BpfMapType,
    pub access_mode: AccessMode,
}

/// Bpf map create event info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct BpfMapCreate {
    pub name: [u8; MAX_BPFNAME_SIZE],
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// Bpf program event info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct BpfProgAccess {
    pub id: u32,
    pub name: [u8; MAX_BPFNAME_SIZE],
    pub hook: [u8; MAX_HOOKNAME_SIZE],
    pub prog_type: BpfProgType,
}

/// Bpf program load event info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct BpfProgLoad {
    pub name: [u8; MAX_BPFNAME_SIZE],
    pub prog_type: BpfProgType,
}

/// Raw Kernel event messages
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum KernelEventVariant {
    BpfMapAccess(BpfMapAccess) = KernelEventNumber::BpfMapAccess as u8,
    BpfMapCreate(BpfMapCreate) = KernelEventNumber::BpfMapCreate as u8,
    BpfProgAccess(BpfProgAccess) = KernelEventNumber::BpfProgAccess as u8,
    BpfProgLoad(BpfProgLoad) = KernelEventNumber::BpfProgLoad as u8,
}

pub enum KernelEventNumber {
    BpfMapAccess = 0,
    BpfMapCreate,
    BpfProgAccess,
    BpfProgLoad,
    TotalKernelEvents,
}
