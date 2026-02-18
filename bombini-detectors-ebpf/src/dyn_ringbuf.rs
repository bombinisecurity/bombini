//! Ring buffer to send events from all detectors.
use core::{cell::UnsafeCell, marker::PhantomData, ptr::NonNull};

use aya_ebpf::{
    bindings::{bpf_dynptr, bpf_map_def, bpf_map_type::BPF_MAP_TYPE_RINGBUF},
    helpers::r#gen::{
        bpf_dynptr_data, bpf_dynptr_write, bpf_ringbuf_discard_dynptr, bpf_ringbuf_submit_dynptr,
    },
    macros::map,
    maps::Array,
};

use aya_ebpf::helpers::r#gen::bpf_ringbuf_reserve_dynptr;

use bombini_common::constants::MAX_EVENT_SIZE;

#[map]
static ZERO_EVENT_MAP: Array<[u8; MAX_EVENT_SIZE]> = Array::with_max_entries(1, 0);

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PinningType {
    None = 0,
    ByName = 1,
}

#[repr(transparent)]
pub struct DynRingBuf {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for DynRingBuf {}

pub struct DynRingBufEntry<T: 'static> {
    pub dynptr: bpf_dynptr,
    pub _type: PhantomData<T>,
}

impl<T: 'static> Default for DynRingBufEntry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: 'static> DynRingBufEntry<T> {
    pub fn new() -> Self {
        DynRingBufEntry {
            dynptr: bpf_dynptr { __opaque: [0, 0] },
            _type: PhantomData,
        }
    }

    /// Discard this ring buffer entry. The entry will be skipped by the userspace reader.
    pub fn discard(&mut self, flags: u64) {
        unsafe { bpf_ringbuf_discard_dynptr(&mut self.dynptr as *mut _, flags) };
    }

    /// Commit this ring buffer entry. The entry will be made visible to the userspace reader.
    pub fn submit(&mut self, flags: u64) {
        unsafe { bpf_ringbuf_submit_dynptr(&mut self.dynptr as *mut _, flags) };
    }

    #[inline(always)]
    pub fn zero_entry(&self) -> Result<(), i32> {
        let Some(zero_ptr) = ZERO_EVENT_MAP.get_ptr_mut(0) else {
            return Err(0);
        };
        unsafe {
            bpf_dynptr_write(
                &self.dynptr as *const _,
                0,
                zero_ptr as *mut _,
                core::mem::size_of::<T>() as u32,
                0,
            );
        }
        Ok(())
    }

    pub fn get_ptr_mut(&mut self) -> Option<*mut T> {
        unsafe {
            NonNull::new(bpf_dynptr_data(
                &mut self.dynptr as *mut _,
                0,
                core::mem::size_of::<T>() as u32,
            ) as *mut T)
            .map(|x| x.as_ptr())
        }
    }
}

impl DynRingBuf {
    /// Declare an eBPF ring buffer.
    ///
    /// The linux kernel requires that `byte_size` be a power-of-2 multiple of the page size. The
    /// loading program may coerce the size when loading the map.
    pub const fn with_byte_size(byte_size: u32, flags: u32) -> Self {
        Self::new(byte_size, flags, PinningType::None)
    }

    /// Declare a pinned eBPF ring buffer.
    ///
    /// The linux kernel requires that `byte_size` be a power-of-2 multiple of the page size. The
    /// loading program may coerce the size when loading the map.
    pub const fn pinned(byte_size: u32, flags: u32) -> Self {
        Self::new(byte_size, flags, PinningType::ByName)
    }

    const fn new(byte_size: u32, flags: u32, pinning_type: PinningType) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries: byte_size,
                map_flags: flags,
                id: 0,
                pinning: pinning_type as u32,
            }),
        }
    }

    #[inline(always)]
    /// Reserve memory in the ring buffer that can fit `T`.
    ///
    /// Returns `Err` if the ring buffer is full.
    ///
    /// The kernel will reserve memory at an 8-bytes aligned boundary, so `mem::align_of<T>()` must
    /// be equal or smaller than 8. If you use this with a `T` that isn't properly aligned, this
    /// function will be compiled to a panic; depending on your panic_handler, this may make
    /// the eBPF program fail to load, or it may make it have undefined behavior.
    pub fn reserve<T: 'static>(&self, flags: u64, ret: &mut DynRingBufEntry<T>) -> Result<(), i32> {
        assert_eq!(8 % core::mem::align_of::<T>(), 0);
        let ret_code = unsafe {
            bpf_ringbuf_reserve_dynptr(
                self.def.get() as *mut _,
                core::mem::size_of::<T>() as u32,
                flags,
                &mut ret.dynptr as *mut _,
            )
        };

        if ret_code < 0 {
            return Err(ret_code as i32);
        }

        Ok(())
    }
}
