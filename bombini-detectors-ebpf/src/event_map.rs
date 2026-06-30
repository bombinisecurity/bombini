//! Ring buffer to send events from all detectors.

use aya_ebpf::{
    bindings::bpf_dynptr,
    helpers::{
        bpf_ktime_get_boot_ns,
        generated::{bpf_dynptr_from_mem, bpf_dynptr_write},
    },
    macros::map,
    maps::{Array, PerCpuArray, RingBuf},
};

use bombini_common::{
    constants::MAX_EVENT_SIZE,
    event::{Event, GenericEvent},
};

#[map]
pub static EVENT_MAP: RingBuf = RingBuf::pinned(1, 0);

#[map]
static ZERO_EVENT_MAP: Array<[u8; MAX_EVENT_SIZE]> = Array::pinned(1, 0);

#[map]
pub static BOMBINI_EVENT: PerCpuArray<GenericEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static BOMBINI_BPF_ERRORS_TOTAL: PerCpuArray<u64> = PerCpuArray::pinned(1, 0);

#[map]
pub static BOMBINI_BPF_EVENTS_LOST_TOTAL: PerCpuArray<u64> = PerCpuArray::pinned(1, 0);

#[inline(always)]
/// Reserve place in the ring buffer event map for given message type
///
/// # Arguments
///
/// * `msg_code` - event message type
///
/// * `zero` - fill buffer with zeros
pub fn rb_event_init(msg_code: u8, zero: bool) -> Result<&'static mut GenericEvent, i32> {
    unsafe {
        let Some(event_ptr) = BOMBINI_EVENT.get_ptr_mut(0) else {
            return Err(-1);
        };
        let event = event_ptr.as_mut();
        let Some(event_ref) = event else {
            return Err(-1);
        };
        if zero {
            let mut tmp = bpf_dynptr { __opaque: [0, 0] };
            let Some(zero_ptr) = ZERO_EVENT_MAP.get_ptr_mut(0) else {
                return Err(-1);
            };
            bpf_dynptr_from_mem(
                event_ref as *mut _ as *mut _,
                core::mem::size_of::<GenericEvent>() as u32,
                0,
                &mut tmp as *mut _,
            );
            bpf_dynptr_write(
                &tmp as *const _,
                0,
                zero_ptr as *mut _,
                core::mem::size_of::<GenericEvent>() as u32,
                0,
            );
        }
        // <VERIFIER_ISSUE>
        // Very dirty hack to make BPF verifier happy with stack area used for dynptr.
        // After dynptr is passed away from the scope, BPF verifier still thinks that stack area is untouchable.
        // We can create new variable that will may separate this stack area from the dynptr.
        let __very_dirty_verifier_hack = 0u8;
        core::hint::black_box(__very_dirty_verifier_hack);

        let p = &mut event_ref.event as *mut Event as *mut u8;
        *p = msg_code;
        event_ref.msg_code = msg_code;
        event_ref.ktime = bpf_ktime_get_boot_ns();
        Ok(event_ref)
    }
}

#[inline(always)]
pub fn trace_error() {
    let Some(errors) = BOMBINI_BPF_ERRORS_TOTAL.get_ptr_mut(0) else {
        return;
    };

    unsafe {
        *errors += 1;
    }
}

#[inline(always)]
pub fn trace_ringbuf_error() {
    let Some(evetnts_lost) = BOMBINI_BPF_EVENTS_LOST_TOTAL.get_ptr_mut(0) else {
        return;
    };

    unsafe {
        *evetnts_lost += 1;
    }
}

/// This macro reserves place for event in ring buffer event map, calls
/// function to fill the event and then submits it.
///
/// # Arguments
///
/// * `ctx` - execution context of the hook: kprobe, tracepoint, etc.
///
/// * `msg_code` - event message type
///
/// * `zero` - fill event with zeros
///
/// * `handler` - function name to handle and fill the event
#[macro_export]
macro_rules! event_capture {
    ($ctx:expr, $msg_code:expr, $zero:expr, $handler:expr) => {{
        let Ok(event_ref) = $crate::event_map::rb_event_init($msg_code, $zero) else {
            $crate::event_map::trace_error();
            return 0;
        };

        match $handler($ctx, event_ref) {
            Ok(ret) => {
                if $crate::event_map::EVENT_MAP
                    .output::<GenericEvent>(event_ref, 0)
                    .is_err()
                {
                    $crate::event_map::trace_ringbuf_error();
                }
                ret
            }
            Err(ret) => {
                if ret != 0 {
                    $crate::event_map::trace_error();
                }
                0
            }
        }
    }};
}
