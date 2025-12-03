//! Ring buffer to send events from all detectors.
use aya_ebpf::{
    helpers::bpf_ktime_get_boot_ns,
    macros::map,
    maps::{RingBuf, ring_buf::RingBufEntry},
};

use bombini_common::event::{Event, GenericEvent};

#[map]
pub static EVENT_MAP: RingBuf = RingBuf::pinned(1, 0);

#[inline(always)]
/// Reserve place in the ring buffer event map for given message type
///
/// # Arguments
///
/// * `msg_code` - event message type
///
/// * `zero` - fill buffer with zeros
///
/// # Return value
///
/// RingBufEntry for Event filled with zeros
pub fn rb_event_init(msg_code: u8, zero: bool) -> Result<RingBufEntry<GenericEvent>, i32> {
    let Some(mut event_rb) = EVENT_MAP.reserve::<GenericEvent>(0) else {
        return Err(0);
    };
    unsafe {
        if zero {
            aya_ebpf::memset(
                event_rb.as_mut_ptr() as *mut u8,
                0,
                core::mem::size_of_val(event_rb.assume_init_ref()),
            );
        }
        let event_ref = &mut *event_rb.as_mut_ptr();
        let p = &mut event_ref.event as *mut Event as *mut u8;
        *p = msg_code;
        event_ref.msg_code = msg_code;
        event_ref.ktime = bpf_ktime_get_boot_ns();
    }
    Ok(event_rb)
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
        let Ok(mut event_rb) = rb_event_init($msg_code, $zero) else {
            return 0;
        };
        let event_ref = unsafe { &mut *event_rb.as_mut_ptr() };
        match $handler($ctx, event_ref) {
            Ok(ret) => {
                event_rb.submit(0);
                ret
            }
            Err(ret) => {
                event_rb.discard(0);
                ret
            }
        }
    }};
}
