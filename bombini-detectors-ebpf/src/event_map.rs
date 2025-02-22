//! Ring buffer to send events from all detectors.
use aya_ebpf::{
    macros::map,
    maps::{ring_buf::RingBufEntry, RingBuf},
};

use bombini_common::event::Event;

#[map]
pub static EVENT_MAP: RingBuf = RingBuf::pinned(1, 0);

#[inline(always)]
/// Reserve place in the ring buffer event map for given message type
///
/// # Arguments
///
/// * `msg_code` - event message type
///
/// # Return value
///
/// RingBufEntry for Event
pub fn rb_event_init(msg_code: u8) -> Result<RingBufEntry<Event>, u32> {
    let Some(mut event_rb) = EVENT_MAP.reserve::<Event>(0) else {
        return Err(0);
    };
    unsafe {
        let p = event_rb.as_mut_ptr() as *mut u8;
        *p = msg_code;
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
/// * `handler` - function name to handle and fill the event
///
/// * `expose` - true if events are aimed to expose
#[macro_export]
macro_rules! event_capture {
    ($ctx:expr, $msg_code:expr, $handler:expr, $expose:expr) => {{
        let Ok(mut event_rb) = rb_event_init($msg_code) else {
            return 0;
        };
        let event_ref = unsafe { &mut *event_rb.as_mut_ptr() };
        match $handler($ctx, event_ref, $expose) {
            Ok(ret) => {
                if $expose {
                    event_rb.submit(0);
                } else {
                    event_rb.discard(0);
                }
                ret
            }
            Err(ret) => {
                event_rb.discard(0);
                ret
            }
        }
    }};
}
