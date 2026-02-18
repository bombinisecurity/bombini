//! Ring buffer to send events from all detectors.

use aya_ebpf::{helpers::bpf_ktime_get_boot_ns, macros::map};

use bombini_common::event::{Event, GenericEvent};

use crate::dyn_ringbuf::{DynRingBuf, DynRingBufEntry};

#[map]
pub static EVENT_MAP: DynRingBuf = DynRingBuf::pinned(1, 0);

#[inline(always)]
/// Reserve place in the ring buffer event map for given message type
///
/// # Arguments
///
/// * `msg_code` - event message type
///
/// * `zero` - fill buffer with zeros
///
/// * `ring_entry` - ring buffer entry
pub fn rb_event_init(
    msg_code: u8,
    zero: bool,
    ring_entry: &mut DynRingBufEntry<GenericEvent>,
) -> Result<(), i32> {
    EVENT_MAP.reserve::<GenericEvent>(0, ring_entry)?;
    unsafe {
        if zero {
            ring_entry.zero_entry()?;
        }
        let Some(event_ref) = ring_entry.get_ptr_mut() else {
            return Err(0);
        };
        let p = event_ref as *mut Event as *mut u8;
        *p = msg_code;
        (*event_ref).msg_code = msg_code;
        (*event_ref).ktime = bpf_ktime_get_boot_ns();
    }
    Ok(())
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
        use bombini_detectors_ebpf::dyn_ringbuf::DynRingBufEntry;
        let mut ring_entry = DynRingBufEntry::new();

        if rb_event_init($msg_code, $zero, &mut ring_entry).is_err() {
            ring_entry.discard(0);
            return 0;
        };
        let Some(ring_data) = ring_entry.get_ptr_mut() else {
            ring_entry.discard(0);
            return 0;
        };
        let event_ref = unsafe { &mut *ring_data };
        match $handler($ctx, event_ref) {
            Ok(ret) => {
                ring_entry.submit(0);
                ret
            }
            Err(ret) => {
                ring_entry.discard(0);
                ret
            }
        }
    }};
}
