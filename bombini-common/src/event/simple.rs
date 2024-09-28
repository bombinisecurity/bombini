//! Simple event message

#[derive(Clone, Debug)]
#[repr(C)]
pub struct SimpleEvent {
    pub pid: u32,
    pub uid: u32,
}
