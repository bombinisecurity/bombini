#![no_std]
#![no_main]

pub mod dyn_ringbuf;
pub mod event_map;
pub mod filter;
pub mod interpreter;
pub mod util;
#[allow(clippy::all)]
#[allow(warnings)]
#[rustfmt::skip]
pub mod vmlinux;
#[allow(unsafe_op_in_unsafe_fn)]
pub mod co_re;
