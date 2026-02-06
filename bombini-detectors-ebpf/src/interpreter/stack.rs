use aya_ebpf::{macros::map, maps::PerCpuArray};

pub const STACK_SIZE: u32 = 64;

#[map]
static STACK_DATA: PerCpuArray<bool> = PerCpuArray::with_max_entries(STACK_SIZE, 0);

#[map]
static STACK_LEN: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

pub(super) struct Stack<'a, T> {
    data: &'a PerCpuArray<T>,
    len_ptr: *mut u32,
}

impl<'a> Stack<'a, bool> {
    pub fn new() -> Result<Self, i32> {
        let Some(len) = STACK_LEN.get_ptr_mut(0) else {
            return Err(0);
        };
        Ok(Self {
            data: &STACK_DATA,
            len_ptr: len,
        })
    }
}

impl<'a, T: Copy> Stack<'a, T> {
    pub fn push(&mut self, value: T) -> Result<(), i32> {
        unsafe {
            let len = self.len_ptr;
            if *len >= STACK_SIZE {
                return Err(0);
            }
            let Some(data_ptr) = self.data.get_ptr_mut(*len) else {
                return Err(0);
            };
            *data_ptr = value;
            *len += 1;
        }
        Ok(())
    }

    pub fn pop(&mut self) -> Result<T, i32> {
        unsafe {
            let len = self.len_ptr;
            if *len == 0 {
                return Err(0);
            }
            let Some(value) = self.data.get(*len - 1) else {
                return Err(0);
            };
            *len -= 1;
            Ok(*value)
        }
    }
}
