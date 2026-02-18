use aya_ebpf::{macros::map, maps::PerCpuArray};

pub const STACK_SIZE: usize = 65;

#[map]
static STACK_DATA: PerCpuArray<[bool; STACK_SIZE]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static STACK_LEN: PerCpuArray<usize> = PerCpuArray::with_max_entries(1, 0);

pub(super) struct Stack<T> {
    data_ptr: *mut [T; STACK_SIZE],
    len_ptr: *mut usize,
}

impl Stack<bool> {
    pub fn new() -> Result<Self, i32> {
        let Some(data) = STACK_DATA.get_ptr_mut(0) else {
            return Err(0);
        };
        let Some(len) = STACK_LEN.get_ptr_mut(0) else {
            return Err(0);
        };
        unsafe {
            // Starting stack from 1 to avoid 0 as a valid value
            // This is because zero check in pop operation is not sufficient for verifier
            // to prove that len is always greater than 0
            *len = 1;
        }
        Ok(Self {
            data_ptr: data,
            len_ptr: len,
        })
    }
}

impl<T: Copy> Stack<T> {
    pub fn push(&mut self, value: T) -> Result<(), i32> {
        unsafe {
            let len = *self.len_ptr;
            if len >= STACK_SIZE {
                return Err(0);
            }
            (*self.data_ptr)[len] = value;
            *self.len_ptr += 1;
        }
        Ok(())
    }

    pub fn pop(&mut self) -> Result<T, i32> {
        unsafe {
            let mut len = *self.len_ptr;
            if len >= STACK_SIZE {
                return Err(0);
            }
            // Stack starts with 1, so we need to check if len will be greater than 1 before subtracting
            if len < 2 {
                return Err(0);
            }
            len -= 1;

            let value = (*self.data_ptr)[len];
            *self.len_ptr -= 1;
            Ok(value)
        }
    }
}
