use super::CoRe;
use super::r#gen::{self, *};

#[allow(non_camel_case_types)]
pub type cred = CoRe<r#gen::cred>;

impl cred {
    #[inline(always)]
    pub unsafe fn uid(&self) -> u32 {
        shim_cred_uid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn gid(&self) -> u32 {
        shim_cred_gid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn euid(&self) -> u32 {
        shim_cred_euid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn egid(&self) -> u32 {
        shim_cred_egid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn cap_effective(&self) -> u64 {
        shim_cred_cap_effective(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn cap_inheritable(&self) -> u64 {
        shim_cred_cap_inheritable(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn cap_permitted(&self) -> u64 {
        shim_cred_cap_permitted(self.as_ptr_mut())
    }
}
