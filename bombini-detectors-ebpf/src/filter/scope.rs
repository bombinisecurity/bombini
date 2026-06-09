use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::config::rule::Predicate;
use bombini_common::config::rule::{Attributes, FileNameMapKey, PathMapKey, PathPrefixMapKey};
use bombini_common::constants::MAX_RULES_COUNT;

use crate::interpreter::{CheckIn, Interpreter};

/// Binary-only scope filter (executing process binary name/path/prefix).
///
/// Used by detectors whose hooks are too complex to also pre-compute
/// parent/ancestor scope within the BPF verifier's instruction limit (netmon,
/// kernelmon). It looks the maps up lazily during rule interpretation — the
/// original, cheap approach — and supports only the `binary_*` scope attributes.
#[repr(C)]
pub struct BinaryScopeFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
}

impl<'a> BinaryScopeFilter<'a> {
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            name,
            path,
            prefix,
        }
    }
}

impl CheckIn for BinaryScopeFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == Attributes::BinaryName as u8 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::BinaryPath as u8 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::BinaryPrefix as u8 => {
                let Some(mask_path) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            }
            _ => Err(-1),
        }
    }
}

/// Generate the six per-hook scope precompute functions for a detector and bind
/// them to that detector's maps. See `bombini-detectors-ebpf/src/bin/procmon`
/// and the `bombini-bpf-mapptr-spill` design note for the rationale (one static
/// filter map live per `#[inline(never)]` subprogram to avoid map-pointer spills,
/// and parent+ancestor combined into one walk to stay under the verifier's
/// instruction limit).
///
/// Generates, given `$hook = foo`:
/// `precompute_foo_binary_name/path/prefix` (walk depth 1 from the supplied pid)
/// and `precompute_foo_pa_name/path/prefix` (walk `$depth` levels, depth 0 fills
/// the parent results, all levels fill the ancestor results).
///
/// Required in scope at the expansion site: `bpf_probe_read_kernel_str_bytes`,
/// `bpf_probe_read_kernel_buf`, `MAX_RULES_COUNT`, `MAX_FILENAME_SIZE`,
/// `MAX_FILE_PATH`, `MAX_FILE_PREFIX`.
#[macro_export]
macro_rules! gen_scope_precompute {
    (
        $hook:ident,
        proc_map = $proc_map:ident,
        results = $results:ident,
        name_key = $name_key:ident,
        path_key = $path_key:ident,
        prefix_key = $prefix_key:ident,
        depth = $depth:expr,
        bin = [$bin_name:ident, $bin_path:ident, $bin_prefix:ident],
        parent = [$parent_name:ident, $parent_path:ident, $parent_prefix:ident],
        ancestor = [$anc_name:ident, $anc_path:ident, $anc_prefix:ident]
        $(,)?
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<precompute_ $hook _binary_name>](pid: u32) -> Result<(), i32> {
                unsafe {
                    let res = $results.get_ptr_mut(0).ok_or(-1i32)?;
                    (*res).binary_name = [0u8; MAX_RULES_COUNT];
                    let mut cur = pid;
                    let mut depth = 0;
                    while depth < 1usize {
                        let Some(p) = $proc_map.get(&cur) else { break; };
                        let key = $name_key.get_ptr_mut(0).ok_or(-1i32)?;
                        (*key).name = [0u8; MAX_FILENAME_SIZE];
                        bpf_probe_read_kernel_str_bytes(p.filename.as_ptr() as *const u8, &mut (*key).name).ok();
                        let mut ridx = 0;
                        while ridx < MAX_RULES_COUNT {
                            (*key).rule_idx = ridx as u8;
                            (*res).binary_name[ridx] |= $bin_name.get(&*key).copied().unwrap_or(0);
                            ridx += 1;
                        }
                        cur = p.ppid;
                        depth += 1;
                    }
                }
                Ok(())
            }

            #[inline(never)]
            fn [<precompute_ $hook _binary_path>](pid: u32) -> Result<(), i32> {
                unsafe {
                    let res = $results.get_ptr_mut(0).ok_or(-1i32)?;
                    (*res).binary_path = [0u8; MAX_RULES_COUNT];
                    let mut cur = pid;
                    let mut depth = 0;
                    while depth < 1usize {
                        let Some(p) = $proc_map.get(&cur) else { break; };
                        let key = $path_key.get_ptr_mut(0).ok_or(-1i32)?;
                        (*key).path = [0u8; MAX_FILE_PATH];
                        bpf_probe_read_kernel_str_bytes(p.binary_path.as_ptr() as *const u8, &mut (*key).path).ok();
                        let mut ridx = 0;
                        while ridx < MAX_RULES_COUNT {
                            (*key).rule_idx = ridx as u8;
                            (*res).binary_path[ridx] |= $bin_path.get(&*key).copied().unwrap_or(0);
                            ridx += 1;
                        }
                        cur = p.ppid;
                        depth += 1;
                    }
                }
                Ok(())
            }

            #[inline(never)]
            fn [<precompute_ $hook _binary_prefix>](pid: u32) -> Result<(), i32> {
                unsafe {
                    let res = $results.get_ptr_mut(0).ok_or(-1i32)?;
                    (*res).binary_prefix = [0u8; MAX_RULES_COUNT];
                    let mut cur = pid;
                    let mut depth = 0;
                    while depth < 1usize {
                        let Some(p) = $proc_map.get(&cur) else { break; };
                        let key = $prefix_key.get_ptr_mut(0).ok_or(-1i32)?;
                        (*key).data.path_prefix = [0u8; MAX_FILE_PREFIX];
                        bpf_probe_read_kernel_buf(p.binary_path.as_ptr() as *const u8, &mut (*key).data.path_prefix).ok();
                        (*key).prefix_len = (MAX_FILE_PREFIX * 8) as u32;
                        let mut ridx = 0;
                        while ridx < MAX_RULES_COUNT {
                            (*key).data.rule_idx = ridx as u8;
                            (*res).binary_prefix[ridx] |= $bin_prefix.get(&*key).copied().unwrap_or(0);
                            ridx += 1;
                        }
                        cur = p.ppid;
                        depth += 1;
                    }
                }
                Ok(())
            }

            #[inline(never)]
            fn [<precompute_ $hook _pa_name>](ppid: u32) -> Result<(), i32> {
                unsafe {
                    let res = $results.get_ptr_mut(0).ok_or(-1i32)?;
                    (*res).parent_name = [0u8; MAX_RULES_COUNT];
                    (*res).ancestor_name = [0u8; MAX_RULES_COUNT];
                    let mut cur = ppid;
                    let mut depth = 0;
                    while depth < $depth {
                        let Some(p) = $proc_map.get(&cur) else { break; };
                        let key = $name_key.get_ptr_mut(0).ok_or(-1i32)?;
                        (*key).name = [0u8; MAX_FILENAME_SIZE];
                        bpf_probe_read_kernel_str_bytes(p.filename.as_ptr() as *const u8, &mut (*key).name).ok();
                        let is_parent = depth == 0;
                        let mut ridx = 0;
                        while ridx < MAX_RULES_COUNT {
                            (*key).rule_idx = ridx as u8;
                            (*res).ancestor_name[ridx] |= $anc_name.get(&*key).copied().unwrap_or(0);
                            if is_parent { (*res).parent_name[ridx] |= $parent_name.get(&*key).copied().unwrap_or(0); }
                            ridx += 1;
                        }
                        cur = p.ppid;
                        depth += 1;
                    }
                }
                Ok(())
            }

            #[inline(never)]
            fn [<precompute_ $hook _pa_path>](ppid: u32) -> Result<(), i32> {
                unsafe {
                    let res = $results.get_ptr_mut(0).ok_or(-1i32)?;
                    (*res).parent_path = [0u8; MAX_RULES_COUNT];
                    (*res).ancestor_path = [0u8; MAX_RULES_COUNT];
                    let mut cur = ppid;
                    let mut depth = 0;
                    while depth < $depth {
                        let Some(p) = $proc_map.get(&cur) else { break; };
                        let key = $path_key.get_ptr_mut(0).ok_or(-1i32)?;
                        (*key).path = [0u8; MAX_FILE_PATH];
                        bpf_probe_read_kernel_str_bytes(p.binary_path.as_ptr() as *const u8, &mut (*key).path).ok();
                        let is_parent = depth == 0;
                        let mut ridx = 0;
                        while ridx < MAX_RULES_COUNT {
                            (*key).rule_idx = ridx as u8;
                            (*res).ancestor_path[ridx] |= $anc_path.get(&*key).copied().unwrap_or(0);
                            if is_parent { (*res).parent_path[ridx] |= $parent_path.get(&*key).copied().unwrap_or(0); }
                            ridx += 1;
                        }
                        cur = p.ppid;
                        depth += 1;
                    }
                }
                Ok(())
            }

            #[inline(never)]
            fn [<precompute_ $hook _pa_prefix>](ppid: u32) -> Result<(), i32> {
                unsafe {
                    let res = $results.get_ptr_mut(0).ok_or(-1i32)?;
                    (*res).parent_prefix = [0u8; MAX_RULES_COUNT];
                    (*res).ancestor_prefix = [0u8; MAX_RULES_COUNT];
                    let mut cur = ppid;
                    let mut depth = 0;
                    while depth < $depth {
                        let Some(p) = $proc_map.get(&cur) else { break; };
                        let key = $prefix_key.get_ptr_mut(0).ok_or(-1i32)?;
                        (*key).data.path_prefix = [0u8; MAX_FILE_PREFIX];
                        bpf_probe_read_kernel_buf(p.binary_path.as_ptr() as *const u8, &mut (*key).data.path_prefix).ok();
                        (*key).prefix_len = (MAX_FILE_PREFIX * 8) as u32;
                        let is_parent = depth == 0;
                        let mut ridx = 0;
                        while ridx < MAX_RULES_COUNT {
                            (*key).data.rule_idx = ridx as u8;
                            (*res).ancestor_prefix[ridx] |= $anc_prefix.get(&*key).copied().unwrap_or(0);
                            if is_parent { (*res).parent_prefix[ridx] |= $parent_prefix.get(&*key).copied().unwrap_or(0); }
                            ridx += 1;
                        }
                        cur = p.ppid;
                        depth += 1;
                    }
                }
                Ok(())
            }

            // Single entry point so the hook has *one* `?` call site for the whole
            // scope precompute instead of six. Six sequential `?` calls in the hot
            // hook each fork the verifier's state on their error path, and with the
            // per-rule event interpreter already near the 1M-insn limit on the
            // 6.2/6.14 verifiers that fan-out tips it over. Collapsing them into one
            // `#[inline(never)]` subprogram (verified once) keeps the hook flat.
            #[inline(never)]
            fn [<precompute_ $hook _all>](pid: u32, ppid: u32) -> Result<(), i32> {
                [<precompute_ $hook _binary_name>](pid)?;
                [<precompute_ $hook _binary_path>](pid)?;
                [<precompute_ $hook _binary_prefix>](pid)?;
                [<precompute_ $hook _pa_name>](ppid)?;
                [<precompute_ $hook _pa_path>](ppid)?;
                [<precompute_ $hook _pa_prefix>](ppid)?;
                Ok(())
            }
        }
    };
}

/// Run the scope precompute generated by [`gen_scope_precompute`] for `$hook` and
/// return a reference to the per-CPU `$results` buffer. Dispatches through the
/// single `precompute_*_all` subprogram (one `?` call site — see its doc comment).
#[macro_export]
macro_rules! run_scope_precompute {
    ($hook:ident, $proc:expr, $results:ident) => {{
        ::paste::paste! {
            [<precompute_ $hook _all>]($proc.pid, $proc.ppid)?;
        }
        let results_ptr = $results.get_ptr(0).ok_or(-1i32)?;
        unsafe { &*results_ptr }
    }};
}

/// Like [`run_scope_precompute`] but only computes the executing-binary scope
/// (`binary_*`); parent/ancestor result masks are cleared (so those attributes
/// never match). Used by detectors whose hooks are too complex for the full
/// parent/ancestor walk to fit under the BPF verifier instruction limit.
#[macro_export]
macro_rules! run_scope_precompute_binary {
    ($hook:ident, $proc:expr, $results:ident) => {{
        ::paste::paste! {
            [<precompute_ $hook _binary_name>]($proc.pid)?;
            [<precompute_ $hook _binary_path>]($proc.pid)?;
            [<precompute_ $hook _binary_prefix>]($proc.pid)?;
        }
        let results_ptr = $results.get_ptr_mut(0).ok_or(-1i32)?;
        unsafe {
            (*results_ptr).parent_name = [0u8; MAX_RULES_COUNT];
            (*results_ptr).parent_path = [0u8; MAX_RULES_COUNT];
            (*results_ptr).parent_prefix = [0u8; MAX_RULES_COUNT];
            (*results_ptr).ancestor_name = [0u8; MAX_RULES_COUNT];
            (*results_ptr).ancestor_path = [0u8; MAX_RULES_COUNT];
            (*results_ptr).ancestor_prefix = [0u8; MAX_RULES_COUNT];
            &*results_ptr
        }
    }};
}

/// Pre-computed scope match masks (one byte per rule, each byte a bitmask over the
/// rule's IN operations) for the executing binary and its parent/ancestor
/// binaries. The detector fills this in a per-CPU buffer before evaluating a rule
/// and hands `ScopeFilter` a single reference to it.
///
/// Crucially, `ScopeFilter` holds *no static map references at all* — every scope
/// match is pre-computed by the detector. Keeping map addresses out of this
/// fully-inlined, hot struct is what avoids the BPF backend spilling them to the
/// stack as split 32-bit constants (which the verifier rejects with "pointer
/// arithmetic on map_ptr prohibited").
#[repr(C)]
pub struct ScopeResults {
    pub binary_name: [u8; MAX_RULES_COUNT],
    pub binary_path: [u8; MAX_RULES_COUNT],
    pub binary_prefix: [u8; MAX_RULES_COUNT],
    pub parent_name: [u8; MAX_RULES_COUNT],
    pub parent_path: [u8; MAX_RULES_COUNT],
    pub parent_prefix: [u8; MAX_RULES_COUNT],
    pub ancestor_name: [u8; MAX_RULES_COUNT],
    pub ancestor_path: [u8; MAX_RULES_COUNT],
    pub ancestor_prefix: [u8; MAX_RULES_COUNT],
}

/// Scope filter for the executing binary as well as its parent/ancestor binaries.
///
/// All matches are pre-computed by the detector (it owns the process map and the
/// per-CPU scratch buffers) into [`ScopeResults`]; this filter just reads the
/// per-rule masks for the rule currently being evaluated (`rule_idx`).
#[repr(C)]
pub struct ScopeFilter<'a> {
    pub results: &'a ScopeResults,
    pub rule_idx: usize,
}

impl<'a> ScopeFilter<'a> {
    pub fn new(results: &'a ScopeResults, rule_idx: usize) -> Self {
        Self { results, rule_idx }
    }
}

/// Evaluate a rule's scope predicate against the pre-computed [`ScopeResults`].
///
/// `#[inline(never)]` is load-bearing: the per-rule loops in every hook would
/// otherwise inline the whole scope stack-machine interpreter once *per rule*
/// (×`MAX_RULES_COUNT`), exploding the number of verifier states and pushing the
/// program past the 1M-instruction limit on the stricter 6.2/6.14 verifiers.
/// Verified once and called per rule instead, it stays well under the limit.
/// This is spill-safe because `ScopeFilter` holds a single `&ScopeResults` and no
/// map pointers, so no map address is materialized across the call boundary (the
/// pattern that triggers "pointer arithmetic on map_ptr prohibited").
#[inline(never)]
pub fn eval_scope_predicate(
    results: &ScopeResults,
    rule_idx: usize,
    predicate: &Predicate,
) -> Result<bool, i32> {
    let mut interpreter = Interpreter::new(ScopeFilter::new(results, rule_idx))?;
    interpreter.check_predicate(predicate)
}

impl CheckIn for ScopeFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        let rule_idx = self.rule_idx;
        if rule_idx >= MAX_RULES_COUNT {
            return Ok(false);
        }
        match attribute_map_id {
            id if id == Attributes::BinaryName as u8 => {
                Ok(self.results.binary_name[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::BinaryPath as u8 => {
                Ok(self.results.binary_path[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::BinaryPrefix as u8 => {
                Ok(self.results.binary_prefix[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::ParentBinaryName as u8 => {
                Ok(self.results.parent_name[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::ParentBinaryPath as u8 => {
                Ok(self.results.parent_path[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::ParentBinaryPrefix as u8 => {
                Ok(self.results.parent_prefix[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::AncestorBinaryName as u8 => {
                Ok(self.results.ancestor_name[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::AncestorBinaryPath as u8 => {
                Ok(self.results.ancestor_path[rule_idx] & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::AncestorBinaryPrefix as u8 => {
                Ok(self.results.ancestor_prefix[rule_idx] & (1 << in_op_idx) != 0)
            }
            _ => Err(-1),
        }
    }
}
