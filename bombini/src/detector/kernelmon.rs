use std::{path::Path, sync::Arc};

use crate::detector::Detector;
use crate::rule::serializer::PredicateSerializer;
use crate::rule::serializer::kernelmon::{
    BpfMapCreatePredicate, BpfMapPredicate, BpfProgLoadPredicate, BpfProgPredicate,
};
use aya::maps::{Array, MapError};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};
use bombini_common::config::kernelmon::KernelMonKernelConfig;
use bombini_common::event::kernel::KernelEventNumber;
use procfs::sys::kernel::Version;

use crate::proto::config::{KernelMonConfig, Rule};
use crate::rule::serializer::SerializedRules;

pub struct KernelMon {
    ebpf: Ebpf,
    config: KernelMonKernelConfig,
    hooks: Vec<Box<dyn KernelMonRuleContainer>>,
}

trait KernelMonRuleContainer {
    fn map_sizes(&self) -> &std::collections::HashMap<String, u32>;
    fn store_rules(&self, ebpf: &mut Ebpf, map_prefix: &'static str) -> Result<(), anyhow::Error>;
    fn hook(&self) -> KernelMonHook;
}

#[derive(Debug)]
struct HookData<T: PredicateSerializer> {
    hook: KernelMonHook,
    serialized_rules: SerializedRules<T>,
    map_sizes: std::collections::HashMap<String, u32>,
}

impl<T: PredicateSerializer + Default> HookData<T> {
    fn new(hook: KernelMonHook, rules: &[Rule]) -> Result<Self, anyhow::Error> {
        let mut serialized_rules = SerializedRules::new();
        serialized_rules.serialize_rules(rules)?;
        let map_sizes = serialized_rules.map_sizes(hook.map_prefix());

        Ok(HookData {
            hook,
            serialized_rules,
            map_sizes,
        })
    }
}

impl<T: PredicateSerializer> KernelMonRuleContainer for HookData<T> {
    fn map_sizes(&self) -> &std::collections::HashMap<String, u32> {
        &self.map_sizes
    }

    fn store_rules(&self, ebpf: &mut Ebpf, map_prefix: &'static str) -> Result<(), anyhow::Error> {
        self.serialized_rules.store_rules(ebpf, map_prefix)
    }

    fn hook(&self) -> KernelMonHook {
        self.hook
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(clippy::enum_variant_names)]
enum KernelMonHook {
    BpfMapAccess,
    BpfMapCreate,
    BpfProgAccess,
    BpfProgLoad,
}

impl KernelMonHook {
    fn map_prefix(&self) -> &'static str {
        match self {
            Self::BpfMapAccess => "KERNELMON_BPF_MAP",
            Self::BpfMapCreate => "KERNELMON_BPF_MAP_CREATE",
            Self::BpfProgAccess => "KERNELMON_BPF_PROG",
            Self::BpfProgLoad => "KERNELMON_BPF_PROG_LOAD",
        }
    }

    fn hook_name(&self, kernel_version: Version) -> &'static str {
        match self {
            Self::BpfMapAccess => "bpf_map",
            Self::BpfMapCreate => {
                if kernel_version >= Version::new(6, 9, 0) {
                    "bpf_map_create"
                } else {
                    "bpf_map_alloc_security"
                }
            }
            Self::BpfProgAccess => "bpf_prog",
            Self::BpfProgLoad => {
                if kernel_version >= Version::new(6, 9, 0) {
                    "bpf_prog_load"
                } else {
                    "bpf"
                }
            }
        }
    }

    fn program_name(&self, kernel_version: Version) -> &'static str {
        match self {
            Self::BpfMapAccess => "bpf_map_capture",
            Self::BpfMapCreate => {
                if kernel_version >= Version::new(6, 9, 0) {
                    "bpf_map_create_capture"
                } else {
                    "bpf_map_alloc_capture"
                }
            }
            Self::BpfProgAccess => "bpf_prog_capture",
            Self::BpfProgLoad => {
                if kernel_version >= Version::new(6, 9, 0) {
                    "bpf_prog_load_capture"
                } else {
                    "bpf_prog_old_load_capture"
                }
            }
        }
    }
}

impl KernelMon {
    pub fn new<P>(
        obj_path: P,
        maps_pin_path: P,
        config: Arc<KernelMonConfig>,
    ) -> Result<Self, anyhow::Error>
    where
        P: AsRef<Path>,
    {
        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader.map_pin_path(maps_pin_path.as_ref());

        let mut hooks: Vec<Box<dyn KernelMonRuleContainer>> = Vec::new();
        let detector_config = KernelMonKernelConfig {
            sandbox_mode: [None; KernelEventNumber::TotalKernelEvents as usize],
        };
        if let Some(bpf_map) = &config.bpf_map
            && bpf_map.enabled
        {
            hooks.push(Box::new(HookData::<BpfMapPredicate>::new(
                KernelMonHook::BpfMapAccess,
                &bpf_map.rules,
            )?));
        }
        if let Some(bpf_map_create) = &config.bpf_map_create
            && bpf_map_create.enabled
        {
            hooks.push(Box::new(HookData::<BpfMapCreatePredicate>::new(
                KernelMonHook::BpfMapCreate,
                &bpf_map_create.rules,
            )?));
        }
        if let Some(bpf_prog) = &config.bpf_prog
            && bpf_prog.enabled
        {
            hooks.push(Box::new(HookData::<BpfProgPredicate>::new(
                KernelMonHook::BpfProgAccess,
                &bpf_prog.rules,
            )?));
        }
        if let Some(bpf_prog_load) = &config.bpf_prog_load
            && bpf_prog_load.enabled
        {
            hooks.push(Box::new(HookData::<BpfProgLoadPredicate>::new(
                KernelMonHook::BpfProgLoad,
                &bpf_prog_load.rules,
            )?));
        }

        resize_all_kernelmon_filter_maps(hooks.as_slice(), ebpf_loader_ref)?;

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(KernelMon {
            ebpf,
            config: detector_config,
            hooks,
        })
    }
}

impl Detector for KernelMon {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        // TODO: Change trait error type to anyhow::Error
        let mut config_map: Array<_, KernelMonKernelConfig> =
            Array::try_from(self.ebpf.map_mut("KERNELMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, self.config, 0);

        init_all_kernelmon_filter_maps(&self.hooks, &mut self.ebpf).map_err(|e| {
            MapError::InvalidName {
                name: e.to_string(),
            }
        })?;
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let kernel_ver = Version::current().expect("Cannot get kernel version");
        for hook in &self.hooks {
            let program: &mut Lsm = self
                .ebpf
                .program_mut(hook.hook().program_name(kernel_ver))
                .unwrap()
                .try_into()?;
            program.load(hook.hook().hook_name(kernel_ver), &btf)?;
            program.attach()?;
        }
        Ok(())
    }
}

#[inline]
fn resize_all_kernelmon_filter_maps<'a>(
    hooks: &'a [Box<dyn KernelMonRuleContainer>],
    loader: &mut EbpfLoader<'a>,
) -> Result<(), anyhow::Error> {
    for hook in hooks {
        hook.map_sizes()
            .iter()
            .filter(|(_, size)| **size > 1)
            .for_each(|(name, size)| {
                loader.set_max_entries(name, *size);
            });
    }
    Ok(())
}

fn init_all_kernelmon_filter_maps(
    hooks: &[Box<dyn KernelMonRuleContainer>],
    ebpf: &mut Ebpf,
) -> Result<(), anyhow::Error> {
    for hook in hooks {
        hook.store_rules(ebpf, hook.hook().map_prefix())?;
    }

    Ok(())
}
