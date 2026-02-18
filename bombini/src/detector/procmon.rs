use std::path::PathBuf;
use std::time::Duration;
use std::{path::Path, sync::Arc};

use crate::detector::Detector;
use crate::options::{EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME};
use crate::rule::serializer::PredicateSerializer;
use crate::rule::serializer::dummy::DummyPredicate;
use crate::rule::serializer::procmon::{CapPredicate, CredPredicate, GidPredicate, UidPredicate};
use aya::maps::{Array, HashMap, Map, MapData, MapError};
use aya::programs::{BtfTracePoint, Lsm};
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};
use bombini_common::config::procmon::ProcMonKernelConfig;
use bombini_common::constants::{MAX_EVENT_SIZE, PAGE_SIZE};
use bombini_common::event::process::ProcInfo;
use procfs::process;
use tokio::time::interval;

use crate::proto::config::{ProcMonConfig, Rule};
use crate::rule::serializer::SerializedRules;

pub struct ProcMon {
    ebpf: Ebpf,
    ima_hash: bool,
    hooks: Vec<Box<dyn ProcMonRuleContainer>>,
}

trait ProcMonRuleContainer {
    fn map_sizes(&self) -> &std::collections::HashMap<String, u32>;
    fn store_rules(&self, ebpf: &mut Ebpf, map_prefix: &'static str) -> Result<(), anyhow::Error>;
    fn hook(&self) -> ProcMonHook;
}

#[derive(Debug)]
struct HookData<T: PredicateSerializer> {
    hook: ProcMonHook,
    serialized_rules: SerializedRules<T>,
    map_sizes: std::collections::HashMap<String, u32>,
}

impl<T: PredicateSerializer + Default> HookData<T> {
    fn new(hook: ProcMonHook, rules: &[Rule]) -> Result<Self, anyhow::Error> {
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

impl<T: PredicateSerializer> ProcMonRuleContainer for HookData<T> {
    fn map_sizes(&self) -> &std::collections::HashMap<String, u32> {
        &self.map_sizes
    }

    fn store_rules(&self, ebpf: &mut Ebpf, map_prefix: &'static str) -> Result<(), anyhow::Error> {
        self.serialized_rules.store_rules(ebpf, map_prefix)
    }

    fn hook(&self) -> ProcMonHook {
        self.hook
    }
}

#[derive(Debug, Copy, Clone)]
enum ProcMonHook {
    Setuid,
    Setgid,
    SetCaps,
    Prctl,
    Userns,
    PtraceAccessCheck,
}

impl ProcMonHook {
    fn map_prefix(&self) -> &'static str {
        match self {
            ProcMonHook::Setuid => "PROCMON_SETUID",
            ProcMonHook::Setgid => "PROCMON_SETGID",
            ProcMonHook::SetCaps => "PROCMON_CAPSET",
            ProcMonHook::Prctl => "PROCMON_PRCTL",
            ProcMonHook::Userns => "PROCMON_USERNS",
            ProcMonHook::PtraceAccessCheck => "PROCMON_PTRACE_ACCESS_CHECK",
        }
    }

    fn hook_name(&self) -> &'static str {
        match self {
            ProcMonHook::Setuid => "task_fix_setuid",
            ProcMonHook::Setgid => "task_fix_setgid",
            ProcMonHook::SetCaps => "capset",
            ProcMonHook::Prctl => "task_prctl",
            ProcMonHook::Userns => "userns_create",
            ProcMonHook::PtraceAccessCheck => "ptrace_access_check",
        }
    }

    fn program_name(&self) -> &'static str {
        match self {
            ProcMonHook::Setuid => "setuid_capture",
            ProcMonHook::Setgid => "setgid_capture",
            ProcMonHook::SetCaps => "capset_capture",
            ProcMonHook::Prctl => "prctl_capture",
            ProcMonHook::Userns => "create_user_ns_capture",
            ProcMonHook::PtraceAccessCheck => "ptrace_access_check_capture",
        }
    }
}

impl ProcMon {
    pub fn new<P>(
        obj_path: P,
        maps_pin_path: P,
        event_map_size: u32,
        proc_map_size: u32,
        config: Arc<ProcMonConfig>,
    ) -> Result<Self, anyhow::Error>
    where
        P: AsRef<Path>,
    {
        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader
            .map_pin_path(maps_pin_path.as_ref())
            .set_max_entries(EVENT_MAP_NAME, event_map_size)
            .set_max_entries(PROCMON_PROC_MAP_NAME, proc_map_size);

        let mut hooks: Vec<Box<dyn ProcMonRuleContainer>> = Vec::new();
        if let Some(setuid) = &config.setuid
            && setuid.enabled
        {
            hooks.push(Box::new(HookData::<UidPredicate>::new(
                ProcMonHook::Setuid,
                &setuid.rules,
            )?));
        }
        if let Some(setgid) = &config.setgid
            && setgid.enabled
        {
            hooks.push(Box::new(HookData::<GidPredicate>::new(
                ProcMonHook::Setgid,
                &setgid.rules,
            )?));
        }
        if let Some(setcaps) = &config.capset
            && setcaps.enabled
        {
            hooks.push(Box::new(HookData::<CapPredicate>::new(
                ProcMonHook::SetCaps,
                &setcaps.rules,
            )?));
        }
        if let Some(prctl) = &config.prctl
            && prctl.enabled
        {
            hooks.push(Box::new(HookData::<DummyPredicate>::new(
                ProcMonHook::Prctl,
                &prctl.rules,
            )?));
        }
        if let Some(userns) = &config.create_user_ns
            && userns.enabled
        {
            hooks.push(Box::new(HookData::<CredPredicate>::new(
                ProcMonHook::Userns,
                &userns.rules,
            )?));
        }
        if let Some(ptrace_access_check) = &config.ptrace_access_check
            && ptrace_access_check.enabled
        {
            hooks.push(Box::new(HookData::<DummyPredicate>::new(
                ProcMonHook::PtraceAccessCheck,
                &ptrace_access_check.rules,
            )?));
        }

        resize_all_procmon_filter_maps(hooks.as_slice(), ebpf_loader_ref)?;

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        // Start GC for PROCMON_PROC_MAP
        start_proc_map_gc(maps_pin_path, config.clone())?;

        Ok(ProcMon {
            ebpf,
            ima_hash: config.ima_hash.unwrap_or_default(),
            hooks,
        })
    }
}

fn start_proc_map_gc<P: AsRef<Path>>(
    maps_pin_path: P,
    config: Arc<ProcMonConfig>,
) -> Result<(), anyhow::Error> {
    let gc_period = config.gc_period.unwrap_or(30);
    let proc_map_path = PathBuf::from(maps_pin_path.as_ref()).join(PROCMON_PROC_MAP_NAME);
    let map = Map::LruHashMap(MapData::from_pin(&proc_map_path)?);
    let mut proc_map: aya::maps::HashMap<_, u32, ProcInfo> = aya::maps::HashMap::try_from(map)?;
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(gc_period));
        interval.tick().await;

        loop {
            interval.tick().await;

            let to_delete: Vec<u32> = proc_map
                .iter()
                .filter_map(|entry| {
                    let (pid, info) = entry.ok()?;
                    if info.exited { Some(pid) } else { None }
                })
                .collect();

            for pid in &to_delete {
                let _ = proc_map.remove(pid);
            }
        }
    });
    Ok(())
}

impl Detector for ProcMon {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        // TODO: Change trait error type to anyhow::Error
        let config = ProcMonKernelConfig {
            ima_hash: self.ima_hash,
        };
        let mut config_map: Array<_, ProcMonKernelConfig> =
            Array::try_from(self.ebpf.map_mut("PROCMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);

        let current_processes = process::all_processes().unwrap();
        let mut proc_map: HashMap<_, u32, ProcInfo> =
            HashMap::try_from(self.ebpf.map_mut("PROCMON_PROC_MAP").unwrap())?;
        current_processes
            .filter_map(|p| p.ok())
            .filter(|p| p.is_alive())
            .filter_map(|p| ProcInfo::from_procfs(&p))
            .for_each(|p| {
                let _ = proc_map.insert(p.pid, p, 0);
            });

        init_all_procmon_filter_maps(&self.hooks, &mut self.ebpf).map_err(|e| {
            MapError::InvalidName {
                name: e.to_string(),
            }
        })?;
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let exec: &mut BtfTracePoint = self
            .ebpf
            .program_mut("execve_capture")
            .unwrap()
            .try_into()?;
        exec.load("sched_process_exec", &btf)?;
        exec.attach()?;

        let fork: &mut BtfTracePoint = self.ebpf.program_mut("fork_capture").unwrap().try_into()?;
        fork.load("sched_process_fork", &btf)?;
        fork.attach()?;

        let exit: &mut BtfTracePoint = self.ebpf.program_mut("exit_capture").unwrap().try_into()?;
        exit.load("sched_process_exit", &btf)?;
        exit.attach()?;

        let program: &mut Lsm = self.ebpf.program_mut("creds_capture").unwrap().try_into()?;
        program.load("bprm_committing_creds", &btf)?;
        program.attach()?;

        for hook in &self.hooks {
            let program: &mut Lsm = self
                .ebpf
                .program_mut(hook.hook().program_name())
                .unwrap()
                .try_into()?;
            program.load(hook.hook().hook_name(), &btf)?;
            program.attach()?;
        }
        Ok(())
    }
}

#[inline]
fn resize_all_procmon_filter_maps<'a>(
    hooks: &'a [Box<dyn ProcMonRuleContainer>],
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

fn init_all_procmon_filter_maps(
    hooks: &[Box<dyn ProcMonRuleContainer>],
    ebpf: &mut Ebpf,
) -> Result<(), anyhow::Error> {
    for hook in hooks {
        hook.store_rules(ebpf, hook.hook().map_prefix())?;
    }

    let mut zero_map: Array<_, [u8; PAGE_SIZE]> =
        Array::try_from(ebpf.map_mut("ZERO_MAP").unwrap())?;
    zero_map.set(0, [0; PAGE_SIZE], 0)?;

    Ok(())
}
