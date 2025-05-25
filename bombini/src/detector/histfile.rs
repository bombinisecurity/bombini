//! Histfile detector

use bombini_common::event::histfile::MAX_BASH_COMMAND_SIZE;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::UProbe;
use aya::{Ebpf, EbpfError};

use std::path::Path;

use super::{load_ebpf_obj, Detector};

pub struct HistFileDetector {
    ebpf: Ebpf,
}

impl Detector for HistFileDetector {
    async fn new<U: AsRef<Path>>(
        obj_path: U,
        _config_path: Option<U>,
    ) -> Result<Self, anyhow::Error> {
        let ebpf = load_ebpf_obj(obj_path).await?;
        Ok(HistFileDetector { ebpf })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut hist_fsz_buf = [0; MAX_BASH_COMMAND_SIZE];
        let mut hist_sz_buf = [0; MAX_BASH_COMMAND_SIZE];
        let hist_fsz_str = "export HISTFILESIZE=0";
        let hist_sz_str = "export HISTSIZE=0";
        hist_fsz_buf[..hist_fsz_str.len()].clone_from_slice(hist_fsz_str.as_bytes());
        hist_sz_buf[..hist_sz_str.len()].clone_from_slice(hist_sz_str.as_bytes());
        let hist_fsz_key = Key::new((hist_fsz_str.len() * 8) as u32, hist_fsz_buf);
        let hist_sz_key = Key::new((hist_sz_str.len() * 8) as u32, hist_sz_buf);
        let mut hist_cmds: LpmTrie<_, [u8; MAX_BASH_COMMAND_SIZE], u32> =
            LpmTrie::try_from(self.ebpf.map_mut("HISTFILE_CHECK_MAP").unwrap())?;
        hist_cmds.insert(&hist_fsz_key, 1, 0)?;
        hist_cmds.insert(&hist_sz_key, 1, 0)?;
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let program: &mut UProbe = self
            .ebpf
            .program_mut("histfile_detect")
            .unwrap()
            .try_into()?;
        program.load()?;
        program.attach(Some("readline"), 0, "/bin/bash", None)?;
        Ok(())
    }
}
