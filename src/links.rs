//! Project configuration names and describe links without following their targets.
use crate::fs::{self, Identity, Root};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt,
    sync::atomic::{AtomicBool, Ordering},
};

pub struct Description {
    pub bytes: Vec<u8>,
    pub identity: Identity,
}
#[derive(Default)]
pub struct Plan {
    pub descriptions: BTreeMap<String, Description>,
    paths: BTreeSet<String>,
    hardlinks: BTreeMap<(u64, u64), Vec<(String, Identity)>>,
    path_bytes: usize,
}
pub fn project(path: &str) -> String {
    path.split('/')
        .map(|part| {
            if part.to_ascii_lowercase().ends_with(".ssync") {
                format!("{part}bak")
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
pub fn sidecar(path: &str) -> String {
    format!("{path}.ssynclink")
}
impl Plan {
    fn insert(&mut self, path: &str) -> Result<()> {
        if !path.is_empty() {
            fs::valid(path)?;
        }
        ensure!(
            self.paths.insert(path.into()),
            "projected source path conflicts with another source path {:?}; rename the conflicting .ssyncbak or .ssynclink entry",
            path
        );
        self.path_bytes += path.len();
        ensure!(
            self.paths.len() <= fs::MAX_ENTRIES && self.path_bytes <= 8 * 1024 * 1024,
            "link manifest limit"
        );
        Ok(())
    }
    pub fn scan(
        &mut self,
        root: &Root,
        source: &str,
        target: &str,
        omitted: &impl Fn(&str) -> bool,
        stop: &AtomicBool,
    ) -> Result<()> {
        ensure!(!stop.load(Ordering::Relaxed), "transfer cancelled");
        if omitted(target) || root.password_path(source)? {
            return Ok(());
        }
        let original_target = target;
        let projected = project(target);
        let target = projected.as_str();
        if omitted(target) {
            return Ok(());
        }
        let meta = root.source_metadata(source)?;
        if meta.is_symlink() {
            let name = sidecar(target);
            if omitted(&name) {
                return Ok(());
            }
            self.insert(&name)?;
            let bytes = root.source_link(source)?;
            let original = fs::split(target).1;
            let mut description = String::from("type: softlink\n");
            match std::str::from_utf8(&bytes) {
                Ok(path) => {
                    description.push_str(&format!("path: {}\n\nRecreate manually from the directory containing this description,\nwith no existing entry at the original name:\n  ln -s -- {} {}\n", serde_json::to_string(path)?, shell_words::quote(path), shell_words::quote(original)));
                }
                Err(_) => {
                    let hex = hex::encode(&bytes);
                    let name_hex = hex::encode(original.as_bytes());
                    let code = format!(
                        "import os; os.symlink(bytes.fromhex({hex:?}), bytes.fromhex({name_hex:?}))"
                    );
                    description.push_str(&format!("path_hex: {hex}\n\nThe target contains non-UTF-8 bytes. Recreate manually from the\ndirectory containing this description, with no existing original entry:\n  python3 -c {}\n", shell_words::quote(&code)));
                }
            }
            description.push_str(
                "\nSSync did not follow this link or copy its target through the link.\n",
            );
            self.descriptions.insert(
                target.into(),
                Description {
                    bytes: description.into_bytes(),
                    identity: fs::identity(&meta),
                },
            );
        } else {
            self.insert(target)?;
            if meta.is_dir() {
                let before = fs::identity(&meta);
                for name in root.list(source)? {
                    let child = |p: &str| {
                        if p.is_empty() {
                            name.clone()
                        } else {
                            format!("{p}/{name}")
                        }
                    };
                    self.scan(root, &child(source), &child(original_target), omitted, stop)?;
                }
                ensure!(
                    fs::identity(&root.source_metadata(source)?) == before,
                    "source directory changed while planning links"
                );
            } else if meta.nlink() > 1 {
                let name = sidecar(target);
                if !omitted(&name) {
                    self.insert(&name)?;
                    self.hardlinks
                        .entry((meta.dev(), meta.ino()))
                        .or_default()
                        .push((target.into(), fs::identity(&meta)));
                }
            }
        }
        Ok(())
    }
    pub fn finish(&mut self) -> Result<()> {
        for paths in self.hardlinks.values() {
            for (path, identity) in paths {
                let partner = paths.iter().find(|(other, _)| other != path);
                let mut description = String::from("type: hardlink\n");
                if let Some((other, _)) = partner {
                    description.push_str(&format!("path: {}\npath_base: transfer-root\n\nSSync copied this name's contents as an independent regular file.\nTo restore the hard link manually, change to the transfer destination\nroot and move/remove the copied file at {} first, then run:\n  ln -- {} {}\n", serde_json::to_string(other)?, serde_json::to_string(path)?, shell_words::quote(other), shell_words::quote(path)));
                } else {
                    description.push_str("path: null\n\nOther names for this inode were not included in this transfer.\nSSync copied its contents as an independent regular file. To restore\nthe hard link, locate another name for the original inode, then\nreplace this copy manually with a hard link to that file.\n");
                }
                self.descriptions.insert(
                    path.clone(),
                    Description {
                        bytes: description.into_bytes(),
                        identity: identity.clone(),
                    },
                );
            }
        }
        Ok(())
    }
}
