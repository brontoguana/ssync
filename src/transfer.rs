use crate::{
    auth::Channel,
    cli::Transfer,
    fs::{self, Root},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};
pub const BLOCK: usize = 200_000;
const MAX_FILE: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Message {
    Options {
        merge: bool,
        dryrun: bool,
        skip: Vec<String>,
    },
    Begin {
        roots: Vec<(String, bool)>,
        skip: Vec<String>,
        dryrun: bool,
    },
    Approved {
        yes: bool,
    },
    Directory {
        path: String,
    },
    File {
        path: String,
        size: u64,
        hash: String,
    },
    Need {
        skip: bool,
    },
    Block {
        offset: u64,
        len: usize,
        hash: String,
    },
    Want {
        yes: bool,
    },
    EndFile {
        hash: String,
    },
    Ack,
    Done {
        entries: usize,
    },
    Finished {
        stats: Stats,
    },
}
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Stats {
    pub content_bytes: u64,
    pub reused_bytes: u64,
    pub files: usize,
    pub skipped: usize,
    pub deleted: usize,
    pub wire_sent: u64,
    pub wire_received: u64,
}
struct Selected {
    root: Root,
    path: String,
    name: String,
    is_dir: bool,
}
fn selected(path: &Path) -> Result<Selected> {
    let abs = fs::absolute(path)?;
    let name = abs
        .file_name()
        .context("cannot transfer filesystem root")?
        .to_str()
        .context("non UTF8 name")?
        .to_string();
    fs::valid(&name)?;
    let parent = Root::new(abs.parent().context("missing parent")?)?;
    let meta = parent.metadata(&name)?.context("source does not exist")?;
    if meta.is_dir() {
        Ok(Selected {
            root: Root::new(&abs)?,
            path: String::new(),
            name,
            is_dir: true,
        })
    } else {
        Ok(Selected {
            root: parent,
            path: name.clone(),
            name,
            is_dir: false,
        })
    }
}
fn filtered(path: &str, skip: &[String]) -> bool {
    skip.iter().any(|s| path.contains(s))
}
fn check_filters(skip: &[String]) -> Result<()> {
    ensure!(
        skip.len() <= 32 && skip.iter().all(|s| !s.is_empty() && s.len() <= 1024),
        "invalid filter list"
    );
    Ok(())
}
fn check_hash(hash: &str) -> Result<()> {
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid digest"
    );
    Ok(())
}
fn cancelled(stop: &AtomicBool) -> Result<()> {
    ensure!(!stop.load(Ordering::Relaxed), "transfer cancelled");
    Ok(())
}
fn approve(t: &Transfer, channel: &mut Channel, connector: bool, description: &str) -> Result<()> {
    if connector {
        println!(
            "Authenticated transfer: {description}; local paths {:?}",
            t.paths
        );
        let yes = if t.options.force {
            true
        } else {
            print!("Is this correct? (y|n): ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim() == "y"
        };
        channel.send(&Message::Approved { yes })?;
        ensure!(yes, "transfer cancelled");
    } else {
        ensure!(
            matches!(channel.recv()?, Message::Approved { yes: true }),
            "transfer cancelled"
        );
    }
    Ok(())
}
pub fn run(
    t: &Transfer,
    channel: &mut Channel,
    connector: bool,
    stop: &AtomicBool,
) -> Result<Stats> {
    let mut stats = if t.sending() {
        send(t, channel, connector, stop)?
    } else {
        receive(t, channel, connector, stop)?
    };
    stats.wire_sent = channel.wire_sent;
    stats.wire_received = channel.wire_received;
    println!("SSYNC_STATS {}", serde_json::to_string(&stats)?);
    Ok(stats)
}
fn send(t: &Transfer, c: &mut Channel, connector: bool, stop: &AtomicBool) -> Result<Stats> {
    let Message::Options {
        merge,
        dryrun,
        skip: remote_skip,
    } = c.recv()?
    else {
        bail!("expected receiver options")
    };
    check_filters(&remote_skip)?;
    let mut skip = t.options.skip.clone();
    skip.extend(remote_skip);
    ensure!(skip.len() <= 64, "too many combined filters");
    let sources = t
        .paths
        .iter()
        .map(|p| selected(p))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !sources.is_empty() && sources.len() <= 128,
        "source selection limit"
    );
    if merge {
        ensure!(
            sources.len() == 1 && sources[0].is_dir,
            "merge requires one source directory"
        );
    }
    let mut names = BTreeSet::new();
    for s in &sources {
        ensure!(names.insert(s.name.clone()), "duplicate source basename");
    }
    c.send(&Message::Begin {
        roots: sources.iter().map(|s| (s.name.clone(), s.is_dir)).collect(),
        skip: t.options.skip.clone(),
        dryrun: t.options.dryrun,
    })?;
    approve(t, c, connector, "send selected files")?;
    let mut stats = Stats::default();
    let mut count = 0;
    for s in &sources {
        let target = if merge { String::new() } else { s.name.clone() };
        send_entry(
            &s.root,
            &s.path,
            &target,
            &skip,
            dryrun || t.options.dryrun,
            c,
            &mut stats,
            &mut count,
            stop,
        )?;
    }
    cancelled(stop)?;
    c.send(&Message::Done { entries: count })?;
    let Message::Finished { stats: remote } = c.recv()? else {
        bail!("receiver did not verify completed transfer")
    };
    ensure!(
        remote.content_bytes == stats.content_bytes,
        "transfer byte accounting mismatch"
    );
    stats.deleted = remote.deleted;
    Ok(stats)
}
#[allow(clippy::too_many_arguments)]
fn send_entry(
    root: &Root,
    source: &str,
    target: &str,
    skip: &[String],
    dry: bool,
    c: &mut Channel,
    stats: &mut Stats,
    count: &mut usize,
    stop: &AtomicBool,
) -> Result<()> {
    cancelled(stop)?;
    if !target.is_empty() && filtered(target, skip) {
        return Ok(());
    }
    let meta = root.metadata(source)?.context("source disappeared")?;
    let before = fs::identity(&meta);
    if meta.is_dir() {
        if !target.is_empty() {
            c.send(&Message::Directory {
                path: target.into(),
            })?;
            expect_ack(c)?;
            *count += 1;
        }
        for name in root.list(source)? {
            let source = if source.is_empty() {
                name.clone()
            } else {
                format!("{source}/{name}")
            };
            let target = if target.is_empty() {
                name
            } else {
                format!("{target}/{name}")
            };
            send_entry(root, &source, &target, skip, dry, c, stats, count, stop)?;
        }
        ensure!(
            root.metadata(source)?.as_ref().map(fs::identity) == Some(before),
            "source directory changed during enumeration"
        );
    } else {
        fs::regular(&meta)?;
        ensure!(meta.len() <= MAX_FILE, "file exceeds 16 GiB limit");
        let mut file = root.read(source)?;
        ensure!(
            fs::identity(&file.metadata()?) == before,
            "source changed before opening"
        );
        let hash = fs::digest(&mut file)?.to_hex().to_string();
        c.send(&Message::File {
            path: target.into(),
            size: meta.len(),
            hash: hash.clone(),
        })?;
        let Message::Need { skip: whole_skip } = c.recv()? else {
            bail!("expected block request")
        };
        if whole_skip {
            stats.skipped += 1;
            ensure!(
                fs::identity(&file.metadata()?) == before,
                "source changed during skip"
            );
        } else {
            file.seek(SeekFrom::Start(0))?;
            // Hash/read producer overlaps the network comparison and streaming consumer.
            let (tx, rx) = mpsc::sync_channel::<Result<(u64, Vec<u8>, String)>>(2);
            std::thread::scope(|scope| -> Result<()> {
                scope.spawn(move || {
                    let result = (|| -> Result<()> {
                        let mut offset = 0;
                        loop {
                            let mut bytes = vec![0; BLOCK];
                            let mut n = 0;
                            while n < BLOCK {
                                let got = file.read(&mut bytes[n..])?;
                                if got == 0 {
                                    break;
                                }
                                n += got;
                            }
                            if n == 0 {
                                break;
                            }
                            bytes.truncate(n);
                            let hash = blake3::hash(&bytes).to_hex().to_string();
                            if tx.send(Ok((offset, bytes, hash))).is_err() {
                                return Ok(());
                            }
                            offset += n as u64;
                        }
                        ensure!(
                            fs::identity(&file.metadata()?) == before,
                            "source changed while streaming"
                        );
                        Ok(())
                    })();
                    if let Err(e) = result {
                        let _ = tx.send(Err(e));
                    }
                });
                for block in rx {
                    cancelled(stop)?;
                    let (offset, bytes, hash) = block?;
                    c.send(&Message::Block {
                        offset,
                        len: bytes.len(),
                        hash,
                    })?;
                    let Message::Want { yes } = c.recv()? else {
                        bail!("expected block comparison")
                    };
                    if yes {
                        ensure!(!dry, "dry run requested payload");
                        stats.content_bytes += bytes.len() as u64;
                        c.send_bytes(&bytes)?;
                        expect_ack(c)?;
                    } else {
                        stats.reused_bytes += bytes.len() as u64;
                    }
                }
                Ok(())
            })?;
            let mut reopened = root.read(source)?;
            ensure!(
                fs::digest(&mut reopened)?.to_hex().as_str() == hash,
                "source content changed during transfer"
            );
            c.send(&Message::EndFile { hash })?;
            expect_ack(c)?;
            stats.files += 1;
        }
        *count += 1;
    }
    ensure!(*count <= fs::MAX_ENTRIES, "manifest entry limit");
    Ok(())
}
fn expect_ack(c: &mut Channel) -> Result<()> {
    ensure!(matches!(c.recv()?, Message::Ack), "expected acknowledgment");
    Ok(())
}

fn receive(t: &Transfer, c: &mut Channel, connector: bool, stop: &AtomicBool) -> Result<Stats> {
    c.send(&Message::Options {
        merge: t.options.merge,
        dryrun: t.options.dryrun,
        skip: t.options.skip.clone(),
    })?;
    let Message::Begin {
        roots,
        skip: remote_skip,
        dryrun: remote_dry,
    } = c.recv()?
    else {
        bail!("expected selected roots")
    };
    ensure!(
        !roots.is_empty() && roots.len() <= 128,
        "source selection limit"
    );
    check_filters(&remote_skip)?;
    let mut top = BTreeSet::new();
    for (name, _) in &roots {
        fs::valid(name)?;
        ensure!(
            !name.contains('/') && top.insert(name.clone()),
            "invalid source root"
        );
    }
    if t.options.merge {
        ensure!(
            roots.len() == 1 && roots[0].1,
            "merge requires a single directory"
        );
    }
    let mut skip = t.options.skip.clone();
    skip.extend(remote_skip);
    approve(t, c, connector, &format!("receive {:?}", roots))?;
    let mut effective = t.clone();
    effective.options.dryrun |= remote_dry;
    let t = &effective;
    let root = Root::new(&t.paths[0])?;
    root.lock()?;
    let mut stats = Stats::default();
    let mut seen = BTreeSet::new();
    let mut path_bytes = 0usize;
    loop {
        cancelled(stop)?;
        let msg = c.recv()?;
        match msg {
            Message::Directory { path } => {
                authorize(&path, &roots, t.options.merge, &skip)?;
                ensure!(seen.insert(path.clone()), "duplicate entry");
                path_bytes += path.len();
                ensure!(path_bytes <= 8 * 1024 * 1024, "manifest path-byte limit");
                if t.options.dryrun {
                    println!("Would create directory {:?}", path);
                    if let Some(m) = root.metadata(&path)? {
                        ensure!(m.is_dir(), "directory/file conflict");
                    }
                } else {
                    root.mkdirs(&path)?;
                }
                c.send(&Message::Ack)?;
            }
            Message::File { path, size, hash } => {
                authorize(&path, &roots, t.options.merge, &skip)?;
                ensure!(seen.insert(path.clone()), "duplicate entry");
                path_bytes += path.len();
                ensure!(path_bytes <= 8 * 1024 * 1024, "manifest path-byte limit");
                check_hash(&hash)?;
                ensure!(size <= MAX_FILE, "file size limit");
                receive_file(&root, &path, size, &hash, t, c, &mut stats, stop)?;
            }
            Message::Done { entries } => {
                ensure!(entries == seen.len(), "incomplete manifest");
                break;
            }
            _ => bail!("unexpected transfer operation"),
        }
        ensure!(seen.len() <= fs::MAX_ENTRIES, "manifest entry limit");
    }
    cancelled(stop)?;
    if !t.options.nodelete && !t.options.dryrun {
        // Complete verified manifest is mandatory before any deletion. Scopes fixed by selected roots.
        let scopes: Vec<String> = if t.options.merge {
            vec![String::new()]
        } else {
            roots
                .iter()
                .filter(|(_, d)| *d)
                .map(|(n, _)| n.clone())
                .collect()
        };
        for scope in scopes {
            delete_extras(&root, &scope, &seen, &skip, &mut stats, stop)?;
        }
    }
    if t.options.verify {
        println!("Directory Verification Hash: {}", tree_hash(&root, "")?);
    }
    c.send(&Message::Finished {
        stats: stats.clone(),
    })?;
    Ok(stats)
}
fn authorize(path: &str, roots: &[(String, bool)], merge: bool, skip: &[String]) -> Result<()> {
    fs::valid(path)?;
    ensure!(!filtered(path, skip), "entry violates protected filter");
    if !merge {
        ensure!(
            roots
                .iter()
                .any(|(name, dir)| path == name || (*dir && path.starts_with(&format!("{name}/")))),
            "entry outside selected transfer layout"
        );
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn receive_file(
    root: &Root,
    path: &str,
    size: u64,
    hash: &str,
    t: &Transfer,
    c: &mut Channel,
    stats: &mut Stats,
    stop: &AtomicBool,
) -> Result<()> {
    let meta = root.metadata(path)?;
    if let Some(m) = &meta {
        fs::regular(m)?;
    }
    let expected = meta.as_ref().map(fs::identity);
    let mut old = if meta.is_some() {
        Some(root.read(path)?)
    } else {
        None
    };
    if let Some(f) = old.as_mut()
        && f.metadata()?.len() == size
        && fs::digest(f)?.to_hex().as_str() == hash
    {
        ensure!(
            root.metadata(path)?.as_ref().map(fs::identity) == expected,
            "destination changed during comparison"
        );
        c.send(&Message::Need { skip: true })?;
        stats.skipped += 1;
        return Ok(());
    }
    println!(
        "{} {:?} ({} bytes)",
        if t.options.dryrun {
            "Would transfer"
        } else {
            "Transferring"
        },
        path,
        size
    );
    if !t.options.dryrun {
        root.mkdirs(fs::split(path).0)?;
    }
    let resume_key = zeroize::Zeroizing::new(blake3::derive_key(
        "SSync 4 credential-bound private resume",
        t.password.as_bytes(),
    ));
    let id = blake3::keyed_hash(&resume_key, format!("{path}\0{size}\0{hash}").as_bytes())
        .to_hex()
        .to_string();
    let mut stage = if t.options.dryrun {
        None
    } else {
        Some(root.stage(&id)?)
    };
    if let Some((state, _)) = &stage {
        root.partial_capacity(state, &id, size)?;
    }
    c.send(&Message::Need { skip: false })?;
    let mut offset = 0u64;
    let mut final_hash = blake3::Hasher::new();
    while offset < size {
        cancelled(stop)?;
        let Message::Block {
            offset: remote,
            len,
            hash: block_hash,
        } = c.recv()?
        else {
            bail!("expected block metadata")
        };
        check_hash(&block_hash)?;
        ensure!(
            remote == offset && len == (size - offset).min(BLOCK as u64) as usize,
            "invalid block range"
        );
        let mut data = vec![0; len];
        let mut reused = false;
        if let Some((_, f)) = stage.as_mut() {
            reused = read_matching(f, offset, &mut data, &block_hash)?;
        }
        if !reused && let Some(f) = old.as_mut() {
            reused = read_matching(f, offset, &mut data, &block_hash)?;
        }
        let want = !reused && !t.options.dryrun;
        c.send(&Message::Want { yes: want })?;
        if want {
            let bytes = c.recv_bytes()?;
            ensure!(
                bytes.len() == len && blake3::hash(&bytes).to_hex().as_str() == block_hash,
                "block content verification failed"
            );
            data = bytes;
            stats.content_bytes += len as u64;
        } else if reused {
            stats.reused_bytes += len as u64;
        }
        if let Some((_, f)) = stage.as_mut() {
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(&data)?;
            final_hash.update(&data);
        }
        if want {
            c.send(&Message::Ack)?;
        }
        offset += len as u64;
    }
    let Message::EndFile { hash: source_hash } = c.recv()? else {
        bail!("expected complete-file verification")
    };
    ensure!(source_hash == hash, "source changed");
    if let Some((state, f)) = stage.as_mut() {
        ensure!(
            final_hash.finalize().to_hex().as_str() == hash,
            "final reconstructed digest mismatch"
        );
        f.set_len(size)?;
        ensure!(
            fs::digest(f)?.to_hex().as_str() == hash,
            "staged file changed"
        );
        f.sync_all()?;
        // Verify receiver base has not changed even if copied ranges were identical.
        ensure!(
            root.metadata(path)?.as_ref().map(fs::identity) == expected,
            "destination changed during transfer"
        );
        root.commit(state, &id, path, &expected)?;
    }
    stats.files += 1;
    c.send(&Message::Ack)?;
    Ok(())
}
fn read_matching(f: &mut File, offset: u64, data: &mut [u8], hash: &str) -> Result<bool> {
    if f.metadata()?.len() < offset + data.len() as u64 {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(data)?;
    Ok(blake3::hash(data).to_hex().as_str() == hash)
}
fn delete_extras(
    root: &Root,
    path: &str,
    seen: &BTreeSet<String>,
    skip: &[String],
    stats: &mut Stats,
    stop: &AtomicBool,
) -> Result<()> {
    if filtered(path, skip) {
        return Ok(());
    }
    let Some(m) = root.metadata(path)? else {
        return Ok(());
    };
    if m.is_dir() {
        for name in root.list(path)? {
            let child = if path.is_empty() {
                name
            } else {
                format!("{path}/{name}")
            };
            delete_extras(root, &child, seen, skip, stats, stop)?;
        }
    }
    if !path.is_empty() && !seen.contains(path) {
        if m.is_dir() && !root.list(path)?.is_empty() {
            return Ok(());
        }
        cancelled(stop)?;
        let current = root.metadata(path)?.context("delete path disappeared")?;
        let id = fs::identity(&current);
        root.remove(path, &id)?;
        stats.deleted += 1;
    }
    Ok(())
}
pub fn tree_hash(root: &Root, path: &str) -> Result<String> {
    fn walk(root: &Root, path: &str, h: &mut blake3::Hasher, count: &mut usize) -> Result<()> {
        *count += 1;
        ensure!(*count <= fs::MAX_ENTRIES, "hash entry limit");
        let m = root.metadata(path)?.context("hash entry missing")?;
        h.update(&(path.len() as u64).to_be_bytes());
        h.update(path.as_bytes());
        h.update(&[u8::from(m.is_dir())]);
        if m.is_dir() {
            for name in root.list(path)? {
                walk(
                    root,
                    &if path.is_empty() {
                        name
                    } else {
                        format!("{path}/{name}")
                    },
                    h,
                    count,
                )?;
            }
        } else {
            let mut f = root.read(path)?;
            h.update(&m.len().to_be_bytes());
            h.update(fs::digest(&mut f)?.as_bytes());
        }
        Ok(())
    }
    let mut h = blake3::Hasher::new();
    walk(root, path, &mut h, &mut 0)?;
    Ok(h.finalize().to_hex().to_string())
}
