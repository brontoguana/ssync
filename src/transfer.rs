use crate::{
    auth::{Channel, TransportFailure},
    cli::Transfer,
    fs::{self, Root},
    links::{self, Plan},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
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
        #[serde(default)]
        permissions: bool,
        chmod: Option<u32>,
    },
    Begin {
        roots: Vec<(String, bool)>,
        skip: Vec<String>,
        dryrun: bool,
        nodelete: bool,
    },
    Approved {
        yes: bool,
    },
    Directory {
        path: String,
        mode: u32,
    },
    File {
        path: String,
        size: u64,
        hash: String,
        modified_secs: i64,
        modified_nanos: u32,
        mode: u32,
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
        reused: bool,
    },
    WindowEnd {},
    EndFile {
        hash: String,
    },
    Ack {},
    Done {
        entries: usize,
    },
    Finished {
        stats: Stats,
    },
    Confirmed {},
    Failed {
        report: FailureReport,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureReport {
    reason: FailureReason,
    phase: Option<ReceivePhase>,
    operation: Option<Operation>,
    entry: Option<String>,
}
impl FailureReport {
    fn from_error(error: &anyhow::Error, phase: Option<ReceivePhase>) -> Self {
        Self {
            reason: FailureReason::from_error(error),
            phase,
            operation: error.downcast_ref::<Operation>().copied(),
            entry: error
                .downcast_ref::<TransferEntry>()
                .and_then(|entry| report_entry(&entry.0)),
        }
    }
    fn summary(&self, channel: &Channel, role: &str) -> String {
        let detail = failure_detail(self.entry.as_deref(), self.operation);
        let mut summary = format!(
            "Transfer {} failed on {role}{detail}: {}",
            channel.transfer_id(),
            self.reason
        );
        if let Some(phase) = self.phase {
            summary.push_str(&format!(". The receiver stopped {phase}"));
        }
        summary
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ReceivePhase {
    Preparing,
    DryRun,
    Receiving,
    Finalizing,
}
impl std::fmt::Display for ReceivePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Preparing => "while preparing the destination. This attempt made no destination changes",
            Self::DryRun => "during the dry run. This attempt made no destination changes",
            Self::Receiving => "while receiving entries. Earlier copies or other destination changes may remain",
            Self::Finalizing => "while finalizing the transfer. Earlier copies or other destination changes may remain",
        })
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum FailureReason {
    DestinationBusy,
    DiskHeadroom,
    PermissionDenied,
    MissingEntry,
    WrongType,
    MultipleLinks(u64),
    UnexpectedEntry(fs::EntryType),
    ExpectedRegularFile,
    ExpectedDirectory,
    DirectoryPolicy,
    UnsafeState,
    Changed,
    ReadOnlyFilesystem,
    NoSpace,
    QuotaExceeded,
    UnsafePath,
    FileTooLarge,
    Integrity,
    ListenerBusy,
    Declined,
    Cancelled,
    Other,
}
impl FailureReason {
    fn from_error(error: &anyhow::Error) -> Self {
        if let Some(reason) = error.downcast_ref::<Self>() {
            return *reason;
        }
        if let Some(issue) = error.downcast_ref::<fs::FileFailure>() {
            return match issue {
                fs::FileFailure::DestinationBusy => Self::DestinationBusy,
                fs::FileFailure::DiskHeadroom => Self::DiskHeadroom,
                fs::FileFailure::WrongType => Self::WrongType,
                fs::FileFailure::MultipleLinks(count) => Self::MultipleLinks(*count),
                fs::FileFailure::UnexpectedEntry(kind) => Self::UnexpectedEntry(*kind),
                fs::FileFailure::DirectoryPolicy => Self::DirectoryPolicy,
                fs::FileFailure::UnsafeState => Self::UnsafeState,
                fs::FileFailure::Changed => Self::Changed,
                fs::FileFailure::UnsafePath => Self::UnsafePath,
            };
        }
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return match error.raw_os_error() {
                Some(libc::EROFS) => Self::ReadOnlyFilesystem,
                Some(libc::ENOSPC) => Self::NoSpace,
                Some(libc::EDQUOT) => Self::QuotaExceeded,
                Some(libc::EISDIR) => Self::ExpectedRegularFile,
                Some(libc::ENOTDIR) => Self::ExpectedDirectory,
                Some(libc::ELOOP | libc::EXDEV) => Self::UnsafePath,
                _ if error.kind() == io::ErrorKind::PermissionDenied => Self::PermissionDenied,
                _ if error.kind() == io::ErrorKind::NotFound => Self::MissingEntry,
                _ => Self::Other,
            };
        }
        Self::Other
    }
}
impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationBusy => fs::FileFailure::DestinationBusy.fmt(f),
            Self::DiskHeadroom => fs::FileFailure::DiskHeadroom.fmt(f),
            Self::PermissionDenied => f.write_str("permission denied by the filesystem"),
            Self::MissingEntry => f.write_str("required file or directory is missing"),
            Self::WrongType => {
                f.write_str("unexpected file type or unsupported link or special file")
            }
            Self::MultipleLinks(count) => fs::FileFailure::MultipleLinks(*count).fmt(f),
            Self::UnexpectedEntry(kind) => fs::FileFailure::UnexpectedEntry(*kind).fmt(f),
            Self::ExpectedRegularFile => {
                f.write_str("found a directory where a regular file was expected")
            }
            Self::ExpectedDirectory => f.write_str("found a file where a directory was expected"),
            Self::DirectoryPolicy => f.write_str(
                "directory ownership or permissions violate the local sole-owned policy",
            ),
            Self::UnsafeState => {
                f.write_str("private .ssync-state has unsafe ownership or permissions")
            }
            Self::Changed => f.write_str("file or directory changed during the transfer"),
            Self::ReadOnlyFilesystem => f.write_str("filesystem is read-only"),
            Self::NoSpace => f.write_str("filesystem is out of space"),
            Self::QuotaExceeded => f.write_str("filesystem quota exceeded"),
            Self::UnsafePath => {
                f.write_str("path is unsafe or crosses a symlink or mount boundary")
            }
            Self::FileTooLarge => f.write_str("file exceeds the 16 GiB limit"),
            Self::Integrity => f.write_str("file or block content failed integrity verification"),
            Self::ListenerBusy => f.write_str("listener transfer slots busy; retry later"),
            Self::Declined => f.write_str("transfer declined by the connecting operator"),
            Self::Cancelled => f.write_str("transfer cancelled locally"),
            Self::Other => f.write_str(
                "SSync could not finish the operation; the log on this side has details",
            ),
        }
    }
}
impl std::error::Error for FailureReason {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Operation {
    ScanSource,
    ReadSource,
    VerifySource,
    OpenDestination,
    InspectDestination,
    CreateDirectory,
    SetPermissions,
    PreparePartial,
    WritePartial,
    PreserveTimestamp,
    ReplaceFile,
    DeleteExtras,
    VerifyDestination,
}
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ScanSource => "scanning the source",
            Self::ReadSource => "reading the source file",
            Self::VerifySource => "verifying the source",
            Self::OpenDestination => "opening or locking the destination root",
            Self::InspectDestination => "inspecting the destination entry",
            Self::CreateDirectory => "creating the destination directory",
            Self::SetPermissions => "setting destination permissions",
            Self::PreparePartial => "preparing private resume data",
            Self::WritePartial => "writing private resume data",
            Self::PreserveTimestamp => "preserving the modification timestamp",
            Self::ReplaceFile => "publishing the destination file",
            Self::DeleteExtras => "removing extra destination entries",
            Self::VerifyDestination => "verifying the destination",
        })
    }
}
#[derive(Debug)]
pub(crate) struct TransferEntry(pub(crate) String);
impl fmt::Display for TransferEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("handling the transfer root")
        } else {
            write!(f, "handling transfer entry {:?}", self.0)
        }
    }
}

#[derive(Debug)]
struct PeerFailure(String);
impl fmt::Display for PeerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PeerFailure {}

fn report_entry(path: &str) -> Option<String> {
    (path.is_empty() || fs::valid(path).is_ok()).then(|| path.to_owned())
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
fn selected(path: &Path, sole_owned: bool, entry_limit: usize) -> Result<Selected> {
    let abs = fs::absolute(path)?;
    let name = abs
        .file_name()
        .context("cannot transfer filesystem root")?
        .to_str()
        .context("non UTF8 name")?
        .to_string();
    fs::valid(&name)?;
    // A locally selected directory can itself be a mount/subvolume. Opening it
    // beneath its parent would incorrectly apply the child-mount prohibition.
    match Root::with_policy(&abs, sole_owned) {
        Ok(root) => Ok(Selected {
            root: root.with_entry_limit(entry_limit),
            path: String::new(),
            name,
            is_dir: true,
        }),
        Err(directory_error) => {
            let parent = Root::with_policy(abs.parent().context("missing parent")?, sole_owned)?;
            let meta = parent.source_metadata(&name)?;
            if meta.is_dir() {
                return Err(directory_error);
            }
            Ok(Selected {
                root: parent.with_entry_limit(entry_limit),
                path: name.clone(),
                name,
                is_dir: false,
            })
        }
    }
}
// Protect configuration names and their descendants, including directory/file conflicts.
// Match the CLI's case-insensitive configuration suffix.
fn protected_config(path: &str) -> bool {
    path.split('/')
        .any(|part| part.to_ascii_lowercase().ends_with(".ssync"))
}
fn warn_config(path: &str) {
    eprintln!(
        "SSync warning: skipping protected .ssync path {:?}; continuing transfer",
        path
    );
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
    ensure!(!stop.load(Ordering::Relaxed), FailureReason::Cancelled);
    Ok(())
}
fn approve(t: &Transfer, channel: &mut Channel, connector: bool, description: &str) -> Result<()> {
    if connector {
        println!(
            "Authenticated transfer {} ({description}), local paths {:?}",
            channel.transfer_id(),
            t.paths
        );
        let yes = if t.options.force {
            true
        } else {
            print!("Is this correct? (y|n): ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            println!();
            line.trim() == "y"
        };
        channel.send(&Message::Approved { yes })?;
        ensure!(yes, FailureReason::Declined);
    } else {
        match transfer_message(channel)? {
            Message::Approved { yes: true } => {}
            Message::Approved { yes: false } => {
                // The unchanged approval message also works with older connectors.
                return Err(peer_failure(
                    channel,
                    FailureReport {
                        reason: FailureReason::Declined,
                        phase: None,
                        operation: None,
                        entry: None,
                    },
                ));
            }
            _ => bail!("expected transfer approval from the connecting peer"),
        }
    }
    Ok(())
}
pub fn run(
    t: &Transfer,
    channel: &mut Channel,
    connector: bool,
    stop: &AtomicBool,
) -> Result<Stats> {
    let mut phase = ReceivePhase::Preparing;
    let result = if t.sending() {
        send(t, channel, connector, stop)
    } else {
        receive(t, channel, connector, stop, &mut phase)
    };
    let mut stats = result.map_err(|error| {
        if error.is::<PeerFailure>() {
            return error;
        }
        if error.is::<TransportFailure>() && !stop.load(Ordering::Relaxed) {
            let receiver_status = if t.sending() {
                ". Transfer completion was not confirmed; earlier destination changes may remain"
            } else {
                ""
            };
            return error.context(format!(
                "Transfer {} interrupted on {}. Failure origin unknown; check the {} log{receiver_status}",
                channel.transfer_id(),
                channel.local_role(),
                channel.peer_role(),
            ));
        }

        let mut report = FailureReport::from_error(&error, (!t.sending()).then_some(phase));
        if matches!(report.reason, FailureReason::Declined) {
            report.phase = None;
        }
        if error.is::<TransportFailure>() && stop.load(Ordering::Relaxed) {
            report.reason = FailureReason::Cancelled;
        }
        let summary = report.summary(channel, channel.local_role());
        if !matches!(report.reason, FailureReason::Declined) {
            channel.report_failure(&Message::Failed { report });
        }
        error.context(summary)
    })?;
    stats.wire_sent = channel.wire_sent;
    stats.wire_received = channel.wire_received;
    println!(
        "Transfer {} completed on {}",
        channel.transfer_id(),
        channel.local_role()
    );
    println!("SSYNC_STATS {}", serde_json::to_string(&stats)?);
    Ok(stats)
}

pub(crate) fn listener_busy(channel: &mut Channel, sending: bool) -> anyhow::Error {
    let report = FailureReport {
        reason: FailureReason::ListenerBusy,
        phase: (!sending).then_some(ReceivePhase::Preparing),
        operation: None,
        entry: None,
    };
    let summary = report.summary(channel, channel.local_role());
    channel.report_failure(&Message::Failed { report });
    anyhow::anyhow!(summary)
}

fn peer_failure(channel: &Channel, report: FailureReport) -> anyhow::Error {
    PeerFailure(report.summary(channel, channel.peer_role())).into()
}

fn transfer_message(channel: &mut Channel) -> Result<Message> {
    match channel.recv()? {
        Message::Failed { report } if channel.peer_diagnostics() => {
            Err(peer_failure(channel, report))
        }
        message => Ok(message),
    }
}

fn failure_detail(entry: Option<&str>, operation: Option<Operation>) -> String {
    let mut detail = match entry {
        Some("") => " for the transfer root".to_owned(),
        Some(path) if fs::valid(path).is_ok() => format!(" for transfer entry {path:?}"),
        _ => String::new(),
    };
    if let Some(op) = operation {
        detail.push_str(&format!(" while {op}"));
    }
    detail
}
fn send(t: &Transfer, c: &mut Channel, connector: bool, stop: &AtomicBool) -> Result<Stats> {
    let Message::Options {
        merge,
        dryrun,
        skip: remote_skip,
        permissions,
        chmod: remote_chmod,
    } = transfer_message(c).context("waiting for receiver options")?
    else {
        bail!("expected receiver options")
    };
    ensure!(
        permissions,
        "permission preservation requires updated SSync on both machines; receiver is too old"
    );
    if let Some(mode) = remote_chmod {
        fs::validate_mode(mode)?;
    }
    let chmod = remote_chmod.or(t.options.chmod);
    check_filters(&remote_skip)?;
    let mut skip = t.options.skip.clone();
    skip.extend(remote_skip);
    ensure!(skip.len() <= 64, "too many combined filters");
    let limits = fs::TransferLimits::new(t.options.large_transfer);
    let mut sources = Vec::new();
    for path in &t.paths {
        let path = fs::absolute(path)
            .with_context(|| format!("resolving source path {path:?}"))
            .context(Operation::ScanSource)?;
        if !path.components().any(|c| c.as_os_str() == fs::STATE) {
            sources.push(
                selected(&path, t.options.sole_owned, limits.entries)
                    .with_context(|| format!("opening source {:?}", path))
                    .context(Operation::ScanSource)
                    .with_context(|| {
                        TransferEntry(
                            path.file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .into_owned(),
                        )
                    })?,
            );
        }
    }
    ensure!(sources.len() <= 128, "source selection limit");
    if merge && !sources.is_empty() {
        ensure!(
            sources.len() == 1 && sources[0].is_dir,
            "merge requires one source directory"
        );
    }
    let mut names = BTreeSet::new();
    for s in &sources {
        ensure!(
            names.insert(s.name.clone()),
            "duplicate source basename {:?}",
            s.name
        );
    }
    let mut plan = Plan::new(limits);
    let omitted = |p: &str| filtered(p, &skip);
    for s in &sources {
        plan.scan(
            &s.root,
            &s.path,
            if merge { "" } else { &s.name },
            &omitted,
            stop,
        )
        .context(Operation::ScanSource)?;
    }
    plan.finish()?;
    let mut roots = Vec::new();
    for s in &sources {
        let name = links::project(&s.name);
        let source_path = || format!("checking selected source {:?}", s.root.path.join(&s.path));
        if s.root
            .password_path(&s.path)
            .with_context(source_path)
            .context(Operation::ScanSource)?
        {
            continue;
        }
        if s.root
            .source_metadata(&s.path)
            .with_context(source_path)
            .context(Operation::ScanSource)?
            .is_symlink()
        {
            roots.push((links::sidecar(&name), false));
        } else {
            roots.push((name.clone(), s.is_dir));
            if !merge && !s.is_dir && plan.descriptions.contains_key(&name) {
                roots.push((links::sidecar(&name), false));
            }
        }
    }
    ensure!(
        roots.len() <= 128,
        "source selection including link descriptions exceeds 128 roots"
    );
    c.send(&Message::Begin {
        roots,
        skip: t.options.skip.clone(),
        dryrun: t.options.dryrun,
        nodelete: t.options.nodelete,
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
            t.options.verbose,
            chmod,
            &plan,
            c,
            &mut stats,
            &mut count,
            stop,
        )?;
    }
    cancelled(stop)?;
    c.send(&Message::Done { entries: count })?;
    let Message::Finished { stats: remote } =
        transfer_message(c).context("waiting for the receiver to confirm completion")?
    else {
        bail!("receiver did not verify completed transfer")
    };
    ensure!(
        remote.content_bytes == stats.content_bytes,
        "transfer byte accounting mismatch"
    );
    stats.deleted = remote.deleted;
    if t.options.verify {
        for s in &sources {
            println!(
                "Directory Verification Hash {:?}: {}",
                s.name,
                tree_hash(&s.root, &s.path)
                    .context(Operation::VerifySource)
                    .with_context(|| TransferEntry(links::project(&s.name)))?
            );
        }
    }
    if c.peer_diagnostics() {
        c.send(&Message::Confirmed {})?;
    }
    Ok(stats)
}
#[allow(clippy::too_many_arguments)]
fn send_entry(
    root: &Root,
    source: &str,
    target: &str,
    skip: &[String],
    dry: bool,
    verbose: bool,
    chmod: Option<u32>,
    plan: &Plan,
    c: &mut Channel,
    stats: &mut Stats,
    count: &mut usize,
    stop: &AtomicBool,
) -> Result<()> {
    cancelled(stop)?;
    let source_path = || format!("source entry {:?}", root.path.join(source));
    if root
        .password_path(source)
        .with_context(source_path)
        .context(Operation::ScanSource)?
    {
        stats.skipped += 1;
        return Ok(());
    }
    if !target.is_empty() && filtered(target, skip) {
        return Ok(());
    }
    let original_target = target;
    let projected = links::project(target);
    let target = projected.as_str();
    if !target.is_empty() && filtered(target, skip) {
        return Ok(());
    }
    let entry = || TransferEntry(target.to_owned());
    let meta = root
        .source_metadata(source)
        .with_context(source_path)
        .context(Operation::ScanSource)
        .with_context(entry)?;
    let before = fs::identity(&meta);
    if meta.is_symlink() {
        let name = links::sidecar(target);
        if filtered(&name, skip) {
            return Ok(());
        }
        send_description(root, source, target, chmod, plan, dry, c, stats, count).with_context(
            || {
                format!(
                    "sending link description {name:?} for {:?}",
                    root.path.join(source)
                )
            },
        )?;
    } else if meta.is_dir() {
        c.send(&Message::Directory {
            path: target.into(),
            mode: meta.mode() & 0o777,
        })
        .with_context(|| format!("announcing destination directory {target:?}"))?;
        expect_ack(c).with_context(|| format!("waiting for destination directory {target:?}"))?;
        *count += 1;
        for name in root
            .list(source)
            .with_context(source_path)
            .context(Operation::ScanSource)?
        {
            let source = if source.is_empty() {
                name.clone()
            } else {
                format!("{source}/{name}")
            };
            let target = if original_target.is_empty() {
                name
            } else {
                format!("{original_target}/{name}")
            };
            send_entry(
                root, &source, &target, skip, dry, verbose, chmod, plan, c, stats, count, stop,
            )?;
        }
        if fs::identity(
            &root
                .source_metadata(source)
                .with_context(source_path)
                .context(Operation::VerifySource)?,
        ) != before
        {
            return Err(fs::FileFailure::Changed)
                .with_context(source_path)
                .context(Operation::VerifySource);
        }
    } else {
        ensure!(
            meta.is_file(),
            "source {:?} is not a regular file",
            root.path.join(source)
        );
        if meta.len() > MAX_FILE {
            return Err(FailureReason::FileTooLarge)
                .with_context(|| {
                    format!(
                        "source file {:?} is {} bytes",
                        root.path.join(source),
                        meta.len()
                    )
                })
                .context(Operation::ReadSource)
                .with_context(entry);
        }
        let (mut file, hash) = (|| -> Result<_> {
            let mut file = root.read_source(source)?;
            ensure!(
                fs::identity(&file.metadata()?) == before,
                fs::FileFailure::Changed
            );
            let hash = fs::digest(&mut file)?.to_hex().to_string();
            Ok((file, hash))
        })()
        .with_context(source_path)
        .context(Operation::ReadSource)
        .with_context(entry)?;
        c.send(&Message::File {
            path: target.into(),
            size: meta.len(),
            hash: hash.clone(),
            modified_secs: std::os::unix::fs::MetadataExt::mtime(&meta),
            modified_nanos: std::os::unix::fs::MetadataExt::mtime_nsec(&meta) as u32,
            mode: chmod.unwrap_or(meta.mode() & 0o777),
        })
        .with_context(|| format!("announcing destination file {target:?}"))?;
        let Message::Need { skip: whole_skip } = transfer_message(c)
            .with_context(|| format!("checking destination file {:?}", target))?
        else {
            bail!("expected block request")
        };
        if whole_skip {
            stats.skipped += 1;
            if fs::identity(
                &file
                    .metadata()
                    .with_context(source_path)
                    .context(Operation::VerifySource)?,
            ) != before
            {
                return Err(fs::FileFailure::Changed)
                    .with_context(source_path)
                    .context(Operation::VerifySource);
            }
        } else {
            file.seek(SeekFrom::Start(0))
                .with_context(source_path)
                .context(Operation::ReadSource)?;
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
                        if fs::identity(&file.metadata()?) != before {
                            return Err(fs::FileFailure::Changed)
                                .context("source changed while streaming");
                        }
                        Ok(())
                    })();
                    if let Err(e) = result.context(Operation::ReadSource) {
                        let _ = tx.send(Err(e));
                    }
                });
                let mut blocks = rx.into_iter();
                if let Some(first) = blocks.next() {
                    let mut current = first?;
                    c.send(&Message::Block {
                        offset: current.0,
                        len: current.1.len(),
                        hash: current.2.clone(),
                    })?;
                    loop {
                        cancelled(stop)?;
                        let Message::Want { yes, reused } = transfer_message(c)? else {
                            bail!("expected block comparison");
                        };
                        ensure!(
                            !(yes && reused) && (yes || reused || dry),
                            "invalid block comparison"
                        );
                        let next = blocks.next().transpose()?;
                        if let Some((offset, bytes, hash)) = &next {
                            c.send(&Message::Block {
                                offset: *offset,
                                len: bytes.len(),
                                hash: hash.clone(),
                            })?;
                        } else {
                            c.send(&Message::WindowEnd {})?;
                        }
                        if verbose {
                            println!(
                                "Block {:?}@{}+{}: {}",
                                target,
                                current.0,
                                current.1.len(),
                                if yes {
                                    "send"
                                } else if reused {
                                    "reuse"
                                } else {
                                    "preview"
                                }
                            );
                        }
                        if yes {
                            ensure!(!dry, "dry run requested payload");
                            stats.content_bytes += current.1.len() as u64;
                            c.send_bytes(&current.1)?;
                            expect_ack(c)?;
                        } else if reused {
                            stats.reused_bytes += current.1.len() as u64;
                        }
                        if let Some(next) = next {
                            current = next;
                        } else {
                            break;
                        }
                    }
                }
                Ok(())
            })
            .with_context(entry)?;
            (|| -> Result<()> {
                let mut reopened = root
                    .read_source(source)
                    .context("checking whether the source changed after copying")?;
                if fs::digest(&mut reopened)?.to_hex().as_str() != hash {
                    return Err(fs::FileFailure::Changed)
                        .context("source changed during final verification");
                }
                Ok(())
            })()
            .with_context(source_path)
            .context(Operation::VerifySource)
            .with_context(entry)?;
            c.send(&Message::EndFile { hash })
                .with_context(|| format!("completing destination file {target:?}"))?;
            expect_ack(c).with_context(|| {
                format!("waiting for the receiver to confirm file {:?}", target)
            })?;
            stats.files += 1;
        }
        *count += 1;
        if plan.descriptions.contains_key(target) {
            send_description(root, source, target, chmod, plan, dry, c, stats, count)
                .with_context(|| {
                    format!(
                        "sending link description {:?} for {:?}",
                        links::sidecar(target),
                        root.path.join(source)
                    )
                })?;
        }
    }
    ensure!(*count <= root.entry_limit(), "manifest entry limit");
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn send_description(
    root: &Root,
    source: &str,
    target: &str,
    chmod: Option<u32>,
    plan: &Plan,
    dry: bool,
    c: &mut Channel,
    stats: &mut Stats,
    count: &mut usize,
) -> Result<()> {
    let description = plan
        .descriptions
        .get(target)
        .context("source link changed since planning")?;
    ensure!(
        fs::identity(&root.source_metadata(source)?) == description.identity,
        "source link changed since planning"
    );
    let path = links::sidecar(target);
    let bytes = &description.bytes;
    ensure!(bytes.len() < BLOCK, "link description too large");
    let hash = blake3::hash(bytes).to_hex().to_string();
    let meta = root.source_metadata(source)?;
    eprintln!("SSync: describing source link {:?} as {:?}", target, path);
    c.send(&Message::File {
        path,
        size: bytes.len() as u64,
        hash: hash.clone(),
        modified_secs: meta.mtime(),
        modified_nanos: meta.mtime_nsec() as u32,
        mode: chmod.unwrap_or(0o600),
    })?;
    let Message::Need { skip } = transfer_message(c)? else {
        bail!("expected link description request")
    };
    if skip {
        stats.skipped += 1;
    } else {
        c.send(&Message::Block {
            offset: 0,
            len: bytes.len(),
            hash: hash.clone(),
        })?;
        let Message::Want { yes, reused } = transfer_message(c)? else {
            bail!("expected link description comparison")
        };
        ensure!(
            !(yes && reused) && (yes || reused || dry),
            "invalid link description comparison"
        );
        c.send(&Message::WindowEnd {})?;
        if yes {
            ensure!(!dry, "dry run requested link description payload");
            c.send_bytes(bytes)?;
            stats.content_bytes += bytes.len() as u64;
            expect_ack(c)?;
        } else if reused {
            stats.reused_bytes += bytes.len() as u64;
        }
        ensure!(
            fs::identity(&root.source_metadata(source)?) == description.identity,
            "source link changed during transfer"
        );
        c.send(&Message::EndFile { hash })?;
        expect_ack(c)?;
        stats.files += 1;
    }
    ensure!(
        fs::identity(&root.source_metadata(source)?) == description.identity,
        "source link changed during transfer"
    );
    *count += 1;
    Ok(())
}
fn expect_ack(c: &mut Channel) -> Result<()> {
    ensure!(
        matches!(transfer_message(c)?, Message::Ack {}),
        "expected acknowledgment"
    );
    Ok(())
}

fn receive(
    t: &Transfer,
    c: &mut Channel,
    connector: bool,
    stop: &AtomicBool,
    phase: &mut ReceivePhase,
) -> Result<Stats> {
    c.send(&Message::Options {
        merge: t.options.merge,
        dryrun: t.options.dryrun,
        skip: t.options.skip.clone(),
        permissions: true,
        chmod: t.options.chmod,
    })?;
    let Message::Begin {
        roots,
        skip: remote_skip,
        dryrun: remote_dry,
        nodelete: remote_nodelete,
    } = transfer_message(c).context("waiting for the sender's selected paths")?
    else {
        bail!("expected selected roots")
    };
    ensure!(roots.len() <= 128, "source selection limit");
    check_filters(&remote_skip)?;
    let mut top = BTreeSet::new();
    for (name, _) in &roots {
        fs::valid(name).with_context(|| format!("invalid source root {name:?}"))?;
        ensure!(
            !name.contains('/') && top.insert(name.clone()),
            "invalid or duplicate source root {name:?}"
        );
    }
    if t.options.merge && !roots.is_empty() {
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
    effective.options.nodelete |= remote_nodelete;
    let t = &effective;
    let limits = fs::TransferLimits::new(t.options.large_transfer);
    let root = Root::with_policy(&t.paths[0], t.options.sole_owned)
        .with_context(|| format!("opening destination root {:?}", t.paths[0]))
        .context(Operation::OpenDestination)?
        .with_entry_limit(limits.entries);
    root.lock()
        .context(Operation::OpenDestination)
        .with_context(|| TransferEntry(String::new()))?;
    if t.options.dryrun {
        *phase = ReceivePhase::DryRun;
    }
    let mut stats = Stats::default();
    let mut seen = BTreeSet::new();
    let mut path_bytes = 0usize;
    let mut directories = Vec::new();
    let result = (|| -> Result<()> {
        loop {
            cancelled(stop)?;
            let msg = transfer_message(c)?;
            match msg {
                Message::Directory { path, mode } => (|| -> Result<()> {
                    if path.is_empty() {
                        ensure!(
                            t.options.merge && roots.len() == 1 && roots[0].1,
                            "root permissions require a selected merge directory"
                        );
                    } else {
                        authorize(&path, &roots, t.options.merge, &skip)?;
                    }
                    root.validate_directory_mode(mode)
                        .context(Operation::SetPermissions)?;
                    ensure!(seen.insert(path.clone()), "duplicate entry");
                    path_bytes += path.len();
                    ensure!(path_bytes <= limits.path_bytes, "manifest path-byte limit");
                    if root
                        .password_path(&path)
                        .context(Operation::InspectDestination)?
                        || protected_config(&path)
                    {
                        if protected_config(&path) {
                            warn_config(&path);
                        }
                        stats.skipped += 1;
                    } else if t.options.dryrun {
                        println!("Would create directory {:?}", path);
                        if let Some(m) = root
                            .metadata(&path)
                            .context(Operation::InspectDestination)?
                            && !m.is_dir()
                        {
                            return Err(FailureReason::ExpectedDirectory)
                                .context(Operation::CreateDirectory);
                        }
                    } else {
                        root.check_receive_space()
                            .context(Operation::CreateDirectory)?;
                        *phase = ReceivePhase::Receiving;
                        root.mkdirs(&path).context(Operation::CreateDirectory)?;
                        directories.push(
                            root.prepare_directory_mode(&path, mode)
                                .with_context(|| format!("preparing mode {mode:04o}"))
                                .context(Operation::SetPermissions)?,
                        );
                    }
                    c.send(&Message::Ack {})
                })()
                .with_context(|| TransferEntry(path))?,
                Message::File {
                    path,
                    size,
                    hash,
                    modified_secs,
                    modified_nanos,
                    mode,
                } => (|| -> Result<()> {
                    authorize(&path, &roots, t.options.merge, &skip)?;
                    ensure!(seen.insert(path.clone()), "duplicate entry");
                    path_bytes += path.len();
                    ensure!(path_bytes <= limits.path_bytes, "manifest path-byte limit");
                    check_hash(&hash)?;
                    ensure!(size <= MAX_FILE, FailureReason::FileTooLarge);
                    receive_file(
                        &root,
                        &path,
                        size,
                        &hash,
                        (modified_secs, modified_nanos),
                        mode,
                        t,
                        c,
                        &mut stats,
                        stop,
                        phase,
                    )
                })()
                .with_context(|| TransferEntry(path))?,
                Message::Done { entries } => {
                    ensure!(entries == seen.len(), "incomplete manifest");
                    break;
                }
                _ => bail!("unexpected transfer operation"),
            }
            ensure!(seen.len() <= limits.entries, "manifest entry limit");
        }
        cancelled(stop)?;
        if !t.options.dryrun {
            *phase = ReceivePhase::Finalizing;
        }
        if !roots.is_empty() && !t.options.nodelete && !t.options.dryrun {
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
                delete_extras(&root, &scope, &seen, &skip, &mut stats, stop)
                    .context(Operation::DeleteExtras)?;
            }
        }
        if t.options.verify {
            println!(
                "Directory Verification Hash: {}",
                tree_hash(&root, "").context(Operation::VerifyDestination)?
            );
        }
        Ok(())
    })();
    // Finalize children before parents, including when a later file fails. Keep
    // directories writable until mirror cleanup and verification have finished.
    directories.sort_by_key(|d| {
        std::cmp::Reverse(d.path.matches('/').count() + usize::from(!d.path.is_empty()))
    });
    let mut mode_error = None;
    for directory in directories {
        if let Err(error) = root
            .finish_directory_mode(&directory)
            .with_context(|| format!("applying directory mode {:04o}", directory.mode))
            .context(Operation::SetPermissions)
            .with_context(|| TransferEntry(directory.path))
        {
            eprintln!(
                "Transfer {} failed to preserve directory permissions on {}: {error:#}",
                c.transfer_id(),
                c.local_role()
            );
            mode_error.get_or_insert(error);
        }
    }
    result?;
    if let Some(error) = mode_error {
        return Err(error);
    }
    // All destination work is complete. Release the root before the sender
    // finishes its optional local verification and confirms the result.
    drop(root);
    c.send(&Message::Finished {
        stats: stats.clone(),
    })?;
    if c.peer_diagnostics() {
        ensure!(
            matches!(
                transfer_message(c).context("waiting for the sender's completion confirmation")?,
                Message::Confirmed {}
            ),
            "expected the sender's completion confirmation"
        );
    }
    Ok(stats)
}
fn authorize(path: &str, roots: &[(String, bool)], merge: bool, skip: &[String]) -> Result<()> {
    fs::valid(path).context(fs::FileFailure::UnsafePath)?;
    ensure!(!roots.is_empty(), "entry without a selected source root");
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
    modified: (i64, u32),
    mode: u32,
    t: &Transfer,
    c: &mut Channel,
    stats: &mut Stats,
    stop: &AtomicBool,
    phase: &mut ReceivePhase,
) -> Result<()> {
    fs::validate_mode(mode)
        .with_context(|| format!("invalid source file mode {mode:04o}"))
        .context(Operation::SetPermissions)?;
    let mode = t.options.chmod.unwrap_or(mode);
    ensure!(
        (-62_135_596_800..=253_402_300_799).contains(&modified.0) && modified.1 < 1_000_000_000,
        "unsupported modification timestamp ({} seconds, {} nanoseconds)",
        modified.0,
        modified.1
    );
    if root
        .password_path(path)
        .context(Operation::InspectDestination)?
        || protected_config(path)
    {
        if protected_config(path) {
            warn_config(path);
        }
        stats.skipped += 1;
        c.send(&Message::Need { skip: true })?;
        return Ok(());
    }
    let meta = root.metadata(path).context(Operation::InspectDestination)?;
    if let Some(m) = &meta {
        if m.is_dir() {
            return Err(FailureReason::ExpectedRegularFile).context(Operation::InspectDestination);
        }
        fs::regular(m).context(Operation::InspectDestination)?;
    }
    let expected = meta.as_ref().map(fs::identity);
    let mut old = if meta.is_some() {
        match root.read(path) {
            Ok(file) => Some(file),
            // An owner can replace a mode-000 file through its writable parent.
            // It cannot be used for comparison; leave it intact until commit.
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) =>
            {
                None
            }
            Err(error) => return Err(error).context(Operation::InspectDestination),
        }
    } else {
        None
    };
    if let Some(f) = old.as_mut()
        && f.metadata().context(Operation::InspectDestination)?.len() == size
        && fs::digest(f)
            .context(Operation::InspectDestination)?
            .to_hex()
            .as_str()
            == hash
    {
        if root
            .metadata(path)
            .context(Operation::InspectDestination)?
            .as_ref()
            .map(fs::identity)
            != expected
        {
            return Err(fs::FileFailure::Changed).context(Operation::InspectDestination);
        }
        if !t.options.dryrun {
            *phase = ReceivePhase::Receiving;
            root.set_file_mode(path, f, &expected, mode)
                .with_context(|| format!("applying file mode {mode:04o}"))
                .context(Operation::SetPermissions)?;
        }
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
        root.check_receive_space()
            .context(Operation::PreparePartial)?;
        *phase = ReceivePhase::Receiving;
        root.mkdirs(fs::split(path).0)
            .context(Operation::CreateDirectory)?;
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
        Some(
            root.stage(&id)
                .with_context(|| format!("opening {:?} on the receiver", root.path.join(fs::STATE)))
                .context(Operation::PreparePartial)?,
        )
    };
    if let Some((state, _)) = &stage {
        root.partial_capacity(state, &id, size)
            .context(Operation::PreparePartial)?;
    }
    c.send(&Message::Need { skip: false })?;
    let mut final_hash = blake3::Hasher::new();
    if size > 0 {
        let partial = stage.as_ref().map(|(_, f)| f.try_clone()).transpose()?;
        let previous = old.as_ref().map(|f| f.try_clone()).transpose()?;
        std::thread::scope(|scope| -> Result<()> {
            type Request = (u64, usize, String);
            let (requests, receive) = mpsc::sync_channel::<Request>(2);
            let (results, compared) = mpsc::sync_channel::<Result<(Vec<u8>, bool)>>(2);
            scope.spawn(move || {
                for (offset, len, hash) in receive {
                    let result = (|| -> Result<(Vec<u8>, bool)> {
                        let mut data = vec![0; len];
                        let mut reused = false;
                        if let Some(f) = &partial {
                            reused = read_matching(f, offset, &mut data, &hash)
                                .context(Operation::InspectDestination)?;
                        }
                        if !reused && let Some(f) = &previous {
                            reused = read_matching(f, offset, &mut data, &hash)
                                .context(Operation::InspectDestination)?;
                        }
                        Ok((data, reused))
                    })();
                    if results.send(result).is_err() {
                        break;
                    }
                }
            });
            let mut offset = 0u64;
            let first = block_request(transfer_message(c)?, 0, size)?;
            requests
                .send(first.clone())
                .map_err(|_| anyhow::anyhow!("comparison worker stopped"))?;
            let mut current = first;
            loop {
                cancelled(stop)?;
                let (mut data, reused) = compared
                    .recv()
                    .map_err(|_| anyhow::anyhow!("comparison worker stopped"))??;
                let want = !reused && !t.options.dryrun;
                c.send(&Message::Want { yes: want, reused })?;
                let next_offset = offset + current.1 as u64;
                let next_message = transfer_message(c)?;
                let next = if next_offset < size {
                    let next = block_request(next_message, next_offset, size)?;
                    requests
                        .send(next.clone())
                        .map_err(|_| anyhow::anyhow!("comparison worker stopped"))?;
                    Some(next)
                } else {
                    ensure!(
                        matches!(next_message, Message::WindowEnd {}),
                        "invalid comparison window end"
                    );
                    None
                };
                // Next range comparison runs concurrently with current payload receipt/write.
                if t.options.verbose {
                    println!(
                        "Block {:?}@{}+{}: {}",
                        path,
                        offset,
                        current.1,
                        if want {
                            "receive"
                        } else if reused {
                            "reuse"
                        } else {
                            "preview"
                        }
                    );
                }
                if want {
                    let bytes = c.recv_bytes()?;
                    if bytes.len() != current.1
                        || blake3::hash(&bytes).to_hex().as_str() != current.2
                    {
                        // A terminal sender report can arrive where a raw block was expected.
                        if c.peer_diagnostics()
                            && bytes.len() <= 6 * 4096 + 256
                            && let Ok(Message::Failed { report }) = serde_json::from_slice(&bytes)
                        {
                            return Err(peer_failure(c, report));
                        }
                        return Err(FailureReason::Integrity).with_context(|| {
                            format!("block content verification failed at offset {offset}")
                        });
                    }
                    data = bytes;
                    stats.content_bytes += current.1 as u64;
                } else if reused {
                    stats.reused_bytes += current.1 as u64;
                }
                if let Some((_, file)) = stage.as_mut() {
                    (|| -> Result<()> {
                        fs::check_receive_space(file, data.len())?;
                        file.seek(SeekFrom::Start(offset))?;
                        file.write_all(&data)?;
                        Ok(())
                    })()
                    .with_context(|| format!("writing {} bytes at offset {offset}", data.len()))
                    .context(Operation::WritePartial)?;
                    final_hash.update(&data);
                }
                if want {
                    c.send(&Message::Ack {})?;
                }
                if let Some(next) = next {
                    current = next;
                    offset = next_offset;
                } else {
                    break;
                }
            }
            drop(requests);
            Ok(())
        })?;
    }
    let Message::EndFile { hash: source_hash } = transfer_message(c)? else {
        bail!("expected complete-file verification")
    };
    ensure!(source_hash == hash, fs::FileFailure::Changed);
    if let Some((state, f)) = stage.as_mut() {
        if final_hash.finalize().to_hex().as_str() != hash {
            return Err(FailureReason::Integrity).context("final reconstructed digest mismatch");
        }
        f.set_len(size).context(Operation::WritePartial)?;
        if fs::digest(f)
            .context(Operation::WritePartial)?
            .to_hex()
            .as_str()
            != hash
        {
            return Err(FailureReason::Integrity).context("staged file changed");
        }
        use std::os::fd::AsRawFd;
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: modified.0,
                tv_nsec: modified.1 as i64,
            },
        ];
        if unsafe { libc::futimens(f.as_raw_fd(), times.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error()).context(Operation::PreserveTimestamp);
        }
        use std::os::unix::fs::MetadataExt;
        let timestamp = f.metadata()?;
        ensure!(
            timestamp.mtime() == modified.0 && timestamp.mtime_nsec() == modified.1 as i64,
            "filesystem cannot preserve modification timestamp"
        );
        f.sync_all().context(Operation::WritePartial)?;
        root.check_receive_space().context(Operation::ReplaceFile)?;
        // Verify receiver base has not changed even if copied ranges were identical.
        if root
            .metadata(path)
            .context(Operation::ReplaceFile)?
            .as_ref()
            .map(fs::identity)
            != expected
        {
            return Err(fs::FileFailure::Changed)
                .context("destination changed during transfer")
                .context(Operation::ReplaceFile);
        }
        root.commit(state, &id, path, &expected)
            .context(Operation::ReplaceFile)?;
        // Resume files remain 0600 until the verified inode is published.
        let committed = Some(fs::identity(&f.metadata()?));
        root.set_file_mode(path, f, &committed, mode)
            .with_context(|| format!("applying file mode {mode:04o}"))
            .context(Operation::SetPermissions)?;
    }
    stats.files += 1;
    c.send(&Message::Ack {})?;
    Ok(())
}
fn block_request(message: Message, offset: u64, size: u64) -> Result<(u64, usize, String)> {
    let Message::Block {
        offset: remote,
        len,
        hash,
    } = message
    else {
        bail!("expected block metadata");
    };
    check_hash(&hash)?;
    ensure!(
        remote == offset && offset < size && len == (size - offset).min(BLOCK as u64) as usize,
        "invalid block range"
    );
    Ok((offset, len, hash))
}
fn read_matching(file: &File, offset: u64, data: &mut [u8], hash: &str) -> Result<bool> {
    use std::os::unix::fs::FileExt;
    if file.metadata()?.len() < offset + data.len() as u64 {
        return Ok(false);
    }
    let mut n = 0;
    while n < data.len() {
        let got = file.read_at(&mut data[n..], offset + n as u64)?;
        if got == 0 {
            return Ok(false);
        }
        n += got;
    }
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
    if protected_config(path) {
        warn_config(path);
        return Ok(());
    }
    let entry = || format!("checking mirror entry {:?}", root.path.join(path));
    if filtered(path, skip) || root.password_path(path).with_context(entry)? {
        return Ok(());
    }
    let Some(m) = root.metadata(path).with_context(entry)? else {
        return Ok(());
    };
    if m.is_dir() {
        for name in root.list(path).with_context(entry)? {
            let child = if path.is_empty() {
                name
            } else {
                format!("{path}/{name}")
            };
            delete_extras(root, &child, seen, skip, stats, stop)?;
        }
    }
    if !path.is_empty() && !seen.contains(path) {
        if m.is_dir() && !root.list(path).with_context(entry)?.is_empty() {
            return Ok(());
        }
        cancelled(stop)?;
        let current = root
            .metadata(path)?
            .context("delete path disappeared")
            .with_context(entry)?;
        let id = fs::identity(&current);
        root.remove(path, &id)
            .with_context(|| format!("removing destination entry {:?}", root.path.join(path)))?;
        stats.deleted += 1;
    }
    Ok(())
}
pub fn tree_hash(root: &Root, path: &str) -> Result<String> {
    fn walk(root: &Root, path: &str, h: &mut blake3::Hasher, count: &mut usize) -> Result<()> {
        let entry = || format!("verifying {:?}", root.path.join(path));
        if root.password_path(path).with_context(entry)? {
            return Ok(());
        }
        *count += 1;
        ensure!(*count <= root.entry_limit(), "hash entry limit");
        let m = root.source_metadata(path).with_context(entry)?;
        h.update(&(path.len() as u64).to_be_bytes());
        h.update(path.as_bytes());
        h.update(&[u8::from(m.is_dir())]);
        if m.is_dir() {
            for name in root.list(path).with_context(entry)? {
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
        } else if m.is_symlink() {
            h.update(b"softlink");
            h.update(&root.source_link(path).with_context(entry)?);
        } else {
            let mut f = root.read_source(path).with_context(entry)?;
            h.update(&m.len().to_be_bytes());
            h.update(fs::digest(&mut f).with_context(entry)?.as_bytes());
        }
        Ok(())
    }
    let mut h = blake3::Hasher::new();
    walk(root, path, &mut h, &mut 0)?;
    Ok(h.finalize().to_hex().to_string())
}
