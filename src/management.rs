//! Local-only native management. No subprocesses or remote scripts.
use crate::fs::{self, Root};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
const OWNER: &str = ".ssync-install.json";
const BINARY: &str = "ssync";
const LIMIT: usize = 64 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    application: String,
    version: String,
    sha256: String,
}
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    html_url: String,
    assets: Vec<Asset>,
    draft: bool,
    prerelease: bool,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn directory() -> Result<PathBuf> {
    let path = std::env::var_os("SSYNC_INSTALL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin"));
    if path == std::path::Path::new("/usr/local/bin") {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "system installation requires sudo"
        );
    }
    ensure!(path.is_absolute(), "SSYNC_INSTALL_DIR must be absolute");
    Ok(path)
}
fn read_file(root: &Root, name: &str, limit: usize) -> Result<Vec<u8>> {
    let file = root.read(name)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "installation file too large"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "installation file too large");
    Ok(bytes)
}
fn ownership(root: &Root) -> Result<Option<Ownership>> {
    if root.metadata(OWNER)?.is_none() {
        ensure!(
            root.metadata(BINARY)?.is_none(),
            "existing ssync has no ownership record; refusing to replace unrelated executable"
        );
        return Ok(None);
    }
    let m = root.metadata(OWNER)?.context("ownership record missing")?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o600,
        "unsafe ownership record"
    );
    let record: Ownership = serde_json::from_slice(&read_file(root, OWNER, 4096)?)?;
    ensure!(
        record.application == "SSync native"
            && hash(&read_file(root, BINARY, LIMIT)?) == record.sha256,
        "installation is unrelated or locally modified; refusing management"
    );
    Ok(Some(record))
}
fn elf(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() > 64 && &bytes[..4] == b"\x7fELF" && bytes[4] == 2 && bytes[5] == 1,
        "release artifact is not a supported Linux ELF"
    );
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    let expected = match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        _ => bail!("unsupported architecture"),
    };
    ensure!(
        machine == expected,
        "release artifact architecture mismatch"
    );
    Ok(())
}
fn install_bytes(root: &Root, bytes: &[u8], version: &str) -> Result<()> {
    elf(bytes)?;
    let prior = ownership(root)?;
    if let Some(record) = prior.as_ref() {
        if record.sha256 == hash(bytes) {
            println!("SSync {version} is already installed in {:?}", root.path);
            return Ok(());
        }
    }
    let binary_expected = root.metadata(BINARY)?.as_ref().map(fs::identity);
    let record_expected = root.metadata(OWNER)?.as_ref().map(fs::identity);
    let id = blake3::hash(crate::auth::password()?.as_bytes())
        .to_hex()
        .to_string();
    let (state, mut file) = root.stage(&id)?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.set_permissions(Permissions::from_mode(0o755))?;
    file.sync_all()?;
    let record = serde_json::to_vec(&Ownership {
        application: "SSync native".into(),
        version: version.into(),
        sha256: hash(bytes),
    })?;
    let rid = blake3::hash(crate::auth::password()?.as_bytes())
        .to_hex()
        .to_string();
    let (rstate, mut rfile) = root.stage(&rid)?;
    rfile.write_all(&record)?;
    rfile.sync_all()?;
    // All checks/downloads/staging finish before replacing the installed binary.
    root.commit(&state, &id, BINARY, &binary_expected)?;
    root.commit(&rstate, &rid, OWNER, &record_expected)?;
    println!("Installed SSync {version} in {:?}", root.path);
    Ok(())
}
fn allowed_url(url: &str, test: bool) -> Result<()> {
    if test {
        ensure!(
            url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:"),
            "test release URLs must be loopback"
        );
    } else {
        ensure!(
            url.starts_with("https://github.com/brontoguana/ssync/")
                || url.starts_with("https://api.github.com/repos/brontoguana/ssync/"),
            "untrusted release URL"
        );
    }
    Ok(())
}
fn download(url: &str, limit: usize, test: bool) -> Result<Vec<u8>> {
    allowed_url(url, test)?;
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .max_redirects(5)
        .build()
        .new_agent();
    let mut response = agent.get(url).header("User-Agent", "ssync/4.0.0").call()?;
    let mut result = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut result)?;
    ensure!(result.len() <= limit, "download size limit");
    Ok(result)
}
pub fn run(action: &str) -> Result<()> {
    let dir = directory()?;
    let root = Root::new(&dir)?;
    root.lock()?;
    match action {
        "install" => {
            let file = File::open("/proc/self/exe")?;
            let mut bytes = Vec::new();
            file.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= LIMIT, "executable size limit");
            install_bytes(&root, &bytes, env!("CARGO_PKG_VERSION"))?;
        }
        "uninstall" => {
            let Some(record) = ownership(&root)? else {
                println!("SSync is not installed in {:?}", root.path);
                return Ok(());
            };
            let _ = record;
            for name in [BINARY, OWNER] {
                let m = root.metadata(name)?.context("installation changed")?;
                root.remove(name, &fs::identity(&m))?;
            }
            println!(
                "Uninstalled SSync from {:?}; transfer data preserved",
                root.path
            );
        }
        "update" => {
            let installed =
                ownership(&root)?.context("SSync is not installed; run ssync install first")?;
            let test = std::env::var("SSYNC_TEST_UPDATE").as_deref() == Ok("1");
            let url = if test {
                std::env::var("SSYNC_RELEASE_API_URL").context("test release URL missing")?
            } else {
                "https://api.github.com/repos/brontoguana/ssync/releases/latest".into()
            };
            let release: Release = serde_json::from_slice(&download(&url, 262144, test)?)?;
            ensure!(
                !release.draft && !release.prerelease && release.assets.len() <= 100,
                "invalid stable release"
            );
            let latest = release
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&release.tag_name);
            let available = semver::Version::parse(latest)?;
            let current = semver::Version::parse(&installed.version)?;
            println!(
                "Current: {current}; available: {available}\nRelease: {}\n{}\n{}",
                release.name.as_deref().unwrap_or(&release.tag_name),
                release.html_url,
                release.body.as_deref().unwrap_or("No release notes")
            );
            if available <= current {
                println!("SSync is up to date");
                return Ok(());
            }
            let arch = match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                _ => bail!("unsupported architecture"),
            };
            let artifact = format!("ssync_linux_{arch}");
            let asset = release
                .assets
                .iter()
                .find(|a| a.name == artifact)
                .context("release platform artifact missing")?;
            ensure!(
                asset.size <= LIMIT as u64 && asset.size > 64,
                "artifact size limit"
            );
            let checksum = release
                .assets
                .iter()
                .find(|a| a.name == "checksums.txt")
                .context("release checksums missing")?;
            let sums = download(&checksum.browser_download_url, 65536, test)?;
            let sums = std::str::from_utf8(&sums)?;
            let mut matches = sums.lines().filter_map(|line| {
                let mut fields = line.split_whitespace();
                let h = fields.next()?;
                let name = fields.next()?.trim_start_matches('*');
                (name == artifact && fields.next().is_none()).then_some(h)
            });
            let expected = matches.next().context("artifact checksum missing")?;
            ensure!(
                matches.next().is_none()
                    && expected.len() == 64
                    && expected.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid or duplicate artifact checksum"
            );
            let bytes = download(&asset.browser_download_url, LIMIT, test)?;
            ensure!(
                bytes.len() as u64 == asset.size && hash(&bytes) == expected.to_lowercase(),
                "release checksum/length verification failed; installed executable preserved"
            );
            install_bytes(&root, &bytes, latest)?;
        }
        _ => bail!("unknown local management operation"),
    }
    Ok(())
}
