use crate::auth;
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::{self, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;

#[derive(Clone, Default, Debug)]
pub struct Options {
    pub merge: bool,
    pub nodelete: bool,
    pub dryrun: bool,
    pub verify: bool,
    pub verbose: bool,
    pub force: bool,
    pub sole_owned: bool,
    pub chmod: Option<u32>,
    pub skip: Vec<String>,
}
#[derive(Clone)]
pub struct Transfer {
    pub action: String,
    pub host: Option<String>,
    pub port: u16,
    pub paths: Vec<PathBuf>,
    pub options: Options,
    pub password: Zeroizing<String>,
}
impl Transfer {
    pub fn sending(&self) -> bool {
        matches!(self.action.as_str(), "put" | "offer")
    }
    pub fn continuous(&self) -> bool {
        matches!(self.action.as_str(), "offer" | "accept")
    }
}
pub enum Command {
    Transfer(Transfer),
    Pwd,
    Version,
    Help(&'static str),
    Guide,
    Diagnostic(String, PathBuf),
    Management(String),
    Config(PathBuf, bool),
    Licenses,
    Backup(crate::backup::Command),
}
pub fn alias_port(alias: &str) -> Result<u16> {
    ensure!(
        !alias.is_empty() && alias.len() <= 256,
        "invalid port or alias"
    );
    let numeric = alias.trim();
    let digits = numeric
        .strip_prefix('+')
        .or_else(|| numeric.strip_prefix('-'))
        .unwrap_or(numeric);
    if !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()) {
        let port: i64 = numeric
            .parse()
            .map_err(|_| anyhow::anyhow!("port must be 1..65535"))?;
        ensure!((1..=65535).contains(&port), "port must be 1..65535");
        return Ok(port as u16);
    }
    let mut hash = 0i32;
    for c in alias.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(c as i32);
    }
    Ok((1000 + (hash as u32 & 0x7fff_ffff) % 50000) as u16)
}
pub fn password_input(env: Option<&str>) -> Result<Option<Zeroizing<String>>> {
    use std::io::Read;
    if let Some(p) = env.filter(|p| !p.is_empty()) {
        return Ok(Some(Zeroizing::new(p.to_string())));
    }
    if let Some(path) = std::env::var_os("SSYNC_PASSWORD_FILE") {
        use std::os::unix::fs::MetadataExt;
        let f = crate::fs::open_config_file(std::path::Path::new(&path))?;
        let m = f.metadata()?;
        ensure!(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0 && m.len() <= 4098,
            "password file must be private, owned, and bounded"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        f.take(4099).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4098, "password file too large");
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        let secret = Zeroizing::new(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| anyhow::anyhow!("password file must be UTF-8"))?,
        );
        auth::validate_password(&secret)?;
        return Ok(Some(secret));
    }
    if let Ok(fd) = std::env::var("SSYNC_PASSWORD_FD") {
        use std::os::fd::FromRawFd;
        let fd: i32 = fd
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid password descriptor"))?;
        ensure!((0..=1024).contains(&fd), "invalid password descriptor");
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(copy >= 0, "password descriptor unavailable");
        let file = unsafe { std::fs::File::from_raw_fd(copy) };
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(4097).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4096, "password descriptor input too large");
        let secret = Zeroizing::new(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| anyhow::anyhow!("password descriptor must be UTF-8"))?,
        );
        auth::validate_password(&secret)?;
        return Ok(Some(secret));
    }
    Ok(None)
}
pub fn parse(args: &[String], env: Option<&str>) -> Result<Command> {
    ensure!(
        args.len() <= 256 && args.iter().all(|a| a.len() <= 8192),
        "command input exceeds limits"
    );
    if args.is_empty() {
        return Ok(Command::Help(HELP));
    }
    if matches!(args[0].to_lowercase().as_str(), "--help" | "help") {
        ensure!(args.len() <= 2, "use ssync --help [topic]");
        return Ok(Command::Help(match args.get(1) {
            Some(topic) => help_topic(topic)?,
            None => HELP,
        }));
    }
    if args.len() == 1 {
        match args[0].to_lowercase().as_str() {
            "backup-server" | "backup-client" => {
                return Ok(Command::Backup(crate::backup::parse_command(
                    args,
                    Options::default(),
                )?));
            }
            "pwd" => return Ok(Command::Pwd),
            "licenses" | "--licenses" => return Ok(Command::Licenses),
            "version" | "--version" => return Ok(Command::Version),
            "?" => return Ok(Command::Guide),
            "install" | "update" | "uninstall" => {
                return Ok(Command::Management(args[0].to_lowercase()));
            }
            _ => {}
        }
        if args[0].to_lowercase().ends_with(".ssync") {
            return Ok(Command::Config(args[0].clone().into(), false));
        }
        if std::path::Path::new(&args[0]).is_file() {
            return Ok(Command::Diagnostic(
                "inspect".into(),
                args[0].clone().into(),
            ));
        }
    }
    if args.len() == 2
        && args[0].eq_ignore_ascii_case("sole-owned")
        && args[1].to_lowercase().ends_with(".ssync")
    {
        return Ok(Command::Config(args[1].clone().into(), true));
    }
    if args.len() == 2 && matches!(args[0].to_lowercase().as_str(), "hash" | "deep" | "scan") {
        return Ok(Command::Diagnostic(
            args[0].to_lowercase(),
            args[1].clone().into(),
        ));
    }
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].to_lowercase().as_str() {
            "sole-owned" => o.sole_owned = true,
            "merge" => o.merge = true,
            "nodelete" => o.nodelete = true,
            "dryrun" => o.dryrun = true,
            "verify" => o.verify = true,
            "verbose" => o.verbose = true,
            "force" | "noprompt" => o.force = true,
            "--chmod" | "--permissions" | "chmod" | "permissions" => {
                i += 1;
                o.chmod = Some(parse_mode(
                    args.get(i)
                        .context("chmod requires an octal mode, e.g. 644")?,
                )?);
            }
            _ if ["chmod:", "permissions:", "--chmod=", "--permissions="]
                .iter()
                .any(|prefix| args[i].to_lowercase().starts_with(prefix)) =>
            {
                let value = args[i].split_once([':', '=']).unwrap().1;
                o.chmod = Some(parse_mode(value)?);
            }
            _ if args[i].to_lowercase().starts_with("skip:") => {
                ensure!(args[i].len() > 5, "empty skip filter");
                o.skip.push(args[i][5..].to_string());
                ensure!(o.skip.len() <= 32, "too many filters");
            }
            _ if args[i].to_lowercase().starts_with("script:") => {
                bail!("execution features are forbidden")
            }
            _ => break,
        }
        i += 1;
    }
    if i < args.len()
        && matches!(
            args[i].to_lowercase().as_str(),
            "backup-server" | "backup-client"
        )
    {
        return Ok(Command::Backup(crate::backup::parse_command(
            &args[i..],
            o,
        )?));
    }
    if args.len() == i + 2 && matches!(args[i].to_lowercase().as_str(), "hash" | "deep" | "scan") {
        return Ok(Command::Diagnostic(
            args[i].to_lowercase(),
            args[i + 1].clone().into(),
        ));
    }
    ensure!(
        args.len() > i + 1,
        "expected action and location; use ssync --help"
    );
    let action = args[i].to_lowercase();
    ensure!(
        matches!(action.as_str(), "put" | "get" | "offer" | "accept"),
        "unknown or forbidden action"
    );
    let location = &args[i + 1];
    let (inline, location) = if let Some((p, l)) = location.split_once('@') {
        (Some(p), l)
    } else {
        (None, location.as_str())
    };
    let (host, port) = if location.starts_with('[') {
        let (host, port) = location
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("IPv6 requires [address]:port"))?;
        (Some(host[1..].to_string()), alias_port(port)?)
    } else if let Some((h, p)) = location.rsplit_once(':') {
        ensure!(
            !h.is_empty() && !h.contains(':'),
            "invalid host; use [IPv6]:port"
        );
        (Some(h.to_string()), alias_port(p)?)
    } else {
        (None, alias_port(location)?)
    };
    let additional = password_input(env)?;
    let password = match additional.as_deref().map(|s| s.as_str()).or(inline) {
        Some(p) => p.to_string(),
        None if host.is_some() => rpassword::prompt_password("Password: ")?,
        None => {
            let p = auth::password()?;
            println!("Your password for this transfer is: {p}");
            p
        }
    };
    auth::validate_password(&password)?;
    let paths = if args.len() == i + 2 {
        vec![PathBuf::from(".")]
    } else {
        args[i + 2..].iter().map(PathBuf::from).collect()
    };
    if matches!(action.as_str(), "get" | "accept") {
        ensure!(
            paths.len() == 1,
            "receiver authorizes exactly one directory"
        );
    }
    Ok(Command::Transfer(Transfer {
        action,
        host,
        port,
        paths,
        options: o,
        password: Zeroizing::new(password),
    }))
}
fn parse_mode(value: &str) -> Result<u32> {
    ensure!(
        (value.len() == 3 || (value.len() == 4 && value.starts_with('0')))
            && value.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        "chmod requires an octal rwx mode from 000 to 777, e.g. 600 or 0755"
    );
    Ok(u32::from_str_radix(value, 8)?)
}
pub const HELP: &str = concat!(
    "SSync v",
    env!("CARGO_PKG_VERSION"),
    " — native file synchronization\n",
    r#"
Usage:
  ssync [qualifiers] <action> <location> [files or folders]
  ssync ?                         Interactive guidance
  ssync --help                    Show this help
  ssync --help <topic>            Show detailed topic help

Actions:
  offer                           Send files continuously
  accept                          Receive uploads continuously
  put                             Send files once
  get                             Receive files once

Locations (accept connections):
  1500                            Listen on TCP port 1500
  MyDocuments                     Listen on a port derived from this alias

Locations (make a connection):
  host:1500                       Connect to a host and TCP port
  host:MyDocuments                Connect to a host and alias-derived port
  [2001:db8::1]:1500              Connect using an IPv6 address

  A host determines who connects; the action determines who sends.
  offer/accept keep listening, or repeat connections when a host is given.
  Local paths default to .; the receiving folder must already exist.

Sample commands:
  ssync offer MyDocuments ./docs   Offer docs under the alias MyDocuments
  ssync get host:MyDocuments ./dl  Download into the existing folder dl
  ssync accept 1500 ./uploads      Continuously receive into uploads
  ssync force put host:1500 ./docs Upload docs without a confirmation prompt
  ssync --chmod 644 put host:1500 ./docs
                                  Upload with mode 644 on every copied file
  ssync nodelete merge get host:MyDocuments ./dl
                                  Merge contents into dl and retain extras

Qualifiers (before the action):
  merge                           Receive one folder's contents into the root
  nodelete                        Keep extra destination entries
  dryrun                          Preview without writing or changing modes
  verify                          Print a final tree hash
  verbose                         Show block comparisons and transfer details
  force | noprompt                Skip the transfer confirmation prompt
  skip:substring                  Protect matching paths from copy/deletion
  sole-owned                      Reject local group/other-writable folders
  --chmod MODE | chmod:MODE        Override all copied file modes, e.g. 600/755
  --permissions MODE              Alias for --chmod; permissions:MODE also works

Saved configurations and backups:
  ssync commands.ssync            Run saved transfer commands concurrently
  ssync backup-server [port] [file]
  ssync backup-client [file]

Special commands:
  ssync pwd                       Print one generated password
  ssync version                   Print the version
  ssync licenses                  Print licence and dependency notices
  ssync hash <folder>             Print a BLAKE3 tree hash
  ssync deep <file>               Hash a file in 200,000-byte blocks
  ssync scan <file>               Count file bytes
  ssync <file>                    Inspect a local file (except .ssync)
  sudo ssync install              Install system-wide
  sudo ssync update               Check for and install the latest release
  sudo ssync uninstall            Remove the owned installation

Detailed help:
  ssync --help permissions        Source modes and file mode overrides
  ssync --help links              Link descriptions and recreation
  ssync --help mirroring          Deletion, filters and local directory policy
  ssync --help passwords          Password inputs and precedence
  ssync --help config             Saved configurations and cron
  ssync --help backup             Backup server/client usage
  ssync --help compatibility      Platforms and endpoint versions

  Linux x86_64, kernel 5.6+. Both peers need updated builds; restart listeners.
"#
);

const HELP_PERMISSIONS: &str = r#"Permissions:
  Default: reproduce source read/write/execute bits on files and folders.
  New, replaced and content-identical files get source modes. New and
  existing selected folders also get source modes, even without content
  changes. Ownership, group, ACLs and special bits are not copied.

  Override file permissions (qualifiers go before the action):
    ssync chmod:600 force put host:1500 ./private
    ssync --chmod 644 force put host:1500 ./docs
    ssync --permissions 755 force get host:1500 ./downloads

  Permission behaviour for items included in the transfer:
    Destination item                     Default      chmod:600
    -----------------------------------  -----------  -----------
    New file                             Source mode  0600
    Existing file, contents updated      Source mode  0600
    Existing file, contents unchanged    Source mode  0600
    New folder                           Source mode  Source mode
    Existing folder, contents updated    Source mode  Source mode
    Existing folder, contents unchanged  Source mode  Source mode

  Source mode means the source item's read/write/execute permissions.

  --chmod MODE, chmod:MODE, --permissions MODE and permissions:MODE are
  equivalent; --chmod=MODE and --permissions=MODE also work. Modes are
  octal 000..777, optionally with one leading zero. No symbolic/special bits.
  Either peer may set an override; the receiving peer's setting wins.
  Folders retain source modes. Overrides also apply to .ssynclink files;
  these descriptions otherwise default to 0600. Private resume data stays
  private. Excluded/protected paths and unrelated retained items are not
  chmodded. A dry run changes nothing.

  Use qualifiers on each saved configuration line, or before backup-client
  / backup-server. Both endpoints need updated builds; restart listeners.

"#;

const HELP_LINKS: &str = r#"Links:
  Source symlinks become X.ssynclink text descriptions with the target and
  manual recreation instructions. Targets are never followed; destination
  symlinks are not created. Broken links and directory links are described.

  Example description for X pointing to A/B/C:
    type: softlink
    path: "A/B/C"

  Hard-linked regular files are copied independently with descriptions of
  known partner paths. Unknown partners are recorded as path: null.
  Descriptions default to 0600; --chmod overrides that file mode.
  Description/source name collisions fail before writes. Rename or filter
  the conflicting entry with skip:. Filters may exclude a link or description.
  Descriptions participate in verification, resume, dry runs and mirroring.
  Existing destination links stay protected; special files are unsupported.

"#;

const HELP_MIRRORING: &str = r#"Mirroring and local directory policy:
  Extra entries inside selected source folders are deleted by default,
  after verification. Use nodelete to retain them. Single files do not
  delete neighbours. Source job.ssync becomes job.ssyncbak (case-insensitive
  suffix), in ordinary transfers and backups. Directory names are renamed too.
  Existing destination .ssync paths remain protected. Name collisions fail
  before copying; skip: filters match original and projected names.
  .ssync-state is reserved and ignored during scans, without inspecting it.
  Receiving resume state must still be private and owned by the receiving user.
  Shared-writable folders are allowed; sole-owned is set independently on
  each peer and adds receiver ownership/ancestor checks. Local users who
  can modify shared folders are trusted. Transfers are atomic per file.

"#;

const HELP_PASSWORDS: &str = r#"Passwords:
  Run ssync pwd to generate a password. Supplied passwords need 16 or more
  characters. Connectors prompt privately; listeners generate a password.
  Precedence: SSYNC_PASSWORD > SSYNC_PASSWORD_FILE > SSYNC_PASSWORD_FD
  > password@location > prompt/generated listener password.
  Password files must be private and owned. Inline passwords can appear
  in process listings and shell history; prefer a password file for cron.
  SSYNC_PASSWORD_FILE can name any file. That configured file and its hard-link
  aliases are excluded from copying, replacement, chmod and mirror deletion,
  including backups. Unidentified secret files cannot be detected; keep them
  outside transfer folders or exclude them with skip:.

"#;

const HELP_CONFIG: &str = r#"Saved configurations:
  ssync commands.ssync            Run one transfer command per line
  ssync sole-owned commands.ssync  Also require trusted local directories

  Lines contain arguments without a leading ssync; quote paths with spaces.
  Example line: force nodelete put host:1500 ./docs
  Commands run concurrently. A failed command cancels sibling commands;
  avoid duplicate listeners when launching configurations from cron.
  Transfers copy job.ssync as job.ssyncbak, including backups. Copies retain
  all contents, possibly inline passwords; keep them suitably protected.
  No shell expansion or script execution. Rename a copy manually to restore.

"#;

const HELP_BACKUP: &str = r#"Backup commands:
  ssync [qualifiers] backup-server [port] [file]
    Persistent upload-only server. Default port: 8425.
    Default file: /opt/backup-server.ssync
    Qualifiers: verbose, sole-owned, --chmod MODE.
  ssync [qualifiers] backup-client [file]
    Upload each source to each server once, without a confirmation prompt.
    Default file: /opt/backup-client.ssync
    Qualifiers: nodelete, dryrun, verify, verbose, sole-owned, skip:substring,
    --chmod MODE. Uses the same permissions and link descriptions.

  A missing backup file is created privately with examples; edit and rerun.
  Configured folders must already exist. Backups mirror by default; use
  nodelete to keep extras. There is no backup history or network restore.

"#;

const HELP_COMPATIBILITY: &str = r#"Compatibility:
  Linux x86_64, kernel 5.6+; supported local, case-sensitive filesystems.
  Both endpoints need the updated permissions-aware build. Restart old
  listeners after upgrading. Published 4.1.3 cannot use these extensions.
"#;

pub fn help_topic(topic: &str) -> Result<&'static str> {
    Ok(match topic.to_ascii_lowercase().as_str() {
        "permissions" => HELP_PERMISSIONS,
        "links" => HELP_LINKS,
        "mirroring" => HELP_MIRRORING,
        "passwords" => HELP_PASSWORDS,
        "config" => HELP_CONFIG,
        "backup" => HELP_BACKUP,
        "compatibility" => HELP_COMPATIBILITY,
        _ => bail!("unknown help topic; use ssync --help to list topics"),
    })
}

pub fn guide() -> Result<Vec<String>> {
    fn ask(label: &str) -> Result<String> {
        print!("{label}: ");
        io::stdout().flush()?;
        let mut s = String::new();
        ensure!(io::stdin().read_line(&mut s)? > 0, "input closed");
        Ok(s.trim_end_matches(['\r', '\n']).to_string())
    }
    println!("SSync interactive guidance. Choose put/get (once) or offer/accept (continuous).");
    let action = ask("Action")?;
    let location = ask("Location (port/alias listens, host:port connects)")?;
    let path = ask("Local file/directory (empty means .)")?;
    let mut args = vec![action, location];
    if !path.is_empty() {
        args.push(path);
    }
    Ok(args)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contract() {
        assert_eq!(alias_port("MyDir").unwrap(), 35545);
        assert!(alias_port("0").is_err());
        assert!(alias_port("65536").is_err());
        assert_eq!(alias_port(" +1500 ").unwrap(), 1500);
        assert!(alias_port("-1").is_err());
        for action in ["put", "get", "offer", "accept"] {
            for location in ["4000", "example:4000", "[::1]:4000", "alias/A"] {
                let c = parse(
                    &[
                        "force".into(),
                        action.into(),
                        format!("abcdefghijklmnop@{location}"),
                        ".".into(),
                    ],
                    Some("environment-pass"),
                )
                .unwrap();
                if let Command::Transfer(c) = c {
                    assert_eq!(&*c.password, "environment-pass");
                    assert_eq!(c.host.is_some(), location.contains(':'));
                } else {
                    panic!()
                }
            }
        }
        assert!(
            parse(
                &["script:x:y".into(), "put".into(), "4000".into()],
                Some("abcdefghijklmnop")
            )
            .is_err()
        );
    }
}
