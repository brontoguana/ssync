//! Latest-copy backup modes. Configured credentials select local upload-only bays.
use crate::{
    auth::{self, Channel, Credential},
    cli::{self, Options, Transfer},
    fs::{self, Root},
    runtime::{self, Admission, Control},
    transfer,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const PORT: u16 = 8425;
const MAX: usize = 32;
const CONFIG_LIMIT: u64 = 1_048_576;
pub enum Command {
    Server {
        port: u16,
        file: PathBuf,
        verbose: bool,
    },
    Client {
        file: PathBuf,
        options: Options,
    },
}
#[derive(Clone)]
struct Entry {
    password: Zeroizing<String>,
    path: PathBuf,
}
#[derive(Clone)]
struct Destination {
    host: String,
    port: u16,
}
struct Config {
    entries: Vec<Entry>,
    servers: Vec<Destination>,
}

pub fn parse_command(args: &[String], options: Options) -> Result<Command> {
    ensure!(!args.is_empty(), "backup action required");
    if args[0].eq_ignore_ascii_case("backup-client") {
        ensure!(args.len() <= 2, "backup-client [file]");
        return Ok(Command::Client {
            file: args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| "/opt/backup-client.ssync".into()),
            options,
        });
    }
    ensure!(args.len() <= 3, "backup-server [port] [file]");
    ensure!(
        !options.nodelete
            && !options.dryrun
            && !options.verify
            && options.skip.is_empty()
            && !options.merge
            && !options.force,
        "backup-server accepts only verbose; backup policy qualifiers belong to backup-client"
    );
    let mut port = PORT;
    let mut file = PathBuf::from("/opt/backup-server.ssync");
    match &args[1..] {
        [p, f] => {
            port = cli::alias_port(p)?;
            file = f.into();
        }
        [value] if value.contains('/') || value.to_lowercase().ends_with(".ssync") => {
            file = value.into()
        }
        [value] => port = cli::alias_port(value)?,
        [] => {}
        _ => unreachable!(),
    }
    Ok(Command::Server {
        port,
        file,
        verbose: options.verbose,
    })
}
fn destination(text: &str) -> Result<Destination> {
    ensure!(!text.is_empty() && text.len() <= 512, "invalid destination");
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("IPv6 destination needs closing bracket")?;
        host.parse::<std::net::Ipv6Addr>()
            .context("invalid IPv6 destination")?;
        ensure!(
            !tail.strip_prefix(':').unwrap_or(tail).contains(':'),
            "invalid destination port"
        );
        let port = if tail.is_empty() {
            PORT
        } else {
            cli::alias_port(tail.strip_prefix(':').context("invalid IPv6 port")?)?
        };
        (host.to_string(), port)
    } else {
        let (host, port) = match text.split_once(':') {
            Some((host, port)) => {
                ensure!(!port.contains(':'), "invalid destination port");
                (host, cli::alias_port(port)?)
            }
            None => (text, PORT),
        };
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c)),
            "invalid destination hostname"
        );
        (host.to_string(), port)
    };
    Ok(Destination { host, port })
}
fn parse_config(data: &str, client: bool) -> Result<Config> {
    ensure!(
        data.len() as u64 <= CONFIG_LIMIT,
        "backup configuration too large"
    );
    let mut entries: Vec<Entry> = Vec::new();
    let mut servers = Vec::new();
    let mut destinations = BTreeSet::new();
    for (n, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Never include the line or nested parser errors in diagnostics: it contains secrets.
        let result = (|| -> Result<()> {
            if client && line.starts_with('@') && !line.contains('=') {
                let server = destination(&line[1..])?;
                ensure!(
                    destinations.insert((server.host.to_lowercase(), server.port)),
                    "duplicate destination"
                );
                servers.push(server);
                ensure!(servers.len() <= MAX, "destination limit");
            } else {
                let (password, path) = line.split_once('=').context("expected password=path")?;
                let password = password.trim();
                auth::validate_password(password)?;
                ensure!(
                    !password.chars().any(char::is_control),
                    "control character in password"
                );
                ensure!(
                    !entries.iter().any(|e| e.password.as_str() == password),
                    "duplicate password"
                );
                let path = Path::new(path.trim());
                ensure!(
                    path.is_absolute() && path != Path::new("/"),
                    "explicit absolute directory required"
                );
                let path = fs::absolute(path)?;
                ensure!(path != Path::new("/"), "filesystem root forbidden");
                if !client {
                    ensure!(
                        !entries
                            .iter()
                            .any(|e| e.path.starts_with(&path) || path.starts_with(&e.path)),
                        "overlapping bays"
                    );
                }
                entries.push(Entry {
                    password: Zeroizing::new(password.to_string()),
                    path,
                });
                ensure!(entries.len() <= MAX, "source/bay limit");
            }
            Ok(())
        })();
        if result.is_err() {
            bail!(
                "invalid backup configuration line {}: expected unique 16+ character password=absolute-directory{}; maximum 32 of each, no overlapping server bays",
                n + 1,
                if client { " or @hostname[:port]" } else { "" }
            );
        }
    }
    ensure!(
        !entries.is_empty(),
        "backup configuration needs an active password=directory entry"
    );
    ensure!(
        !client || !servers.is_empty(),
        "backup-client configuration needs an @server destination"
    );
    Ok(Config { entries, servers })
}
fn load(file: &Path, client: bool) -> Result<Config> {
    let file = fs::absolute(file)?;
    // Check missing via lstat; a symlink or unsafe existing entry must never be replaced.
    match std::fs::symlink_metadata(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = Root::new(file.parent().context("config parent missing")?)?;
            let dir = parent.dir("")?;
            let name = std::ffi::CString::new(
                file.file_name()
                    .context("config filename missing")?
                    .as_encoded_bytes(),
            )?;
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            ensure!(
                fd >= 0,
                "cannot create private backup example: {}",
                std::io::Error::last_os_error()
            );
            let mut out = unsafe { File::from_raw_fd(fd) };
            let password = Zeroizing::new(auth::password()?);
            let example = Zeroizing::new(if client {
                format!(
                    "# SSync backup-client: every server receives every source.\n# @myserver\n# @myotherserver:8125\n# {password}=/absolute/source/directory\n",
                    password = password.as_str()
                )
            } else {
                format!(
                    "# SSync backup-server: password=existing bay directory\n# {password}=/srv/backups/example\n",
                    password = password.as_str()
                )
            });
            out.write_all(example.as_bytes())?;
            out.sync_all()?;
            dir.sync_all()?;
            bail!(
                "created private example {:?}; edit/uncomment entries, create directories, then rerun",
                file
            );
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let input = fs::open_local_file(&file)?;
    let meta = input.metadata()?;
    ensure!(
        meta.mode() & 0o077 == 0 && (meta.uid() == unsafe { libc::geteuid() } || meta.uid() == 0),
        "backup config must be private (chmod 600) and owned by current user or root"
    );
    ensure!(meta.len() <= CONFIG_LIMIT, "backup configuration too large");
    let mut data = Zeroizing::new(String::new());
    input
        .take(CONFIG_LIMIT + 1)
        .read_to_string(&mut data)
        .map_err(|_| anyhow::anyhow!("cannot read bounded UTF-8 backup configuration"))?;
    let config = parse_config(&data, client)?;
    let mut roots = BTreeSet::new();
    for entry in &config.entries {
        ensure!(
            !file.starts_with(&entry.path),
            "backup config must be outside source/bay directories"
        );
        let root = Root::new(&entry.path)?;
        let meta = root.metadata("")?.context("directory missing")?;
        if !client {
            ensure!(
                roots.insert((meta.dev(), meta.ino())),
                "duplicate bay directory"
            );
        }
    }
    Ok(config)
}
fn transfer(entry: &Entry, sending: bool, mut options: Options) -> Transfer {
    options.merge = true;
    options.force = true;
    Transfer {
        action: if sending { "put" } else { "get" }.into(),
        host: None,
        port: PORT,
        paths: vec![entry.path.clone()],
        options,
        password: entry.password.clone(),
    }
}
pub fn run(command: Command, control: Arc<Control>) -> Result<()> {
    match command {
        Command::Server {
            port,
            file,
            verbose,
        } => server(port, load(&file, false)?, verbose, control),
        Command::Client { file, options } => client(load(&file, true)?, options, control),
    }
}
fn server(port: u16, config: Config, verbose: bool, control: Arc<Control>) -> Result<()> {
    let credentials = config
        .entries
        .iter()
        .map(|e| Credential::new(&e.password))
        .collect::<Result<Vec<_>>>()?;
    let listener = runtime::listen(port)?;
    listener.set_nonblocking(true)?;
    println!(
        "backup-server now accepting uploads on port {port} ({} bays)",
        config.entries.len()
    );
    let credentials = Arc::new(credentials);
    let config = Arc::new(config);
    let bay_locks = Arc::new(
        (0..config.entries.len())
            .map(|_| Mutex::new(()))
            .collect::<Vec<_>>(),
    );
    let admission = Arc::new(Mutex::new(Admission::default()));
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !control.stop.load(Ordering::Relaxed) {
        workers.retain(|w| !w.is_finished());
        match listener.accept() {
            Ok((socket, addr)) => {
                let ip = addr.ip().to_canonical();
                if active.load(Ordering::Relaxed) >= 4
                    || !admission.lock().unwrap().allow(ip, Instant::now())
                {
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                let (credentials, config, locks, admission, active, control) = (
                    credentials.clone(),
                    config.clone(),
                    bay_locks.clone(),
                    admission.clone(),
                    active.clone(),
                    control.clone(),
                );
                workers.push(std::thread::spawn(move || {
                    let result = (|| -> Result<()> {
                        let _socket = control.track(&socket)?;
                        let (mut channel, selected) =
                            match Channel::authenticate_backup(socket, "", Some(&credentials)) {
                                Ok(value) => {
                                    admission.lock().unwrap().success(ip);
                                    value
                                }
                                Err(_) => {
                                    admission.lock().unwrap().failure(ip, Instant::now());
                                    bail!("backup authentication/protocol confirmation failed");
                                }
                            };
                        let Ok(_bay) = locks[selected].try_lock() else {
                            channel.send(&false)?;
                            bail!("backup bay busy; retry later");
                        };
                        channel.send(&true)?;
                        let t = transfer(
                            &config.entries[selected],
                            false,
                            Options {
                                verbose,
                                ..Options::default()
                            },
                        );
                        transfer::run(&t, &mut channel, false, &control.stop)?;
                        Ok(())
                    })();
                    if let Err(e) = result {
                        eprintln!("Backup upload failed: {e:#}");
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => {
                control.cancel();
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(e.into());
            }
        }
    }
    control.cancel();
    for worker in workers {
        let _ = worker.join();
    }
    bail!("cancelled")
}
fn upload(
    entry: &Entry,
    destination: &Destination,
    options: &Options,
    control: &Arc<Control>,
) -> Result<()> {
    ensure!(!control.stop.load(Ordering::Relaxed), "cancelled");
    let addresses = (destination.host.as_str(), destination.port)
        .to_socket_addrs()?
        .take(8)
        .collect::<Vec<_>>();
    let mut connected = None;
    for address in addresses {
        ensure!(!control.stop.load(Ordering::Relaxed), "cancelled");
        if let Ok(socket) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            connected = Some(socket);
            break;
        }
    }
    let socket = connected.context("cannot connect to backup server")?;
    let _socket = control.track(&socket)?;
    let (mut channel, _) = Channel::authenticate_backup(socket, &entry.password, None)
        .map_err(|_| anyhow::anyhow!("backup authentication/protocol confirmation failed"))?;
    ensure!(channel.recv::<bool>()?, "backup bay busy; retry later");
    transfer::run(
        &transfer(entry, true, options.clone()),
        &mut channel,
        true,
        &control.stop,
    )?;
    Ok(())
}
fn client(config: Config, options: Options, control: Arc<Control>) -> Result<()> {
    let count = config.entries.len() * config.servers.len();
    let next = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..count.min(4) {
            scope.spawn(|| {
                loop {
                    let job = next.fetch_add(1, Ordering::Relaxed);
                    if job >= count {
                        break;
                    }
                    let entry = &config.entries[job / config.servers.len()];
                    let destination = &config.servers[job % config.servers.len()];
                    match upload(entry, destination, &options, &control) {
                        Ok(()) => println!(
                            "Backup complete: {:?} -> {}:{}",
                            entry.path, destination.host, destination.port
                        ),
                        Err(e) => {
                            failures.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "Backup failed: {:?} -> {}:{}: {e:#}",
                                entry.path, destination.host, destination.port
                            );
                        }
                    }
                }
            });
        }
    });
    let failed = failures.load(Ordering::Relaxed);
    println!(
        "Backup cycle: {} succeeded, {failed} failed",
        count - failed
    );
    ensure!(failed == 0, "one or more backup destinations failed");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_contract() {
        let config = parse_config(
            "# comment\n@host\nabcdefghijklmnop=/source with = sign\n@[::1]:8125\n",
            true,
        )
        .unwrap();
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.servers[0].port, PORT);
        assert_eq!(config.servers[1].host, "::1");
        assert_eq!(config.entries[0].path, Path::new("/source with = sign"));
        for text in [
            "abcdefghijklmnop=/x\nabcdefghijklmnop=/y",
            "abcdefghijklmnop=/x\nqrstuvwxyz123456=/x/y",
            "short=/x",
            "abcdefghijklmnop=relative",
            "abcdefghijklmnop=/",
            "@server",
        ] {
            assert!(parse_config(text, false).is_err());
        }
        for text in [
            "@x:0\nabcdefghijklmnop=/x",
            "@x\n@X:8425\nabcdefghijklmnop=/x",
            "@bad@host\nabcdefghijklmnop=/x",
            "@::1\nabcdefghijklmnop=/x",
            "@x:1:2\nabcdefghijklmnop=/x",
            "@[::1]:1:2\nabcdefghijklmnop=/x",
            "abcdefghijklmnop=/x",
        ] {
            assert!(parse_config(text, true).is_err());
        }
    }
    #[test]
    fn bounded_configs() {
        let lines = (0..33)
            .map(|i| format!("unique-password-{i:04}=/bay-{i}\n"))
            .collect::<String>();
        assert!(parse_config(&lines, false).is_err());
        let config = parse_config("@host\n@password-with-at-sign=/source", true).unwrap();
        assert_eq!(
            config.entries[0].password.as_str(),
            "@password-with-at-sign"
        );
        for action in ["backup-server", "backup-client"] {
            assert!(matches!(
                cli::parse(&[action.into()], Some("ignored")),
                Ok(cli::Command::Backup(_))
            ));
        }
        let cli::Command::Backup(Command::Client { file, .. }) =
            cli::parse(&["backup-client".into()], None).unwrap()
        else {
            panic!()
        };
        assert_eq!(file, Path::new("/opt/backup-client.ssync"));
    }
    #[test]
    fn command_defaults() {
        for (args, expected) in [
            (vec!["backup-server"], PORT),
            (vec!["backup-server", "8125"], 8125),
            (vec!["backup-server", "/tmp/bays"], PORT),
        ] {
            let args = args.into_iter().map(String::from).collect::<Vec<_>>();
            let Command::Server { port, .. } = parse_command(&args, Options::default()).unwrap()
            else {
                panic!()
            };
            assert_eq!(port, expected);
        }
        assert!(parse_command(&["backup-server".into(), "0".into()], Options::default()).is_err());
    }
}
