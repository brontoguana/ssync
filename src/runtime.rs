use crate::{
    auth::{Channel, Credential},
    cli::{self, Command, Transfer},
    fs, transfer,
};
use anyhow::{Result, bail, ensure};
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(1);
pub struct Control {
    pub stop: AtomicBool,
    sockets: Mutex<HashMap<u64, TcpStream>>,
}
impl Default for Control {
    fn default() -> Self {
        Self {
            stop: AtomicBool::new(false),
            sockets: Mutex::new(HashMap::new()),
        }
    }
}
impl Control {
    pub fn cancel(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(sockets) = self.sockets.lock() {
            for s in sockets.values() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
    pub(crate) fn track(self: &Arc<Self>, socket: &TcpStream) -> Result<SocketGuard> {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut sockets = self
            .sockets
            .lock()
            .map_err(|_| anyhow::anyhow!("socket registry unavailable"))?;
        ensure!(!self.stop.load(Ordering::Relaxed), "cancelled");
        ensure!(sockets.len() < 128, "process connection limit");
        sockets.insert(id, socket.try_clone()?);
        Ok(SocketGuard {
            control: self.clone(),
            id,
        })
    }
}
pub(crate) struct SocketGuard {
    control: Arc<Control>,
    id: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.control.sockets.lock() {
            sockets.remove(&self.id);
        }
    }
}
struct Attempts {
    tokens: f64,
    last: Instant,
    failures: u32,
    blocked: Instant,
}
pub struct Admission {
    ips: HashMap<IpAddr, Attempts>,
    global: Attempts,
}
impl Default for Admission {
    fn default() -> Self {
        Self {
            ips: HashMap::new(),
            global: Attempts {
                tokens: 20.,
                last: Instant::now(),
                failures: 0,
                blocked: Instant::now(),
            },
        }
    }
}
impl Admission {
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.ips
            .retain(|_, a| now.saturating_duration_since(a.last) < Duration::from_secs(300));
        // Rejected traffic must not spend another client's admission credit or
        // allocate new per-IP state once the listener-wide budget is exhausted.
        if !Self::available(&mut self.global, now, 20., 1.) {
            return false;
        }
        if !self.ips.contains_key(&ip) && self.ips.len() >= 1024 {
            return false;
        }
        let a = self.ips.entry(ip).or_insert(Attempts {
            tokens: 5.,
            last: now,
            failures: 0,
            blocked: now,
        });
        if !Self::available(a, now, 5., 0.2) {
            return false;
        }
        self.global.tokens -= 1.;
        a.tokens -= 1.;
        true
    }
    fn available(a: &mut Attempts, now: Instant, max: f64, rate: f64) -> bool {
        a.tokens = (a.tokens + now.saturating_duration_since(a.last).as_secs_f64() * rate).min(max);
        a.last = now;
        a.blocked <= now && a.tokens >= 1.
    }
    pub fn failure(&mut self, ip: IpAddr, now: Instant) {
        if let Some(a) = self.ips.get_mut(&ip) {
            a.failures = a.failures.saturating_add(1);
            if a.failures >= 5 {
                a.blocked = now + Duration::from_secs((5u64 << ((a.failures - 5).min(4))).min(60));
            }
        }
        self.global.failures = self.global.failures.saturating_add(1);
        if self.global.failures >= 20 {
            self.global.blocked = now + Duration::from_secs(30);
            self.global.failures = 0;
        }
    }
    pub fn success(&mut self, ip: IpAddr) {
        // Correct authentication returns its admission credit; reusable valid credentials
        // must not exhaust the failed-guess budget during continuous operation.
        self.global.tokens = (self.global.tokens + 1.).min(20.);
        if let Some(a) = self.ips.get_mut(&ip) {
            a.failures = 0;
            a.tokens = (a.tokens + 1.).min(5.);
        } /* global failures intentionally not erased by an attacker with a valid password */
    }
}
fn session(
    t: &Transfer,
    socket: TcpStream,
    credential: Option<&Credential>,
    control: &Arc<Control>,
) -> Result<()> {
    let _guard = control.track(&socket)?;
    let connector = credential.is_none();
    let mut channel = Channel::authenticate(socket, &t.password, credential, t.sending())
        .map_err(|_| anyhow::anyhow!("authentication/protocol confirmation failed; SSync 4 and matching passwords required"))?;
    transfer::run(t, &mut channel, connector, &control.stop)?;
    Ok(())
}
fn connect_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    stop: &AtomicBool,
) -> Result<TcpStream> {
    let mut last_error = None;
    for addr in addresses.into_iter().take(8) {
        ensure!(!stop.load(Ordering::Relaxed), "cancelled");
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(socket) => return Ok(socket),
            Err(e) => last_error = Some(e),
        }
    }
    match last_error {
        Some(e) => Err(e.into()),
        None => bail!("hostname resolved to no addresses"),
    }
}
pub fn transfer_command(t: Transfer, control: Arc<Control>) -> Result<()> {
    if let Some(host) = &t.host {
        loop {
            ensure!(!control.stop.load(Ordering::Relaxed), "cancelled");
            let connected =
                (|| connect_addresses((host.as_str(), t.port).to_socket_addrs()?, &control.stop))();
            if let Ok(s) = connected {
                let result = session(&t, s, None, &control);
                if !t.continuous() {
                    return result;
                }
                if let Err(e) = result {
                    eprintln!("Continuous session failed; retrying: {e:#}");
                }
            } else {
                let error = connected.unwrap_err();
                if !t.continuous() {
                    return Err(error);
                }
                eprintln!("Continuous connection failed; retrying: {error:#}");
            }
            for _ in 0..20 {
                if control.stop.load(Ordering::Relaxed) {
                    bail!("cancelled");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let credential = Arc::new(Credential::new(&t.password)?);
    let listener = listen(t.port)?;
    listener.set_nonblocking(true)?;
    println!(
        "{} now accepting {}connections on port {}",
        t.action,
        if t.continuous() { "ongoing " } else { "" },
        t.port
    );
    let admission = Arc::new(Mutex::new(Admission::default()));
    let active = Arc::new(AtomicUsize::new(0));
    let authenticating = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    while !control.stop.load(Ordering::Relaxed) {
        workers.retain(|worker: &std::thread::JoinHandle<()>| !worker.is_finished());
        match listener.accept() {
            Ok((socket, addr)) => {
                if active.load(Ordering::Relaxed) >= 8
                    || authenticating.load(Ordering::Relaxed) >= 4
                    || !admission
                        .lock()
                        .unwrap()
                        .allow(addr.ip().to_canonical(), Instant::now())
                {
                    continue;
                }
                if !t.continuous() {
                    let result = session(&t, socket, Some(&credential), &control);
                    return result;
                }
                active.fetch_add(1, Ordering::Relaxed);
                authenticating.fetch_add(1, Ordering::Relaxed);
                let t = t.clone();
                let credential = credential.clone();
                let control = control.clone();
                let admission = admission.clone();
                let active = active.clone();
                let authenticating = authenticating.clone();
                workers.push(std::thread::spawn(move || {
                    let result = (|| -> Result<()> {
                        let _guard = match control.track(&socket) {
                            Ok(g) => g,
                            Err(e) => {
                                authenticating.fetch_sub(1, Ordering::Relaxed);
                                return Err(e);
                            }
                        };
                        let authenticated = Channel::authenticate(
                            socket,
                            &t.password,
                            Some(&credential),
                            t.sending(),
                        );
                        authenticating.fetch_sub(1, Ordering::Relaxed);
                        let mut channel = match authenticated {
                            Ok(c) => {
                                admission.lock().unwrap().success(addr.ip().to_canonical());
                                c
                            }
                            Err(_) => {
                                admission
                                    .lock()
                                    .unwrap()
                                    .failure(addr.ip().to_canonical(), Instant::now());
                                bail!("authentication/protocol confirmation failed; SSync 4 and matching passwords required");
                            }
                        };
                        transfer::run(&t, &mut channel, false, &control.stop)?;
                        Ok(())
                    })();
                    if let Err(e) = result {
                        eprintln!("Session failed: {e:#}");
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.into()),
        }
    }
    control.cancel();
    for worker in workers {
        let _ = worker.join();
    }
    bail!("cancelled")
}
pub(crate) fn listen(port: u16) -> Result<TcpListener> {
    // Explicit dual-stack configuration is independent of the host's v6only default.
    let ipv6 = (|| -> std::io::Result<TcpListener> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_only_v6(false)?;
        socket.set_reuse_address(true)?;
        let address = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        socket.bind(&address.into())?;
        socket.listen(128)?;
        Ok(socket.into())
    })();
    let listener = match ipv6 {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::EADDRNOTAVAIL)
            ) =>
        {
            TcpListener::bind(("0.0.0.0", port))?
        }
        Err(e) => return Err(e.into()),
    };
    Ok(listener)
}
pub fn diagnostic(action: &str, path: &Path) -> Result<()> {
    if action == "hash" {
        let root = fs::Root::new(path)?;
        println!("Hash: {}", transfer::tree_hash(&root, "")?);
        return Ok(());
    }
    let mut file = fs::open_local_file(path)?;
    let size = file.metadata()?.len();
    match action {
        "scan" => {
            let mut bytes = 0;
            let mut buf = [0; 65536];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                bytes += n;
            }
            println!("Scanned {bytes} bytes in {:?}", path);
        }
        "deep" => {
            let mut offset = 0;
            loop {
                let mut buf = vec![0; transfer::BLOCK];
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                println!("{offset}: {}", blake3::hash(&buf[..n]));
                offset += n;
            }
        }
        _ => {
            println!(
                "File {:?}: {} bytes, BLAKE3 {}",
                path,
                size,
                fs::digest(&mut file)?
            );
            file.seek(SeekFrom::Start(0))?;
        }
    }
    Ok(())
}
pub fn config(path: &Path, control: Arc<Control>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let file = fs::open_config_file(path)?;
    let m = file.metadata()?;
    ensure!(
        m.mode() & 0o022 == 0 && m.len() <= 1_048_576,
        "unsafe or oversized .ssync file"
    );
    ensure!(
        m.uid() == unsafe { libc::geteuid() } || m.uid() == 0,
        ".ssync configuration must be owned by the current user or root"
    );
    let data = read_config(file)?;
    let mut commands = Vec::new();
    let password = cli::password_input(std::env::var("SSYNC_PASSWORD").ok().as_deref())?;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let args = shell_words::split(line)
            .map_err(|_| anyhow::anyhow!("invalid quoted .ssync command"))?;
        let Command::Transfer(t) = cli::parse(&args, password.as_deref().map(|s| s.as_str()))?
        else {
            bail!(".ssync permits only file transfer commands");
        };
        commands.push(t);
        ensure!(commands.len() <= 32, ".ssync command limit");
    }
    ensure!(!commands.is_empty(), "empty .ssync file");
    if commands.len() > 1 {
        ensure!(
            commands.iter().all(|t| t.host.is_none() || t.options.force),
            "concurrent .ssync connectors require force to avoid interleaved confirmations"
        );
    }
    let mut workers = Vec::new();
    for t in commands {
        let c = control.clone();
        workers.push(std::thread::spawn(move || {
            let result = transfer_command(t, c.clone());
            if result.is_err() {
                c.cancel();
            }
            result
        }));
    }
    let mut failed = false;
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("Configuration transfer failed: {e:#}");
                failed = true;
            }
            Err(_) => failed = true,
        }
    }
    ensure!(!failed, "configuration transfer failed");
    Ok(())
}
fn read_config(reader: impl Read) -> Result<zeroize::Zeroizing<String>> {
    let mut data = zeroize::Zeroizing::new(String::new());
    reader.take(1_048_577).read_to_string(&mut data)?;
    ensure!(data.len() <= 1_048_576, "oversized .ssync file");
    Ok(data)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_ips_cannot_spend_global_credit_or_fill_state() {
        let mut admission = Admission::default();
        let now = Instant::now();
        let blocked = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(admission.allow(blocked, now));
            admission.failure(blocked, now);
        }
        let credit = admission.global.tokens;
        for _ in 0..1000 {
            assert!(!admission.allow(blocked, now));
        }
        assert_eq!(admission.global.tokens, credit);
        assert!(admission.allow("127.0.0.2".parse().unwrap(), now));

        let mut admission = Admission::default();
        let now = Instant::now();
        for i in 0..2000 {
            admission.allow(IpAddr::from([10, 1, (i / 256) as u8, (i % 256) as u8]), now);
        }
        assert_eq!(admission.ips.len(), 20);
    }
    #[test]
    fn config_growth_cannot_bypass_read_limit() {
        use std::io::Write;
        let mut file = tempfile::tempfile().unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
        // Reproduce growth after an acceptable metadata check without a timing-dependent race.
        file.write_all(&vec![b'#'; 2 * 1_048_576]).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        assert!(read_config(&mut file).is_err());
        assert_eq!(file.stream_position().unwrap(), 1_048_577);
        assert_eq!(
            read_config(&b"# comment\n"[..]).unwrap().as_str(),
            "# comment\n"
        );
    }
    #[test]
    fn connection_tries_remaining_addresses_and_honors_cancellation() {
        let live = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let first = closed.local_addr().unwrap();
        drop(closed);
        let stop = AtomicBool::new(false);
        assert!(connect_addresses([first, live.local_addr().unwrap()], &stop).is_ok());
        assert!(connect_addresses([], &stop).is_err());
        stop.store(true, Ordering::Relaxed);
        assert!(connect_addresses([live.local_addr().unwrap()], &stop).is_err());
    }
    #[test]
    fn authenticated_reuse_returns_admission_credit() {
        let mut a = Admission::default();
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..100 {
            assert!(a.allow(ip, now));
            a.success(ip);
        }
        for _ in 0..5 {
            assert!(a.allow(ip, now));
            a.failure(ip, now);
        }
        assert!(!a.allow(ip, now));
    }
    #[test]
    fn bounded_throttling() {
        let mut a = Admission::default();
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(a.allow(ip, now));
            a.failure(ip, now);
        }
        assert!(!a.allow(ip, now));
        assert!(a.allow(ip, now + Duration::from_secs(61)));
        for i in 0..2000 {
            let ip = IpAddr::from([10, 1, (i / 256) as u8, (i % 256) as u8]);
            a.allow(ip, now);
        }
        assert!(a.ips.len() <= 1024);
    }
}
