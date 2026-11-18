use crate::{
    auth::{Channel, Credential},
    cli::{self, Command, Transfer},
    fs, transfer,
};
use anyhow::{Context, Result, bail, ensure};
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
pub(crate) const MAX_PENDING_HANDSHAKES: usize = 8;
const MAX_TRANSFERS: usize = 8;
const MAX_PENDING_PER_IP: usize = 4;
const MAX_PROCESS_HANDSHAKES: usize = 64;
static NEXT: AtomicU64 = AtomicU64::new(1);
const AUTHENTICATION_FAILED: &str =
    "authentication/protocol confirmation failed; SSync 4 and matching passwords required";
pub struct Control {
    pub stop: AtomicBool,
    sockets: Mutex<HashMap<u64, TcpStream>>,
    handshakes: Arc<AtomicUsize>,
}
impl Default for Control {
    fn default() -> Self {
        Self {
            stop: AtomicBool::new(false),
            sockets: Mutex::new(HashMap::new()),
            handshakes: Arc::default(),
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
pub(crate) struct Slot(Arc<AtomicUsize>);
impl Slot {
    pub(crate) fn take(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < limit).then_some(n + 1)
            })
            .ok()?;
        Some(Self(counter.clone()))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Budget {
    tokens: f64,
    last: Instant,
}
impl Budget {
    fn new(tokens: f64, now: Instant) -> Self {
        Self { tokens, last: now }
    }

    fn available(&mut self, now: Instant, max: f64, rate: f64) -> bool {
        self.tokens =
            (self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * rate).min(max);
        self.last = now;
        self.tokens >= 1.
    }
}
struct Attempts {
    budget: Budget,
    blocked: Instant,
    failures: u32,
    pending: usize,
}
struct Admission {
    ips: HashMap<IpAddr, Attempts>,
    global: Budget,
    pending: usize,
}
impl Default for Admission {
    fn default() -> Self {
        Self {
            ips: HashMap::new(),
            global: Budget::new(20., Instant::now()),
            pending: 0,
        }
    }
}
impl Admission {
    fn reserve(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.pending >= MAX_PENDING_HANDSHAKES || !self.global.available(now, 20., 1.) {
            return false;
        }
        self.ips.retain(|_, a| {
            a.pending != 0
                || now.saturating_duration_since(a.budget.last) < Duration::from_secs(300)
        });
        if !self.ips.contains_key(&ip) && self.ips.len() >= 1024 {
            return false;
        }
        let a = self.ips.entry(ip).or_insert(Attempts {
            budget: Budget::new(5., now),
            blocked: now,
            failures: 0,
            pending: 0,
        });
        if a.pending >= MAX_PENDING_PER_IP || a.blocked > now || !a.budget.available(now, 5., 0.2) {
            return false;
        }
        self.global.tokens -= 1.;
        a.budget.tokens -= 1.;
        self.pending += 1;
        a.pending += 1;
        true
    }

    fn release(&mut self, ip: IpAddr, outcome: Option<bool>, now: Instant) {
        self.pending -= 1;
        if outcome == Some(true) {
            self.global.tokens = (self.global.tokens + 1.).min(20.);
        }
        let a = self.ips.get_mut(&ip).unwrap();
        a.pending -= 1;
        match outcome {
            Some(true) => {
                a.failures = 0;
                a.budget.tokens = (a.budget.tokens + 1.).min(5.);
            }
            Some(false) => {
                a.failures = a.failures.saturating_add(1);
                if a.failures >= 5 {
                    let delay = (5u64 << ((a.failures - 5).min(4))).min(60);
                    a.blocked = now + Duration::from_secs(delay);
                }
            }
            None => {}
        }
    }
}
#[derive(Default)]
pub(crate) struct Handshakes(Arc<Mutex<Admission>>);
impl Handshakes {
    pub(crate) fn reserve(&self, ip: IpAddr, control: &Control) -> Option<Handshake> {
        let process_slot = Slot::take(&control.handshakes, MAX_PROCESS_HANDSHAKES)?;
        let ip = ip.to_canonical();
        if !self.0.lock().unwrap().reserve(ip, Instant::now()) {
            return None;
        }
        Some(Handshake {
            admission: self.0.clone(),
            ip,
            outcome: None,
            _process_slot: process_slot,
        })
    }
}
pub(crate) struct Handshake {
    admission: Arc<Mutex<Admission>>,
    ip: IpAddr,
    outcome: Option<bool>,
    _process_slot: Slot,
}
impl Handshake {
    pub(crate) fn record<T>(&mut self, result: &Result<T>) {
        self.outcome = Some(result.is_ok());
    }
}
impl Drop for Handshake {
    fn drop(&mut self) {
        self.admission
            .lock()
            .unwrap()
            .release(self.ip, self.outcome, Instant::now());
    }
}
fn connector_session(t: &Transfer, socket: TcpStream, control: &Arc<Control>) -> Result<()> {
    let _guard = control.track(&socket)?;
    let mut channel = Channel::authenticate(socket, &t.password, None, t.sending())
        .map_err(|_| anyhow::anyhow!(AUTHENTICATION_FAILED))?;
    transfer::run(t, &mut channel, true, &control.stop)?;
    Ok(())
}
fn authenticate_listener(
    t: &Transfer,
    socket: TcpStream,
    credential: &Credential,
) -> Result<Channel> {
    Channel::authenticate(socket, &t.password, Some(credential), t.sending())
        .map_err(|_| anyhow::anyhow!(AUTHENTICATION_FAILED))
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
                let result = connector_session(&t, s, &control);
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
    let listener = listen(t.port)
        .with_context(|| format!("cannot start {} listener on port {}", t.action, t.port))?;
    listener.set_nonblocking(true)?;
    println!(
        "{} now accepting {}connections on port {}",
        t.action,
        if t.continuous() { "ongoing " } else { "" },
        t.port
    );
    let handshakes = Handshakes::default();
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    while !control.stop.load(Ordering::Relaxed) {
        workers.retain(|worker: &std::thread::JoinHandle<()>| !worker.is_finished());
        match listener.accept() {
            Ok((socket, addr)) => {
                if workers.len() >= MAX_PENDING_HANDSHAKES + MAX_TRANSFERS {
                    continue;
                }
                let Some(mut handshake) = handshakes.reserve(addr.ip(), &control) else {
                    continue;
                };
                if !t.continuous() {
                    let _guard = control.track(&socket)?;
                    let authenticated = authenticate_listener(&t, socket, &credential);
                    handshake.record(&authenticated);
                    drop(handshake);
                    match authenticated {
                        Ok(mut channel) => {
                            return transfer::run(&t, &mut channel, false, &control.stop)
                                .map(|_| ());
                        }
                        Err(e) => eprintln!("Session failed: {e:#}"),
                    }
                    continue;
                }
                let t = t.clone();
                let credential = credential.clone();
                let control = control.clone();
                let active = active.clone();
                workers.push(std::thread::spawn(move || {
                    let result = (|| -> Result<()> {
                        let _guard = control.track(&socket)?;
                        let authenticated = authenticate_listener(&t, socket, &credential);
                        handshake.record(&authenticated);
                        let mut channel = authenticated?;
                        let slot = Slot::take(&active, MAX_TRANSFERS);
                        drop(handshake);
                        let _session = slot.context("listener transfer slots busy; retry later")?;
                        transfer::run(&t, &mut channel, false, &control.stop)?;
                        Ok(())
                    })();
                    if let Err(e) = result {
                        eprintln!("Session failed: {e:#}");
                    }
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
pub fn config(path: &Path, sole_owned: bool, control: Arc<Control>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let file = fs::open_transfer_config(path, sole_owned)?;
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
        let Command::Transfer(mut t) = cli::parse(&args, password.as_deref().map(|s| s.as_str()))?
        else {
            bail!(".ssync permits only file transfer commands");
        };
        t.options.sole_owned |= sole_owned;
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
            assert!(admission.reserve(blocked, now));
            admission.release(blocked, Some(false), now);
        }
        let credit = admission.global.tokens;
        for _ in 0..1000 {
            assert!(!admission.reserve(blocked, now));
        }
        assert_eq!(admission.global.tokens, credit);
        assert!(admission.reserve("127.0.0.2".parse().unwrap(), now));

        let mut admission = Admission::default();
        let now = Instant::now();
        for i in 0..2000 {
            let ip = IpAddr::from([10, 1, (i / 256) as u8, (i % 256) as u8]);
            if admission.reserve(ip, now) {
                admission.release(ip, Some(false), now);
            }
        }
        assert_eq!(admission.ips.len(), 20);
        // A new address can use the next replenished token without a global penalty.
        assert!(admission.reserve("192.0.2.1".parse().unwrap(), now + Duration::from_secs(1)));
    }
    #[test]
    fn pending_limits_leave_room_for_another_source_and_release_on_drop() {
        let control = Control::default();
        let handshakes = Handshakes::default();
        let slots: Vec<_> = (0..MAX_PENDING_PER_IP)
            .map(|_| {
                handshakes
                    .reserve("127.0.0.1".parse().unwrap(), &control)
                    .unwrap()
            })
            .collect();
        assert!(
            handshakes
                .reserve("::ffff:127.0.0.1".parse().unwrap(), &control)
                .is_none()
        );
        let other = handshakes
            .reserve("127.0.0.2".parse().unwrap(), &control)
            .unwrap();
        assert_eq!(control.handshakes.load(Ordering::Relaxed), slots.len() + 1);
        drop(slots);
        assert!(
            handshakes
                .reserve("127.0.0.1".parse().unwrap(), &control)
                .is_some()
        );
        drop(other);
        assert_eq!(control.handshakes.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn pending_handshakes_have_independent_listener_and_process_limits() {
        let control = Control::default();
        let listeners: Vec<_> = (0..MAX_PROCESS_HANDSHAKES / MAX_PENDING_HANDSHAKES)
            .map(|_| Handshakes::default())
            .collect();
        let mut pending = Vec::new();
        for listener in &listeners {
            for n in 0..MAX_PENDING_HANDSHAKES {
                let ip = IpAddr::from([192, 0, 2, n as u8]);
                pending.push(listener.reserve(ip, &control).unwrap());
            }
            assert!(
                listener
                    .reserve("198.51.100.1".parse().unwrap(), &control)
                    .is_none()
            );
        }
        let listener = Handshakes::default();
        let ip = "198.51.100.1".parse().unwrap();
        assert!(listener.reserve(ip, &control).is_none());
        pending.pop();
        assert!(listener.reserve(ip, &control).is_some());
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
            assert!(a.reserve(ip, now));
            a.release(ip, Some(true), now);
        }
        for _ in 0..5 {
            assert!(a.reserve(ip, now));
            a.release(ip, Some(false), now);
        }
        assert!(!a.reserve(ip, now));
    }
    #[test]
    fn bounded_throttling() {
        let mut a = Admission::default();
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(a.reserve(ip, now));
            a.release(ip, Some(false), now);
        }
        assert!(!a.reserve(ip, now));
        assert!(a.reserve(ip, now + Duration::from_secs(61)));
        for i in 0..2000 {
            let ip = IpAddr::from([10, 1, (i / 256) as u8, (i % 256) as u8]);
            a.reserve(ip, now);
        }
        assert!(a.ips.len() <= 1024);
    }
}
