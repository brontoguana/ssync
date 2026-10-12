use crate::auth;
use anyhow::{Result, bail, ensure};
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
    Help,
    Guide,
    Diagnostic(String, PathBuf),
    Management(String),
    Config(PathBuf),
    Licenses,
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
        let f = crate::fs::open_local_file(std::path::Path::new(&path))?;
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
        return Ok(Command::Help);
    }
    if args.len() == 1 {
        match args[0].to_lowercase().as_str() {
            "pwd" => return Ok(Command::Pwd),
            "licenses" | "--licenses" => return Ok(Command::Licenses),
            "version" | "--version" => return Ok(Command::Version),
            "?" => return Ok(Command::Guide),
            "--help" | "help" => return Ok(Command::Help),
            "install" | "update" | "uninstall" => {
                return Ok(Command::Management(args[0].to_lowercase()));
            }
            _ => {}
        }
        if args[0].to_lowercase().ends_with(".ssync") {
            return Ok(Command::Config(args[0].clone().into()));
        }
        if std::path::Path::new(&args[0]).is_file() {
            return Ok(Command::Diagnostic(
                "inspect".into(),
                args[0].clone().into(),
            ));
        }
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
            "merge" => o.merge = true,
            "nodelete" => o.nodelete = true,
            "dryrun" => o.dryrun = true,
            "verify" => o.verify = true,
            "verbose" => o.verbose = true,
            "force" | "noprompt" => o.force = true,
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
pub const HELP: &str = concat!(
    "SSync v",
    env!("CARGO_PKG_VERSION"),
    " — native file-only synchronization\n\nssync [merge nodelete dryrun verify verbose force skip:substring] <put|get|offer|accept> <location> [paths...]\n\nput/offer send; get/accept receive. put/get once; offer/accept continuously.\nlocation: port, alias, host:port, host:alias, [IPv6]:port; optional password@ prefix.\nPassword precedence: SSYNC_PASSWORD > SSYNC_PASSWORD_FILE > SSYNC_PASSWORD_FD > inline > prompt/generated listener. Minimum 16 characters.\nReceiver directory must exist. Default layout includes source basenames; receiver merge strips one directory name.\nDefault mirror deletion is confined to selected source directories; use nodelete to retain extras.\n\nssync pwd | version | licenses | ? | hash <dir> | deep <file> | scan <file> | <file.ssync>\nsudo ssync install | update | uninstall\nNo script execution. Both peers require version 4. Linux kernel 5.6+ required.\n"
);
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
