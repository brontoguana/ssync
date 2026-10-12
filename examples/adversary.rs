//! Test-only authenticated malicious peer; never included in release assets.
use anyhow::{Result, bail, ensure};
use ssync::{auth::Channel, transfer::Message};
use std::net::TcpStream;
fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(args.len() >= 2, "address mode [path]");
    let pass = std::env::var("SSYNC_PASSWORD")?;
    let mut channel = Channel::authenticate(TcpStream::connect(&args[0])?, &pass, None, true)?;
    let _: Message = channel.recv()?;
    channel.send(&Message::Begin {
        roots: vec![(
            if args[1] == "hold" {
                args.get(2).unwrap().split('/').next().unwrap().to_string()
            } else {
                "source".into()
            },
            true,
        )],
        skip: vec![],
        dryrun: false,
        nodelete: false,
    })?;
    channel.send(&Message::Approved { yes: true })?;
    let path = args.get(2).map(String::as_str).unwrap_or("source/x");
    match args[1].as_str() {
        "path" => channel.send(&Message::Directory { path: path.into() })?,
        "unknown" => channel.send_bytes(b"{\"type\":\"Execute\",\"command\":\"evil\"}")?,
        "duplicate" => {
            channel.send(&Message::Directory {
                path: "source".into(),
            })?;
            let _: Message = channel.recv()?;
            channel.send(&Message::Directory {
                path: "source".into(),
            })?;
        }
        "size" => channel.send(&Message::File {
            path: path.into(),
            size: u64::MAX,
            hash: "a".repeat(64),
            modified_secs: 1,
            modified_nanos: 0,
        })?,
        "incomplete" => {
            channel.send(&Message::Directory {
                path: "source".into(),
            })?;
            let _: Message = channel.recv()?;
            channel.send(&Message::Done { entries: 0 })?;
        }
        "block" | "digest" | "hold" => {
            let bytes = vec![42; 200_000];
            let hash = blake3::hash(&bytes).to_hex().to_string();
            channel.send(&Message::File {
                path: path.into(),
                size: 200_000,
                hash: hash.clone(),
                modified_secs: 1,
                modified_nanos: 0,
            })?;
            let need: Message = channel.recv()?;
            ensure!(
                matches!(need, Message::Need { skip: false }),
                "expected need"
            );
            channel.send(&Message::Block {
                offset: if args[1] == "block" { 200_000 } else { 0 },
                len: 200_000,
                hash: hash.clone(),
            })?;
            if args[1] != "block" {
                let _: Message = channel.recv()?;
                if args[1] == "hold" {
                    println!("holding");
                    std::thread::sleep(std::time::Duration::from_secs(30));
                } else {
                    channel.send(&Message::WindowEnd {})?;
                    channel.send_bytes(&vec![43; 200_000])?;
                }
            }
        }
        "allocation" => channel.send_bytes(&vec![0; ssync::auth::FRAME_LIMIT + 1])?,
        _ => bail!("unknown test mode"),
    }
    // Most malicious messages must result in immediate peer close, never an ACK.
    match channel.recv_bytes() {
        Err(_) => {
            println!("Rejected");
            Ok(())
        }
        Ok(_) => bail!("malicious request accepted"),
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
