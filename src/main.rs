use anyhow::Result;
use ssync::{
    auth,
    cli::{self, Command},
    management,
    runtime::{self, Control},
};
use std::sync::Arc;
fn run() -> Result<()> {
    let control = Arc::new(Control::default());
    let args = std::env::args_os()
        .skip(1)
        .map(|s| {
            s.into_string()
                .map_err(|_| anyhow::anyhow!("command arguments must be UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    let command = cli::parse(&args, std::env::var("SSYNC_PASSWORD").ok().as_deref())?;
    if matches!(
        &command,
        Command::Transfer(_) | Command::Config(_) | Command::Guide
    ) {
        let signal = control.clone();
        ctrlc::set_handler(move || signal.cancel())?;
    }
    match command {
        Command::Licenses => print!("{}", include_str!("../THIRD_PARTY_NOTICES.txt")),
        Command::Pwd => println!("{}", auth::password()?),
        Command::Version => println!("SSync v{}", env!("CARGO_PKG_VERSION")),
        Command::Help => print!("{}", cli::HELP),
        Command::Guide => {
            let args = cli::guide()?;
            if let Command::Transfer(t) =
                cli::parse(&args, std::env::var("SSYNC_PASSWORD").ok().as_deref())?
            {
                runtime::transfer_command(t, control)?;
            }
        }
        Command::Transfer(t) => runtime::transfer_command(t, control)?,
        Command::Diagnostic(a, p) => runtime::diagnostic(&a, &p)?,
        Command::Config(p) => runtime::config(&p, control)?,
        Command::Management(a) => management::run(&a)?,
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("SSync: {e:#}");
        std::process::exit(1);
    }
}
