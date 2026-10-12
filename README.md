# SSync 4

Native, password-authenticated file synchronization with fixed 200,000-byte deltas. Rust executable; no Java, Python or shell runtime required. Files and directories only: no script hooks or remote execution.

Version **4.0.0** replaces Java SSync 3.3. The command interface is retained; the new wire protocol requires version 4 on both endpoints. Initial supported release target is **Linux x86_64, kernel 5.6+**, with a static musl binary. Other platforms are not claimed tested or supported. Procfs and case-sensitive local Linux filesystems are required; casefold, network/FUSE and pseudo filesystems fail closed.

## Usage

```text
ssync [qualifiers] <action> <location> [files or folders]
```

`put` and `offer` send files; `get` and `accept` receive. `put`/`get` perform one transfer. `offer`/`accept` listen continuously or repeat outgoing connections. A location without a host listens; adding a host connects. TCP initiation and transfer direction are independent.

```bash
ssync pwd                      # one 24-character Base58 password, six groups of four
ssync offer MyDocuments ./docs  # reusable generated listener password
ssync get server:MyDocuments ./downloads
ssync put 1500 ./report.txt     # send, while accepting a connection
ssync get server:1500 ./downloads
ssync ?                        # interactive guidance
```

Receiver directories must already exist. Without `merge`, items retain their source basenames. Receiver `merge` transfers a single directory's contents into the receiver root. Qualifiers precede the action: `merge`, `nodelete`, `dryrun`, `verify`, `verbose`, `force`/`noprompt`, `skip:substring`.

**The default mirrors selected directories, including deletion of extra entries in those scopes.** Use `nodelete` to retain extras. Single-file transfers never delete neighbouring files. Filters protect matching paths from transfer and deletion. Deletion requires a complete verified manifest; `dryrun` writes neither payload nor staging files. `force` skips the transfer prompt; it cannot override safety/authentication checks.

Passwords require 16+ Unicode characters; generated passwords use 24 uniformly sampled Base58 characters, displayed as six groups of four. Credentials do not expire, and each connection derives fresh keys. Precedence is nonempty `SSYNC_PASSWORD`, then `SSYNC_PASSWORD_FILE`, then `SSYNC_PASSWORD_FD`, then `password@location`, then hidden connector prompt/generated listener credential. Inline credentials may be visible in process listings/history. A password file must be private and owned by the current user; one final LF/CRLF is file framing, while descriptor input is preserved exactly. Maximum secret size is 4096 UTF-8 bytes.

`.ssync` files contain quoted declarative transfer commands, one per line, and run concurrently. Only transfer operations are permitted; no shell expansion or execution. Configuration files cannot be group/other writable. Use `force` when unattended. `version`, `licenses`, `hash <directory>`, `deep <file>`, `scan <file>` and single-file inspection are local diagnostics. Hash output is BLAKE3 and intentionally differs from Java output.

## Installation and updates

Download the platform binary and `checksums.txt` from a verified release. Check its SHA-256 before executing it. Release publication is pending; do not assume an unpublished download URL exists.

```bash
chmod +x ./ssync_linux_amd64
sudo ./ssync_linux_amd64 install
sudo ssync update
sudo ssync uninstall
```

Install/update use native filesystem/network APIs and atomic replacement. Linux ownership metadata is attached to the staged executable, so the binary and ownership commit together. Updates consult this project's GitHub releases, print current/available versions and release notes, verify the exact platform asset's SHA-256, and preserve the installed executable on failed downloads/checks. An unowned or modified executable is never overwritten/removed. Uninstall removes owned installation files and preserves transfer data. Default path: `/usr/local/bin/ssync`; `SSYNC_INSTALL_DIR` supports private/disposable installations. Management is local-only, never accepted over the protocol or in `.ssync` lists.

SHA-256 from the same GitHub release verifies artifact integrity, not independent publisher authenticity. GitHub account/release compromise remains a trust risk. No scripts from mutable branches are downloaded/executed. See [security/channel design](docs/PROTOCOL.md) and [command/migration contract](docs/CONTRACT.md).

## Development and verification

Build with Rust 1.88+ and a musl C compiler:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo audit
cargo build --release --target x86_64-unknown-linux-musl
```

[Podman procedures](tests/podman/README.md) isolate tests in two rootless peers with no host-directory mounts or published ports. Actual test runners cover application transfers, protocol attacks, lifecycle/file safety, installation failures and a bounded multi-GiB profile. [Required validation matrix](tests/TEST_MATRIX.md) and [validation report](docs/VALIDATION.md) distinguish executed checks from pending gates. Raw logs are local under ignored `target/` and `DEBUGLOG.md`.

Java/reference imports remain local under ignored `ssync-codebase/` and `ssync-interop-kit/`; their redistribution rights are not established, so they are excluded from public history. They are not runtime/build dependencies of the native tool. See [implementation plan](IMPLEMENTATION_PLAN.md), [original assessment](PORT_REVIEW.md), and [actionable file map](FILE_MAP.md).
