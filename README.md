# SSync 4

Install the latest release on **Linux x86_64, kernel 5.6+** (downloads and verifies the binary, then uses `sudo` to install):

```bash
curl -fsSL https://raw.githubusercontent.com/brontoguana/ssync/main/install.sh | bash
```

Already installed? Run `sudo ssync update`.

Native, password-authenticated file synchronization with fixed 200,000-byte deltas. Rust executable; no Java, Python or shell runtime required. Files and directories only: no script hooks or remote execution.

Version **4.1.2** accepts shared-writable directories by default and adds the optional local `sole-owned` policy. Version **4.1.1** includes security hardening and a [cryptographic integration review](docs/CRYPTO_REVIEW.md). Version **4.1.0** added backup server/client modes to native SSync 4, which replaces Java SSync 3.3. The command interface is retained; the new wire protocol requires version 4 on both endpoints. Initial supported release target is **Linux x86_64, kernel 5.6+**, with a static musl binary. Other platforms are not claimed tested or supported. Procfs and case-sensitive local Linux filesystems are required; casefold, network/FUSE and pseudo filesystems fail closed.

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

Receiver directories must already exist. Without `merge`, items retain their source basenames. Receiver `merge` transfers a single directory's contents into the receiver root. Qualifiers precede the action: `merge`, `nodelete`, `dryrun`, `verify`, `verbose`, `force`/`noprompt`, `sole-owned`, `skip:substring`.

Shared-writable source and destination directories are accepted by default (since 4.1.2). Add `sole-owned` **on either side independently** to reject group/other-writable local roots and traversed directories:

```bash
ssync sole-owned offer MyDocuments ./docs       # strict source directories
ssync sole-owned get server:MyDocuments ./downloads  # strict destination directories
ssync sole-owned backup-client /opt/backup-client.ssync
ssync sole-owned backup-server /opt/backup-server.ssync
```

`sole-owned` retains the earlier directory policy: sources may belong to another user, while destination directories must be owned by the current user or root, with trusted ancestry (sticky shared ancestors such as `/tmp` are allowed). It does not require mode 700 or prohibit other users from reading. The option applies locally and is never imposed by the remote peer. Ordinary `.ssync` transfer lines also accept it. Default shared destinations trust local users who can modify the tree: noncooperating writers can rename entries or change files during a transfer, and advisory locks do not stop them. Link/path/mount containment, file-change checks, and private resume-state checks still apply. Configuration and installation paths retain their separate ownership/permission protections regardless of this option.

**The default mirrors selected directories, including deletion of extra entries in those scopes.** Use `nodelete` to retain extras. Single-file transfers never delete neighbouring files. Filters protect matching paths from transfer and deletion. Deletion requires a complete verified manifest; `dryrun` writes neither payload nor staging files. `force` skips the transfer prompt; it cannot override safety/authentication checks.

Passwords require 16+ Unicode characters; generated passwords use 24 uniformly sampled Base58 characters, displayed as six groups of four. Credentials do not expire, and each connection derives fresh keys. Precedence is nonempty `SSYNC_PASSWORD`, then `SSYNC_PASSWORD_FILE`, then `SSYNC_PASSWORD_FD`, then `password@location`, then hidden connector prompt/generated listener credential. Inline credentials may be visible in process listings/history. A password file must be private and owned by the current user; one final LF/CRLF is file framing, while descriptor input is preserved exactly. Maximum secret size is 4096 UTF-8 bytes.

`.ssync` files contain quoted declarative transfer commands, one per line, and run concurrently. Only transfer operations are permitted; no shell expansion or execution. Configuration files cannot be group/other writable. Use `force` when unattended. `version`, `licenses`, `hash <directory>`, `deep <file>`, `scan <file>` and single-file inspection are local diagnostics. Hash output is BLAKE3 and intentionally differs from Java output.

## Backup server and client

```text
ssync backup-server [port] [file]
ssync backup-client [file]
```

Defaults: port **8425**, server file **`/opt/backup-server.ssync`**, client file **`/opt/backup-client.ssync`**. A server file can be supplied without a port: `ssync backup-server /etc/ssync/bays.ssync`. A missing file is created privately with commented examples; edit it and rerun. Parent directories and source/bay directories must already exist. Use `sudo` for the default `/opt` configuration if needed, or run as an unprivileged user with a private config and owned directories.

Generate each source's password with `ssync pwd`. Put the same password on the client and each destination server. Keep config files mode `600`, outside source/bay directories. Replace the placeholders below with your own generated passwords.

Server configuration, one bay per line:

```text
# password=absolute server-side directory
<documents-password>=/srv/backups/documents
<photos-password>=/srv/backups/photos
```

Client configuration:

```text
# Every destination receives every source, regardless of line order.
@myserver
@myotherserver:8125

# password=absolute local source directory
<documents-password>=/home/user/documents
<photos-password>=/home/user/photos
```

Each password selects its bay on each server. The client cannot choose a server path. **The source directory's contents are mirrored directly into the bay, including deletion of extra files.** There is no native history; accidental source deletion can propagate. `ssync nodelete backup-client` retains extras. `ssync dryrun backup-client` previews without writing files or staging state; `skip:substring`, `verify` and `verbose` also work before the action. These are latest-copy backups, with atomic replacement per file rather than for a whole tree.

The server stays running; the client performs one cycle and exits without prompting. Up to four uploads run concurrently, with independent success/failure reporting. Any failed source/server pair gives a nonzero exit status after the other pairs finish. Run it from your scheduler for recurring backups. Same-bay simultaneous uploads report busy; retry later. Different bays can update concurrently. Config changes require a restart/rerun. Environment passwords do not override credentials in backup files.

Both endpoints need **4.1+ for backup mode**. Ordinary transfer commands retain the 4.0 protocol. Backup mode accepts uploads only: no network restoration, remote execution, Restic integration or at-rest encryption. Retrieve files with normal administrator server access. Blank/comment lines are ignored, `=` splits at its first occurrence, and IPv6 servers use `@[address][:port]`. Configuration limits are 32 servers and 32 sources/bays. Passwords must be unique within each file; server bay directories must not overlap.

Current inherited safety limits include **16 GiB per file, 10,000 manifest entries per source, and 16 GiB of private partial state per bay**. Oversized backups fail clearly rather than silently omitting files.

Fixed 200,000-byte comparisons, bounded pipelining, verified resume and final content verification are reused. Each destination currently scans/hashes independently, reading unchanged contents for integrity; persistent indexing and sharing scans between destinations are future optimizations. `.ssync-state` is reserved for private resume files, which are excluded from transfers; 4.1.1 hardening makes incompatible entries with that name fail clearly. See [backup command contract](docs/CONTRACT.md#backup-commands-41).

## Installation and updates

Download the platform binary and `checksums.txt` from [SSync 4.1.2](https://github.com/brontoguana/ssync/releases/tag/v4.1.2). Check its SHA-256 before executing it. The public download, native install, up-to-date check and uninstall have been tested in the isolated Podman lab.

```bash
curl -fLO https://github.com/brontoguana/ssync/releases/download/v4.1.2/ssync_linux_amd64
curl -fLO https://github.com/brontoguana/ssync/releases/download/v4.1.2/checksums.txt
sha256sum --ignore-missing --check checksums.txt
chmod +x ./ssync_linux_amd64
sudo ./ssync_linux_amd64 install
sudo ssync update
sudo ssync uninstall
```

Install/update use native filesystem/network APIs and atomic replacement. Linux ownership metadata is attached to the staged executable, so the binary and ownership commit together. Updates consult this project's GitHub releases, print current/available versions and release notes, verify the exact platform asset's SHA-256, and preserve the installed executable on failed downloads/checks. An unowned or modified executable is never overwritten/removed. Uninstall removes owned installation files and preserves transfer data. Default path: `/usr/local/bin/ssync`; `SSYNC_INSTALL_DIR` supports private/disposable installations. Management is local-only, never accepted over the protocol or in `.ssync` lists.

SHA-256 from the same GitHub release verifies artifact integrity, not independent publisher authenticity. GitHub account/release compromise remains a trust risk. The optional bootstrap above runs a shell script from this repository; installed SSync performs updates through native APIs without scripts. See [security/channel design](docs/PROTOCOL.md), [command/migration contract](docs/CONTRACT.md), and the [security review](docs/SECURITY_REVIEW.md).

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
