# SSync 4.0.0 command contract

The Java reference is 3.3. Version 4.0 changes the wire protocol, retaining CLI usage. Only regular-file and directory transfers are supported. No process execution, scripts, remote management, ownership, ACL or executable-mode changes.

`ssync [qualifiers] put|get|offer|accept location [paths...]`

`put`/`offer` send; `get`/`accept` receive. A location without a host listens; `host:port`, `host:alias`, `[IPv6]:port` connects, independently of data direction. `put`/`get` perform one successful session; `offer`/`accept` listeners persist with reusable credentials. Continuous connectors repeat after successful sessions, retry bounded-delay connection failures, and stop on operator cancellation. No credential expires.

Aliases use Java UTF-16 String.hashCode: 1000 + ((hash & 0x7fffffff) % 50000), including literal `alias/`. Numeric ports must be 1..65535 (invalid numeric ports fail rather than becoming aliases).

Password precedence: nonempty SSYNC_PASSWORD, otherwise password@location, otherwise hidden connector prompt or generated listener password. Inline passwords are always stripped from location, even when environment overrides them (fixes legacy parsing bug). Passwords are preserved exactly, 16+ Unicode characters and at most 4096 UTF-8 bytes. Generated secrets: 24 uniformly sampled Base58 characters in six groups of four. `ssync pwd` emits only password + newline. No additional composition/blocklist policy. Passwords are zeroized on drop where library types support it; environment/arguments are exposed to the local OS/operator.

Paths default to `.`. Senders allow multiple selected files/directories. Receivers authorize exactly one existing directory. Without `merge`, each selected sender item appears under its basename. Receiver `merge` merges one directory's contents into the receiver root. Duplicate basenames fail. Missing receiver roots must be created locally by the operator; no preauthentication root creation.

Qualifiers precede action: `merge`, `nodelete`, `dryrun`, `verify`, `verbose`, `force`/`noprompt`, `skip:substring`. Matching is case-insensitive for command words; filter values/passwords remain case-sensitive. `skip:` protects matching paths from transfer AND deletion on either side. Defaults retain overwrite and scoped mirroring deletion: delete extraneous entries only inside transferred directories after all files/complete manifest verify. Single-file upload never deletes neighbours. `nodelete` disables deletion. `dryrun` negotiates a write-free preview on both peers. `force`/`noprompt` skips interactive transfer confirmation only. Receiver-owned permissions and roots cannot be expanded by wire options. `verify` prints a modern verified tree digest; content validation always occurs regardless of qualifier.

Local diagnostics: `version`/`--version`, `hash directory`, `deep file` (200,000-byte BLAKE3 hashes), `scan file` (byte count), file-only argument (inspection), `?` interactive guidance, no args/`--help` usage. Hashes intentionally differ from legacy Java MD5/long formatting. Terminal controls in filenames are escaped.

A single `.ssync` argument loads UTF-8 declarative transfer commands, quoted using shell-like tokenization without shell expansion/execution. Blank lines/comments ignored. At most 32 commands/1 MiB config; only transfer commands allowed, fully validated before workers start. Concurrent workers share cancellation; failures produce nonzero status. Config must be regular, single-link and not group/other writable. Relative paths use process CWD, retaining legacy semantics.

`install`, `update`, `uninstall` are local standalone commands, never wire/config operations. Installation is `/usr/local/bin/ssync` with private SSync ownership record; directory override SSYNC_INSTALL_DIR supports disposable testing. Root required in default location. Native APIs only. Update reads github.com/brontoguana/ssync releases, reports current/latest/release details, selects platform, verifies SHA-256 before atomic install; checksum authenticity depends on GitHub release/account security. No remote scripts. Uninstall verifies ownership/hash and removes only owned files; unrelated or locally modified installations fail safely.

Initial verified release platform: Linux x86_64, standalone musl binary. Linux aarch64 builds/testing and macOS support require their own validation. Windows unsupported. Path safety requires Linux openat2 (kernel 5.6+); unsupported kernels fail closed. No unverified platform claims.

Errors and cancellation exit nonzero; persistent listeners log individual session failures and continue. No legacy swallowed worker errors. Per-file atomicity only, no tree transaction. Fixed-block efficiency preserved; inserting bytes can retransmit many blocks. Resume rehashes staged content; private state is credential/root/file bound and bounded. Details and exact resource limits in PROTOCOL.md.
