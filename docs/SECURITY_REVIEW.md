# SSync security and correctness review — 2026-10-31

**Directory policy update (4.1.2):** transfer directories accept shared writers by default, as explicitly requested. Use the local `sole-owned` qualifier on ordinary or backup senders/receivers to retain the directory trust checks described in this historical 4.1.1 review. Unreleased follow-up: ordinary command configs also accept shared-writable parent directories, with one warning; `ssync sole-owned file.ssync` retains strict config ancestry and enables strict local transfer directories. Configuration files retain ownership/mode checks. Password-file, backup-config and installation ancestry and private state remain strict. Shared destinations trust other local writers, who may replace or rename entries during transfer; containment checks are not a snapshot or isolation from those writers. Historical rejection tests now request `sole-owned`; `tests/podman/sharing.py` covers permissive defaults and independent peer policies.


Scope: the native application at `cf76fb0`, including all nine Rust modules, bootstrap, release/notices scripts, the adversarial example, test runners, dependency lock and protocol/contract documentation. The ignored Java imports are historical references, not compiled or distributed application code. This is an implementation review and targeted testing, not an independent cryptographic audit or proof that no vulnerabilities exist.

Status: fixes in this review are included in **4.1.1**, alongside the [cryptographic integration review](CRYPTO_REVIEW.md). The older 4.1.0 download does not contain them.

## Findings and fixes

| Finding | Assessment | Resolution |
|---|---|---|
| Rejected IP attempts still consumed global credits and tracking slots | Medium, unauthenticated denial of service. A single locally blocked address could drain credits needed by other clients; globally rejected addresses could fill the bounded IP table. | Check eligibility before spending either budget; allocate new IP state only while global admission is available. Baseline regressions reproduce both failures; new regressions preserve other-client credit and cap inserted state to admitted attempts. Flooding/global failure throttles can still affect availability. |
| Writable directory trust checked mode bits but not owner or ancestors | Medium, local trust boundary. A different local UID could own a bay/subdirectory or rename an ancestor despite a private final directory. Root-run receivers must not treat such owners as trusted. This is not a demonstrated unauthenticated remote escape. | Require current-user/root ownership for writable roots, traversed write directories and config ancestry; reject writable ancestors without sticky protection. Revalidate the pinned root's device/inode. Preserve read-only access to other-user sources. Backup server preflight applies the rule before listening. |
| Lexical bay-overlap checks missed bind aliases of a descendant | Medium, configuration-driven isolation gap. Distinct configured paths can refer to overlapping underlying storage through bind mounts, without having equal root inodes. | Use the pinned descriptor mount ID and bounded `/proc/self/mountinfo` to map kernel-resolved descriptor paths to their underlying filesystem paths, then reject ancestor/equal bay storage keys on the same device before listening. The same check keeps the private config outside source/bay storage even through aliases. Escaped paths and stacked mount points are tested. Directory-capability traversal also rejects a change of device ID, including child Btrfs subvolumes. Explicitly selected directory mounts/subvolumes are opened as their own source capability, correcting an inherited parent-lookup rejection. Stable administrator-controlled mount topology remains required. |
| Directory creation/deletion did not sync parent directory metadata | Medium, backup correctness. An acknowledged empty-directory creation or deletion could be lost after power failure, even though file replacement already used fsync. | Sync parents after successful mkdir/unlink, including creation of private staging state. Propagate sync errors rather than reporting success. Empty staging cleanup also attempts directory sync. |
| The scanner silently excluded any `.ssync-state` entry | Medium, backup correctness. A user file with that reserved name could be absent from a backup reported as successful. | Reject reserved-name files or malformed state directories. Only recognizable private resume state is intentionally excluded: a 0700 directory containing at most 128 single-link 0600 files, with 64-hex-character names and the same owner as that directory. The name remains reserved for SSync; unrelated data must be renamed. |
| Ordinary `.ssync` reads were unbounded after the initial size stat | Low, local resource/correctness issue. A concurrently growing otherwise trusted file could exceed the advertised 1 MiB bound and consume memory. | Limit the actual read to 1 MiB + one detection byte, then reject oversize input. Keep the raw config buffer zeroizing because it may contain inline passwords. Backup configs already bounded their reads. |
| A one-shot connector stopped at the first failed resolved address; continuous mode exited on resolver errors | Medium, availability/correctness. An unavailable IPv6/IPv4 address could hide a reachable alternative; temporary DNS errors stopped continuous synchronization. | Try up to eight addresses, honor cancellation between attempts, and retry connection/resolver failures in continuous mode. Socket attempts retain their ten-second bound. System resolver calls themselves still depend on OS resolver timeouts. |
| Management/large-file test assertions were pinned to 4.0 versions | Test coverage defect, not a runtime vulnerability. Reusing these runners on 4.1 could test an already-current path instead of the intended upgrade or fail on version labels. | Derive versions from the actual binaries and require the synthetic update fixture to be newer. |

Compatibility consequence: a privileged server/installer may now reject bays, destination subdirectories or configuration ancestry owned by an unrelated user. Use directories owned by the account running SSync (or root), without group/other write permissions. A trusted sticky ancestor such as `/tmp` is allowed; a receiver root itself must still be private against other-user writes. Source directories remain read-only capabilities and can belong to another user. The `.ssync-state` name remains reserved; malformed collisions now produce errors. The wire protocol and password/command conventions are unchanged.

## Remaining security limitations

**Upload-only does not mean a password holder learns nothing about stored content.** The existing delta protocol returns whether a supplied file/block digest matches stored bytes. An authenticated client can therefore test guessed content, including in a write-free dry run. The review regression demonstrates correct and incorrect guesses against a synthetic bay without downloading bytes or changing files. Low-entropy content may be inferred this way. This is inherent in the current skip/reuse optimization, not an unauthenticated disclosure or a network restore endpoint. Do not share a bay password across mutually distrustful clients or place unrelated server secrets in that bay. Eliminating the comparison oracle requires changing the transfer behavior or the confidentiality model; this review retains the requested delta algorithm.

**One dependency advisory remains unsuppressed:** [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html), `crypto-bigint` 0.5.5 through `opaque-ke`/`voprf`/`elliptic-curve`. The affected secret integer operations are not used by SSync's fixed Ristretto255 suite: selected scalar/point arithmetic uses `curve25519-dalek`, and the shared elliptic-curve hash expansion uses digest operations. This source reachability assessment reduces the apparent exposure; it does not patch the crate or prove exploitability impossible. The current stable OPAQUE dependency retains that older dependency. No advisory suppression or clean-audit claim is made.

Other existing boundaries remain material:

- The multi-candidate backup OPAQUE wrapper and PAKE-to-Noise integration have no independent security audit. Tested confirmation, replay rejection and fixed suites do not replace one.
- The bay password authorizes overwrite and completed-manifest deletion throughout that bay. There is no retained history, ransomware protection, at-rest encryption or whole-tree transaction. Earlier successfully committed files can remain after a later failure.
- All servers using a password belong to one trust group; a compromised server has that reusable plaintext credential. Hostnames do not provide an independent certificate identity.
- Application admission/deadline/frame/state limits reduce abuse but do not guarantee availability under flooding. Post-authentication socket timeouts are per-I/O idle timeouts, not a total session deadline.
- Cancellation closes tracked sockets; synchronous filesystem/resolver calls can still wait for operating-system I/O to return.
- Same-identity/root compromise and arbitrary noncooperating filesystem writers remain outside transactional guarantees. Advisory locks coordinate cooperating SSync processes. The new ownership rules narrow other-user races; they do not create a filesystem snapshot.
- Bootstrap/updater checksums rely on GitHub TLS/account/release integrity. They are not independent publisher signatures. Loopback HTTP update overrides are explicit test functionality, not accepted over the transfer protocol.
- Inline arguments/environment can expose credentials locally; ordinary transfer-list files containing inline passwords should be mode 600. Backup/password files enforce private permissions. Debugger/core-dump/endpoint compromise can still expose memory.

No unauthenticated remote execution or remote path escape was found in the reviewed code and executed tests. This is a bounded review finding, not a claim that such defects cannot exist.

## Verification

Baseline: the published 4.1.0 binary was observed accepting a synthetic bay owned by UID 1001 when run as container root. The process was stopped without performing a transfer. The patched server rejects it before listening and also rejects an owned bay beneath an unrelated-UID ancestor. Read-only backup of another user's source still passes preflight.

Targeted native tests cover fallback to a second listening address, cancellation, and file growth after an acceptable metadata check. Two ignored filesystem probes require actual syscall error injection; ordinary `cargo test` does not count them as executed:

```sh
cargo test --locked --test fs_durability --no-run --message-format=json
# Use the test executable returned above; run each test independently:
strace -f -e trace=fsync -e inject=fsync:error=EIO:when=1 \
  <test-executable> --ignored --exact directory_create_propagates_sync_failure
strace -f -e trace=fsync -e inject=fsync:error=EIO:when=1 \
  <test-executable> --ignored --exact deletion_propagates_sync_failure
```

Both injected EIO cases pass: directory operations may already have taken effect, but the caller receives failure instead of a false durable-success result. This validates error propagation, not physical power-loss behavior on every supported filesystem.

Mount-alias tests cover synthetic bind/stacked-mount records, whitespace/backslash/control escapes, missing/mismatched records and the actual developer mount table; backup tests exercise actual container tmpfs mount metadata. The lab does not add mount capabilities or create a new bind mount for this test. Field interpretation follows the [Linux kernel proc documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html).

Completed review validation:

| Suite | Recorded passing checks |
|---|---:|
| Ordinary application / targeted review / backup | 13 / 10 / 30 |
| Security / lifecycle / CLI inputs / advanced filesystem | 33 / 14 / 12 / 11 |
| Management / bootstrap / cross-version compatibility | 9 / 5 / 4 |
| Multi-GiB / transfer exceeding idle-timeout duration | 4 / 1 |
| **Total across review builds** | **146** |

Additionally, 16 native unit tests and two parser/path tests pass (including 20,000 deterministic mutations), plus both explicitly injected fsync-EIO probes. Formatting, warnings-denied Clippy, Rust 1.88 all-target checks, shellcheck and Python compilation pass. Cargo audit still reports the single advisory discussed above, without suppression.

At the original review completion, the development binary was static Linux x86_64 musl, 5,505,952 bytes, SHA-256 `9883b5429a8447911349e89f15185d059843c6c6a07e0a25c4a972beeffee63e`. Its package version still printed 4.1.0 because these changes were then unreleased; it was **not** the published 4.1.0 artifact. That review binary passed 53 actual application/targeted-review/backup checks after the last mount/config/source-root refinements. Other integration groups passed on preceding review builds; no claim is made that a new public release artifact completed the full release matrix. The selected-source mount test transfers only its root-owned synthetic fixture and filters copied-up image tools/symlinks.

The large-file run transfers 2,400,000,017 bytes, skips identical contents with zero content bytes, and sends exactly 200,000 bytes for an edit beyond the 2 GiB offset. The rate-limited encrypted transfer completes in 121.93 seconds. Management tests use a private synthetic 4.1.1 fixture for a real version increase, never a public release. All container tests use the existing two labelled rootless peers; no host data mounts or new capabilities were introduced. The bootstrap test's bounded executable tmpfs exhaustion and source-mount fixture's copied-up symlinks were harness failures, corrected and rerun; they were not counted as passes.

Source fixes and this report were initially committed/pushed separately from public 4.1.0; they are now included in 4.1.1. No production host was installed or upgraded during review. Raw commands, output and hashes stay in ignored `DEBUGLOG.md` and `target/security-review-*`; new repeatable regressions are `tests/podman/review.py` and `tests/fs_durability.rs`.
