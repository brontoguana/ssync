# SSync required validation matrix

Status: native implementation and actual application/security/lifecycle/management runners exist. See ../docs/VALIDATION.md for executed evidence and platform/feature dispositions; publication/public updater smoke remain pending credentials. The rows below remain the required inventory, not an assertion that unexecuted combinations passed. Use the two-peer lab in `podman/README.md`, synthetic fixtures and passwords only, and executable version/hash plus exact settings in each report.

## Command/configuration contract

| Area | Cases and required outcome |
|---|---|
| Generator | `ssync pwd` emits exactly six groups of four alphabet-valid Base58 characters separated by five hyphens, then one newline; no labels or side effects; CSPRNG failure exits nonzero. Verify unbiased sampling algorithm and deterministic sampler boundary tests, not statistical claims from a few outputs. |
| Password inputs | Hidden prompt, environment precedence, `password@location`, `.ssync` lists; minimum 16 Unicode code points enforced consistently before network start; long passphrases preserved; too-long bounded input rejected without truncation; grouped separators/case preserved exactly; secrets redacted from SSync errors/logs. |
| Location | Numeric port, alias-to-port mapping, hostname/IP/IPv6 syntax according to recorded legacy contract, invalid values, documented omitted-root/current-directory behavior. |
| Actions/directions | `put` listener + `get` connector; `get` listener + `put` connector; `offer` listener + `accept` connector; `accept` listener + `offer` connector. Record data sender separately from TCP initiator. Exercise valid connections in all four cases. |
| Qualifiers | `merge`, `nodelete`, `dryrun`, `verify`, `verbose`, `force`/`noprompt`, `skip:` substring filters; overwrite/delete defaults match the frozen API/migration guide. Authentication/safety checks cannot be bypassed by force. |
| Config/diagnostics | `.ssync` declarative transfer lists and safe concurrency, quoted/spaced/Unicode paths, `?`, version, file inspection, `hash`/`deep` output contract; clear nonzero status on worker and parser failure. |
| File-only boundary | Reject script hooks, command execution, executable config and unknown wire operations. Shell metacharacters in names remain data. No subprocess-based transfer helpers or self-install execution. |

## Password authentication and encryption

| Area | Cases and required outcome |
|---|---|
| Protocol construction | Selected maintained library/profile, published vectors and peer interoperability appropriate to that profile; documented state/key derivation; no bespoke cryptographic construction. |
| Mutual confirmation | Both peers verify fresh session-bound confirmation; wrong password, one-character change, wrong case, missing group separators, malformed/truncated proof, missing final confirmation, cancelled handshake all fail without file metadata or changes in either root. |
| Context/replay | Reuse captured handshake/proofs in new sessions, reflect roles, alter version/negotiation/transfer direction or authenticated operation context; reject. Java protocol-6 peer fails clearly. |
| Fresh keys | Repeated successful sessions with the same nonexpiring credential derive distinct fresh keys/nonces; check library test instrumentation without persisting secret keys to ordinary logs. Persistent/repeated transfer credentials remain usable. |
| Authenticated data | Flip ciphertext/tag/header bits, truncate frames, reorder/duplicate records, replay prior-session records, malformed sizes; reject with bounded work/allocation and no committed corruption. |
| Wire privacy | Proxy capture contains no plaintext password, filenames, content or known markers; this supplements validation of the chosen construction and does not alone prove cryptographic security. Bound metadata/frame leakage in the threat model. |
| Brute force | Per-IP and global limits in every listening mode, multiple attacker connections/addresses, half-open/slow handshakes, concurrent expensive work, state exhaustion, restart behavior, legitimate NAT users; no permanent attacker-triggered lockout and no disruption of authenticated transfers. |
| Offline attacks | Document selected PAKE's capture-based offline-guessing resistance and separate endpoint/credential compromise assumptions. A fast guessed-password loop is not a proof of PAKE security. |

## Efficient and correct file transfers

Use strong final content hashes plus independent directory/file comparisons. Include empty files/directories, Unicode, spaces, leading hyphens, newline/control-character names, deep trees, many small files, and large files within lab quotas. Escape terminal controls in user output.

| Fixture/run | Required outcome |
|---|---|
| First transfer | Exact bytes, lengths and agreed metadata; verified individual-file atomic replacement; bounded streaming memory. |
| Identical repeat | Zero file-content bytes sent; protocol/hash metadata reported separately. No rewrite of unchanged files where contract permits. |
| One-byte modification | In a 20,000,000-byte/100-block file, transmit only the changed 200,000-byte block plus protocol/hash metadata; correct final digest. |
| Separated changed blocks | Transfer only differing blocks, including partial final blocks. Measure file payload vs total wire bytes separately. |
| Append/shrink | Reuse verified unchanged ranges, send only changed/new ranges; truncate to exact final length; no stale suffix. |
| Corrupted destination | Same file size and mtime must not hide corrupted content; block comparison/final hash detects it. |
| Shift/insertion | Correct reconstruction; report potentially broad fixed-block retransmission honestly. Rolling-checksum behavior is not required. |
| Overlapped pipeline | Metadata/hash comparison and data streaming overlap with bounded queues/backpressure; slow link/hash/disk cases cannot cause unbounded manifests/allocations or deadlock. |
| Interrupted resume | Kill/disconnect mid-transfer then reconnect using the same password; revalidate retained ranges and identity; reuse valid bytes; wrong credential/root/file state is never reused. |
| Mutable source/destination | Change source during hash/read, swap same-size content, truncate, rename, or concurrently alter destination; fail/retry clearly; never report a mixed file as successful. |
| Verified staged update | Reuse unchanged ranges locally without sending them over the network; final digest checked before rename; original destination survives failed update. Measure extra local disk I/O separately. |
| Performance evidence | Record payload bytes, wire/control bytes, elapsed time, peak RSS, local I/O where available, hardware/runtime limits; compare full vs incremental run. No whole-file fallback for ordinary one-block edits. |

## File safety and destructive-operation controls

| Area | Cases and required outcome |
|---|---|
| Root authorization | Authenticated peer cannot select a broader source/destination root or permissions than the local operator allowed. |
| Path attacks | Absolute/parent traversal, alternative separators, NUL, invalid encoding/platform paths, duplicate/colliding names, excessive depth/path length; reject safely. Test adversarial protocol messages, not only cooperative CLI peers. |
| Link races | Source/destination symlinks, hard-linked existing files, directory replacement races, final-component swap, mount/reparse boundaries; no read/write/delete outside root. Check container-local outside-root canaries before/after each case. |
| Special files/metadata | Reject symlink/hardlink creation, FIFOs/sockets/devices, unsupported metadata and remote executable/setuid/ownership/ACL changes; permission failures explicit. |
| Deletion/filtering | Enabled deletion only from complete authenticated verified state and within root; interrupted/incomplete manifest cannot delete; `nodelete`, filters and merge preserve protected files. Defaults follow API decisions. |
| Dry run | Accurate scoped preview; zero payload/file/partial/config writes attributable to sync; metadata inspection only after authentication. |
| Overwrite/atomicity | Existing file remains intact on checksum failure, disconnect, permission failure, disk-full and staging errors. Per-file atomicity claimed; no tree-wide atomicity claim. |
| Resource exhaustion | Fill bounded tmpfs, hit file/frame/allocation/count limits, slow writes, many small files; truthful failure, bounded partial cleanup, no changes to canaries or unrelated files. |
| Concurrency | Two transfers targeting same file/tree, config parallelism, deletion vs transfer; locks/conflict errors prevent corrupt commits and unauthorized cleanup. |

## Lifecycle and release

Long-lived `offer`/`accept` listeners support many sequential and concurrent sessions with the same password and no forced expiry. Exercise graceful stop, worker crash, abrupt process kill, listener restart, revocation/rotation, partial retention limits, and active transfer progress without arbitrary total-duration cutoffs. Reconnect cannot reuse traffic keys.

Run malformed-frame/parser fuzzing with strict resource limits. Complete Linux/macOS and selected architecture tests; Linux Podman is not a substitute for native macOS filesystem/CLI behavior or any future Windows support. Test multi-GiB/sparse files and persistence in a separate documented bounded test-storage profile before claiming them supported. Verify release artifacts/version/checksums, installer integrity, and absence of Java/Python/shell runtime dependencies. Inspect reference redistribution terms before public upload.

Reports must distinguish implemented/passed, failed, and unimplemented gates. Record raw runs under ignored `target/` and `DEBUGLOG.md`; keep reproducible helpers, fixtures recipes, expected outcomes and regression tests tracked.
