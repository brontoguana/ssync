# SSync validation and delivery history

Current release: **4.1.7**. See [the oversized transfer release gate](#417-oversized-transfer-release-gate--2026-11-25).

**SSync 4.0.0 is published and the public delivery smoke passes.** The public repository is [brontoguana/ssync](https://github.com/brontoguana/ssync), with [release v4.0.0](https://github.com/brontoguana/ssync/releases/tag/v4.0.0) pointing to source commit `decf099c73ee1df6424f35b87e7ca767853b1236`. On 2026-10-13, all six downloaded release assets matched the prepared files and SHA-256 manifest. `tests/podman/public_smoke.py --tag v4.0.0` downloaded and verified the public binary, installed it in the existing isolated peer, queried the real public updater (current/available 4.0.0, release details and explicit up-to-date result), and uninstalled it. No host files were mounted; the temporary egress network was removed. Raw evidence is in ignored `target/public-smoke.json` and `target/public-smoke-run.log`.

## Implementation/API

Native Rust executable, no separately installed Java/Python/shell runtime. Version4.0.0 replaces Java3.3. Preserved `put/get/offer/accept`, TCP direction independence, Java UTF-16 alias mapping, ordinary numeric ports, env/inline/password-prompt precedence, `.ssync` quoted concurrent transfer lists, qualifiers, default/merge layouts, scoped mirroring and diagnostics/guidance. Added `pwd`, safe password-file/descriptor inputs and local native install/update/uninstall; local `licenses` exposes embedded public dependency notices.

Intentional differences are in CONTRACT.md: incompatible wire, minimum16 Unicode characters/4096 bytes, 24 uniform Base58 generated characters in six groups of four, no expiry, no execution features, stricter roots/types/links/permissions/config, modern hashes and truthful failures. `nodelete` on either peer narrows deletion. Missing receiver roots and file/directory type conflicts fail safely. Changed/new files preserve supported source mtimes; fully matching files keep existing timestamps.

## Security

OPAQUE4.0.1, Ristretto255/TripleDH/SHA512 with fixed Argon2id64MiB/3passes/1lane. HKDF feeds fresh NoiseNNpsk0_25519_ChaChaPoly_SHA256 sessions, with explicit mutual confirmation before roots/metadata. Source hashing and receiver range comparisons overlap current streaming through bounded queues. BLAKE3 range/final verification, credential/root/file-bound private resume, atomic individual-file replacement, locked receiver roots, no-follow openat2 capabilities and complete-verified-state deletion. Per-IP/listener guessing budgets, bounded state/concurrency/frames and15s handshake deadline; no credential expiry. Details/limitations in PROTOCOL.md.

Native installation attaches ownership to the staged executable before one atomic rename. Update downloads exact GitHub release assets and checks SHA256 over HTTPS; failed checks/downloads preserve old bytes. Uninstall verifies ownership/hash and leaves transfer/unrelated data. Checksums from the same release do not independently authenticate the publisher; account/release compromise remains a trust risk. Neither SSync integration nor the current full dependency set is claimed independently audited.

## Executed evidence (4.0.0, 2026-10-13)

- **97 recorded actual Podman checks**:13 application,33 security,14 lifecycle,12 input/API,11 advanced,9 management,4 large-profile,1 long-duration. The actual --bin-only release artifact, not only the dev/example build, was rerun through these application groups. All outside-root canaries survived.
- Native unit/path tests and20,000 deterministic parser mutations pass; lint with warnings denied and formatting pass.
-84 exact-tag upstream opaque-ke4.0.1 tests pass, including published-vector coverage. This is dependency validation, not a SSync security audit.
- Cargo audit:zero vulnerabilities and warnings; vulnerable transitive time dependency updated to0.3.55.
- Rust1.88.0 `cargo check --locked --all-targets` passes. Final release build uses rustc1.97.1, Linux x86_64 musl static PIE with no ELF interpreter.
- CLI/guidance/hidden PTY input, config concurrency, all transfer/connection directions and continuous pairings, nodelete/filter/dryrun/verify/verbose, IPv6, rotation/restart and concurrent roots tested.
- Wrong password/case/grouping, incomplete confirmation, replay, tamper/duplicate/truncated ciphertext, role reflection, unauthenticated malformed frames and metadata/root rejection tested.
- Traversal/reserved/duplicate paths, bad size/range/digest, source/destination links, FIFO, directory symlink races, external source/target mutation, ENOSPC, SIGINT/SIGTERM/SIGKILL, tampered resume, quotas, insertion,1000 small/deep/control-named files and nonexecuted program content tested.
- Distributed40-address admission test accepted20; temporary delay recovered; repeated correct credentials return admission credit. Slow trickle closed around16s observable wall-clock (15s server deadline plus client socket detection).
- Disposable management covers unchanged version, valid next-version fixture, failed download, bad/duplicate checksum, malformed release, modified/unrelated executable and unrelated-file preservation. Actual root-owned default `/usr/local/bin` install/uninstall runs inside a rootless container tmpfs. Archive version/install/uninstall smoke passes. Synthetic4.0.1 fixture is not a public release.

## Efficiency

20,000,000-byte fixture plus9 bytes in another file, independently checked with SHA256. Record counters include encrypted ready/application framing, exclude PAKE/Noise setup and TCP/IP headers.

| Run | Content bytes sent | Encrypted record bytes both directions |
|---|---:|---:|
| delta baseline | 20,000,009 | 20,035,452 |
| identical repeat | 0 | 1,483 |
| one block | 200,000 | 222,755 |
| separated blocks | 400,000 | 422,877 |
| append | 12,345 | 35,249 |
| shrink | 0 | 21,578 |
| same-size same-mtime corruption | 200,000 | 221,705 |

2,400,000,017-byte sparse-source logical transfer: 21.67s native, 66,580KiB peakRSS. Identical repeat:0 content bytes. Edit beyond2GiB offset:200,000 content bytes; final SHA256 matches. Physical sparse preservation is not promised. Tmpfs physical I/O block counters are0; changed files are reconstructed through full staged local writes/read verification even when network deltas are small.

Progressing rate-limited transfer completed in **121.85s**, exceeding120s idle threshold without a total-duration cutoff. No host data mounts or published ports: two labelled rootless peers, dropped capabilities/read-only roots, bounded tmpfs/memory/CPU/PIDs. Large profile uses6GiB work tmpfs/7GiB memory/1CPU per peer; small profile256MiB work/512MiB memory/1CPU. Containers share the host kernel, so this is filesystem/network isolation, not VM isolation.

## Artifact/platform scope and delivery

Verified release binary SHA256: `bfdf24deeb11dcb2a1c09685df1f2f7034725f25f596420d22c8d491747d6d83` (5,424,032bytes). Platform **Linux x86_64 only**, kernel5.6+/procfs/case-sensitive local filesystem. Native developer filesystem tests run on Btrfs; transfer/system-install tests use tmpfs. Other allowed FS combinations, real casefold image setup, native macOS/Windows/ARM, and files above2.4GB are not claimed tested. Network/FUSE/pseudo/casefold filesystems are unsupported and rejected. Same-identity/privileged endpoint compromise and arbitrary noncooperating OS races are outside remote-peer isolation; advisory locks are not a filesystem transaction. Per-file atomicity only; successful earlier files/directories persist when a later operation fails. Private abandoned state remains bounded and may need operator cleanup.

The matrix is a required-case inventory, not proof of every possible OS/fault combination. Live OS-random-failure injection and each filesystem/driver race permutation were not executed; unbiased sampling/error handling and unsupported-operation paths are source/unit-reviewed. No unsupported-platform claim is inferred from Linux container passes.

Private Java/reference sources/JARs remain on disk, ignored and absent from Git/source archives. Public dependency notices are embedded/distributed. Published assets: static raw Linux binary, versioned archive, public-source archive, notices, source-commit manifest and checksums. Formatting/lint/unit/parser/dependency/API/security/efficiency/management gates passed locally, and public repository/push/release and the real public installation/update/uninstall smoke are complete. A newer-version replacement was validated using the isolated synthetic 4.0.1 fixture; only 4.0.0 is publicly released, so the public updater smoke validates its up-to-date path. The published source archive records the pre-publication status; this follow-up documentation records completed delivery without changing the verified binary or release tag.

## 4.1.0 backup validation — 2026-10-31

Backup implementation reuses the existing verified delta/receiver filesystem engine. Private fixtures run in the same labelled two-peer rootless large-profile lab, with no host mounts or published ports. `tests/podman/backup.py` records backup results; ordinary application/security/lifecycle runners check the shared code. Final counts and public delivery results are recorded after completion below.

Dependency refresh: rustls 0.23.46, rustls-webpki 0.103.16, webpki-roots 1.0.11 resolve six new TLS/trust-store advisories since 4.0.0. Regenerated public notices are embedded in the binary. **Raw `cargo audit` still reports one transitive advisory**, [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) in crypto-bigint 0.5.5 via opaque-ke/voprf -> elliptic-curve. Stable opaque-ke 4.0.1 requires that older dependency. Source review of the selected Ristretto255 OPRF and TripleDH implementations shows their scalars/points use curve25519-dalek, while shared hash expansion uses digest operations; the affected crypto-bigint integer arithmetic is not selected by SSync's fixed suite. No remote suite negotiation, P-curve instantiation or secret bigint arithmetic is exposed. This is a reviewed reachability assessment, not a formal proof or a patched transitive crate. No audit suppression is committed; a clean audit is not claimed. Follow upstream updates rather than vendoring or rewriting cryptography.

Scope remains latest-copy per-file atomicity, independent full scans per destination and Linux x86_64. No Restic, restore endpoint, retained history, source snapshot consistency across destinations or at-rest encryption. The multi-candidate backup authentication wrapper has been tested but not independently audited.

### Executed 4.1 local release gates

- **99 recorded Podman checks**: 30 backup, 13 ordinary application, 33 ordinary security, 14 ordinary lifecycle, 4 cross-version transfers, 5 bootstrap cases. Backup includes two sources x two servers, default/custom ports, Unicode/empty/large fixtures, repeated zero-content transfer, 200,000-byte edits per destination, private templates/config validation, full config preflight, independent unavailable destinations, wrong secrets, old protocol upload/download rejection, traversal/link/unknown/size/block/digest/incomplete attacks, fresh/replayed/tampered/truncated/duplicated channels, missing confirmation, interrupted verified resume, SIGTERM, busy-bay exclusion, different-bay availability, listener recovery, and last candidate of 32 bays over IPv6. Outside canaries survive.
- Final static binary: SHA-256 `63646d1780e8a2dd21262b4c64118c0e5feca0b232e7fc8d172358f8f45052eb` (5,489,568 bytes). The final dependency/notices binary passed the 30 backup, 4 cross-version and 5 installer checks; the 60 ordinary shared-engine checks passed before the TLS/notices-only refresh. Four interoperability cases use the previously published 4.0.0 binary SHA-256 `bfdf24deeb11dcb2a1c09685df1f2f7034725f25f596420d22c8d491747d6d83` in both endpoint and connection roles.
- 11 native unit tests plus 2 parser/path tests (20,000 deterministic mutations including backup CLI parsing); formatting, Clippy with warnings denied, shellcheck and Python syntax checks pass. `cargo +1.88.0 check --locked --all-targets` passes. Release build is static Linux x86_64 musl; no ELF interpreter. No new independently audited-security claim.
- Real bootstrap script tested in peer B with syntactically validated mocked download responses: bad, duplicate and missing checksum, failed download, valid artifact. Failure-specific checks and unchanged installed-byte hashes verify preservation. These are fixture download checks; real public bootstrap/update verification follows publication.
- Whole-file repeat sent 0 content bytes; one edit sent exactly 200,000 bytes to each destination. Interrupted 20,000,003-byte update resumed with 1,000,000 verified reused bytes. Final matching SHA-256/tree comparisons use independent Python hashes. Full-read scans and local staged reconstruction remain, as documented.

### Completed 4.1 public delivery

Published [SSync 4.1.0](https://github.com/brontoguana/ssync/releases/tag/v4.1.0) from exact source commit `4afcf01d226127abb4645f6d395fca2bb9989633`. All six downloaded public assets passed the generated checksums/manifest, and archive/raw binary hashes match the locally tested SHA-256 above. Public GitHub README matches the reviewed installer/config documentation.

The real public smoke passed inside the rootless large-profile peer: checksum-verified public download, root-owned default install, actual installed 4.0.0 -> 4.1.0 update via GitHub with release details, already-current 4.1.0 check, uninstall preserving transfer data, and the exact README `curl ... | bash` bootstrap. The temporary labelled egress network was disconnected/removed in cleanup. No production host installation or host mounts were used. Raw public output is in ignored `target/backup-public-smoke.log` / `target/public-smoke.json`; all local/raw investigation notes remain ignored. This follow-up documentation does not change the verified executable or release tag.

## Security review — 2026-10-31 (before 4.1.1)

[Full findings, fixes and remaining boundaries](SECURITY_REVIEW.md). Review evidence totals 146 recorded Podman checks across review builds, 18 native/parser tests and two explicit fsync-EIO probes; format/Clippy/MSRV/shellcheck/Python checks pass. The final development binary passed 53 application/targeted-review/backup checks after the last source-root and mount/config changes. The report distinguishes these from groups run on preceding review builds, and records the remaining unsuppressed transitive advisory and authenticated delta-comparison disclosure. At that review completion, no new public release, production installation or independent-audit claim was made; published 4.1.0 assets stayed unchanged. The source hardening is included in 4.1.1 below.


## 4.1.1 crypto and security release

Local release validation completed 2026-11-01. This version includes the post-4.1.0 [security hardening](SECURITY_REVIEW.md) and [cryptographic integration review](CRYPTO_REVIEW.md). Wire suites/passwords/commands are unchanged. The implementation review is not an independent audit or security proof. One unsuppressed transitive crypto-bigint advisory remains, with selected-suite reachability assessed in those reports.

**193 recorded Podman checks passed against the same static release-candidate binary**: SHA-256 `cc65a96e6c7c238953af1b7ebad742c8edc994cf7e235f33621c6a95512d3107` (5,510,048 bytes). This is a new complete run, rather than the preceding review's counts across intermediate builds.

| Suite | Passing checks |
|---|---:|
| Crypto handshake stage faults and valid baselines | 45 |
| Ordinary application / targeted security review | 13 / 10 |
| Security / lifecycle / input and configuration / advanced filesystem | 33 / 14 / 12 / 11 |
| Backup / native management / bootstrap | 30 / 9 / 5 |
| Cross-version interoperability / multi-GiB / long-duration | 6 / 4 / 1 |
| **Total** | **193** |

Additionally, **26 native/parser tests**, the **84 exact-tag upstream OPAQUE tests**, and **two explicitly injected fsync-EIO probes** pass. The two injection-only probes remain ignored by ordinary cargo test; their separate successful runs are recorded. Formatting, warnings-denied Clippy, Rust 1.88 all-target checking, shellcheck, Python and embedded-fixture syntax checks pass. Cargo audit has the documented single advisory, with no suppression. New crypto tests cover record boundaries, key/context separation, replay/reordering/reflection/cross-session rejection, malformed authenticated records, nonce exhaustion, permanent channel closure, all handshake stages and backup candidate routing attacks. An unused-candidate modification is explicitly tested as compatible with a valid selected login; whole-list authentication is not claimed.

Packaging initially rejected a different combined binary/example build: development-dependency feature unification changes the ctrlc/nix/bitflags graph. The final complete run uses the production-only `--bin ssync` build, with packaged identity enforcement through `scripts/build-release.py --expected-sha256`. The earlier candidate evidence is retained separately and is not added to these counts. See the build order in `tests/podman/README.md`. All application groups use the final production executable identity above, including ordinary transfers with public 4.0.0 and backups with public 4.1.0 in both old/new endpoint arrangements. Source/bay safety, delta comparison disclosure, cancelled/tampered resume, root ownership, reserved-name collisions and installer failure preservation are exercised. Synthetic update fixture **4.1.2 is private**, used only to verify an actual version increase from the 4.1.1 candidate.

The final 2,400,000,017-byte transfer passes independent SHA-256 comparison, identical repetition sends zero content bytes, and an edit past 2 GiB sends exactly 200,000 bytes. Peak transfer RSS is 66,576 KiB. The rate-limited encrypted transfer completes in 121.91 seconds, beyond the 120-second idle timeout without a total-session cutoff. Two labelled rootless peers use bounded tmpfs/CPU/memory, dropped capabilities, no host-directory mounts or published ports; they share the host kernel.

Published [SSync 4.1.1](https://github.com/brontoguana/ssync/releases/tag/v4.1.1) from exact source commit `9906b1e4f23de3b4d42b0ad462ff22a8b69d899c`. All six public assets match the tested local package byte for byte and pass checksums/source-manifest verification. Public delivery passed: the exact README bootstrap, root-owned default installation, a real 4.1.0-to-4.1.1 native update through GitHub with release details, already-current reporting and uninstall in the disposable peer. The temporary egress network was removed, and the test installation was absent after cleanup. Raw public results are in ignored `target/crypto-audit-public-smoke.log` and `target/crypto-audit-public-receipt.json`. This follow-up documentation leaves the tested release binary and tag unchanged. No production host is installed or upgraded. Raw evidence is ignored under `target/crypto-audit-*`, `target/podman-*`, and `DEBUGLOG.md`.

## 4.1.2 directory policy — 2026-11-05

Shared source/destination directories are accepted by default. Each ordinary/backup peer can independently request `sole-owned`; config/installation paths and private resume state retain their protections. The versioned 4.1.2 binary and public delivery have passed the checks below.

Pre-version-bump validation: `cargo test --locked` passed 29 native/parser tests (two syscall-injection durability probes remain explicitly ignored); `cargo clippy --locked --all-targets -- -D warnings` passed. The static musl production binary SHA-256 `b78e35b4601b25389cd15c7296f2f3c422917297705b6a8261497c729baa3417` passed 97 isolated Podman checks: sharing 11, application 13, review 10, backup 30, security 33. These cover shared roots/children, independently strict senders/receivers, backup defaults/preflight, private config/state, retained root identity checks, delta transfers, resume, cancellation, owner/ancestor checks in opt-in mode, and link/path attacks. Linux only; no new handle-soak/log-growth validation is claimed. Raw logs: ignored `target/directory-policy-*.log`, per-suite JSON, and `DEBUGLOG.md`.

Versioned 4.1.2 release gate: 29 native/parser tests, warnings-denied Clippy, formatting and shell syntax checks pass. The production-only static musl binary SHA-256 `6dbb744906e1c77b08e3e9be9cebd7f0726b4f0bf821fe779b62825d0d824879` passed a fresh run of all 97 checks above (sharing 11, application 13, review 10, backup 30, security 33). No dependency or protocol changes. Raw evidence: ignored `target/release-412-*.log` and `target/release-412-tests.json`.

Published [SSync 4.1.2](https://github.com/brontoguana/ssync/releases/tag/v4.1.2) from source commit `422006e55c611f4f7106ef892e879264ca36d03f`. All six public downloads match the local checksum-verified assets byte for byte; the release tag and latest-release API select 4.1.2. The disposable rootless peer passed the exact README bootstrap, root-owned installation, real 4.1.1-to-4.1.2 update, already-current check and uninstall. The temporary egress network and test installation were removed; no production installation was changed. Public evidence: ignored `target/release-412-public-receipt.json`, `target/release-412-public-smoke.json` and `target/release-412-public-smoke.log`.

## Ordinary configuration-directory follow-up (included in 4.1.3) — 2026-11-05

Ordinary saved transfer commands accept shared-writable parent directories with one stderr warning and continue without a confirmation prompt. `ssync sole-owned file.ssync` retains strict parent checks and enables the local strict policy for every contained transfer. Existing config-file ownership, mode, no-link and read-size checks remain; password/backup config loaders remain strict.

Validation: 30 native/parser tests passed (two unrelated injected-sync probes remain ignored), warnings-denied Clippy passed, and all 16 isolated sharing checks passed against the rebuilt static binary. New checks cover successful saved-command transfer with exactly one warning, strict config parent rejection, propagation to contained local transfers, file mode rejection and symlink rejection. Existing ordinary/backup sharing checks also pass. This development validation preceded the versioned 4.1.3 release gate below.

## Configuration transfer protection (included in 4.1.3) — 2026-11-05

Transfers skip `.ssync` names case-insensitively, warn and continue. Updated senders omit these paths; updated receivers independently skip older peers’ file/directory entries without breaking the manifest or byte accounting. Mirror cleanup preserves destination configurations and ancestor directories containing them. Old receivers require `nodelete` until upgraded. Local backup template creation remains unchanged.

Validation: 30 native/parser tests, warnings-denied Clippy and 35 isolated container checks (six new configuration-protection, 16 sharing/config-policy and 13 ordinary transfer/delta checks). New checks cover new/new and old/new peers, no creation/overwrite/deletion, mixed-case names, nested configurations, directory/file conflicts, explicit config-file selection, dry runs and backup transfers. Static candidate SHA-256: `ebe12929dc697881f05994ad975a4f542ad51c2a1b8d5881f148ec2757b933e3`. Raw commands/results: ignored `target/config-protection-*.log` and `target/config-protection-summary.json`. This development validation preceded the versioned 4.1.3 release gate below.

## 4.1.3 configuration release gate — 2026-11-05

The versioned production-only static musl binary SHA-256 `5b211553a78faa7cb5c4abdd5248b26fe2d90cfd8d905b4f5cc673ff40e5edbe` passed 108 isolated container checks: configuration protection 6, sharing/configuration policy 16, application/delta 13, directory trust 10, backup 30 and security 33. All 30 native/parser tests, warnings-denied Clippy, formatting, shell syntax and diff checks pass; two unrelated syscall-injection probes remain explicitly ignored. The legacy ordinary-config ancestor regression now selects `sole-owned` to exercise the retained strict policy. Test commands/logs and the binary identity are recorded in ignored `target/release-413-*.log`, `target/release-413-tests.json` and `DEBUGLOG.md`. No dependency or wire-format change; Linux platform limits and the sustained handle/log-soak validation gap remain.

Published [SSync 4.1.3](https://github.com/brontoguana/ssync/releases/tag/v4.1.3) from exact source commit `7e093fa1f5e5898ea9fcf33f6a8cecea576c090f`. All six public assets match the locally verified release packages byte for byte, and the latest-release API selects 4.1.3. The disposable rootless peer passed public download/checksum verification, root-owned install, real 4.1.2-to-4.1.3 update, already-current reporting, uninstall preserving data and the exact README bootstrap. The temporary egress network and test installation were removed; no production installation changed. Evidence: ignored `target/release-413-public-receipt.json`, `target/release-413-public-smoke.json` and `target/release-413-public-smoke.log`.

## Unreleased source permission fix — 2026-11-18

Source rwx permissions now transfer for regular files and directories, including content-identical files, merge roots and backup roots. Ownership, groups, ACLs and special mode bits are excluded. Both endpoints require the updated wire messages; mixed-version ordinary and backup transfers refuse before modifying data. No release or production installation was made.

The final production-only static musl build SHA-256 `1f231c76db10a366d3a14a0dbc5a14f8900c4ea1e11aeab4aa368a6473028284` passed **72 isolated container checks**: source permissions 14, application/delta 13, security 35, configuration protection 4 and legacy-version refusal 6. The permission suite covers replacements, unchanged contents, both listener directions, read-only directory reuse, merge roots, dry runs, late-failure directory finalization, local strict-directory policy, special-bit exclusion, another user's unchanged readable file and backups. Security checks cover malicious modes, link/path rejection, authenticated framing faults, private resume reuse, protected deletion and unchanged outside canaries. All 32 native/parser tests and warnings-denied Clippy pass; two unrelated syscall-injection probes remain ignored. Formatting, Python syntax and diff checks pass.

Private resume files remain `0600`; source modes apply only after verified publication. Directory modes finalize after cleanup, deepest first, including ordinary failure/cancellation paths. A forced process termination can leave temporary directory modes or a just-renamed file at `0600`; rerun the transfer to finish metadata. This work does not change duplicate-listener cancellation, root-lock contention or rejection of links/special files. Raw evidence: ignored `target/transfer-failure-20261118/permission-fix-*.log`, `permission-fix-summary.json` and `DEBUGLOG.md`. Earlier reproduction and intermediate runs are not added to the 72 final-build checks.

## Unreleased link descriptions, permission overrides and help — 2026-11-18

The updated static musl binary SHA-256 `8aa4fa07ad00ec17d1c9751e2c121777ca7bb6205acd8a07abd2ffd195a69fe6` passed **103 isolated container checks**: links/overrides 20, application/delta 13, security 35, source permissions 14, configuration protection 4, legacy ordinary/backup refusal 6 and advanced containment/resume 11. All **33 native/parser tests**, warnings-denied Clippy, formatting, Python syntax and diff checks pass. Two unrelated syscall-injection probes remain explicitly ignored. No release, push or production installation was made.

Link checks cover relative/absolute/broken/directory/self-loop symlinks, targets containing shell punctuation/quotes/newlines, non-UTF-8 byte targets, safe manual recreation, independent hardlink contents and known/unknown partner descriptions, individual link selections, description/source name collisions before writes, filters on original/projected paths, zero-payload repeats, dry runs, nodelete retention, stale-description mirror cleanup and backups. Mode tests cover all parser aliases/rejected inputs, 600/755/000/644 overrides on new/unchanged files and descriptions, replacement of unreadable existing files, preserved directory modes, receiver precedence in either connection direction and backup receiver policy. Advanced tests retain destination symlink/hardlink outside canaries and verify executable rwx preservation with stripped setuid and no execution. Fixed-block delta and private-resume checks still pass.

Source-only O_PATH/no-follow metadata and pinned readlinkat do not weaken destination/configuration/private-state restrictions. Descriptions are ordinary verified file data and never interpreted by SSync. All projected entries remain subject to manifest/path quotas and selection scopes; descriptions default to0600 unless overridden. Existing unsupported destination links/special files and ordinary-config duplicate-listener cancellation remain separate limitations. Both endpoints require updated builds and restarted listeners. Historical full release/long-run/platform gates are not claimed by this targeted development run. Raw commands/results: ignored `target/transfer-failure-20261118/links-*.log`, `links-summary.json`, `links-help.txt` and `DEBUGLOG.md`.


## Unreleased inert configuration copies and scan exclusions — 2026-11-18

Final static Linux x86_64 binary SHA-256 `027deee90f9302cd90e13855c85fb4b12313fcac2ce97ff9b97ebdb1f033b6d0` passed **54 isolated container checks**: configuration projection/exclusions 18 and security 36. All **34 native/parser tests**, warnings-denied Clippy, formatting, Python syntax and diff checks pass; two unrelated fault-injection probes remain ignored. Supplementary link/override 20 and application/delta 13 checks passed on the earlier build of this update; subsequent original-descendant-filter and resume-credential guards are covered by the final configuration/native/security runs. No commit, push, release or production installation was made.

Checks cover case-insensitive `.ssyncbak` copies in ordinary/backup transfers, direct selections, unchanged content/chmod, config/link/directory name collisions before writes, original/projected path filters, preserved live destination configs, malformed source state exclusion, explicit reserved-state no-ops, arbitrary configured password filenames, real password-file authentication and higher-priority environment input, source/destination hard-link aliases, protected mode/overwrite/deletion, and malformed receiving-state rejection. Native descriptor tests preserve credentials even if they occupy a resume path or their inode moves. The malicious empty-root test confirms excluded/no-op selections cannot authorize merge-root chmod. Resume, authenticated framing faults, dry runs, path containment and filter-protected deletion pass with outside canaries intact.

Security runner now resets its own synthetic fixture tree; a preliminary count mismatch came from configuration-suite leftovers and was confirmed as correct deletion of six extras rather than the expected one. Initial fixture/runner errors are recorded in ignored `DEBUGLOG.md`. Final raw commands/results: `target/transfer-failure-20261118/configbak-*.log` and `configbak-summary.json`. Normal OS access/chmod errors and optional `sole-owned` policies remain; this change does not alter cron sibling cancellation or concurrent destination locks.

## 4.1.4 permissions, links and configuration release gate — 2026-11-18

The versioned production-only static Linux x86_64 musl binary SHA-256 `8a90638c4e43bf94ac45e69298e860f66f6d5403d9c5d50150362134078ad4ba` (5,591,968 bytes) passed **153 isolated container checks**: links/overrides 20, configuration projection/exclusions 18, source permissions 14, application/delta 13, security 36, backup 30, mixed-version refusal 6, advanced containment/resume 11 and bootstrap failure/success 5. All **34 native/parser tests**, warnings-denied Clippy, formatting, shell syntax, Python syntax and diff checks pass. Two unrelated syscall-injection probes remain explicitly ignored. All seven help topics and the permission table were checked on the versioned executable. No dependency changes.

The published 4.1.3 binary used for compatibility/upgrade checks was checksum-verified as `5b211553a78faa7cb5c4abdd5248b26fe2d90cfd8d905b4f5cc673ff40e5edbe`. Mixed ordinary and backup peers fail before transfer-data changes; upgrade both endpoints and restart listeners. The final parser mutation seed now includes the required mode field and asserts that the seed decodes successfully.

Security and advanced runners reset their own fixtures and install the candidate. An initial advanced run correctly refused the legacy executable left by compatibility testing; the standalone rerun passed all 11 checks after fixing suite setup. No production transfer-code correction was needed for that finding. Final executable identity stayed unchanged throughout the integration suites. Raw commands, results, fixture diagnosis and hashes are in ignored `target/release-414/`, per-suite lab JSON and `DEBUGLOG.md`.

Ordinary configuration sibling cancellation, destination-lock contention and destination links/special-file restrictions remain unchanged. Source modes copy only rwx bits; receiving ownership/group/ACLs are not reproduced. Normal OS access/chmod failures remain possible. Forced termination can leave temporary modes; rerun to finish metadata. Source state and configured password exclusions do not identify other unconfigured secrets. No independent audit, new platform coverage or sustained handle-count soak is claimed.

These are local versioned release gates. Checksum-gated packaging, exact-commit publication, public asset verification, bootstrap and real 4.1.3-to-4.1.4 update are the remaining delivery steps; their results will be recorded after publication. No production installation has been changed.

### Completed 4.1.4 public delivery

Published [SSync 4.1.4](https://github.com/brontoguana/ssync/releases/tag/v4.1.4) from exact source commit `dc3f7dd91790310c10cee091532dcc19daba0d1d`. Checksum-gated packaging rebuilt the identical tested binary. All six uploaded draft assets and subsequent anonymous public downloads matched the locally prepared files byte for byte, including checksums, notices and source-commit manifest. The public latest-release API and tag select this exact release/commit. The source archive excludes private Java references, local logs and generated directories; licence/notices are present in source and binary packages.

The disposable rootless peer passed verified public download, root-owned installation, a real installed **4.1.3-to-4.1.4** update through the public updater, already-current reporting, uninstall and the exact README bootstrap. The temporary egress network and test installation were removed. No production installation was upgraded. Raw evidence: ignored `target/release-414/public-receipt.json`, `public-smoke.json`, `public-smoke.log`, `prepared-manifest.json` and `DEBUGLOG.md`. This follow-up documentation leaves the published source tag and tested binary unchanged.

## 4.1.5 listener and disk-headroom release gate — 2026-11-18

The versioned production-only Linux x86_64 musl build passed **37 native/parser tests** (32 library, 5 parser), formatting and warnings-denied all-target lint. The two opt-in filesystem fault-injection probes remain ignored by the ordinary native test run; this release does not claim a fresh injected-fsync run.

The exact executable passed **188 recorded isolated container checks**: application 13, security 36, crypto 45, backup 30, permissions 10, links 20, configuration protection 18, advanced 11 and bootstrap 5. Historical authentication-failure assertions in the security, crypto and advanced harnesses now verify one-shot listener survival; ordinary security cases additionally complete a valid transfer after rejection. Authentication completed before any post-authentication source/root error remains fatal. Stage-six listener-ready faults remain authenticated-session failures.

The dedicated `tests/podman/receiver_limits.py` passed on the same executable: four admitted idle sockets from one source leave ordinary and backup listeners able to authenticate another source; a write that would cross the 99% cutoff preserves the prior destination and private partial, resumes verified bytes after space is freed, and applies equally to backup receives. Four legitimate concurrent backup workers from one source complete across distinct bays. A combined-fixture test initially lost its replacement canary to the preceding successful backup mirror; restoring that canary before the cutoff check fixed the harness, with no product change.

Six loopback cases passed with the production binary, covering both one-shot directions after malformed handshakes, a timed-out idle handshake, fatal post-authentication/bind errors, sibling one-shot jobs after rejection, and continuous reuse/cancellation. Four mixed-version checks passed ordinary and backup transfers in both 4.1.4/4.1.5 client/listener combinations. Releases before 4.1.4 remain incompatible with the permissions extension; this release does not change that wire extension.

Tested executable SHA-256: `86789fc5049cf7351fe9cf1324111fb3fda8ea04f5c0e13b6a2f09ab5c1a6c53`. Packaging must enforce this identity. The added-source scan found no credential patterns or private machine paths. Evidence: ignored `target/release-415/{identity,summary,suites}.json`, individual suite logs, `receiver_limits.log`, `loopback.log`, `compatibility.log` and `DEBUGLOG.md`.

The disk cutoff is filesystem-wide and best effort under concurrent allocations, not a per-bay quota. Distributed sources can still exhaust listener admission. Merge/backup root mode handling and general saved-configuration sibling cancellation on local failures are unchanged. No production listener or installation was modified during validation.

### 4.1.5 public delivery

Published [v4.1.5](https://github.com/brontoguana/ssync/releases/tag/v4.1.5) from exact source commit `17a939bc88b6b28a7fe582bc757e488a2060aa39`. All six anonymous public downloads match their prepared SHA-256 hashes and sizes. The GitHub tag resolves to that source commit, and the binary archive contains the exact tested executable plus README, licence and dependency notices. The clean source archive includes the new regression runner and excludes private/debug/reference-import artifacts.

The disposable rootless peer passed checksum-verified public download, root-owned installation, a real installed **4.1.4-to-4.1.5** public update, already-current reporting, uninstall and the exact README bootstrap. The temporary egress network and installed executable were removed. No production installation was upgraded. Evidence: ignored `target/release-415/public-receipt.json`, `prepared-manifest.json`, `public-smoke.json`, `public-smoke.log` and `DEBUGLOG.md`. This documentation follow-up leaves the source tag and tested executable unchanged.

## 4.1.5 deleted-but-open file review — 2026-11-18

Reviewed published production binary SHA-256
`86789fc5049cf7351fe9cf1324111fb3fda8ea04f5c0e13b6a2f09ab5c1a6c53`
at checkout `2629efb`, with no runtime changes. The Java report concerned open
files with link count zero retaining disk allocation. No equivalent persistent
leak was found in the native file-lifetime review or these bounded Linux tests.

`tests/podman/handles.py` exercises two labelled, isolated rootless peers, without
host mounts or production listeners. It samples `/proc/PID/fd` link counts,
unique allocated bytes by device/inode, mappings, descriptors, threads and
filesystem free blocks. This checks the deleted/open condition reported by
`lsof +L1`, without needing lsof in the peers. An intentional 8,003,584-byte
allocated/unlinked file validates detection and reclamation on close.

Passing runs covered 110 transfer attempts:

| Scenario | Attempts | Result |
| --- | ---: | --- |
| Persistent accept: replacements and recursive mirror deletion | 40 | Stable disk use; no retained deleted handles |
| Identical-file comparisons | 10 | No handle growth |
| Authenticated missing-source errors | 10 | Listener returned to baseline |
| Mid-file disconnect followed by verified partial resume | 6 | Named partials closed; recovery succeeded |
| External destination unlink, rejection and retry | 2 | 6,000,640 transient deleted bytes, then zero |
| Persistent offer: source replacements and downloads | 20 | No retained source handles |
| External source unlink, rejection and retry | 2 | 12,001,280 transient deleted bytes, then zero |
| Persistent backup: replacements and mirror deletion | 20 | Stable disk use; no retained deleted handles |

All three persistent listener types returned to **4 descriptors and 2 threads**
after sessions, with **zero deleted-open bytes and zero deleted mappings**.
Free space was exactly constant across the measured accept and backup
replacement loops. Source and destination canaries/content were checked;
listeners stayed running between iterations. The unlink races proved that a
handle can briefly retain an unlinked inode while actively used, then closes on
transfer failure. No restart/cleanup was needed to release these handles.

Source review: `fs.rs` immediately wraps successful raw opens in owning `File`
values. `transfer.rs` owns old/staged files per file and joins scoped producer/
comparison threads on success and error; cloned comparison handles do not live
past the scope. Root locks are tied to root descriptors, directory permission
records contain identities rather than held descriptors, and the listener has
no persistent file-handle cache. `runtime.rs` removes socket clones through
`SocketGuard`; authentication watchdog clones are released after guard-triggered
thread joins. No unowned raw descriptor or file-backed mapping was found in
these paths.

Interrupted or abandoned transfers can retain **named**, closed `.ssync-state`
partials. They occupy visible disk space for resumption and are not the reported
deleted-open leak. Retrying identical content consumes the partial; changing the
source can leave the old partial until local removal or the existing state
limits require attention. This review does not establish the original Java
cause and is not a multi-day soak or a production deployment measurement.

`cargo test --locked`: 37 native/parser tests passed; two existing optional
strace fault probes remain ignored. Python syntax and Git whitespace checks
passed. Raw evidence: ignored `target/podman-handles/{samples.jsonl,run.log,
source-unlink.log,results.json,native.log}`. Initial test-only assertion
corrections and their raw outputs are preserved in `DEBUGLOG.md`. The base run
passed 108 attempts, followed by the targeted two-attempt source-unlink case.
No runtime change, commit or release was made for this investigation.

## 4.1.6 transfer diagnostics release gate — 2026-11-19

The versioned, production-only Linux x86_64 musl build reported `SSync v4.1.6`.
Native and parser tests passed (39 total, with two optional strace probes
ignored), along with formatting and warnings-denied lint.

Loopback tests verified matching failure IDs and summaries in all four
client/server and send/receive combinations. An interrupted backup released
its bay for a verified retry on the same server while another bay remained
available. A Btrfs test verified the `Lock held by: PID …` wording, including
the process name when visible, when `fstat` and `/proc/locks` reported different
device IDs for the same lock. The sender received the same failure ID with no
holder PID or process name. The receiver kept its existing destination content.

The disposable lab verified the new wording during live lock contention. A
receiver killed partway through a copy released the exact-root lock immediately.
The retry reused 800,000 staged bytes and verified the result. Receiver disk
headroom checks preserved existing files and reused private partial data once
space was freed. Raw evidence is in ignored `target/release-416/` and `DEBUGLOG.md`.

All 13 ordinary application, 14 permission and 30 backup cases passed. Twelve
mixed-version cases passed with the public 4.1.4 and 4.1.5 executables, covering
ordinary uploads and downloads and backup in both version arrangements.

### 4.1.6 public delivery

[SSync v4.1.6](https://github.com/brontoguana/ssync/releases/tag/v4.1.6) points
to source commit `df89754ae080fc853bea8ae583368de12dcbfc02`. All six anonymous
downloads matched the prepared checksums and sizes. The archive contains the
tested executable with SHA-256
`e25bc06b50f80772bae5f571006bb4dadf02ddb8cf275ae000083d20e970c1d4`,
the README, licence and third-party notices.

The disposable rootless peer passed the exact README bootstrap, a public
4.1.5-to-4.1.6 upgrade, already-current reporting and uninstall. The temporary
egress network was removed. Raw receipts and smoke results are in ignored
`target/release-416/`.


## 4.1.7 oversized transfer release gate — 2026-11-25

Rust 1.88 passed 40 native and parser tests with two optional strace probes
ignored. Formatting and warnings-denied Clippy passed. The Linux x86_64 musl
build reported `SSync v4.1.7` and had SHA-256
`5e7e8f7ab667170bbf9945bc92c3bf17afc7e856139cae68dd96a51f875101e8`.

The two-peer lab verified four scenarios with a 10,001-file tree. Receiver-only
opt-in left the source directory limit active. Sender-only opt-in stopped before
writing the first entry over the receiver's manifest limit. Enabling the option
on both peers let a saved command and a backup transfer the entire tree and
remove stale entries. Independent file hashes, modes and timestamps matched.
The saved-command case also exercised both peers' verification passes. The
manifest unit test covers the separate aggregate path-byte limit.


The production-only build passed 99 container checks, including four oversized
transfer cases, 13 ordinary, 14 permission, 20 link and 30 backup cases. Eighteen
mixed-version checks covered ordinary uploads and downloads and backup with
each of 4.1.4, 4.1.5 and 4.1.6. Mixed sessions with 4.1.6 used the same shared
transfer ID at both ends.

### 4.1.7 public delivery

[SSync v4.1.7](https://github.com/brontoguana/ssync/releases/tag/v4.1.7) points
to source commit `81ae194be170aca234c30f23f0e967442573adc3`, which includes
[PR #1](https://github.com/brontoguana/ssync/pull/1). All six anonymous public
downloads matched the prepared checksums and sizes. The binary archive
contains the exact executable tested above, the README, licence and
third-party notices.

The disposable rootless peer passed the public README bootstrap, a native
4.1.6-to-4.1.7 upgrade, already-current reporting and uninstall. The temporary
egress network was removed. Raw results and receipts are in ignored
`target/release-417/`.
