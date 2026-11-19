# Changelog

## 4.1.6 — 2026-11-19

- Report `Lock held by: PID …` and the process name when available in the receiving peer's busy-destination log. Keep process details local.
- Correlate authenticated ordinary and backup transfers with a shared nine-character log ID. Report the same failure summary on both updated peers, identify the client or server and data direction, and keep full local details at the origin. Negotiate diagnostics and final confirmation while retaining transfer compatibility with 4.1.4 and 4.1.5.
- Document the exact-root advisory lock and verify that killing a receiver during a copy releases the lock and leaves its partial available for resume. Release the in-process backup bay reservation even if its worker panics.

- Name the actual destination entry type when refusing a symbolic link or special file. Report hard-link counts only for regular files.

- Include the affected file or directory, operation and underlying error in transfer diagnostics. Share bounded failure codes and eligible relative entry names between updated peers for errors such as denied permissions, file-type conflicts, changed files and unsafe resume state. Include the filename in local configuration and password-file errors and the exact failing path during source scans and mirror cleanup.

- Report receiver lock contention and the 99% disk cutoff to the sender, along with the transfer stage and whether earlier destination changes may remain. Identify the first failed line in a saved configuration and distinguish it from jobs interrupted during cancellation. Explain incomplete connection messages and keep detailed receiver errors in its local log.
- Add a persistent-listener regression for deleted-but-open files and descriptor/thread accumulation during replacements, mirror cleanup, failures, resume and backup transfers. Record a 4.1.5 review with 110 transfer attempts and no persistent deleted-file or handle leak found.

## 4.1.5 — 2026-11-18

- Publish the exact tested binary; verify all six public downloads, README bootstrap, real 4.1.4 upgrade, already-current reporting and uninstall in the disposable rootless lab.

- Validate the exact versioned static binary with 37 native/parser tests, 188 recorded container checks, dedicated listener/disk-headroom regressions, six loopback cases, four 4.1.4 compatibility cases, formatting and warnings-denied lint.

- Add repeatable idle-peer and disk-headroom regressions. Update authentication fault tests to require one-shot listener survival and a subsequent valid transfer.

- Keep one-shot `put` and `get` listeners open after rejected or timed-out handshakes, with the same failed-attempt accounting as continuous listeners. Return the first authenticated transfer's result and keep local listener errors fatal.
- Separate pending handshakes from authenticated transfer slots on continuous and backup listeners. Limit pending handshakes to four per source IP, eight per listener and 64 per process. Keep per-IP backoff and the listener-wide token rate, and remove the fixed listener-wide failure lockout. Release process-wide OPAQUE work permits before waiting on the network.
- Stop staging incoming file data when the next write would push a capacity-reporting destination filesystem above 99% usage. Check before preparing destination entries and publishing replacements. Apply the same policy to normal receives and backups, preserving existing targets and private resume state on refusal.

## 4.1.4 — 2026-11-18

- Publish the exact tested binary and verify all six anonymous public downloads, README bootstrap, real 4.1.3 upgrade, already-current reporting and uninstall in the disposable rootless lab.

- Validate the versioned production binary with 34 native/parser tests, 153 isolated container checks, warnings-denied lint and formatting.

- Reproduce source read/write/execute permissions on new, replaced and content-identical files and directories, including merge and backup roots. Exclude ownership, groups, ACLs and special mode bits. Keep private staging and finalize directory modes after cleanup and normal failures; forced termination may require a rerun.
- Add `--chmod MODE` / `chmod:MODE` and `permissions` aliases to override all copied file modes, including unchanged files and link descriptions. Receiver overrides take priority; directories retain source modes.
- Describe source symlinks as inert `.ssynclink` files without following their targets. Copy hard-linked regular contents independently with relationship descriptions and manual recreation instructions. Reject projected-name collisions before copying.
- Copy `.ssync` sources as inert `.ssyncbak` names in ordinary transfers and backups, including direct selections and directory components. Keep live destination configurations protected; apply filters to original and projected paths.
- Skip source `.ssync-state` entries without inspecting ownership or contents. Exclude the configured `SSYNC_PASSWORD_FILE` and its hard-link aliases from copying, replacement, mode changes and mirror deletion. Retain private receiving-state and credential-use checks.
- Restore structured main help and add `ssync --help <topic>` (also `ssync help <topic>`) for permissions, links, mirroring, passwords, configurations, backups and compatibility. Include the default-versus-`chmod:600` permissions table.
- Include rejected paths, busy destination roots and failed action/listener ports in diagnostics. Keep destination link protections, concurrent-writer exclusion and ordinary-configuration sibling cancellation unchanged.
- Require updated endpoints for ordinary and backup transfers; mixed versions refuse before modifying transfer data. Restart listeners after upgrading.
- Update the parser mutation seed for permission-bearing file messages and isolate security/advanced fixtures. Development validation and final versioned release evidence are recorded in `docs/VALIDATION.md`.

## 4.1.3 — 2026-11-05

- Publish the exact tested binary; verify all six public assets, README bootstrap, real 4.1.2 upgrade, already-current reporting and uninstall in the disposable rootless lab.

- Validate the versioned production binary with 30 native/parser tests, warnings-denied lint and 108 isolated container checks; update the strict ancestor regression to select `sole-owned`.
- Skip `.ssync` paths (case-insensitive) with a warning during ordinary and backup transfers; preserve destination configurations during mirror cleanup and continue other files. Updated senders omit configurations and updated receivers also refuse older senders’ configuration writes. Destination cleanup protection requires an updated receiver (or `nodelete` with older receivers).
- Warn once and run ordinary `.ssync` configurations in shared-writable folders by default.
- Add `ssync sole-owned file.ssync` to retain trusted configuration directories and enforce strict local directories on each contained transfer.
- Retain configuration-file ownership/mode checks and separate password-file, backup-configuration and installation protections.
- Validate 30 native/parser tests, warnings-denied lint and 16 isolated sharing/config/backup-policy checks.

## 4.1.2 — 2026-11-05

- Publish the exact tested binary; verify all six downloads, README bootstrap, real 4.1.1 upgrade, already-current reporting and uninstall in the disposable rootless lab.

- Accept shared-writable source and destination directories by default for ordinary and backup transfers.
- Add the local `sole-owned` qualifier on either peer to retain directory mode checks and receiver owner/ancestor checks; keep configuration/installation paths and private resume state protected.
- Include the affected path in directory permission errors and document the local-writer trust boundary.
- Validate 29 native/parser tests, warning-free lint, and 97 isolated sharing/transfer/backup/security regression checks.

## 4.1.1 — 2026-11-01

- Publish the exact tested production artifact; verify all six public assets, the README installer, actual 4.1.0-to-4.1.1 update, already-current reporting and uninstall in the rootless lab.

- Audit OPAQUE/Argon2id/HKDF/Noise integration and backup candidate selection; document findings, tests and limits in docs/CRYPTO_REVIEW.md.
- Wipe application-owned OPAQUE export/session results promptly, including failed confirmation paths.
- Close and permanently reject channel reuse after encrypted framing, authentication, decoding or I/O failure.
- Document separate helper/production builds and add a tested-binary hash gate before release packaging.
- Include the previously unreleased filesystem, durability, config-read, resolver and authentication-admission hardening described in docs/SECURITY_REVIEW.md.

- Validate 193 final-candidate Podman checks, 26 native/parser tests, 84 upstream OPAQUE tests and two explicit sync-failure probes; retain the documented unsuppressed dependency advisory.
- Prevent rejected IP traffic spending global authentication credits or filling admission state.
- Detect backup bay overlap through bind-mount aliases using bounded descriptor/kernel mount metadata, prohibit recursive cross-device/subvolume access, and correctly allow explicitly selected directory mounts as source roots.
- Tighten writable-directory ownership/ancestor checks, reject silent reserved-state filename collisions, bound ordinary config reads during concurrent growth, make directory changes durable, and try every resolved address before failing a connection.

## 4.1.0 — 2026-10-31

- Add persistent password-selected backup bays and multi-server latest-copy backup clients, without Restic or remote restoration.
- Add private line-based configuration templates, bounded bay authentication, and backup protocol separation.
- Publish 4.1.0 and verify all public assets, the README bootstrap, real 4.0-to-4.1 upgrade, up-to-date reporting and uninstall in the rootless lab.
- Add isolated backup, cross-version interoperability, installer failure and public upgrade tests; document inherited file/entry/state limits.
- Refresh TLS/trust-store dependencies and embedded notices; document the remaining unselected crypto-bigint advisory without suppressing it.
- Publish a checksum-verified copy-and-paste installation command at the top of the README.

## Unreleased

- Corrected the password-generation command to `ssync pwd`.
- Made preservation of the efficient 200,000-byte block comparison/changed-block transfer method a required release gate, including bandwidth measurements.
- Specified explicit mutual password/key confirmation before any file metadata or transfer-root access; expanded negative authentication tests.
- Added reproducible rootless two-peer Podman lab tooling and a feature, encryption, failure, efficiency, and file-safety test matrix. Lab isolation/connectivity is tested; native feature tests await implementation.

- Accepted a 16-character supplied-password minimum and 24 uniformly random Base58 characters displayed in six groups of four for generated passwords, without automatic expiry.
- Specified `ssync pwd` to print one generated password and a newline without labels or transfer side effects.
- Recorded readiness to begin implementation; authentication construction selection remains an initial engineering gate.

- Confirmed the Java wire-compatibility break while preserving CLI/configuration and transfer workflows as an API.
- Revised authentication planning for reusable passwords with no automatic expiry, denser unbiased Base58 generation, proposed minimum length/weak-password checks, and a password-only PAKE/channel evaluation.
- Removed mandatory pairing tickets and expiry-based release gates; recorded command/default compatibility decisions and long-running/repeated-sync verification requirements.

- Added the file-transfer-only implementation plan, excluding script/command execution and assessing password generation, existing throttling, stronger authentication, and the tradeoff of dropping Java compatibility.
- Updated the project objective to distinguish confirmed file-only requirements from the proposed new protocol and authentication design.

- Imported the supplied Java interoperability kit unchanged, including the missing JWrapper sources, bundled Java reference/dependencies, wire notes, vectors, and verification harness.
- Verified all 743 kit manifest hashes and confirmed its source includes the 70 original snapshot files unchanged.
- Verified supplied and source-rebuilt Java references on Linux, all four Java/Java transfer pairings, crypto/authentication self-tests, and byte-for-byte regeneration of all 35 fixture files.
- Updated the compatibility assessment and file map to record the resolved dependency gap and remaining native-port validation work.
- Imported the supplied Java SSync codebase as an unchanged reference for a native compatibility port.
- Initialized the separate SSync project and local review notes.
- Added project README, development file map, and initial native-port assessment.
- Verified the extraction against all ZIP entries and the 70 supplied SHA-256 manifest entries.

## 4.0.0 — 2026-10-13

- Freeze native 4.0 command contract, file-only operations, persistent passwords and fixed 200,000-byte delta transfers.
- Exclude proprietary Java/reference imports from public Git while preserving local review copies.
- Add Rust package and begin authenticated-channel validation before transfer implementation.
- Implement CLI parsing/guidance, OPAQUE/Argon2id and Noise confirmation, Linux directory-relative file safety, fixed-block deltas/resume and atomic per-file commit.
- Add persistent listeners/connectors, scoped mirroring/filter/dry-run behavior, diagnostics, declarative concurrent configuration and native install/update/uninstall.
- Add actual two-peer application/security/lifecycle/management runners and a test-only authenticated adversarial peer.
- Measure zero-content identical repeats, 200,000-byte single-block deltas, verified interruption resume and scoped deletion.
- Harden wall-clock handshake deadlines and process-wide expensive-authentication concurrency, manifest/state quotas, IPv6 listening and continuous reconnect.
- Make ownership metadata part of the atomically installed executable; fix stale test-result reuse and update vulnerable transitive time dependency.
- Add genuine receiver comparison/data overlap using bounded lookahead and positional reads; keep dry-run reuse counters truthful.
- Preserve supported source file mtimes and reject unsupported/clamped timestamps, unsafe/casefold filesystems and untrusted config ownership.
- Keep frequent valid credential reuse outside failed-guess budgets, configure dual-stack listening explicitly, and preserve numeric/diagnostic command compatibility.
- Embed public Rust dependency notices with a local `licenses` command; retain private references outside public Git history.
- Extend tests with SIGTERM/SIGKILL, deep/control-named files, destination links, rotation, quota boundaries and multi-GiB/high-offset transfers.

- Complete97 recorded rootless-Podman checks against the exact release artifact, including2.4GB sparse-source/high-offset deltas and a121.85-second progressing transfer.
- Verify Rust1.88 minimum compatibility, zero dependency advisories, embedded notices, static release archives/checksums and isolated archive install/uninstall.
- Publish the public repository and v4.0.0 release from verified source commit decf099c73ee1df6424f35b87e7ca767853b1236 with all six prepared assets.
- Verify every downloaded release asset and run public checksum/download, native install, real GitHub up-to-date check and uninstall in the isolated Podman peer.
- Add public download/checksum commands and update validation records to reflect completed delivery.
