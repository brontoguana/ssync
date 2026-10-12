# SSync4.0.0 validation and delivery status

**Native implementation and local release preparation are complete. Publication is blocked.** GitHub CLI rejects the configured credentials (HTTP401), including repository creation. No public repository/push/release is claimed. Public installation/update smoke is prepared in `tests/podman/public_smoke.py` and cannot run until publication succeeds. User authentication restoration was requested; no token is stored in this project.

## Implementation/API

Native Rust executable, no separately installed Java/Python/shell runtime. Version4.0.0 replaces Java3.3. Preserved `put/get/offer/accept`, TCP direction independence, Java UTF-16 alias mapping, ordinary numeric ports, env/inline/password-prompt precedence, `.ssync` quoted concurrent transfer lists, qualifiers, default/merge layouts, scoped mirroring and diagnostics/guidance. Added `pwd`, safe password-file/descriptor inputs and local native install/update/uninstall; local `licenses` exposes embedded public dependency notices.

Intentional differences are in CONTRACT.md: incompatible wire, minimum16 Unicode characters/4096 bytes, 24 uniform Base58 generated characters in six groups of four, no expiry, no execution features, stricter roots/types/links/permissions/config, modern hashes and truthful failures. `nodelete` on either peer narrows deletion. Missing receiver roots and file/directory type conflicts fail safely. Changed/new files preserve supported source mtimes; fully matching files keep existing timestamps.

## Security

OPAQUE4.0.1, Ristretto255/TripleDH/SHA512 with fixed Argon2id64MiB/3passes/1lane. HKDF feeds fresh NoiseNNpsk0_25519_ChaChaPoly_SHA256 sessions, with explicit mutual confirmation before roots/metadata. Source hashing and receiver range comparisons overlap current streaming through bounded queues. BLAKE3 range/final verification, credential/root/file-bound private resume, atomic individual-file replacement, locked receiver roots, no-follow openat2 capabilities and complete-verified-state deletion. Per-IP/listener guessing budgets, bounded state/concurrency/frames and15s handshake deadline; no credential expiry. Details/limitations in PROTOCOL.md.

Native installation attaches ownership to the staged executable before one atomic rename. Update downloads exact GitHub release assets and checks SHA256 over HTTPS; failed checks/downloads preserve old bytes. Uninstall verifies ownership/hash and leaves transfer/unrelated data. Checksums from the same release do not independently authenticate the publisher; account/release compromise remains a trust risk. Neither SSync integration nor the current full dependency set is claimed independently audited.

## Executed evidence

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

## Artifact/platform scope and remaining delivery gate

Verified release binary SHA256: `bfdf24deeb11dcb2a1c09685df1f2f7034725f25f596420d22c8d491747d6d83` (5,424,032bytes). Platform **Linux x86_64 only**, kernel5.6+/procfs/case-sensitive local filesystem. Native developer filesystem tests run on Btrfs; transfer/system-install tests use tmpfs. Other allowed FS combinations, real casefold image setup, native macOS/Windows/ARM, and files above2.4GB are not claimed tested. Network/FUSE/pseudo/casefold filesystems are unsupported and rejected. Same-identity/privileged endpoint compromise and arbitrary noncooperating OS races are outside remote-peer isolation; advisory locks are not a filesystem transaction. Per-file atomicity only; successful earlier files/directories persist when a later operation fails. Private abandoned state remains bounded and may need operator cleanup.

The matrix is a required-case inventory, not proof of every possible OS/fault combination. Live OS-random-failure injection and each filesystem/driver race permutation were not executed; unbiased sampling/error handling and unsupported-operation paths are source/unit-reviewed. No unsupported-platform claim is inferred from Linux container passes.

Private Java/reference sources/JARs remain on disk, ignored and absent from Git/source archives. Public dependency notices are embedded/distributed. Prepared assets:static raw Linux binary, versioned archive, public-source archive, notices, source-commit manifest andchecksums. Formatting/lint/unit/parser/dependency/API/security/efficiency/management gates passed locally. Required public repository/push/release and real public update smoke remain **blocked by GitHub authentication**, so the complete end-to-end delivery request is not declared finished.
