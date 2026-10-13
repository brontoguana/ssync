# SSync development file map

- `README.md` — native usage, passwords, installation, platform scope and verification entrypoints.
- `docs/CONTRACT.md` — frozen 4.0 CLI/configuration API and intentional Java migration differences.
- `docs/PROTOCOL.md` — OPAQUE/Noise construction, authenticated transfer state machine, threat model and limits.
- `docs/VALIDATION.md` — concrete test evidence, efficiency, platform scope and completed public release verification.
- `IMPLEMENTATION_PLAN.md` — accepted requirements and historical implementation sequence; final contract is in docs/CONTRACT.md.
- `PORT_REVIEW.md` — original source assessment and Java reference verification history.
- `Cargo.toml` / `Cargo.lock` — Rust 4.0.0 package, minimum toolchain and pinned dependencies.
- `src/main.rs` / `src/lib.rs` — executable dispatch and native library modules.
- `src/cli.rs` — qualifiers, Java-compatible aliases, password inputs, guidance and local-only commands.
- `src/auth.rs` — unbiased Base58 generation, OPAQUE/Argon2id, Noise confirmation and bounded framing.
- `src/fs.rs` — Linux openat2 capabilities, directory/FS checks, no-follow single-link files, private partials and atomic replacement.
- `src/transfer.rs` — fixed 200,000-byte pipeline, overlapped comparison/streaming, verified resume, layouts, filters and verified-state deletion.
- `src/runtime.rs` — listening/connecting independently of data direction, persistent operation, bounded admission/concurrency, cancellation and config workers.
- `src/management.rs` — native local install/update/uninstall and ownership attached atomically to the executable.
- `tests/parsers.rs` — 20,000 seeded parser mutations and path-contract boundary tests.
- `tests/TEST_MATRIX.md` — required feature/security gate inventory and disposition references.
- `tests/podman/lab.py` / `tests/podman/README.md` — labelled rootless two-peer lifecycle, small/large profiles and procedures.
- `tests/podman/application.py` — actual transfers, layouts and measured delta cases.
- `tests/podman/security.py` / `tests/podman/proxy.py` — wrong-password, replay/tamper, metadata rejection, resume and scoped deletion tests.
- `tests/podman/lifecycle.py` — continuous/concurrent operations, mutation, races, disk-full and cancellation.
- `tests/podman/inputs.py` — PTY/password inputs, exact command pairs, config concurrency, throttling and IPv6.
- `tests/podman/advanced.py` — many/deep/control-named files, link targets, rotation, quotas, insertion and killed/tampered resume.
- `tests/podman/management.py` — disposable release-server fixture and atomic native management failure tests.
- `tests/podman/large.py` — bounded multi-GiB profile, high-offset deltas and root-owned default installation.
- `examples/adversary.rs` — test-only authenticated malicious peer; excluded from release archives.
- `scripts/notices.py` / `THIRD_PARTY_NOTICES.txt` / `LICENSE` — public dependency provenance/notices embedded in the binary and distributed with archives.
- `CHANGELOG.md` — tracked changes.
- `.gitignore` — prevents private references, logs and generated artifacts entering public history.
- `TRACKING.md` / `DEBUGLOG.md` — ignored recent analysis and raw run evidence.

Local private references, not published or needed for native builds:

- `ssync-codebase/sh-additional/Tools/src/main/java/com/shelp/ssync/SSync.java` — Java 3.3 CLI/alias/layout reference.
- `ssync-codebase/simplehelp_new/Utils_ExtendedCore/src/main/java/utils/files/FileMirror.java` — original 200,000-byte transfer/deletion/mtime behavior.
- `ssync-interop-kit/README.md` / `ssync-interop-kit/verify.py` — runnable Java behavior oracle for any further migration questions.
- `scripts/build-release.py` — versioned static Linux assets, source archive, dependency notices, source-commit manifest and SHA-256 checksums from committed source.
- `tests/podman/longrun.py` — encrypted progressing transfer beyond socket idle deadline, with deterministic byte-rate proxy delay.
- `tests/podman/public_smoke.py` — post-publication integrity/native install/update/uninstall smoke in the existing disposable peer, with scoped temporary egress and cleanup.
