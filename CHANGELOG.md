# Changelog

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

## 4.0.0 — in development

- Freeze native 4.0 command contract, file-only operations, persistent passwords and fixed 200,000-byte delta transfers.
- Exclude proprietary Java/reference imports from public Git while preserving local review copies.
- Add Rust package and begin authenticated-channel validation before transfer implementation.
- Implement CLI parsing/guidance, OPAQUE/Argon2id and Noise confirmation, Linux directory-relative file safety, fixed-block deltas/resume and atomic per-file commit.
- Add persistent listeners/connectors, scoped mirroring/filter/dry-run behavior, diagnostics, declarative concurrent configuration and native install/update/uninstall.
- Add actual two-peer application/security/lifecycle/management runners and a test-only authenticated adversarial peer.
- Measure zero-content identical repeats, 200,000-byte single-block deltas, verified interruption resume and scoped deletion.
- Harden wall-clock handshake deadlines and process-wide expensive-authentication concurrency, manifest/state quotas, IPv6 listening and continuous reconnect.
- Make ownership metadata part of the atomically installed executable; fix stale test-result reuse and update vulnerable transitive time dependency.
