# Native-port assessment

Reviewed 2026-10-12. Source inspection, Java source rebuild, deterministic-vector regeneration, and Java/Java transfer verification completed on Linux. No native implementation or Java/native interoperability run has been performed.

## Recommendation

Rust is a good fit for a standalone file-transfer executable. Go is also viable and would align with VMRelay; its runtime can be included in the binary rather than installed separately. Ordinary Python deployment requires an interpreter, so it does not directly meet the requested deployment model.

An exact CLI and wire-compatible replacement is feasible, but this remains a medium-to-high complexity compatibility project rather than a small command rewrite. The supplementary interop kit resolves the earlier dependency gap and provides a working oracle for implementing and verifying a Rust port.

## What the supplied application does

- Reports application version 3.3 and requires exact wire magic for protocol 6 when establishing connections.
- Supports `put` and `get` once, and `offer` and `accept` continuously. `put`/`get` can either connect outward or listen for a single peer; transfer direction and TCP connection direction are independent.
- Uses numeric ports or aliases derived from Java String.hashCode, including Java UTF-16 and signed overflow semantics.
- Accepts passwords from `SSYNC_PASSWORD`, legacy `password@location`, interactive prompts, or generated listener passwords. The environment variable takes precedence.
- Supports `merge`, `nodelete`, `dryrun`, `verify`, `verbose`, `force`/`noprompt`, and substring `skip:` filters. Also has `hash`, `deep`, `scan`, `version`, `install`, interactive `?`, and concurrent command lists in `.ssync` files.
- Uses a custom SRP-6a construction with a 2048-bit group and SHA-256; its password hashing and proof formulas must match the source rather than assuming a generic library configuration is identical. The sender (`put`/`offer`) is the SRP server even when it initiated TCP.
- Derives separate directional AES key/IV material from SHA-512 of the session key, then uses BCUtil streams for encrypted framing.
- FileMirror exchanges metadata and file data concurrently. It compares MD5 hashes of fixed 200,000-byte chunks and transfers mismatching chunks; this is not rsync's rolling-checksum algorithm.
- Supports deletion, file truncation, last-modified times, multiple sources, and directory creation. Source traversal skips symlinks; received paths are checked against the destination boundary.
- Contains script-hook code, but `SCRIPTS_ENABLED` defaults to false and no enabling assignment was found. Notification helpers also exist, but their presence does not establish active transfer notifications.

## Dependency gap resolved

The initial archive omitted `BCUtilJW`, inherited serializers, and StringChunker. The supplementary kit supplies their original sources, including `AbstractBCUtil`, AES counter handling, MAC selection, primitive/variable serializers, and `.ssync` tokenization. It also supplies the runnable reference, dependency JARs, an offline source-overlay build, golden vectors, and an optional native-peer verification runner.

The now-visible details matter for a compatible port: booleans are `EE`/`FF`; variable integers use a byte-count followed by big-endian bytes, not LEB128; encrypted records transmit their AES counter and encrypt an inner MAC/length/payload/padding buffer. Default MAC is HMAC-SHA-256, with a legacy shortened-SHA-512 HMAC also supported by the original decoder. Preserve role-dependent keys independently of TCP connection direction. Use the original source as authoritative and `ssync-interop-kit/WIRE-NOTES.md` as its guide.

Local verification on Linux/OpenJDK 21.0.12.1:

- Supplied reference reports `SSync v3.3` and passes the encryption/SRP self-test: both directions, padding boundaries, independent JCE AES-CTR/HMAC checks, tamper rejection, 200,000-byte records, a 500,000-byte multi-record stream, password success/rejection.
- All four Java/Java `offer/get` and `accept/put` test pairings pass file-set/SHA-256 comparison, empty files/directories, Unicode filenames, and a 512,000-byte file.
- All 35 regenerated fixture files match the supplied vectors byte-for-byte.
- `build.py` compiles the original source overlay for Java 17 using only bundled dependencies; the rebuilt reference reports version 3.3 and passes the same self-test and all four transfer cases. Compilation has original deprecation/unchecked warnings.
- Tests run in an ignored copy under `target/interop-review/`; imported artifacts remain unchanged. Raw local evidence is in ignored `DEBUGLOG.md`.

This establishes an operational Java reference, not native compatibility. Delta updates, deletion, merge/filter semantics, CLI aliases/configuration, disconnect/error handling, older-MAC peers, and macOS/Windows behavior still require port-specific tests. The kit is a source-built reference and does not establish which build any production host runs.

## Findings to resolve when specifying exactness

- `isSsyncMagic` and `getProtocolVersion` subtract the protocol remainder and compare the result with `SSYNC_MAGIC`, which already includes version 6. This appears to misclassify modern SSync magic in mismatch diagnostics; normal connection checks compare the exact magic directly.
- SSync waits for FileMirror completion but does not call its `checkForFailures()` method. Worker failures may consequently be logged without making a one-shot command fail.
- `verify` prints a hash of the current working directory; it does not exchange and compare sender/receiver hashes.
- The `.ssync` runner catches per-command exceptions and exits with status zero after joining its threads.

These are source observations, not reproduced defects. Preserve the documented CLI and protocol contract; explicitly decide how to treat observable error-handling quirks rather than accidentally copying them or silently changing them. Do not modify the imported reference during this review.

## Suggested implementation sequence

1. Define the complete CLI/behavior contract using the now-available source and working Java oracle.
2. Use the supplied primitive/encryption vectors and add golden vectors for aliases (including Unicode), SRP proofs, legacy-MAC behavior, and directory hashes.
3. Implement Rust modules for CLI/config, protocol codecs, authentication/framing, mirror engine, and server lifecycle.
4. Test Java-to-Rust and Rust-to-Java in both transfer and connection directions: fresh and incremental transfers, empty/large files, truncation, merge/deletion/skip filters, wrong passwords, disconnects, and destination containment.
5. Add platform builds, installer, release checksums, and the separate public repository workflow.

No runnable replacement exists yet. Initial project setup is complete; public repository creation and implementation remain future work.

## Import validation

All 72 ZIP entries were checked byte-for-byte after extraction. All 70 supplied manifest hashes passed. The snapshot contains 60 Java files (12,491 lines); SSync.java has 1,490 lines and FileMirror.java has 1,236. Supporting modules account for much of the remaining code and need not all be ported.

The supplementary kit has 744 entries; extraction matched every entry byte-for-byte and all 743 supplied manifest hashes passed. All 70 original snapshot source/POM/script files also match their counterparts under the kit's `sources/` exactly. Archive SHA-256: `364cbde6a45f94b260b36a3c5d0346260e9a58a1a83f152d7b6ae41fbf7b3115`.

## Updated scope — 2026-10-12

The user requires a strict file-transfer-only executable with no script or command execution. Java wire compatibility is now explicitly dropped; CLI/configuration and actual transfer usage must largely remain the same and are treated as an API. Passwords must support long-running/repeated syncs without automatic expiry. See `IMPLEMENTATION_PLAN.md` for the revised Base58/password policy recommendations, password-only PAKE/channel evaluation, filesystem restrictions, brute-force controls, and staged delivery. The source assessment above remains a historical record of the exact-wire-port option; its Java/native compatibility gates do not override this scope.
