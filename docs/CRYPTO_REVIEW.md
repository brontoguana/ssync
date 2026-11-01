# SSync 4.1.1 cryptographic integration review

Reviewed 2026-10-31/2026-11-01, starting from `72e513a`. Scope: application authentication and record code, backup candidate selection, admission/cancellation callers, credential inputs and resume-key use, and the locked upstream implementations selected by these paths. This is a source review with adversarial tests by the implementing agent. It is **not an independent audit, formal proof, or certification** of this composite protocol.

## Findings and changes

| Finding | Consequence | Change |
|---|---|---|
| OPAQUE registration/login result objects expose export/session key arrays without automatically wiping those result fields. The client retained them while reading later bay candidates or writing KE3; failures could drop them unwiped. | Memory hygiene weakness; no demonstrated remote disclosure. | Explicitly wipe unused export keys, copy session keys immediately into a zeroizing guard and wipe their original result fields before subsequent fallible I/O. Guarded keys are wiped on all subsequent returns. |
| A caller could reuse a `Channel` after a failed encrypted read/write or malformed decoded message. Existing production callers propagated these errors and dropped the channel. | Defense in depth: future recovery code must not continue on a damaged authenticated byte stream. No demonstrated production authentication bypass. | Permanently poison and shut down both socket directions on encrypted framing, AEAD, decoded-message or I/O error. Retries require a new authenticated connection. |

The fixed suites, key derivation bytes, ordinary/backup magic and command/password conventions are unchanged. This release also includes all filesystem and admission fixes from [the broader security review](SECURITY_REVIEW.md).

## Construction reviewed

- **Password generation:** OS CSPRNG, rejection of bytes 232..255, then modulo 58. Each alphabet symbol has exactly four accepted preimages. Twenty-four random characters provide approximately 140.6 bits before formatting; separators add no entropy. Supplied passwords remain at least 16 Unicode characters, at most 4096 UTF-8 bytes, with exact case/separator/Unicode preservation. Length does not prove a human-chosen password strong.
- **OPAQUE:** `opaque-ke` 4.0.1, Ristretto255 OPRF and TripleDH/Ristretto255/SHA-512. Local-only registration uses fresh server setup, the same credential identifier at registration/login, default public-key-derived identities, and fixed Argon2id v0x13, 64 MiB/3 passes/1 lane. No peer-selected KSF or algorithm negotiation. Client finish verifies the server MAC; server finish checks the client MAC using the upstream constant-time comparison. Invalid/identity Ristretto encodings are rejected by the upstream deserializer. The application does not implement group arithmetic or proof verification.
- **Binding:** the OPAQUE context includes the fixed suite/version label and connector data role; backup adds a separate upload label. Opposite roles and protocol magic are checked before login. The authenticated backup selection index is added to the HKDF salt and Noise prologue. Defaults deliberately authenticate a password holder; no separate hostname/certificate identity or persistent server-key pin is claimed.
- **Composition:** the fresh OPAQUE session key, never the raw password/export key, enters HKDF-SHA256 with the context as salt and `SSync-4 Noise PAKE session PSK` as the expand label. Its 32-byte output enters `Noise_NNpsk0_25519_ChaChaPoly_SHA256`. Fresh OS-generated ephemeral keys, the prologue, distinct confirmation payloads and encrypted ready exchange bind the resulting channel. HKDF-Extract accepts public salts; this use does not require a secret or random salt. Source review and tests support this composition; they do not supply a reduction proving the custom composite protocol secure.
- **Before transfer:** successful key confirmation is required before a caller enters the transfer engine. No 0-RTT, remote registration, restore/management dispatch or peer-selected filesystem root. A final acknowledgement lost or altered in transit cannot give both sides simultaneous knowledge of completion: one already authenticated side can enter its engine before the other rejects that last acknowledgement. Subsequent metadata is still encrypted, and no unauthenticated participant gains access.
- **Transport:** Snow maintains separate directional keys and implicit ordered nonces; the application never resets nonces or installs transport keys manually. Upstream refuses the exhausted nonce instead of wrapping it. AEAD tags authenticate plaintext lengths inside records. Outer lengths are untrusted and bounded before allocation; logical messages are bounded at 1 MiB and ciphertext records at 60,016 bytes. Record failures now close the channel permanently. Connections receive fresh keys; there is no key reuse for resume.
- **Resource controls:** 15-second ordinary/60-second backup wall-clock authentication watchdogs, bounded handshake frames, fixed KSF costs and four process-wide expensive-authentication permits. Listener concurrency, per-IP/listener attempt budgets and bounded expiring address state apply independently of cryptography. Watchdogs close the socket at the deadline; synchronous KSF work already in progress is not preempted and must return before its worker exits. These are availability controls, not a flooding guarantee or persistent lockout.
- **File integrity/resume:** unkeyed BLAKE3 file/block digests travel inside the authenticated channel. Credential/root/file identity selects private resume state; every reused range and final reconstructed file is rehashed. Resume does not serialize or restore a Noise session/nonce. Content comparison still reveals guessed-content matches to an authenticated sender.

References checked against the locked source: [OPAQUE API and usage](https://docs.rs/opaque-ke/4.0.1/opaque_ke/), [upstream TripleDH](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/key_exchange/tripledh.rs), [HKDF RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), [Noise specification, PSK/prologue/nonce rules](https://noiseprotocol.org/noise.html), and [Snow 0.10.0 source](https://docs.rs/crate/snow/0.10.0/source/src/). This is implementation inspection, not a claim of general RFC conformance beyond the library's own supported protocol/version.

## Multi-bay wrapper and remaining risks

The backup wrapper tries at most 32 independently registered KE2 candidates against a cloned local KE1 state. The library's OPRF blinding/ephemeral login state is confined to this one bounded composite login; no state is persisted or shared between connections. A matching KE2 supplies the server proof; its KE3 must verify at the corresponding listener state, and the selected index must agree in the subsequent PSK/prologue. Swapping intact candidates or altering the selected index fails confirmation. The complete candidate list/count is **not** an authenticated directory manifest; changes to unused candidates can cause availability failures and are not claimed detectable in all cases.

The wrapper amplifies online guessing in both directions: a guessing client can test one password against up to 32 configured bays per attempt; a rogue backup listener can supply up to 32 password guesses as candidates to one connecting client. These are interactive attempts involving the client, not a demonstrated offline verifier from a passive capture. The per-connection cap and random generated passwords matter; this review is not a formal proof of multi-candidate OPAQUE security. Eliminating this amplification while keeping password-selected bays would require a different routing/authentication construction. No unauthenticated bypass or passive offline-password verifier was found in this bounded inspection/testing.

Other material limits:

- OPAQUE and Noise provide no post-quantum claim. The selected elliptic-curve groups set a conventional roughly 128-bit classical security ceiling; a 256-bit derived key does not change that ceiling.
- Server configs hold reusable plaintext passwords. Any server sharing a password belongs to its trust group and can impersonate a password holder. An attacker controlling an endpoint can read data/credentials, alter the program, or disable reporting. Native bays are not encrypted at rest and have no history.
- **Memory wiping is partial.** Application result fields and guarded buffers are improved; compiler/register/stack copies and all upstream HKDF/Snow/Argon2 internals are not guaranteed erased. In particular, Snow's default resolver key arrays do not implement a wiping destructor. No memory-compromise or core-dump secrecy guarantee is made.
- Record length, timing, addresses, public transfer roles, bay count and selected index leak. An authenticated uploader retains the [documented content-comparison oracle](SECURITY_REVIEW.md). AEAD protects integrity/confidentiality, not endpoint authorization policy or data availability.
- `cargo audit` still reports [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) for transitive `crypto-bigint` 0.5.5. Source tracing of this fixed Ristretto suite finds secret scalar/point operations in `curve25519-dalek`, while `elliptic-curve::hash2curve` supplies digest expansion. The advisory's affected bigint secret arithmetic was not found on these selected paths. This is a reachability assessment, not a patched dependency or a formal guarantee; the advisory remains unsuppressed. No prerelease cryptographic dependency or local fork is introduced to hide it.
- A separate human cryptographic review remains advisable, especially for the multi-candidate wrapper and PAKE-to-Noise composition.

## Reproducible validation

New native cases in `src/auth_tests.rs` exercise exact record-size boundaries (including empty and 1 MiB logical messages), directional key separation, corrupted/short tags, invalid outer/inner lengths, missing message lengths, empty/excess continuations, truncation, permanent closure, malformed JSON, replay/reordering/reflection/cross-session rejection, nonce exhaustion, OPAQUE context mismatch, and a derivation known-answer independently calculated with Python's HMAC/SHA256. These test the application integration, not cryptographic strength by statistical sampling.

`tests/podman/crypto.py` faults each of seven real handshake stages (KE1/KE2/KE3, both Noise messages, both encrypted ready records), checks role reflection, all-zero OPAQUE messages and oversized lengths, and adds invalid backup counts, intact KE2 swaps and selected-index substitution. It asserts nonzero client results, unchanged bay contents, listener survival and successful ordinary/backup baselines afterward. A separate positive case confirms that tampering with an unused candidate need not fail a valid selected login; no whole-list authentication claim is made. Only synthetic data/credentials and the existing labelled rootless peers are used.

Commands:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo +1.88.0 check --locked --all-targets
# Build the static application and adversarial helper using the documented lab toolchain.
python3 tests/podman/crypto.py
# Then run the ordinary application/security/lifecycle/inputs/advanced/review/backup,
# management/bootstrap/compatibility/large/longrun release suites.
```

Final counts, binary identity, completed release matrix and public upgrade evidence are recorded in [VALIDATION.md](VALIDATION.md). Raw commands/logs remain ignored in `DEBUGLOG.md` and `target/crypto-audit-*`. The exact-tag upstream `opaque-ke` v4.0.1 library/vector suite was rerun: **84 passed**. That dependency test result is separate from application coverage and does not audit the composition.
