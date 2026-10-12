# SSync

Standalone native file-transfer tool based on the supplied Java SSync. Script execution is excluded. Java wire compatibility is dropped. CLI syntax, configuration, and transfer workflows remain an API and will largely stay the same. Reusable passwords will not expire automatically. Supplied passwords must have at least 16 characters. Generated passwords use 24 random Base58 characters displayed in six groups of four; `ssync pwd` will print one generated password.

Status: complete Java interoperability kit imported, source-rebuilt, and verified on Linux. Native implementation has not started. A two-peer rootless Podman test lab is prepared and its connectivity/isolation smoke is verified.

The original unchanged attachment is extracted in `ssync-codebase/`, retaining its original workspace layout. The supplementary `ssync-interop-kit/` supplies the missing JWrapper sources, a runnable reference JAR, bundled dependencies, wire notes, deterministic vectors, and a Java/native interoperability runner. Both references target SSync version 3.3 and wire protocol version 6; all 70 original snapshot files are included unchanged in the kit.

The earlier dependency blocker is resolved. The supplied and locally rebuilt references pass the kit's encryption/SRP self-tests and all four complete Java/Java transfer cases on Linux. The Java reference informs CLI and behavior tests; Java/native wire interoperability is no longer a requirement.

See `ssync-interop-kit/README.md` for reference commands. Keep the imported kit unchanged: copy it under ignored `target/` before running its build or verification scripts, which overwrite the reference JAR and verification logs. Java 17+ is needed for reference tests, and a JDK is needed for rebuilding; these are development dependencies of the Java reference.

The native tool must retain the fixed 200,000-byte changed-block transfer approach, with stronger content validation and explicit mutual password confirmation before file access. See `tests/podman/README.md` for the disposable lab and `tests/TEST_MATRIX.md` for the planned feature/security release tests.

See `IMPLEMENTATION_PLAN.md` for the current file-only design proposal, `PORT_REVIEW.md` for the initial compatibility assessment, and `FILE_MAP.md` for the development map.

Proposed implementation language: Rust, producing platform-specific executables without requiring Java or a Python interpreter. This remains an implementation recommendation.

Development records: `CHANGELOG.md` is tracked; `TRACKING.md` and `DEBUGLOG.md` are local and ignored. Git is initialized locally on `main`; no remote repository or release has been created.
