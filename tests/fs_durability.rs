//! Run ignored probes under strace fsync fault injection; see SECURITY_REVIEW.md.
use ssync::fs::{Root, identity};

#[test]
#[ignore = "requires first fsync to fail via strace fault injection"]
fn directory_create_propagates_sync_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = Root::new(temp.path()).unwrap();
    assert!(
        root.mkdirs("empty").is_err(),
        "mkdir durability error was hidden"
    );
    assert!(temp.path().join("empty").is_dir());
}

#[test]
#[ignore = "requires first fsync to fail via strace fault injection"]
fn deletion_propagates_sync_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = Root::new(temp.path()).unwrap();
    std::fs::write(temp.path().join("old"), b"old").unwrap();
    let expected = identity(&root.metadata("old").unwrap().unwrap());
    assert!(
        root.remove("old", &expected).is_err(),
        "unlink durability error was hidden"
    );
    assert!(!temp.path().join("old").exists());
}
