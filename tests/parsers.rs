//! Bounded deterministic parser fuzzing: no networking or transfer-root access.
use rand::{RngCore, SeedableRng, rngs::StdRng};
use ssync::{cli, fs, transfer::Message};
#[test]
fn bounded_mutated_protocol_and_cli_inputs() {
    let mut random = StdRng::seed_from_u64(0x5353594e4334);
    let seed=br#"{"type":"File","path":"source/file","size":200000,"modified_secs":1,"modified_nanos":0,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    for i in 0..20_000 {
        let mut bytes = if i % 2 == 0 {
            seed.to_vec()
        } else {
            vec![0; (random.next_u32() % 1024) as usize]
        };
        if i % 2 == 0 {
            let n = (random.next_u32() as usize) % bytes.len();
            bytes[n] = random.next_u32() as u8;
        } else {
            random.fill_bytes(&mut bytes);
        }
        let _ = serde_json::from_slice::<Message>(&bytes);
        let text = String::from_utf8_lossy(&bytes).to_string();
        let _ = cli::parse(
            &["force".into(), "put".into(), text.clone(), ".".into()],
            Some("abcdefghijklmnop"),
        );
        let _ = fs::valid(&text);
        let _ = shell_words::split(&text);
    }
    assert!(serde_json::from_slice::<Message>(&vec![b'['; 1000]).is_err());
    assert!(serde_json::from_str::<Message>(r#"{"type":"Execute","command":"true"}"#).is_err());
    assert!(serde_json::from_str::<Message>(r#"{"type":"Ack","extra":1}"#).is_err());
}
#[test]
fn path_contract_and_large_inputs() {
    for p in [
        "",
        "/absolute",
        "../parent",
        "x/../parent",
        "x//y",
        "x/./y",
        "x\\y",
        "x\0y",
        ".ssync-state/x",
    ] {
        assert!(fs::valid(p).is_err(), "{p:?}");
    }
    assert!(fs::valid(&"x/".repeat(65)).is_err());
    assert!(fs::valid(&"x".repeat(4097)).is_err());
    for p in [
        "é/你好",
        "space name/-leading",
        "new\nline",
        "literal;$(data)",
    ] {
        assert!(fs::valid(p).is_ok(), "{p:?}");
    }
}
