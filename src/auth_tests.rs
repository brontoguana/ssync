//! Adversarial authenticated records, independent of the filesystem engine.
use super::*;
use std::net::TcpListener;

fn pair() -> (Channel, TcpStream, snow::TransportState) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let other = listener.accept().unwrap().0;
    for s in [&socket, &other] {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    }
    let build = || {
        snow::Builder::new("Noise_NNpsk0_25519_ChaChaPoly_SHA256".parse().unwrap())
            .psk(0, &[7; 32])
            .unwrap()
            .prologue(b"test-only")
            .unwrap()
    };
    let mut a = build().build_responder().unwrap();
    let mut b = build().build_initiator().unwrap();
    let mut msg = [0; 256];
    let mut plain = [0; 256];
    let n = b.write_message(b"connector-confirm", &mut msg).unwrap();
    a.read_message(&msg[..n], &mut plain).unwrap();
    let n = a.write_message(b"listener-confirm", &mut msg).unwrap();
    b.read_message(&msg[..n], &mut plain).unwrap();
    (
        Channel {
            socket,
            noise: a.into_transport_mode().unwrap(),
            failed: false,
            wire_sent: 0,
            wire_received: 0,
        },
        other,
        b.into_transport_mode().unwrap(),
    )
}

fn encrypt(noise: &mut snow::TransportState, plain: &[u8]) -> Vec<u8> {
    let mut out = vec![0; plain.len() + 16];
    let n = noise.write_message(plain, &mut out).unwrap();
    out.truncate(n);
    out
}

fn closed(channel: &mut Channel) {
    assert!(channel.failed);
    assert!(channel.send_bytes(b"must not send").is_err());
    assert!(channel.recv_bytes().is_err());
}

#[test]
fn transport_boundaries_and_bidirectional_keys() {
    for len in [0, 1, RECORD - 4, RECORD - 3, RECORD, FRAME_LIMIT] {
        let (mut a, socket, noise) = pair();
        let worker = std::thread::spawn(move || {
            let mut b = Channel {
                socket,
                noise,
                failed: false,
                wire_sent: 0,
                wire_received: 0,
            };
            b.send_bytes(&vec![42; len]).unwrap();
            assert_eq!(b.recv_bytes().unwrap(), b"ack");
        });
        assert_eq!(a.recv_bytes().unwrap(), vec![42; len]);
        a.send_bytes(b"ack").unwrap();
        worker.join().unwrap();
    }
}

#[test]
fn malformed_authenticated_records_close_channel() {
    for case in 0..9 {
        let (mut channel, mut socket, mut noise) = pair();
        match case {
            0 => socket.write_all(&0u32.to_be_bytes()).unwrap(),
            1 => socket
                .write_all(&((RECORD + 17) as u32).to_be_bytes())
                .unwrap(),
            2 => send_raw(&mut socket, &[0; 15]).unwrap(),
            3 => {
                let mut record = encrypt(&mut noise, &[0, 0, 0, 1, 42]);
                *record.last_mut().unwrap() ^= 1;
                send_raw(&mut socket, &record).unwrap();
            }
            4 => {
                let record = encrypt(&mut noise, &[0, 0, 0]);
                send_raw(&mut socket, &record).unwrap();
            }
            5 => {
                let record = encrypt(&mut noise, &((FRAME_LIMIT + 1) as u32).to_be_bytes());
                send_raw(&mut socket, &record).unwrap();
            }
            6 => {
                let record = encrypt(&mut noise, &[0, 0, 0, 0, 42]);
                send_raw(&mut socket, &record).unwrap();
            }
            7 | 8 => {
                let first = encrypt(&mut noise, &[0, 0, 0, 1]);
                send_raw(&mut socket, &first).unwrap();
                let next = encrypt(&mut noise, if case == 7 { b"" } else { b"xx" });
                send_raw(&mut socket, &next).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(channel.recv_bytes().is_err(), "case {case}");
        closed(&mut channel);
    }
}

#[test]
fn truncated_record_and_oversized_send_close_channel() {
    let (mut channel, mut socket, _) = pair();
    socket.write_all(&32u32.to_be_bytes()).unwrap();
    socket.write_all(&[0; 16]).unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    assert!(channel.recv_bytes().is_err());
    closed(&mut channel);
    let (mut channel, _, _) = pair();
    assert!(channel.send_bytes(&vec![0; FRAME_LIMIT + 1]).is_err());
    closed(&mut channel);
}

#[test]
fn replay_reorder_reflection_and_cross_session_fail() {
    for case in 0..4 {
        let (mut channel, mut socket, mut noise) = pair();
        let first = encrypt(&mut noise, &[0, 0, 0, 1, 42]);
        let second = encrypt(&mut noise, &[0, 0, 0, 1, 43]);
        let bad = match case {
            0 => {
                send_raw(&mut socket, &first).unwrap();
                assert_eq!(channel.recv_bytes().unwrap(), [42]);
                first
            }
            1 => second,
            2 => encrypt(&mut channel.noise, &[0, 0, 0, 1, 42]),
            3 => {
                let (_, _, mut foreign) = pair();
                encrypt(&mut foreign, &[0, 0, 0, 1, 42])
            }
            _ => unreachable!(),
        };
        send_raw(&mut socket, &bad).unwrap();
        assert!(channel.recv_bytes().is_err(), "case {case}");
        closed(&mut channel);
    }
}

#[test]
fn nonce_exhaustion_does_not_wrap() {
    let (mut channel, mut socket, mut noise) = pair();
    channel.noise.set_receiving_nonce(u64::MAX);
    send_raw(&mut socket, &encrypt(&mut noise, &[0, 0, 0, 0])).unwrap();
    assert!(channel.recv_bytes().is_err());
    assert_eq!(channel.noise.receiving_nonce(), u64::MAX);
    closed(&mut channel);
}

#[test]
fn malformed_decoded_message_closes_channel() {
    let (mut channel, mut socket, mut noise) = pair();
    send_raw(&mut socket, &encrypt(&mut noise, &[0, 0, 0, 1, b'{'])).unwrap();
    assert!(channel.recv::<serde_json::Value>().is_err());
    closed(&mut channel);
}

#[test]
fn psk_separates_role_bay_protocol_and_session() {
    // Independent Python hashlib/hmac RFC5869 calculation, not output of this helper.
    assert_eq!(
        hex::encode(*derive_psk(&[3; 64], b"context").unwrap()),
        "1d390095c86e9d8229455324cf4393ca9f1a35bb501380bceef108b09adc398c"
    );
    let session = [1; 64];
    let contexts = [
        b"transfer/role0".as_slice(),
        b"transfer/role1",
        b"backup/bay0",
        b"backup/bay1",
    ];
    let keys: Vec<_> = contexts
        .iter()
        .map(|c| derive_psk(&session, c).unwrap())
        .collect();
    for i in 0..keys.len() {
        for j in i + 1..keys.len() {
            assert_ne!(*keys[i], *keys[j]);
        }
    }
    assert_ne!(*keys[0], *derive_psk(&[2; 64], contexts[0]).unwrap());
}

#[test]
fn opaque_context_and_server_proof_are_required() {
    let password = "1234567890abcdef";
    let credential = Credential::new(password).unwrap();
    for client_context in [b"role0".as_slice(), b"role1", b"backup"] {
        let start = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
        let response = ServerLogin::start(
            &mut OsRng,
            &credential.setup,
            Some(credential.record.clone()),
            start.message,
            CONTEXT,
            ServerLoginParameters {
                context: Some(b"role0"),
                ..Default::default()
            },
        )
        .unwrap();
        let finish = start.state.finish(
            &mut OsRng,
            password.as_bytes(),
            response.message,
            ClientLoginFinishParameters {
                context: Some(client_context),
                ksf: Some(&ksf()),
                ..Default::default()
            },
        );
        if client_context == b"role0" {
            let mut finish = finish.unwrap();
            let mut server = response
                .state
                .finish(
                    finish.message,
                    ServerLoginParameters {
                        context: Some(b"role0"),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(finish.session_key, server.session_key);
            finish.session_key.zeroize();
            finish.export_key.zeroize();
            server.session_key.zeroize();
        } else {
            assert!(finish.is_err());
        }
    }
}
