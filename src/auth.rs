//! OPAQUE authenticated key exchange followed by PSK-authenticated Noise.
use anyhow::{Result, ensure};
use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAGIC: &[u8; 8] = b"SSYNC4\0\x01";
const CONTEXT: &[u8] = b"SSync-4.0/OPAQUE-ristretto255-SHA512/Noise-NNpsk0";
const HANDSHAKE_LIMIT: usize = 2048;
pub const FRAME_LIMIT: usize = 1_048_576;
const RECORD: usize = 60_000;
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);
static AUTH_WORK: AtomicUsize = AtomicUsize::new(0);
struct AuthPermit;
impl AuthPermit {
    fn acquire() -> Result<Self> {
        let end = Instant::now() + AUTH_TIMEOUT;
        loop {
            if AUTH_WORK
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    (n < 4).then_some(n + 1)
                })
                .is_ok()
            {
                return Ok(Self);
            }
            ensure!(Instant::now() < end, "authentication concurrency limit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for AuthPermit {
    fn drop(&mut self) {
        AUTH_WORK.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn password() -> Result<String> {
    let mut result = String::with_capacity(29);
    let mut b = [0u8; 1];
    for i in 0..24 {
        if i > 0 && i % 4 == 0 {
            result.push('-');
        }
        loop {
            OsRng
                .try_fill_bytes(&mut b)
                .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
            if let Some(c) = sample(b[0]) {
                result.push(c);
                break;
            }
        }
    }
    Ok(result)
}
fn sample(b: u8) -> Option<char> {
    (b < 232).then(|| ALPHABET[(b % 58) as usize] as char)
}
pub fn validate_password(p: &str) -> Result<()> {
    ensure!(
        p.chars().count() >= 16,
        "password must have at least 16 characters"
    );
    ensure!(p.len() <= 4096, "password exceeds 4096-byte limit");
    Ok(())
}
struct Suite;
impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}
fn ksf() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65_536, 3, 1, None).expect("fixed parameters"),
    )
}
// Registration is performed entirely locally, not exposed as a wire operation.
pub struct Credential {
    setup: ServerSetup<Suite>,
    record: ServerRegistration<Suite>,
}
impl Credential {
    pub fn new(password: &str) -> Result<Self> {
        validate_password(password)?;
        let _permit = AuthPermit::acquire()?;
        let setup = ServerSetup::<Suite>::new(&mut OsRng);
        let start = ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes())?;
        let response = ServerRegistration::start(&setup, start.message, CONTEXT)?;
        let mut finish = start.state.finish(
            &mut OsRng,
            password.as_bytes(),
            response.message,
            ClientRegistrationFinishParameters {
                ksf: Some(&ksf()),
                ..Default::default()
            },
        )?;
        // The library result does not wipe this unused output on drop.
        finish.export_key.zeroize();
        Ok(Self {
            setup,
            record: ServerRegistration::finish(finish.message),
        })
    }
}
fn send_raw(s: &mut TcpStream, data: &[u8]) -> Result<()> {
    ensure!(data.len() <= FRAME_LIMIT, "frame too large");
    s.write_all(&(data.len() as u32).to_be_bytes())?;
    s.write_all(data)?;
    Ok(())
}
fn recv_raw(s: &mut TcpStream, limit: usize) -> Result<Vec<u8>> {
    let mut len = [0; 4];
    s.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    ensure!(len > 0 && len <= limit, "invalid frame length");
    let mut data = vec![0; len];
    s.read_exact(&mut data)?;
    Ok(data)
}
fn deadline(s: &TcpStream, end: Instant) -> Result<()> {
    let time = end
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow::anyhow!("authentication timeout"))?;
    s.set_read_timeout(Some(time))?;
    s.set_write_timeout(Some(time))?;
    Ok(())
}

pub struct Channel {
    socket: TcpStream,
    noise: snow::TransportState,
    failed: bool,
    pub wire_sent: u64,
    pub wire_received: u64,
}
impl Channel {
    pub fn authenticate(
        socket: TcpStream,
        password: &str,
        credential: Option<&Credential>,
        sending: bool,
    ) -> Result<Self> {
        Ok(Self::authenticate_inner(
            socket,
            password,
            credential.map(std::slice::from_ref),
            sending,
            false,
        )?
        .0)
    }
    /// Backup-only, upload-only channel. Returns the authenticated bay index.
    pub fn authenticate_backup(
        socket: TcpStream,
        password: &str,
        credentials: Option<&[Credential]>,
    ) -> Result<(Self, usize)> {
        Self::authenticate_inner(socket, password, credentials, credentials.is_none(), true)
    }
    fn authenticate_inner(
        mut socket: TcpStream,
        password: &str,
        credentials: Option<&[Credential]>,
        sending: bool,
        backup: bool,
    ) -> Result<(Self, usize)> {
        if credentials.is_none() || !backup {
            validate_password(password)?;
        }
        if let Some(c) = credentials {
            ensure!(!c.is_empty() && c.len() <= 32, "credential limit");
        }
        let end = Instant::now()
            + if backup {
                Duration::from_secs(60)
            } else {
                AUTH_TIMEOUT
            };
        let _permit = AuthPermit::acquire()?;
        // A wall-clock watchdog prevents slow trickle reads extending read_exact indefinitely.
        let deadline_socket = socket.try_clone()?;
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let notify = done.clone();
        let watchdog = std::thread::spawn(move || {
            let (lock, cv) = &*notify;
            let guard = lock.lock().unwrap();
            let result = cv
                .wait_timeout_while(
                    guard,
                    end.saturating_duration_since(Instant::now()),
                    |done| !*done,
                )
                .unwrap();
            if !*result.0 {
                let _ = deadline_socket.shutdown(Shutdown::Both);
            }
        });
        struct DeadlineGuard(
            Arc<(Mutex<bool>, Condvar)>,
            Option<std::thread::JoinHandle<()>>,
        );
        impl Drop for DeadlineGuard {
            fn drop(&mut self) {
                let (lock, cv) = &*self.0;
                *lock.lock().unwrap() = true;
                cv.notify_one();
                if let Some(h) = self.1.take() {
                    let _ = h.join();
                }
            }
        }
        let watchdog_guard = DeadlineGuard(done, Some(watchdog));
        socket.set_nodelay(true)?;
        deadline(&socket, end)?;
        let magic = if backup { b"SSYNCB\0\x01" } else { MAGIC };
        let mut hello = magic.to_vec();
        hello.push(u8::from(sending));
        socket.write_all(&hello)?;
        let mut peer = [0; 9];
        socket.read_exact(&mut peer)?;
        ensure!(
            &peer[..8] == magic,
            "incompatible SSync protocol; both peers require SSync 4"
        );
        ensure!(
            peer[8] <= 1 && peer[8] != u8::from(sending),
            "transfer direction mismatch"
        );
        let initiator = credentials.is_none();
        let connector_role = if initiator {
            u8::from(sending)
        } else {
            peer[8]
        };
        let mut context = CONTEXT.to_vec();
        context.push(connector_role);
        deadline(&socket, end)?;
        if backup {
            context.extend_from_slice(b"/backup-upload-v1");
        }
        let (session, selected) = if let Some(credentials) = credentials {
            let request = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
            let request = CredentialRequest::deserialize(&request)?;
            let mut states = Vec::new();
            if backup {
                send_raw(&mut socket, &[credentials.len() as u8])?;
            }
            for c in credentials {
                let start = ServerLogin::start(
                    &mut OsRng,
                    &c.setup,
                    Some(c.record.clone()),
                    request.clone(),
                    CONTEXT,
                    ServerLoginParameters {
                        context: Some(&context),
                        ..Default::default()
                    },
                )?;
                deadline(&socket, end)?;
                send_raw(&mut socket, &start.message.serialize())?;
                states.push(start.state);
            }
            let finalization = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
            let (selected, finalization) = if backup {
                ensure!(finalization.len() > 1, "missing bay confirmation");
                (finalization[0] as usize, &finalization[1..])
            } else {
                (0, finalization.as_slice())
            };
            ensure!(selected < states.len(), "invalid bay confirmation");
            let state = states.swap_remove(selected);
            let mut finish = state.finish(
                CredentialFinalization::deserialize(finalization)?,
                ServerLoginParameters {
                    context: Some(&context),
                    ..Default::default()
                },
            )?;
            let session = Zeroizing::new(finish.session_key);
            finish.session_key.zeroize();
            (session, selected)
        } else {
            let start = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes())?;
            send_raw(&mut socket, &start.message.serialize())?;
            let count = if backup {
                let count = recv_raw(&mut socket, 1)?;
                ensure!((1..=32).contains(&count[0]), "bay count limit");
                count[0] as usize
            } else {
                1
            };
            let mut matched = None;
            for index in 0..count {
                let response = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
                if matched.is_none() {
                    deadline(&socket, end)?;
                    if let Ok(mut finish) = start.state.clone().finish(
                        &mut OsRng,
                        password.as_bytes(),
                        CredentialResponse::deserialize(&response)?,
                        ClientLoginFinishParameters {
                            context: Some(&context),
                            ksf: Some(&ksf()),
                            ..Default::default()
                        },
                    ) {
                        // Protect outputs before any later candidate read or KE3 write fails.
                        finish.export_key.zeroize();
                        let session = Zeroizing::new(finish.session_key);
                        finish.session_key.zeroize();
                        matched = Some((finish.message, session, index));
                    }
                }
            }
            let (message, session, index) =
                matched.ok_or_else(|| anyhow::anyhow!("authentication failed"))?;
            deadline(&socket, end)?;
            let mut finalization = Vec::new();
            if backup {
                finalization.push(index as u8);
            }
            finalization.extend_from_slice(&message.serialize());
            send_raw(&mut socket, &finalization)?;
            (session, index)
        };
        if backup {
            // Bind bay selection and upload protocol into the final authenticated channel.
            context.push(selected as u8);
        }
        let psk = derive_psk(&session, &context)?;
        let builder = snow::Builder::new("Noise_NNpsk0_25519_ChaChaPoly_SHA256".parse()?)
            .psk(0, &psk)?
            .prologue(&context)?;
        let mut handshake = if initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        };
        let mut buf = vec![0; HANDSHAKE_LIMIT];
        deadline(&socket, end)?;
        if initiator {
            let n = handshake.write_message(b"connector-confirm", &mut buf)?;
            send_raw(&mut socket, &buf[..n])?;
            let msg = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
            let n = handshake.read_message(&msg, &mut buf)?;
            ensure!(&buf[..n] == b"listener-confirm", "invalid confirmation");
        } else {
            let msg = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
            let n = handshake.read_message(&msg, &mut buf)?;
            ensure!(&buf[..n] == b"connector-confirm", "invalid confirmation");
            let n = handshake.write_message(b"listener-confirm", &mut buf)?;
            send_raw(&mut socket, &buf[..n])?;
        }
        let mut channel = Self {
            socket,
            noise: handshake.into_transport_mode()?,
            failed: false,
            wire_sent: 0,
            wire_received: 0,
        };
        // The listener gates roots on the final encrypted acknowledgment.
        if initiator {
            channel.send_bytes(b"ready-connector")?;
            ensure!(
                channel.recv_bytes()? == b"ready-listener",
                "confirmation failed"
            );
        } else {
            ensure!(
                channel.recv_bytes()? == b"ready-connector",
                "confirmation failed"
            );
            channel.send_bytes(b"ready-listener")?;
        }
        drop(watchdog_guard);
        channel
            .socket
            .set_read_timeout(Some(Duration::from_secs(120)))?;
        channel
            .socket
            .set_write_timeout(Some(Duration::from_secs(120)))?;
        Ok((channel, selected))
    }
    pub fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.send_bytes(&serde_json::to_vec(value)?)
    }
    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        let result = serde_json::from_slice(&self.recv_bytes()?)
            .map_err(|_| anyhow::anyhow!("malformed or unknown transfer message"));
        self.fail_closed(result)
    }
    fn fail_closed<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.failed = true;
            let _ = self.socket.shutdown(Shutdown::Both);
        }
        result
    }
    pub fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
        ensure!(!self.failed, "channel is closed after a previous failure");
        let result = self.send_bytes_inner(data);
        self.fail_closed(result)
    }
    fn send_bytes_inner(&mut self, data: &[u8]) -> Result<()> {
        ensure!(data.len() <= FRAME_LIMIT, "message too large");
        let mut first = true;
        // All message lengths are authenticated inside Noise records.
        let mut plain = Vec::with_capacity(data.len() + 4);
        plain.extend_from_slice(&(data.len() as u32).to_be_bytes());
        plain.extend_from_slice(data);
        for piece in plain.chunks(RECORD) {
            let mut out = vec![0; piece.len() + 16];
            let n = self.noise.write_message(piece, &mut out)?;
            send_raw(&mut self.socket, &out[..n])?;
            self.wire_sent += n as u64 + 4;
            first = false;
        }
        ensure!(!first, "empty encrypted framing");
        Ok(())
    }
    pub fn recv_bytes(&mut self) -> Result<Vec<u8>> {
        ensure!(!self.failed, "channel is closed after a previous failure");
        let result = self.recv_bytes_inner();
        self.fail_closed(result)
    }
    fn recv_bytes_inner(&mut self) -> Result<Vec<u8>> {
        let encrypted = recv_raw(&mut self.socket, RECORD + 16)?;
        self.wire_received += encrypted.len() as u64 + 4;
        let mut buf = vec![0; RECORD];
        let n = self.noise.read_message(&encrypted, &mut buf)?;
        ensure!(n >= 4, "missing message length");
        let size = u32::from_be_bytes(buf[..4].try_into()?) as usize;
        ensure!(size <= FRAME_LIMIT, "message too large");
        let mut result = Vec::with_capacity(size);
        ensure!(n - 4 <= size, "excess message data");
        result.extend_from_slice(&buf[4..n]);
        while result.len() < size {
            let encrypted = recv_raw(&mut self.socket, RECORD + 16)?;
            self.wire_received += encrypted.len() as u64 + 4;
            let n = self.noise.read_message(&encrypted, &mut buf)?;
            ensure!(n > 0 && result.len() + n <= size, "invalid record boundary");
            result.extend_from_slice(&buf[..n]);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unbiased_sampler() {
        let mut counts = [0; 58];
        for b in 0..=255u8 {
            if let Some(c) = sample(b) {
                counts[ALPHABET.iter().position(|x| *x == c as u8).unwrap()] += 1;
            }
        }
        assert!(counts.iter().all(|c| *c == 4));
    }
    #[test]
    fn passwords() {
        for _ in 0..64 {
            let p = password().unwrap();
            assert_eq!(p.len(), 29);
            assert_eq!(p.split('-').count(), 6);
            assert!(
                p.split('-')
                    .all(|s| s.len() == 4 && s.bytes().all(|b| ALPHABET.contains(&b)))
            );
        }
        assert!(validate_password("123456789012345").is_err());
        assert!(validate_password("é".repeat(16).as_str()).is_ok());
    }
    #[test]
    fn channel_and_wrong_password() {
        use std::net::TcpListener;
        for correct in [true, false] {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let c = Credential::new("1234567890abcdef").unwrap();
                let mut channel = Channel::authenticate(
                    l.accept().unwrap().0,
                    "1234567890abcdef",
                    Some(&c),
                    true,
                )?;
                channel.send_bytes(&vec![42; 200_000])?;
                ensure!(channel.recv_bytes()? == b"ok", "bad ack");
                Ok::<_, anyhow::Error>(())
            });
            let result = Channel::authenticate(
                TcpStream::connect(addr).unwrap(),
                if correct {
                    "1234567890abcdef"
                } else {
                    "1234567890abcdeg"
                },
                None,
                false,
            );
            if correct {
                let mut c = result.unwrap();
                assert_eq!(c.recv_bytes().unwrap(), vec![42; 200_000]);
                c.send_bytes(b"ok").unwrap();
                assert!(worker.join().unwrap().is_ok());
            } else {
                assert!(result.is_err());
                assert!(worker.join().unwrap().is_err());
            }
        }
    }
}

// Keep suite/role/bay separation in one testable derivation; never use the password as a PSK.
fn derive_psk(session: &[u8], context: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut psk = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(context), session)
        .expand(b"SSync-4 Noise PAKE session PSK", psk.as_mut())
        .map_err(|_| anyhow::anyhow!("key derivation failed"))?;
    Ok(psk)
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod crypto_tests;
