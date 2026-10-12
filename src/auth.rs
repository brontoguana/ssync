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
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAGIC: &[u8; 8] = b"SSYNC4\0\x01";
const CONTEXT: &[u8] = b"SSync-4.0/OPAQUE-ristretto255-SHA512/Noise-NNpsk0";
const HANDSHAKE_LIMIT: usize = 2048;
pub const FRAME_LIMIT: usize = 1_048_576;
const RECORD: usize = 60_000;
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);

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
        let setup = ServerSetup::<Suite>::new(&mut OsRng);
        let start = ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes())?;
        let response = ServerRegistration::start(&setup, start.message, CONTEXT)?;
        let finish = start.state.finish(
            &mut OsRng,
            password.as_bytes(),
            response.message,
            ClientRegistrationFinishParameters {
                ksf: Some(&ksf()),
                ..Default::default()
            },
        )?;
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
    pub wire_sent: u64,
    pub wire_received: u64,
}
impl Channel {
    pub fn authenticate(
        mut socket: TcpStream,
        password: &str,
        credential: Option<&Credential>,
        sending: bool,
    ) -> Result<Self> {
        validate_password(password)?;
        let end = Instant::now() + AUTH_TIMEOUT;
        // A wall-clock watchdog prevents slow trickle reads extending read_exact indefinitely.
        let deadline_socket = socket.try_clone()?;
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let notify = done.clone();
        let watchdog = std::thread::spawn(move || {
            let (lock, cv) = &*notify;
            let guard = lock.lock().unwrap();
            let result = cv
                .wait_timeout_while(guard, AUTH_TIMEOUT, |done| !*done)
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
        let mut hello = MAGIC.to_vec();
        hello.push(u8::from(sending));
        socket.write_all(&hello)?;
        let mut peer = [0; 9];
        socket.read_exact(&mut peer)?;
        ensure!(
            &peer[..8] == MAGIC,
            "incompatible SSync protocol; both peers require SSync 4"
        );
        ensure!(
            peer[8] <= 1 && peer[8] != u8::from(sending),
            "transfer direction mismatch"
        );
        let initiator = credential.is_none();
        let connector_role = if initiator {
            u8::from(sending)
        } else {
            peer[8]
        };
        let mut context = CONTEXT.to_vec();
        context.push(connector_role);
        deadline(&socket, end)?;
        let session = if let Some(c) = credential {
            let request = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
            let start = ServerLogin::start(
                &mut OsRng,
                &c.setup,
                Some(c.record.clone()),
                CredentialRequest::deserialize(&request)?,
                CONTEXT,
                ServerLoginParameters {
                    context: Some(&context),
                    ..Default::default()
                },
            )?;
            deadline(&socket, end)?;
            send_raw(&mut socket, &start.message.serialize())?;
            let finalization = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
            start
                .state
                .finish(
                    CredentialFinalization::deserialize(&finalization)?,
                    ServerLoginParameters {
                        context: Some(&context),
                        ..Default::default()
                    },
                )?
                .session_key
        } else {
            let start = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes())?;
            send_raw(&mut socket, &start.message.serialize())?;
            let response = recv_raw(&mut socket, HANDSHAKE_LIMIT)?;
            let finish = start.state.finish(
                &mut OsRng,
                password.as_bytes(),
                CredentialResponse::deserialize(&response)?,
                ClientLoginFinishParameters {
                    context: Some(&context),
                    ksf: Some(&ksf()),
                    ..Default::default()
                },
            )?;
            deadline(&socket, end)?;
            send_raw(&mut socket, &finish.message.serialize())?;
            finish.session_key
        };
        let session = Zeroizing::new(session);
        let mut psk = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&context), &session[..])
            .expand(b"SSync-4 Noise PAKE session PSK", psk.as_mut())
            .map_err(|_| anyhow::anyhow!("key derivation failed"))?;
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
        Ok(channel)
    }
    pub fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.send_bytes(&serde_json::to_vec(value)?)
    }
    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        Ok(serde_json::from_slice(&self.recv_bytes()?)?)
    }
    pub fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
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
