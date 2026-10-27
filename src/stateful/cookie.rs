use crate::auth::{AUTH_SECRET_BYTES, AuthSecret};
use crate::envelope::{self, KEY_BYTES, Key, NONCE_BYTES, TAG_BYTES};
use std::net::SocketAddr;
use zeroize::Zeroizing;

const TIMESTAMP_BYTES: usize = 4;
const SEALED_BYTES: usize = TIMESTAMP_BYTES + AUTH_SECRET_BYTES;
pub const COOKIE_BYTES: usize = NONCE_BYTES + SEALED_BYTES + TAG_BYTES;
const KEY_SLOTS: usize = 2;
const COOKIE_AAD_DOMAIN: &[u8] = b"hqclethe-stateful-cookie-v2";

pub type Cookie = [u8; COOKIE_BYTES];

pub struct CookieKeys {
    current: Key,
    previous: Key,
    rotated_at_ms: u64,
}

fn associated_data(addr: &SocketAddr) -> Vec<u8> {
    let mut out = COOKIE_AAD_DOMAIN.to_vec();
    match addr.ip() {
        std::net::IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
    out.extend_from_slice(&addr.port().to_le_bytes());
    out
}

fn try_open(key: &Key, addr: &SocketAddr, cookie: &Cookie) -> Option<[u8; SEALED_BYTES]> {
    let nonce: envelope::Nonce = cookie[..NONCE_BYTES].try_into().unwrap();
    let mut plain: [u8; SEALED_BYTES] = cookie[NONCE_BYTES..NONCE_BYTES + SEALED_BYTES]
        .try_into()
        .unwrap();
    let tag = &cookie[NONCE_BYTES + SEALED_BYTES..];
    envelope::open(key, &nonce, &associated_data(addr), &mut plain, tag).ok()?;
    Some(plain)
}

pub fn cookie_nonce(cookie: &Cookie) -> &[u8] {
    &cookie[..NONCE_BYTES]
}

impl CookieKeys {
    pub fn new(current: [u8; KEY_BYTES], previous: [u8; KEY_BYTES], now_ms: u64) -> Self {
        Self {
            current: Zeroizing::new(current),
            previous: Zeroizing::new(previous),
            rotated_at_ms: now_ms,
        }
    }

    pub fn rotations_due(&self, now_ms: u64, interval_ms: u64) -> usize {
        let elapsed_intervals = now_ms.saturating_sub(self.rotated_at_ms) / interval_ms.max(1);
        elapsed_intervals.min(KEY_SLOTS as u64) as usize
    }

    pub fn rotate(&mut self, fresh: [u8; KEY_BYTES], now_ms: u64) {
        self.previous = std::mem::replace(&mut self.current, Zeroizing::new(fresh));
        self.rotated_at_ms = now_ms;
    }

    pub fn issue(
        &self,
        addr: &SocketAddr,
        now_ms: u64,
        nonce: envelope::Nonce,
        k_auth: &AuthSecret,
    ) -> Cookie {
        let timestamp = ((now_ms / 1000) as u32).to_le_bytes();
        let mut sealed = [0u8; SEALED_BYTES];
        sealed[..TIMESTAMP_BYTES].copy_from_slice(&timestamp);
        sealed[TIMESTAMP_BYTES..].copy_from_slice(&k_auth[..]);
        let tag = envelope::seal(&self.current, &nonce, &associated_data(addr), &mut sealed)
            .expect("cookie seal cannot fail");
        let mut cookie = [0u8; COOKIE_BYTES];
        cookie[..NONCE_BYTES].copy_from_slice(&nonce);
        cookie[NONCE_BYTES..NONCE_BYTES + SEALED_BYTES].copy_from_slice(&sealed);
        cookie[NONCE_BYTES + SEALED_BYTES..].copy_from_slice(&tag);
        cookie
    }

    pub fn open(
        &self,
        addr: &SocketAddr,
        cookie: &Cookie,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Option<AuthSecret> {
        let plain = try_open(&self.current, addr, cookie)
            .or_else(|| try_open(&self.previous, addr, cookie))?;
        let timestamp: [u8; TIMESTAMP_BYTES] = plain[..TIMESTAMP_BYTES].try_into().unwrap();
        let issued_ms = u32::from_le_bytes(timestamp) as u64 * 1000;
        let fresh = issued_ms <= now_ms && now_ms - issued_ms <= lifetime_ms;
        fresh.then(|| Zeroizing::new(plain[TIMESTAMP_BYTES..].try_into().unwrap()))
    }
}
