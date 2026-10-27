use blake3::Hasher;
use std::net::IpAddr;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const NONCE_BYTES: usize = 16;
pub const TAG_BYTES: usize = 16;
pub const COUNTER_BYTES: usize = 8;
pub const CHALLENGE_BYTES: usize = NONCE_BYTES + 1 + 4 + TAG_BYTES;
pub const ADDRESS_BYTES: usize = 16;
pub const SOLUTION_BYTES: usize = CHALLENGE_BYTES + COUNTER_BYTES;

const MAC_KEY_CONTEXT: &str = "HQCLethe 2026-10 puzzle mac key v1";
const COINS_KEY_CONTEXT: &str = "HQCLethe 2026-10 solved handshake coins key v1";

pub type MacKey = Zeroizing<[u8; 32]>;
pub type CoinsKey = Zeroizing<[u8; 32]>;
pub type Digest = [u8; 32];
pub type PeerAddress = [u8; ADDRESS_BYTES];

pub fn peer_address(ip: IpAddr) -> PeerAddress {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

pub fn mac_key(cookie_key: &[u8; 32]) -> MacKey {
    Zeroizing::new(blake3::derive_key(MAC_KEY_CONTEXT, cookie_key))
}

pub fn coins_key(cookie_key: &[u8; 32]) -> CoinsKey {
    Zeroizing::new(blake3::derive_key(COINS_KEY_CONTEXT, cookie_key))
}

pub fn fill_handshake_coins(
    key: &CoinsKey,
    challenge_nonce: &[u8; NONCE_BYTES],
    request_digest: &Digest,
    out: &mut [u8],
) {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(challenge_nonce);
    hasher.update(request_digest);
    hasher.finalize_xof().fill(out);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; NONCE_BYTES],
    pub difficulty: u8,
    pub timestamp: u32,
    pub tag: [u8; TAG_BYTES],
}

impl Challenge {
    pub fn issue(
        key: &MacKey,
        peer: &PeerAddress,
        nonce: [u8; NONCE_BYTES],
        difficulty: u8,
        timestamp: u32,
    ) -> Self {
        Self {
            nonce,
            difficulty,
            timestamp,
            tag: Self::tag_for(key, peer, &nonce, difficulty, timestamp),
        }
    }

    fn tag_for(
        key: &MacKey,
        peer: &PeerAddress,
        nonce: &[u8; NONCE_BYTES],
        difficulty: u8,
        timestamp: u32,
    ) -> [u8; TAG_BYTES] {
        let mut hasher = Hasher::new_keyed(key);
        hasher.update(peer);
        hasher.update(nonce);
        hasher.update(&[difficulty]);
        hasher.update(&timestamp.to_le_bytes());
        let mut tag = [0u8; TAG_BYTES];
        hasher.finalize_xof().fill(&mut tag);
        tag
    }

    pub fn is_authentic(&self, key: &MacKey, peer: &PeerAddress) -> bool {
        let expected = Self::tag_for(key, peer, &self.nonce, self.difficulty, self.timestamp);
        bool::from(expected.ct_eq(&self.tag))
    }

    pub fn to_bytes(&self) -> [u8; CHALLENGE_BYTES] {
        let mut bytes = [0u8; CHALLENGE_BYTES];
        let (nonce, rest) = bytes.split_at_mut(NONCE_BYTES);
        let (difficulty, rest) = rest.split_at_mut(1);
        let (timestamp, tag) = rest.split_at_mut(4);
        nonce.copy_from_slice(&self.nonce);
        difficulty[0] = self.difficulty;
        timestamp.copy_from_slice(&self.timestamp.to_le_bytes());
        tag.copy_from_slice(&self.tag);
        bytes
    }

    pub fn from_bytes(bytes: &[u8; CHALLENGE_BYTES]) -> Self {
        let (nonce, rest) = bytes.split_at(NONCE_BYTES);
        let (difficulty, rest) = rest.split_at(1);
        let (timestamp, tag) = rest.split_at(4);
        Self {
            nonce: nonce.try_into().expect("split at the nonce length"),
            difficulty: difficulty[0],
            timestamp: u32::from_le_bytes(timestamp.try_into().expect("split at four bytes")),
            tag: tag.try_into().expect("the rest is the tag"),
        }
    }
}

pub fn is_fresh(timestamp: u32, now: u32, max_age_secs: u32) -> bool {
    now.checked_sub(timestamp)
        .is_some_and(|age| age <= max_age_secs)
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0;
    for byte in hash {
        zeros += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    zeros
}

struct SolutionHasher {
    prefix: Hasher,
}

impl SolutionHasher {
    fn new(challenge: &Challenge, peer: &PeerAddress, request_digest: &Digest) -> Self {
        let mut prefix = Hasher::new();
        prefix.update(&challenge.to_bytes());
        prefix.update(peer);
        prefix.update(request_digest);
        Self { prefix }
    }

    fn hash(&self, counter: u64) -> [u8; 32] {
        let mut hasher = self.prefix.clone();
        hasher.update(&counter.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    fn meets(&self, counter: u64, difficulty: u8) -> bool {
        leading_zero_bits(&self.hash(counter)) >= u32::from(difficulty)
    }
}

pub fn is_solution(
    challenge: &Challenge,
    peer: &PeerAddress,
    request_digest: &Digest,
    counter: u64,
) -> bool {
    SolutionHasher::new(challenge, peer, request_digest).meets(counter, challenge.difficulty)
}

pub fn solve(challenge: &Challenge, peer: &PeerAddress, request_digest: &Digest) -> u64 {
    let hasher = SolutionHasher::new(challenge, peer, request_digest);
    (0..)
        .find(|counter| hasher.meets(*counter, challenge.difficulty))
        .expect("counter space is exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MacKey {
        mac_key(&[7u8; 32])
    }

    const PEER: PeerAddress = [5u8; ADDRESS_BYTES];
    const OTHER_PEER: PeerAddress = [6u8; ADDRESS_BYTES];

    fn challenge(difficulty: u8) -> Challenge {
        Challenge::issue(&key(), &PEER, [3u8; NONCE_BYTES], difficulty, 1_000)
    }

    #[test]
    fn challenge_roundtrips_through_bytes() {
        let issued = challenge(12);
        assert_eq!(Challenge::from_bytes(&issued.to_bytes()), issued);
    }

    #[test]
    fn challenge_authenticates_only_under_its_key() {
        let issued = challenge(12);
        assert!(issued.is_authentic(&key(), &PEER));
        assert!(!issued.is_authentic(&mac_key(&[8u8; 32]), &PEER));
        assert!(!issued.is_authentic(&key(), &OTHER_PEER));
    }

    #[test]
    fn every_challenge_field_is_covered_by_the_tag() {
        let issued = challenge(12);
        let mut nonce = issued;
        nonce.nonce[0] ^= 1;
        let mut difficulty = issued;
        difficulty.difficulty -= 1;
        let mut timestamp = issued;
        timestamp.timestamp += 1;
        let mut tag = issued;
        tag.tag[0] ^= 1;
        for forged in [nonce, difficulty, timestamp, tag] {
            assert!(!forged.is_authentic(&key(), &PEER));
        }
    }

    #[test]
    fn freshness_window_is_inclusive_and_rejects_the_future() {
        assert!(is_fresh(100, 100, 90));
        assert!(is_fresh(10, 100, 90));
        assert!(!is_fresh(9, 100, 90));
        assert!(!is_fresh(101, 100, 90));
    }

    #[test]
    fn leading_zero_bits_counts_across_bytes() {
        let mut hash = [0xffu8; 32];
        assert_eq!(leading_zero_bits(&hash), 0);
        hash[0] = 0x01;
        assert_eq!(leading_zero_bits(&hash), 7);
        hash[0] = 0;
        hash[1] = 0x10;
        assert_eq!(leading_zero_bits(&hash), 11);
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
    }

    #[test]
    fn solution_meets_difficulty_and_binds_the_request_digest() {
        let issued = challenge(10);
        let digest = [9u8; 32];
        let counter = solve(&issued, &PEER, &digest);
        assert!(is_solution(&issued, &PEER, &digest, counter));
        let other_digest_accepts = (0..64u8)
            .filter(|byte| is_solution(&issued, &PEER, &[*byte; 32], counter))
            .count();
        assert!(other_digest_accepts < 8);
    }

    #[test]
    fn solution_binds_the_peer_address() {
        let issued = challenge(10);
        let digest = [9u8; 32];
        let counter = solve(&issued, &PEER, &digest);
        let other_peer_accepts = (0..64u8)
            .filter(|byte| is_solution(&issued, &[*byte; ADDRESS_BYTES], &digest, counter))
            .count();
        assert!(other_peer_accepts < 8);
    }

    #[test]
    fn mapped_and_plain_ipv4_give_the_same_address() {
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        assert_eq!(peer_address(v4), peer_address(mapped));
        assert_ne!(peer_address(v4), peer_address(v6));
    }

    #[test]
    fn coins_key_is_separate_from_the_mac_key() {
        let cookie_key = [7u8; 32];
        assert_ne!(*coins_key(&cookie_key), *mac_key(&cookie_key));
    }

    #[test]
    fn handshake_coins_depend_on_key_nonce_and_digest() {
        let coins_of = |cookie_key: u8, nonce: u8, digest: u8| {
            let mut out = [0u8; 64];
            fill_handshake_coins(
                &coins_key(&[cookie_key; 32]),
                &[nonce; NONCE_BYTES],
                &[digest; 32],
                &mut out,
            );
            out
        };
        let base = coins_of(1, 2, 3);
        assert_eq!(base, coins_of(1, 2, 3));
        assert_ne!(base, coins_of(9, 2, 3));
        assert_ne!(base, coins_of(1, 9, 3));
        assert_ne!(base, coins_of(1, 2, 9));
    }

    #[test]
    fn difficulty_zero_accepts_any_counter() {
        assert!(is_solution(&challenge(0), &PEER, &[0u8; 32], 0));
    }
}
