//! Wire format.
//!
//! Every packet starts with a two-byte header: flags and kind, then index.
//! Bit 7 of the first byte is the direction (set: server to client). Bit 5
//! is the cookie key index. Bits 0-2 are the kind.
//!
//! ```text
//! handshake request   header | hash_ek_kem | h_seed | ct_auth | zeros
//! handshake response  header | nonce | AE(cookie | salt | gamma) | tag
//! challenge response  header | puzzle nonce | difficulty | timestamp | mac | client address
//! solved handshake    header | hash_ek_kem | h_seed | ct_auth | challenge | counter | zeros
//! u-chunk request     header | cookie | tag | zeros
//! u-chunk response    header | nonce | AE(u bytes of the chunk) | tag
//! v-residue request   header | cookie | AE(s mod f_i) | tag | zeros
//! v-residue response  header | nonce | AE(v-residue mod f_i) | tag
//! ```
//!
//! The AE of a request covers the header and the cookie as associated data.
//!
//! Each request is padded with zero bytes to the length of the longest reply
//! it can trigger. The server accepts one request length per kind.
//!
//! A server with a non-zero puzzle difficulty answers a plain handshake
//! request with a challenge response, which is shorter than the request. The
//! client answers with a solved handshake request. Its header has the key
//! index of the key that authenticated the challenge. Its challenge field is
//! the 37 bytes of the challenge response after the header, unchanged. The
//! client address in the challenge response is the source address the server
//! saw, as 16 bytes (an IPv4 address in its IPv4-mapped IPv6 form). The client
//! needs it for the solution hash, because a client behind address translation
//! does not know it. The server does not read it back: it uses the source
//! address of the solved request.

use crate::auth::auth_ciphertext_bytes;
use crate::envelope::{Direction, Key, NONCE_BYTES, Nonce, TAG_BYTES, open, request_nonce, seal};
use crate::error::{Error, Result};
use crate::hqc::HqcScheme;
use crate::puzzle::{
    ADDRESS_BYTES, CHALLENGE_BYTES, COUNTER_BYTES, Challenge, PeerAddress, SOLUTION_BYTES,
};

pub const MAX_UDP_PAYLOAD: usize = 1232;
pub const HEADER_BYTES: usize = 2;
pub const SEED_BYTES: usize = 32;
pub const SALT_BYTES: usize = 16;
pub const GAMMA_BYTES: usize = 32;
pub const UCHUNK_MAX_BYTES: usize = MAX_UDP_PAYLOAD - HEADER_BYTES - NONCE_BYTES - TAG_BYTES;

const DIRECTION_BIT: u8 = 0x80;
const KEY_BIT: u8 = 0x20;
const KIND_MASK: u8 = 0x07;
const RESERVED_BITS: u8 = 0x58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Handshake = 0,
    UChunk = 1,
    VResidue = 2,
    Challenge = 3,
    SolvedHandshake = 4,
}

impl Kind {
    pub const SESSION: [Kind; 3] = [Kind::Handshake, Kind::UChunk, Kind::VResidue];
    pub const PUZZLE: [Kind; 2] = [Kind::Challenge, Kind::SolvedHandshake];

    fn from_bits(bits: u8) -> Option<Self> {
        Self::SESSION
            .into_iter()
            .chain(Self::PUZZLE)
            .find(|kind| *kind as u8 == bits)
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Handshake => "handshake",
            Kind::UChunk => "uchunk",
            Kind::Challenge => "challenge",
            Kind::SolvedHandshake => "solved-handshake",
            Kind::VResidue => "vresidue",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub direction: Direction,
    pub key_index: u8,
    pub kind: Kind,
    pub index: u8,
}

impl Header {
    pub fn request(kind: Kind, key_index: u8, index: u8) -> Self {
        Self {
            direction: Direction::ClientToServer,
            key_index,
            kind,
            index,
        }
    }

    pub fn response(kind: Kind, key_index: u8, index: u8) -> Self {
        Self {
            direction: Direction::ServerToClient,
            key_index,
            kind,
            index,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut flags = self.kind as u8;
        if self.direction == Direction::ServerToClient {
            flags |= DIRECTION_BIT;
        }
        if self.key_index == 1 {
            flags |= KEY_BIT;
        }
        [flags, self.index]
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let [flags, index] = *data
            .first_chunk::<HEADER_BYTES>()
            .ok_or(Error::SerializationError)?;
        if flags & RESERVED_BITS != 0 {
            return Err(Error::SerializationError);
        }
        let kind = Kind::from_bits(flags & KIND_MASK).ok_or(Error::SerializationError)?;
        let direction = if flags & DIRECTION_BIT != 0 {
            Direction::ServerToClient
        } else {
            Direction::ClientToServer
        };
        Ok(Self {
            direction,
            key_index: u8::from(flags & KEY_BIT != 0),
            kind,
            index,
        })
    }
}

pub fn cookie_plaintext_len<T: HqcScheme>() -> usize {
    32 + T::PARAM_SECURITY_BYTES + SEED_BYTES + 32
}

pub fn cookie_len<T: HqcScheme>() -> usize {
    NONCE_BYTES + cookie_plaintext_len::<T>() + TAG_BYTES
}

pub fn uchunk_count<T: HqcScheme>() -> usize {
    T::VEC_N_SIZE_BYTES.div_ceil(UCHUNK_MAX_BYTES)
}

pub fn uchunk_payload_len<T: HqcScheme>(chunk_index: usize) -> usize {
    UCHUNK_MAX_BYTES.min(T::VEC_N_SIZE_BYTES - chunk_index * UCHUNK_MAX_BYTES)
}

pub fn handshake_request_body_len<T: HqcScheme>() -> usize {
    32 + SEED_BYTES + auth_ciphertext_bytes::<T>()
}

pub fn handshake_response_payload_len<T: HqcScheme>() -> usize {
    cookie_len::<T>() + SALT_BYTES + GAMMA_BYTES
}

pub fn crt_request_payload_len<T: HqcScheme>() -> usize {
    crate::crt::params::request_payload_bytes(T::CRT_MODULI)
}

pub fn request_payload_len<T: HqcScheme>(kind: Kind) -> usize {
    match kind {
        Kind::VResidue => crt_request_payload_len::<T>(),
        Kind::Handshake | Kind::UChunk | Kind::Challenge | Kind::SolvedHandshake => 0,
    }
}

fn sealed_len(payload: usize) -> usize {
    payload + TAG_BYTES
}

const RESPONSE_FRAMING_BYTES: usize = HEADER_BYTES + NONCE_BYTES;

pub fn challenge_response_len() -> usize {
    HEADER_BYTES + CHALLENGE_BYTES + ADDRESS_BYTES
}

pub fn response_len<T: HqcScheme>(kind: Kind, index: usize) -> usize {
    let sealed_payload = match kind {
        Kind::Challenge => return challenge_response_len(),
        Kind::Handshake | Kind::SolvedHandshake => handshake_response_payload_len::<T>(),
        Kind::UChunk => uchunk_payload_len::<T>(index),
        Kind::VResidue => T::CRT_MODULI[index].residue_bytes(),
    };
    RESPONSE_FRAMING_BYTES + sealed_len(sealed_payload)
}

fn request_prefix_len<T: HqcScheme>() -> usize {
    HEADER_BYTES + cookie_len::<T>()
}

fn unpadded_request_len<T: HqcScheme>(kind: Kind) -> usize {
    match kind {
        Kind::Handshake => HEADER_BYTES + handshake_request_body_len::<T>(),
        Kind::SolvedHandshake => HEADER_BYTES + handshake_request_body_len::<T>() + SOLUTION_BYTES,
        Kind::Challenge => 0,
        Kind::UChunk | Kind::VResidue => {
            request_prefix_len::<T>() + sealed_len(request_payload_len::<T>(kind))
        }
    }
}

pub fn request_len<T: HqcScheme>(kind: Kind) -> usize {
    unpadded_request_len::<T>(kind).max(response_len::<T>(kind, 0))
}

/// Number of zero bytes at the end of every request of `kind`.
pub fn request_padding_len<T: HqcScheme>(kind: Kind) -> usize {
    request_len::<T>(kind) - unpadded_request_len::<T>(kind)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, b| acc | b) == 0
}

pub struct HandshakeRequestView<'a> {
    pub hash_ek_kem: &'a [u8; 32],
    pub h_seed: &'a [u8; SEED_BYTES],
    pub auth_ct: &'a [u8],
    pub body: &'a [u8],
}

pub fn write_handshake_request<T: HqcScheme>(
    out: &mut [u8],
    hash_ek_kem: &[u8; 32],
    h_seed: &[u8; SEED_BYTES],
    auth_ct: &[u8],
) -> Result<usize> {
    let total = request_len::<T>(Kind::Handshake);
    if auth_ct.len() != auth_ciphertext_bytes::<T>() || out.len() < total {
        return Err(Error::SerializationError);
    }
    let out = &mut out[..total];
    out.fill(0);
    out[..HEADER_BYTES].copy_from_slice(&Header::request(Kind::Handshake, 0, 0).encode());
    let mut pos = HEADER_BYTES;
    for part in [&hash_ek_kem[..], h_seed, auth_ct] {
        out[pos..pos + part.len()].copy_from_slice(part);
        pos += part.len();
    }
    Ok(total)
}

fn split_handshake_body(body: &[u8]) -> Result<HandshakeRequestView<'_>> {
    let (hash_ek_kem, rest) = body
        .split_first_chunk::<32>()
        .ok_or(Error::SerializationError)?;
    let (h_seed, auth_ct) = rest
        .split_first_chunk::<SEED_BYTES>()
        .ok_or(Error::SerializationError)?;
    Ok(HandshakeRequestView {
        hash_ek_kem,
        h_seed,
        auth_ct,
        body,
    })
}

pub fn parse_handshake_request<T: HqcScheme>(data: &[u8]) -> Result<HandshakeRequestView<'_>> {
    if data.len() != request_len::<T>(Kind::Handshake) {
        return Err(Error::SerializationError);
    }
    if Header::decode(data)? != Header::request(Kind::Handshake, 0, 0) {
        return Err(Error::SerializationError);
    }
    let body_len = handshake_request_body_len::<T>();
    let body = &data[HEADER_BYTES..HEADER_BYTES + body_len];
    if !is_zero(&data[HEADER_BYTES + body_len..]) {
        return Err(Error::SerializationError);
    }
    split_handshake_body(body)
}

pub fn write_challenge_response(
    out: &mut [u8],
    key_index: u8,
    challenge: &Challenge,
    peer: &PeerAddress,
) -> Result<usize> {
    let total = challenge_response_len();
    let out = out.get_mut(..total).ok_or(Error::SerializationError)?;
    out[..HEADER_BYTES].copy_from_slice(&Header::response(Kind::Challenge, key_index, 0).encode());
    let (challenge_out, peer_out) = out[HEADER_BYTES..].split_at_mut(CHALLENGE_BYTES);
    challenge_out.copy_from_slice(&challenge.to_bytes());
    peer_out.copy_from_slice(peer);
    Ok(total)
}

/// A challenge is not authenticated for the client. Only the server that
/// issued it can check its MAC.
pub fn parse_challenge_response(data: &[u8]) -> Result<(u8, Challenge, PeerAddress)> {
    let header = Header::decode(data)?;
    let expected = Header::response(Kind::Challenge, header.key_index, 0);
    if header != expected || data.len() != challenge_response_len() {
        return Err(Error::SerializationError);
    }
    let (challenge, peer) = data[HEADER_BYTES..].split_at(CHALLENGE_BYTES);
    let challenge: &[u8; CHALLENGE_BYTES] = challenge
        .try_into()
        .map_err(|_| Error::SerializationError)?;
    let peer: PeerAddress = peer.try_into().map_err(|_| Error::SerializationError)?;
    Ok((header.key_index, Challenge::from_bytes(challenge), peer))
}

pub struct SolvedHandshakeView<'a> {
    pub request: HandshakeRequestView<'a>,
    pub key_index: u8,
    pub challenge: Challenge,
    pub counter: u64,
}

/// Builds a solved handshake request from the plain request it answers.
pub fn write_solved_handshake_request<T: HqcScheme>(
    out: &mut [u8],
    plain_request: &[u8],
    key_index: u8,
    challenge: &Challenge,
    counter: u64,
) -> Result<usize> {
    let total = request_len::<T>(Kind::SolvedHandshake);
    let body_len = handshake_request_body_len::<T>();
    let plain = parse_handshake_request::<T>(plain_request)?;
    if out.len() < total {
        return Err(Error::SerializationError);
    }
    let out = &mut out[..total];
    out.fill(0);
    out[..HEADER_BYTES]
        .copy_from_slice(&Header::request(Kind::SolvedHandshake, key_index, 0).encode());
    let (body, rest) = out[HEADER_BYTES..].split_at_mut(body_len);
    let (challenge_out, rest) = rest.split_at_mut(CHALLENGE_BYTES);
    body.copy_from_slice(plain.body);
    challenge_out.copy_from_slice(&challenge.to_bytes());
    rest[..COUNTER_BYTES].copy_from_slice(&counter.to_le_bytes());
    Ok(total)
}

pub fn parse_solved_handshake_request<T: HqcScheme>(
    data: &[u8],
) -> Result<SolvedHandshakeView<'_>> {
    if data.len() != request_len::<T>(Kind::SolvedHandshake) {
        return Err(Error::SerializationError);
    }
    let header = Header::decode(data)?;
    if header != Header::request(Kind::SolvedHandshake, header.key_index, 0) {
        return Err(Error::SerializationError);
    }
    let body_len = handshake_request_body_len::<T>();
    let (body, rest) = data[HEADER_BYTES..].split_at(body_len);
    let (challenge, rest) = rest.split_at(CHALLENGE_BYTES);
    let (counter, padding) = rest.split_at(COUNTER_BYTES);
    if !is_zero(padding) {
        return Err(Error::SerializationError);
    }
    let challenge: &[u8; CHALLENGE_BYTES] = challenge
        .try_into()
        .map_err(|_| Error::SerializationError)?;
    let counter: [u8; COUNTER_BYTES] = counter.try_into().map_err(|_| Error::SerializationError)?;
    Ok(SolvedHandshakeView {
        request: split_handshake_body(body)?,
        key_index: header.key_index,
        challenge: Challenge::from_bytes(challenge),
        counter: u64::from_le_bytes(counter),
    })
}

pub struct RequestView<'a> {
    pub header: Header,
    pub cookie: &'a [u8],
    pub sealed: &'a [u8],
    pub tag: &'a [u8],
    pub aad: &'a [u8],
}

impl RequestView<'_> {
    pub fn cookie_nonce(&self) -> &Nonce {
        self.cookie
            .first_chunk::<NONCE_BYTES>()
            .expect("a parsed request holds a whole cookie")
    }
}

fn valid_request_index<T: HqcScheme>(header: &Header) -> bool {
    let index = header.index as usize;
    match header.kind {
        Kind::UChunk => index < uchunk_count::<T>(),
        Kind::VResidue => index < T::CRT_MODULI.len(),
        Kind::Handshake | Kind::Challenge | Kind::SolvedHandshake => index == 0,
    }
}

pub fn parse_request<T: HqcScheme>(data: &[u8]) -> Result<RequestView<'_>> {
    let header = Header::decode(data)?;
    if header.direction != Direction::ClientToServer
        || !matches!(header.kind, Kind::UChunk | Kind::VResidue)
    {
        return Err(Error::SerializationError);
    }
    if data.len() != request_len::<T>(header.kind) {
        return Err(Error::SerializationError);
    }
    if !valid_request_index::<T>(&header) {
        return Err(Error::InvalidResidueIndex);
    }
    let payload_len = request_payload_len::<T>(header.kind);
    let prefix_len = request_prefix_len::<T>();
    let sealed_end = prefix_len + sealed_len(payload_len);
    if !is_zero(&data[sealed_end..]) {
        return Err(Error::SerializationError);
    }
    Ok(RequestView {
        header,
        cookie: &data[HEADER_BYTES..prefix_len],
        sealed: &data[prefix_len..prefix_len + payload_len],
        tag: &data[prefix_len + payload_len..sealed_end],
        aad: &data[..prefix_len],
    })
}

pub fn write_request<T: HqcScheme>(
    out: &mut [u8],
    header: Header,
    cookie: &[u8],
    payload: &[u8],
    key: &Key,
) -> Result<usize> {
    let total = request_len::<T>(header.kind);
    let prefix_len = request_prefix_len::<T>();
    if cookie.len() != cookie_len::<T>()
        || out.len() < total
        || payload.len() != request_payload_len::<T>(header.kind)
    {
        return Err(Error::SerializationError);
    }
    let out = &mut out[..total];
    out.fill(0);
    out[..HEADER_BYTES].copy_from_slice(&header.encode());
    out[HEADER_BYTES..prefix_len].copy_from_slice(cookie);
    let (aad, rest) = out.split_at_mut(prefix_len);
    let (sealed, rest) = rest.split_at_mut(payload.len());
    sealed.copy_from_slice(payload);
    let nonce = request_nonce(&cookie[..NONCE_BYTES], header.kind as u8, header.index);
    let tag = seal(key, &nonce, aad, sealed)?;
    rest[..TAG_BYTES].copy_from_slice(&tag);
    Ok(total)
}

/// Opens the payload of a parsed request into `payload`; returns its length.
pub fn open_request(view: &RequestView<'_>, key: &Key, payload: &mut [u8]) -> Result<usize> {
    let payload = payload
        .get_mut(..view.sealed.len())
        .ok_or(Error::SerializationError)?;
    payload.copy_from_slice(view.sealed);
    let nonce = request_nonce(
        view.cookie_nonce(),
        view.header.kind as u8,
        view.header.index,
    );
    open(key, &nonce, view.aad, payload, view.tag)?;
    Ok(payload.len())
}

const MAX_RESPONSE_EXTRA_AAD_BYTES: usize = 32;
const MAX_RESPONSE_AAD_BYTES: usize = HEADER_BYTES + MAX_RESPONSE_EXTRA_AAD_BYTES;

fn response_aad(
    header: &Header,
    extra: &[u8],
    buf: &mut [u8; MAX_RESPONSE_AAD_BYTES],
) -> Result<usize> {
    if extra.len() > MAX_RESPONSE_EXTRA_AAD_BYTES {
        return Err(Error::SerializationError);
    }
    buf[..HEADER_BYTES].copy_from_slice(&header.encode());
    buf[HEADER_BYTES..HEADER_BYTES + extra.len()].copy_from_slice(extra);
    Ok(HEADER_BYTES + extra.len())
}

/// The place where a response writer puts its plaintext before
/// [`finish_response`] seals it.
pub fn response_payload_mut(out: &mut [u8], payload_len: usize) -> &mut [u8] {
    &mut out[RESPONSE_FRAMING_BYTES..RESPONSE_FRAMING_BYTES + payload_len]
}

/// Seals the payload placed by [`response_payload_mut`], writes the header,
/// nonce and tag around it, and returns the packet length.
pub fn finish_response(
    out: &mut [u8],
    header: Header,
    payload_len: usize,
    extra_aad: &[u8],
    key: &Key,
    nonce: &Nonce,
) -> Result<usize> {
    let total = RESPONSE_FRAMING_BYTES + sealed_len(payload_len);
    if out.len() < total {
        return Err(Error::SerializationError);
    }
    let mut aad_buf = [0u8; MAX_RESPONSE_AAD_BYTES];
    let aad_len = response_aad(&header, extra_aad, &mut aad_buf)?;
    out[..HEADER_BYTES].copy_from_slice(&header.encode());
    out[HEADER_BYTES..RESPONSE_FRAMING_BYTES].copy_from_slice(nonce);
    let (_, rest) = out.split_at_mut(RESPONSE_FRAMING_BYTES);
    let (payload, tail) = rest.split_at_mut(payload_len);
    let tag = seal(key, nonce, &aad_buf[..aad_len], payload)?;
    tail[..TAG_BYTES].copy_from_slice(&tag);
    Ok(total)
}

pub struct ResponseView<'a> {
    pub header: Header,
    pub nonce: &'a Nonce,
    pub sealed: &'a [u8],
    pub tag: &'a [u8],
}

pub fn parse_response<T: HqcScheme>(data: &[u8]) -> Result<ResponseView<'_>> {
    let header = Header::decode(data)?;
    if header.direction != Direction::ServerToClient
        || !Kind::SESSION.contains(&header.kind)
        || !valid_request_index::<T>(&header)
    {
        return Err(Error::SerializationError);
    }
    if data.len() != response_len::<T>(header.kind, header.index as usize) {
        return Err(Error::SerializationError);
    }
    let nonce = data[HEADER_BYTES..RESPONSE_FRAMING_BYTES]
        .try_into()
        .map_err(|_| Error::SerializationError)?;
    let tag_start = data.len() - TAG_BYTES;
    Ok(ResponseView {
        header,
        nonce,
        sealed: &data[RESPONSE_FRAMING_BYTES..tag_start],
        tag: &data[tag_start..],
    })
}

/// Opens the payload of a parsed response into `payload`; returns its length.
pub fn open_response(
    view: &ResponseView<'_>,
    extra_aad: &[u8],
    key: &Key,
    payload: &mut [u8],
) -> Result<usize> {
    let payload = payload
        .get_mut(..view.sealed.len())
        .ok_or(Error::SerializationError)?;
    payload.copy_from_slice(view.sealed);
    let mut aad_buf = [0u8; MAX_RESPONSE_AAD_BYTES];
    let aad_len = response_aad(&view.header, extra_aad, &mut aad_buf)?;
    open(key, view.nonce, &aad_buf[..aad_len], payload, view.tag)?;
    Ok(payload.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hqc::{Hqc1, Hqc3, Hqc5};

    #[test]
    fn header_roundtrips() {
        for kind in Kind::SESSION.into_iter().chain(Kind::PUZZLE) {
            for key_index in 0..2 {
                for direction in [Direction::ClientToServer, Direction::ServerToClient] {
                    let header = Header {
                        direction,
                        key_index,
                        kind,
                        index: 17,
                    };
                    assert_eq!(Header::decode(&header.encode()).unwrap(), header);
                }
            }
        }
    }

    #[test]
    fn header_rejects_reserved_bits_and_unknown_kinds() {
        assert!(Header::decode(&[0x40, 0]).is_err());
        assert!(Header::decode(&[0x08, 0]).is_err());
        assert!(Header::decode(&[0x05, 0]).is_err());
        assert!(Header::decode(&[0x00]).is_err());
    }

    fn check_sizes<T: HqcScheme>(chunks: usize) {
        assert_eq!(uchunk_count::<T>(), chunks);
        let covered: usize = (0..chunks).map(uchunk_payload_len::<T>).sum();
        assert_eq!(covered, T::VEC_N_SIZE_BYTES);
        for kind in Kind::SESSION {
            let reply_count = match kind {
                Kind::UChunk => chunks,
                Kind::VResidue => T::CRT_MODULI.len(),
                _ => 1,
            };
            let longest = (0..reply_count)
                .map(|i| response_len::<T>(kind, i))
                .max()
                .unwrap();
            assert!(request_len::<T>(kind) >= longest, "{kind:?}");
            assert!(request_len::<T>(kind) <= MAX_UDP_PAYLOAD);
            assert!(longest <= MAX_UDP_PAYLOAD);
        }
    }

    #[test]
    fn sizes_satisfy_padding_and_datagram_bounds() {
        check_sizes::<Hqc1>(2);
        check_sizes::<Hqc3>(4);
        check_sizes::<Hqc5>(7);
    }

    /// A puzzle challenge answers a phase-1 (handshake) request before the
    /// server has spent the ML-KEM decapsulation on it; it must not let an
    /// off-path attacker turn one small forged request into a larger
    /// response (reflection amplification), on any scheme.
    fn check_challenge_not_larger_than_handshake<T: HqcScheme>() {
        let handshake = request_len::<T>(Kind::Handshake);
        let challenge = challenge_response_len();
        assert!(
            challenge <= handshake,
            "challenge response ({challenge} B) is larger than the handshake request that would trigger it ({handshake} B)"
        );
    }

    #[test]
    fn challenge_response_is_not_larger_than_the_handshake_request() {
        check_challenge_not_larger_than_handshake::<Hqc1>();
        check_challenge_not_larger_than_handshake::<Hqc3>();
        check_challenge_not_larger_than_handshake::<Hqc5>();
    }
}
