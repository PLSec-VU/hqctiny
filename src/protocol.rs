use crate::error::{Error, Result};
use crate::limits::{MAX_COOKIE_BYTES, MAX_WITNESS_BYTES};
use crate::math::gf2_9009::Gf2_9009;

/// A byte buffer backed by a fixed-size stack array rather than a `Vec`, for
/// wire fields (cookie ciphertext, Merkle witness) whose maximum size is
/// known at compile time (see `crate::limits`). Avoids a heap allocation on
/// every packet the server decodes, and — since the buffer rejects input
/// longer than `N` — bounds the allocation an attacker can induce by
/// claiming a bogus length on the wire.
#[derive(Clone, Copy)]
pub struct FixedBytes<const N: usize> {
    data: [u8; N],
    len: u16,
}

impl<const N: usize> FixedBytes<N> {
    pub fn from_slice(bytes: &[u8], too_long: Error) -> Result<Self> {
        if bytes.len() > N {
            return Err(too_long);
        }
        let mut data = [0u8; N];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len() as u16,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> std::ops::Deref for FixedBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> std::ops::DerefMut for FixedBytes<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len as usize;
        &mut self.data[..len]
    }
}

impl<const N: usize> PartialEq for FixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl<const N: usize> Eq for FixedBytes<N> {}

impl<const N: usize> std::fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FixedBytes").field(&self.as_slice()).finish()
    }
}

/// Cookie ciphertext: `nonce(24) || AEAD-ciphertext(theta || m) || tag(16)`.
pub type CookieBuf = FixedBytes<MAX_COOKIE_BYTES>;
/// Merkle inclusion proof: one 32-byte sibling hash per tree level.
pub type WitnessBuf = FixedBytes<MAX_WITNESS_BYTES>;

#[derive(Clone)]
pub struct Blake3Algorithm;

impl Blake3Algorithm {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}

pub fn serialize_point_leaf(
    point_index: u8,
    point_type: PointType,
    public_eval: &Gf2_9009,
) -> [u8; 1130] {
    let mut bytes = [0u8; 1130];
    bytes[0] = point_index;
    bytes[1] = match point_type {
        PointType::U => 0,
        PointType::V => 1,
    };
    for (i, &limb) in public_eval.data.iter().enumerate() {
        bytes[2 + i * 8..2 + i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub hash_ek_kem: [u8; 32],
    pub merkle_root: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct HandshakeResponse {
    pub cookie: CookieBuf,
    pub salt: [u8; 16],
    pub key_index: u8,
    pub mac: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointType {
    U,
    V,
}

#[derive(Debug, Clone, Copy)]
pub struct PointRequest {
    pub cookie: CookieBuf,
    pub key_index: u8,
    pub point_index: u8,
    pub point_type: PointType,
    /// The client's public evaluation at x_i = a^(point_index).
    /// For Type::U this is h(x_i), for Type::V this is s(x_i).
    pub public_eval: Gf2_9009,
    pub merkle_root: [u8; 32],
    pub witness: WitnessBuf,
}

#[derive(Debug, Clone)]
pub struct PointResponse {
    pub point_index: u8,
    pub point_type: PointType,
    pub eval: Gf2_9009,
}
