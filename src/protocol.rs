use crate::error::{Error, Result};
use crate::limits::MAX_AUTH_CT_BYTES;

/// A byte buffer backed by a fixed-size stack array rather than a `Vec`, for
/// wire fields (the ML-KEM ciphertext) whose maximum size is
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

/// ML-KEM-768 ciphertext to the server's long-term key.
pub type AuthCtBuf = FixedBytes<MAX_AUTH_CT_BYTES>;
