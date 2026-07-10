//! Compile-time upper bounds across all three HQC parameter sets
//! (HQC-1/3/5), used to size fixed (stack) buffers instead of heap
//! allocations in the packet-handling path. HQC-5 is the largest variant
//! in every dimension below, so it alone determines each bound.

/// `PARAM_SECURITY_BYTES`: 16 / 24 / 32 for HQC-1/3/5.
pub const MAX_PARAM_SECURITY_BYTES: usize = 32;

/// Cookie plaintext is `theta(32) || m(PARAM_SECURITY_BYTES)`.
pub const MAX_COOKIE_PLAINTEXT_BYTES: usize = 32 + MAX_PARAM_SECURITY_BYTES;

/// Cookie wire format is `nonce(24) || AEAD-ciphertext(plaintext) || tag(16)`.
pub const MAX_COOKIE_BYTES: usize = 24 + MAX_COOKIE_PLAINTEXT_BYTES + 16;

/// Merkle proof is `tree_depth * 32` bytes. HQC-5 has 25 points x 2 leaves
/// = 50 leaves -> capacity 64 -> depth 6, the deepest of the three trees.
pub const MAX_WITNESS_BYTES: usize = 6 * 32;

/// `VEC_N_SIZE_64` (`ceil(PARAM_N / 64)`): 277 / 561 / 901 for HQC-1/3/5.
pub const MAX_VEC_N_SIZE_64: usize = 901;
