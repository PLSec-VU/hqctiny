//! Compile-time upper bounds across all three HQC parameter sets
//! (HQC-1/3/5), used to size fixed (stack) buffers instead of heap
//! allocations in the packet-handling path. HQC-5 is the largest variant
//! in every dimension below, so it alone determines each bound.

/// `PARAM_SECURITY_BYTES`: 16 / 24 / 32 for HQC-1/3/5.
pub const MAX_PARAM_SECURITY_BYTES: usize = 32;

/// Cookie plaintext is `theta(32) || m(PARAM_SECURITY_BYTES) || h_seed(32) ||
/// K_auth(32)`.
pub const MAX_COOKIE_PLAINTEXT_BYTES: usize = 32 + MAX_PARAM_SECURITY_BYTES + 32 + 32;

/// Cookie wire format is `nonce(24) || AEAD-ciphertext(plaintext) || tag(16)`.
pub const MAX_COOKIE_BYTES: usize = 24 + MAX_COOKIE_PLAINTEXT_BYTES + 16;

/// ML-KEM-768 ciphertext in the Phase-0 request, used at every HQC level.
pub const MAX_AUTH_CT_BYTES: usize = 1088;

/// `VEC_N_SIZE_64` (`ceil(PARAM_N / 64)`): 277 / 561 / 901 for HQC-1/3/5.
pub const MAX_VEC_N_SIZE_64: usize = 901;

/// `VEC_N_SIZE_BYTES` (`ceil(PARAM_N / 8)`): 2209 / 4482 / 7205 for HQC-1/3/5.
pub const MAX_VEC_N_SIZE_BYTES: usize = 7205;

/// The largest opened request payload: the s residue of the HQC-5 CRT moduli.
pub const MAX_REQUEST_PAYLOAD_BYTES: usize = crate::crt::MAX_RESIDUE_BYTES;

/// Seconds between cookie-key rotations. A cookie key stays usable for one more
/// rotation after it stops being the active key, so a cookie is accepted for
/// at least one and less than two rotation periods. This is also how long the
/// replay filter must remember a request (see `replay`).
pub const COOKIE_ROTATION_SECS: u32 = 10;

/// A puzzle challenge is accepted for as long as the key that authenticated it
/// is certain to exist: one rotation interval.
pub const PUZZLE_MAX_AGE_SECS: u32 = COOKIE_ROTATION_SECS;
