use zeroize::Zeroize;

const SESSION_KEY_CONTEXT: &str = "HQCLethe 2026-07 session key v1";
const TRANSCRIPT_KEY_CONTEXT: &str = "HQCLethe 2026-07 transcript key v1";

/// Canonical handshake transcript length: `hash_ek_kem(32) || merkle_root(32)
/// || salt(16) || key_index(1)`. Every field is fixed-width, so plain
/// concatenation is an unambiguous encoding.
pub const TRANSCRIPT_BYTES: usize = 32 + 32 + 16 + 1;
pub const CONFIRM_TAG_BYTES: usize = 32;

/// Derive the exported session key `K_session = KDF(K, session-context)`.
pub fn derive_session_key(k: &[u8]) -> [u8; 32] {
    blake3::derive_key(SESSION_KEY_CONTEXT, k)
}

/// Derive the transcript-MAC key `K_transcript = KDF(K, transcript-context)`.
pub fn derive_transcript_key(k: &[u8]) -> [u8; 32] {
    blake3::derive_key(TRANSCRIPT_KEY_CONTEXT, k)
}

/// Serialize the handshake transcript in its canonical fixed layout.
pub fn compute_transcript(
    hash_ek_kem: &[u8; 32],
    merkle_root: &[u8; 32],
    salt: &[u8; 16],
    key_index: u8,
) -> [u8; TRANSCRIPT_BYTES] {
    let mut t = [0u8; TRANSCRIPT_BYTES];
    t[..32].copy_from_slice(hash_ek_kem);
    t[32..64].copy_from_slice(merkle_root);
    t[64..80].copy_from_slice(salt);
    t[80] = key_index;
    t
}

/// Compute the confirmation tag `MAC(K_transcript, transcript)`.
pub fn confirmation_tag(k_transcript: &[u8; 32], transcript: &[u8]) -> [u8; CONFIRM_TAG_BYTES] {
    *blake3::keyed_hash(k_transcript, transcript).as_bytes()
}

/// Verify a confirmation tag in constant time.
pub fn verify_confirmation_tag(
    k_transcript: &[u8; 32],
    transcript: &[u8],
    tag: &[u8; CONFIRM_TAG_BYTES],
) -> bool {
    let expected = blake3::keyed_hash(k_transcript, transcript);
    expected == blake3::Hash::from_bytes(*tag)
}

/// Derive `(K_session, K_transcript)` from the raw KEM secret `K`, then wipe a
/// caller-owned copy of `K`. Returned keys are the caller's responsibility to
/// zeroize.
pub fn expand_shared_secret(k: &mut [u8]) -> ([u8; 32], [u8; 32]) {
    let k_session = derive_session_key(k);
    let k_transcript = derive_transcript_key(k);
    k.zeroize();
    (k_session, k_transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_and_transcript_keys_differ() {
        let k = [7u8; 32];
        assert_ne!(
            derive_session_key(&k),
            derive_transcript_key(&k),
            "domain separation must make the two subkeys independent"
        );
    }

    #[test]
    fn tag_roundtrips_and_rejects_tampering() {
        let k = [3u8; 32];
        let kt = derive_transcript_key(&k);
        let transcript = compute_transcript(&[1; 32], &[2; 32], &[4; 16], 1);
        let tag = confirmation_tag(&kt, &transcript);
        assert!(verify_confirmation_tag(&kt, &transcript, &tag));

        // Wrong key (e.g. attacker made the client decapsulate a different K).
        let kt_other = derive_transcript_key(&[9u8; 32]);
        assert!(!verify_confirmation_tag(&kt_other, &transcript, &tag));

        // Tampered transcript (e.g. a swapped merkle_root).
        let mut t2 = transcript;
        t2[40] ^= 1;
        assert!(!verify_confirmation_tag(&kt, &t2, &tag));

        // Tampered tag.
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!verify_confirmation_tag(&kt, &transcript, &bad));
    }
}
