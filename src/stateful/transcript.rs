const TRANSCRIPT_CONTEXT: &str = "HQCLethe 2026-10 stateful transcript v1";

/// What the server's tag covers: the level, the client's HQC public key and
/// the ciphertext. Each part is hashed first,
/// so the encoding is unambiguous. A fresh HQC key per session makes a
/// replayed reply fail.
pub fn transcript(level: u8, public_key: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(TRANSCRIPT_CONTEXT);
    hasher.update(&[level]);
    for part in [public_key, ciphertext] {
        hasher.update(blake3::hash(part).as_bytes());
    }
    *hasher.finalize().as_bytes()
}
