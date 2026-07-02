#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub hash_ek_kem: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub cookie: Vec<u8>,
    pub salt: [u8; 16],
    pub key_index: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointType {
    U,
    V,
}

#[derive(Debug, Clone)]
pub struct PointRequest {
    pub cookie: Vec<u8>,
    pub key_index: u8,
    pub point_index: u8,
    pub point_type: PointType,
    /// The client's public evaluation at x_i = a^(point_index).
    /// For Type::U this is h(x_i), for Type::V this is s(x_i).
    pub public_eval: crate::math::gf2_8984::Gf2_8984,
}

#[derive(Debug, Clone)]
pub struct PointResponse {
    pub point_index: u8,
    pub point_type: PointType,
    pub eval: crate::math::gf2_8984::Gf2_8984,
}

pub trait SessionStore {
    fn save_session(&self, hash_ek_kem: &[u8; 32], k_session: [u8; 32]);
    fn get_session(&self, hash_ek_kem: &[u8; 32]) -> Option<[u8; 32]>;
}

pub trait EntropyProvider {
    fn random_bytes(&self, out: &mut [u8]);
}

pub trait CookieKeyProvider {
    /// Get the index of the current active key (0 or 1).
    fn current_key_index(&self) -> u8;

    /// Get the key for the given index (0 or 1).
    /// Returns None if the key has expired or is invalid.
    fn get_key(&self, index: u8) -> Option<[u8; 32]>;
}
