use crate::math::gf2_8984::Gf2_8984;

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
    pub public_eval: Gf2_8984,
}

#[derive(Debug, Clone)]
pub struct PointResponse {
    pub point_index: u8,
    pub point_type: PointType,
    pub eval: Gf2_8984,
}
