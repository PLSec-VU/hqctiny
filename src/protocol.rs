use crate::math::gf2_9009::Gf2_9009;

#[derive(Clone)]
pub struct Blake3Algorithm;

impl Blake3Algorithm {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}

impl rs_merkle::Hasher for Blake3Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        Self::hash(data)
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
    pub public_eval: Gf2_9009,
    pub merkle_root: [u8; 32],
    pub witness: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PointResponse {
    pub point_index: u8,
    pub point_type: PointType,
    pub eval: Gf2_9009,
}
