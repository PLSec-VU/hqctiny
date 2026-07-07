//! Custom binary packet encoding.

use crate::error::{Error, Result};
use crate::hqc::HqcScheme;
use crate::math::gf2_9009::{GF29009_NUM_U64, Gf2_9009};
use crate::protocol::*;

// ── Packet type enum ───────────────────────────────────────────────

#[derive(Debug)]
pub enum Packet {
    HandshakeRequest(HandshakeRequest),
    HandshakeResponse(HandshakeResponse),
    PointRequest(PointRequest),
    PointResponse(PointResponse),
}

// ── Header constants ───────────────────────────────────────────────

const DIR_BIT: u8 = 0x80; // bit 7: set = server→client
const TYPE_BIT: u8 = 0x40; // bit 6: point_type (0=U, 1=V) — ignored for handshake
const KEY_BIT: u8 = 0x20; // bit 5: key_index (0 or 1) — ignored for handshake request/response kind, used in PointRequest and HandshakeResponse
const KIND_MASK: u8 = 0x1F; // bits 4-0: 0=handshake, 1-31=point_index
const KIND_HANDSHAKE: u8 = 0;

// ── Fixed field sizes ──────────────────────────────────────────────

const GF2_9009_BYTES: usize = GF29009_NUM_U64 * 8; // 1128

// ── Helpers ────────────────────────────────────────────────────────

fn get_array<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    if *pos + N > data.len() {
        return Err(Error::SerializationError);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    Ok(arr)
}

fn get_gf2(data: &[u8], pos: &mut usize) -> Result<Gf2_9009> {
    let bytes: [u8; GF2_9009_BYTES] = get_array(data, pos)?;
    Ok(Gf2_9009::from_bytes(&bytes))
}

fn put_gf2_into(buf: &mut [u8], pos: &mut usize, val: &Gf2_9009) {
    buf[*pos..*pos + GF2_9009_BYTES].copy_from_slice(&val.to_bytes());
    *pos += GF2_9009_BYTES;
}

// ── Public API ─────────────────────────────────────────────────────

pub fn encode_handshake_request<'o>(
    req: &HandshakeRequest,
    out: &'o mut [u8],
) -> Result<&'o mut [u8]> {
    let total = 65;
    if out.len() < total {
        return Err(Error::SerializationError);
    }
    let mut pos = 0;
    out[pos] = 0x00; // c→s, handshake (all bits 0)
    pos += 1;
    out[pos..pos + 32].copy_from_slice(&req.hash_ek_kem);
    pos += 32;
    out[pos..pos + 32].copy_from_slice(&req.merkle_root);
    pos += 32;
    Ok(&mut out[..pos])
}

pub fn decode_handshake_request(data: &[u8]) -> Result<HandshakeRequest> {
    if data.len() < 65 {
        return Err(Error::SerializationError);
    }
    if data[0] != 0x00 {
        return Err(Error::SerializationError);
    }
    let mut pos = 1;
    let hash_ek_kem = get_array::<32>(data, &mut pos)?;
    let merkle_root = get_array::<32>(data, &mut pos)?;
    Ok(HandshakeRequest {
        hash_ek_kem,
        merkle_root,
    })
}

pub fn cookie_size(param_security_bytes: usize) -> usize {
    24 + 32 + param_security_bytes + 16
}

pub fn encode_handshake_response<'o, T: HqcScheme>(
    res: &HandshakeResponse,
    out: &'o mut [u8],
) -> Result<&'o mut [u8]> {
    let cookie_len = cookie_size(T::PARAM_SECURITY_BYTES);
    if res.cookie.len() != cookie_len {
        return Err(Error::SerializationError);
    }
    let total = 1 + cookie_len + 16;
    if out.len() < total {
        return Err(Error::SerializationError);
    }
    let mut pos = 0;
    let mut tag = DIR_BIT; // s→c, handshake
    if res.key_index == 1 {
        tag |= KEY_BIT;
    }
    out[pos] = tag;
    pos += 1;
    out[pos..pos + cookie_len].copy_from_slice(&res.cookie);
    pos += cookie_len;
    out[pos..pos + 16].copy_from_slice(&res.salt);
    pos += 16;
    Ok(&mut out[..pos])
}

pub fn decode_handshake_response<T: HqcScheme>(data: &[u8]) -> Result<HandshakeResponse> {
    let cookie_len = cookie_size(T::PARAM_SECURITY_BYTES);
    let total = 1 + cookie_len + 16;
    if data.len() < total {
        return Err(Error::SerializationError);
    }
    let header = data[0];
    if header & DIR_BIT == 0 || header & KIND_MASK != KIND_HANDSHAKE {
        return Err(Error::SerializationError);
    }
    let key_index = if header & KEY_BIT != 0 { 1 } else { 0 };
    let mut pos = 1;
    let mut cookie = vec![0u8; cookie_len];
    cookie.copy_from_slice(&data[pos..pos + cookie_len]);
    pos += cookie_len;
    let salt = get_array::<16>(data, &mut pos)?;
    Ok(HandshakeResponse {
        cookie,
        salt,
        key_index,
    })
}

pub fn public_eval_limbs<T: HqcScheme>() -> usize {
    let w = crate::math::segmentation::W;
    let num_blocks = (T::VEC_N_SIZE_64 * 64).div_ceil(w).max(1);
    let max_bits = w + T::POINTS_NUM * (num_blocks - 1);
    max_bits.div_ceil(64)
}

pub fn encode_point_request<'o, T: HqcScheme>(
    req: &PointRequest,
    out: &'o mut [u8],
) -> Result<&'o mut [u8]> {
    let cookie_len = cookie_size(T::PARAM_SECURITY_BYTES);
    if req.cookie.len() != cookie_len {
        return Err(Error::SerializationError);
    }
    let limbs = public_eval_limbs::<T>();
    let eval_bytes = limbs * 8;
    let witness_len = req.witness.len();
    let total = 1 + cookie_len + eval_bytes + 32 + witness_len;
    if out.len() < total {
        return Err(Error::SerializationError);
    }
    let mut pos = 0;
    let idx = req.point_index.max(1);
    let mut tag = idx & KIND_MASK;
    if req.key_index == 1 {
        tag |= KEY_BIT;
    }
    if req.point_type == PointType::V {
        tag |= TYPE_BIT;
    }
    out[pos] = tag;
    pos += 1;

    out[pos..pos + cookie_len].copy_from_slice(&req.cookie);
    pos += cookie_len;

    for i in 0..limbs {
        out[pos..pos + 8].copy_from_slice(&req.public_eval.data[i].to_le_bytes());
        pos += 8;
    }

    out[pos..pos + 32].copy_from_slice(&req.merkle_root);
    pos += 32;

    out[pos..pos + witness_len].copy_from_slice(&req.witness);
    pos += witness_len;

    Ok(&mut out[..pos])
}

pub fn decode_point_request<T: HqcScheme>(data: &[u8]) -> Result<PointRequest> {
    if data.is_empty() {
        return Err(Error::SerializationError);
    }
    let header = data[0];
    if header & DIR_BIT != 0 {
        return Err(Error::SerializationError);
    }
    let kind = header & KIND_MASK;
    if kind == KIND_HANDSHAKE {
        return Err(Error::SerializationError);
    }
    let key_index = if header & KEY_BIT != 0 { 1 } else { 0 };
    let point_type = if header & TYPE_BIT != 0 {
        PointType::V
    } else {
        PointType::U
    };
    let point_index = kind;
    let mut pos = 1;

    let cookie_len = cookie_size(T::PARAM_SECURITY_BYTES);
    let limbs = public_eval_limbs::<T>();
    let eval_bytes = limbs * 8;
    if pos + cookie_len + eval_bytes + 32 > data.len() {
        return Err(Error::SerializationError);
    }

    let mut cookie = vec![0u8; cookie_len];
    cookie.copy_from_slice(&data[pos..pos + cookie_len]);
    pos += cookie_len;

    let mut data_limbs = [0u64; GF29009_NUM_U64];
    for limb in data_limbs.iter_mut().take(limbs) {
        *limb = u64::from_le_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| Error::SerializationError)?,
        );
        pos += 8;
    }
    let public_eval = Gf2_9009::new(data_limbs);

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    let witness_len = data.len() - pos;
    let mut witness = vec![0u8; witness_len];
    witness.copy_from_slice(&data[pos..]);

    Ok(PointRequest {
        cookie,
        key_index,
        point_index,
        point_type,
        public_eval,
        merkle_root,
        witness,
    })
}

pub fn encode_point_response<'o>(res: &PointResponse, out: &'o mut [u8]) -> Result<&'o mut [u8]> {
    let total = 1 + GF2_9009_BYTES;
    if out.len() < total {
        return Err(Error::SerializationError);
    }
    let mut pos = 0;
    let idx = res.point_index.max(1);
    let mut tag = DIR_BIT | (idx & KIND_MASK);
    if res.point_type == PointType::V {
        tag |= TYPE_BIT;
    }
    out[pos] = tag;
    pos += 1;
    put_gf2_into(out, &mut pos, &res.eval);
    Ok(&mut out[..pos])
}

pub fn decode_point_response(data: &[u8]) -> Result<PointResponse> {
    let total = 1 + GF2_9009_BYTES;
    if data.len() < total {
        return Err(Error::SerializationError);
    }
    let header = data[0];
    if header & DIR_BIT == 0 {
        return Err(Error::SerializationError);
    }
    let kind = header & KIND_MASK;
    if kind == KIND_HANDSHAKE {
        return Err(Error::SerializationError);
    }
    let point_index = kind;
    let point_type = if header & TYPE_BIT != 0 {
        PointType::V
    } else {
        PointType::U
    };
    let mut pos = 1;
    let eval = get_gf2(data, &mut pos)?;
    Ok(PointResponse {
        point_index,
        point_type,
        eval,
    })
}

pub fn encode_packet<'o, T: HqcScheme>(pkt: &Packet, out: &'o mut [u8]) -> Result<&'o mut [u8]> {
    match pkt {
        Packet::HandshakeRequest(req) => encode_handshake_request(req, out),
        Packet::HandshakeResponse(res) => encode_handshake_response::<T>(res, out),
        Packet::PointRequest(req) => encode_point_request::<T>(req, out),
        Packet::PointResponse(res) => encode_point_response(res, out),
    }
}

pub fn decode_packet<T: HqcScheme>(data: &[u8]) -> Result<Packet> {
    if data.is_empty() {
        return Err(Error::SerializationError);
    }
    let header = data[0];
    let is_server = header & DIR_BIT != 0;
    let kind = header & KIND_MASK;

    if kind == KIND_HANDSHAKE {
        if is_server {
            let res = decode_handshake_response::<T>(data)?;
            Ok(Packet::HandshakeResponse(res))
        } else {
            let req = decode_handshake_request(data)?;
            Ok(Packet::HandshakeRequest(req))
        }
    } else {
        if is_server {
            let res = decode_point_response(data)?;
            Ok(Packet::PointResponse(res))
        } else {
            let req = decode_point_request::<T>(data)?;
            Ok(Packet::PointRequest(req))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_request_roundtrip() {
        let req = HandshakeRequest {
            hash_ek_kem: [0x42; 32],
            merkle_root: [0x55; 32],
        };
        let mut buf = [0u8; 100];
        let enc = encode_handshake_request(&req, &mut buf).unwrap();
        assert_eq!(enc.len(), 65);
        let dec = decode_handshake_request(enc).unwrap();
        assert_eq!(dec.hash_ek_kem, req.hash_ek_kem);
        assert_eq!(dec.merkle_root, req.merkle_root);
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        use crate::hqc::Hqc1;
        let res = HandshakeResponse {
            cookie: vec![0xaa; 88],
            salt: [9; 16],
            key_index: 1,
        };
        let mut buf = [0u8; 200];
        let enc = encode_handshake_response::<Hqc1>(&res, &mut buf).unwrap();
        let dec = decode_handshake_response::<Hqc1>(enc).unwrap();
        assert_eq!(dec.cookie, res.cookie);
        assert_eq!(dec.salt, res.salt);
        assert_eq!(dec.key_index, res.key_index);
    }

    #[test]
    fn test_point_request_roundtrip() {
        use crate::hqc::Hqc1;
        let req = PointRequest {
            cookie: vec![0xaa; 88],
            key_index: 0,
            point_index: 1,
            point_type: PointType::U,
            public_eval: Gf2_9009::one(),
            merkle_root: [0x55; 32],
            witness: vec![9, 8, 7, 6],
        };
        let mut buf = [0u8; 2000];
        let enc = encode_point_request::<Hqc1>(&req, &mut buf).unwrap();
        // limbs for Hqc1:
        // W = 4505, num_blocks = (277 * 64).div_ceil(4505) = 4
        // max_bits = 4505 + 7 * 3 = 4526
        // limbs = 4526.div_ceil(64) = 71
        // size = 1 + 88 (cookie) + 568 (eval) + 32 (merkle_root) + 4 (witness) = 693 bytes
        assert_eq!(enc.len(), 693);
        let dec = decode_point_request::<Hqc1>(enc).unwrap();
        assert_eq!(dec.cookie, req.cookie);
        assert_eq!(dec.key_index, req.key_index);
        assert_eq!(dec.point_index, req.point_index);
        assert_eq!(dec.point_type, req.point_type);
        assert_eq!(dec.public_eval, req.public_eval);
        assert_eq!(dec.merkle_root, req.merkle_root);
        assert_eq!(dec.witness, req.witness);
    }
}
