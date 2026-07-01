//! Custom binary packet encoding.

use crate::error::{Error, Result};
use crate::math::gf2_8984::{Gf2_8984, GF28984_NUM_U64};
use crate::traits::*;

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
const KIND_MASK: u8 = 0x3F; // bits 5-0: 0=handshake, 1-63=point_index
const KIND_HANDSHAKE: u8 = 0;

// ── Fixed field sizes ──────────────────────────────────────────────

const GF2_8984_BYTES: usize = GF28984_NUM_U64 * 8; // 1128

// ── Helpers ────────────────────────────────────────────────────────

fn put_u64_into(buf: &mut [u8], pos: &mut usize, v: u64) {
    buf[*pos..*pos + 8].copy_from_slice(&v.to_le_bytes());
    *pos += 8;
}

fn get_u64(data: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos + 8 > data.len() {
        return Err(Error::SerializationError);
    }
    let bytes: [u8; 8] = data[*pos..*pos + 8].try_into().unwrap();
    *pos += 8;
    Ok(u64::from_le_bytes(bytes))
}

fn put_u16_into(buf: &mut [u8], pos: &mut usize, v: u16) {
    buf[*pos..*pos + 2].copy_from_slice(&v.to_le_bytes());
    *pos += 2;
}

fn get_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > data.len() {
        return Err(Error::SerializationError);
    }
    let bytes: [u8; 2] = data[*pos..*pos + 2].try_into().unwrap();
    *pos += 2;
    Ok(u16::from_le_bytes(bytes))
}

fn get_array<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    if *pos + N > data.len() {
        return Err(Error::SerializationError);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    Ok(arr)
}

fn get_gf2(data: &[u8], pos: &mut usize) -> Result<Gf2_8984> {
    let bytes: [u8; GF2_8984_BYTES] = get_array(data, pos)?;
    Ok(Gf2_8984::from_bytes(&bytes))
}

fn put_gf2_into(buf: &mut [u8], pos: &mut usize, val: &Gf2_8984) {
    buf[*pos..*pos + GF2_8984_BYTES].copy_from_slice(&val.to_bytes());
    *pos += GF2_8984_BYTES;
}

// ── Public API ─────────────────────────────────────────────────────

pub fn encode_handshake_request<'o>(req: &HandshakeRequest, out: &'o mut [u8]) -> &'o mut [u8] {
    let total = 41;
    assert!(
        out.len() >= total,
        "encode_handshake_request buffer too small"
    );
    let mut pos = 0;
    out[pos] = 0x00; // c→s, handshake
    pos += 1;
    out[pos..pos + 32].copy_from_slice(&req.hash_ek_kem);
    pos += 32;
    put_u64_into(out, &mut pos, req.timestamp);
    &mut out[..pos]
}

pub fn decode_handshake_request(data: &[u8]) -> Result<HandshakeRequest> {
    if data.len() < 41 {
        return Err(Error::SerializationError);
    }
    if data[0] != 0x00 {
        return Err(Error::SerializationError);
    }
    let mut pos = 1;
    let hash_ek_kem = get_array::<32>(data, &mut pos)?;
    let timestamp = get_u64(data, &mut pos)?;
    Ok(HandshakeRequest {
        hash_ek_kem,
        timestamp,
    })
}

pub fn encode_handshake_response<'o>(res: &HandshakeResponse, out: &'o mut [u8]) -> &'o mut [u8] {
    let cookie_len = res.cookie.len();
    let total = 1 + 2 + cookie_len + 16;
    assert!(
        out.len() >= total,
        "encode_handshake_response buffer too small"
    );
    let mut pos = 0;
    out[pos] = 0x80; // s→c, handshake
    pos += 1;
    put_u16_into(out, &mut pos, cookie_len as u16);
    out[pos..pos + cookie_len].copy_from_slice(&res.cookie);
    pos += cookie_len;
    out[pos..pos + 16].copy_from_slice(&res.salt);
    pos += 16;
    &mut out[..pos]
}

pub fn decode_handshake_response(data: &[u8]) -> Result<HandshakeResponse> {
    if data.len() < 19 {
        return Err(Error::SerializationError);
    }
    if data[0] != 0x80 {
        return Err(Error::SerializationError);
    }
    let mut pos = 1;
    let cookie_len = get_u16(data, &mut pos)? as usize;
    if pos + cookie_len + 16 > data.len() {
        return Err(Error::SerializationError);
    }
    let mut cookie = vec![0u8; cookie_len];
    cookie.copy_from_slice(&data[pos..pos + cookie_len]);
    pos += cookie_len;
    let salt = get_array::<16>(data, &mut pos)?;
    Ok(HandshakeResponse {
        cookie,
        salt,
    })
}

pub fn encode_point_request<'o>(req: &PointRequest, out: &'o mut [u8]) -> &'o mut [u8] {
    let cookie_len = req.cookie.len();
    let total = 1 + 2 + cookie_len + 8 + GF2_8984_BYTES;
    assert!(
        out.len() >= total,
        "encode_point_request buffer too small"
    );
    let mut pos = 0;
    let idx = req.point_index.max(1);
    out[pos] = (idx & KIND_MASK)
        | match req.point_type {
            PointType::U => 0,
            PointType::V => TYPE_BIT,
        };
    pos += 1;
    put_u16_into(out, &mut pos, cookie_len as u16);
    out[pos..pos + cookie_len].copy_from_slice(&req.cookie);
    pos += cookie_len;
    put_u64_into(out, &mut pos, req.handshake_timestamp);
    put_gf2_into(out, &mut pos, &req.public_eval);
    &mut out[..pos]
}

pub fn decode_point_request(data: &[u8]) -> Result<PointRequest> {
    if data.len() < 1 + 2 + 8 + GF2_8984_BYTES {
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
    let mut pos = 1;
    let cookie_len = get_u16(data, &mut pos)? as usize;
    if pos + cookie_len + 8 + GF2_8984_BYTES > data.len() {
        return Err(Error::SerializationError);
    }
    let mut cookie = vec![0u8; cookie_len];
    cookie.copy_from_slice(&data[pos..pos + cookie_len]);
    pos += cookie_len;
    let handshake_timestamp = get_u64(data, &mut pos)?;
    let point_index = kind;
    let point_type = if header & TYPE_BIT != 0 {
        PointType::V
    } else {
        PointType::U
    };
    let public_eval = get_gf2(data, &mut pos)?;
    Ok(PointRequest {
        cookie,
        handshake_timestamp,
        point_index,
        point_type,
        public_eval,
    })
}

pub fn encode_point_response<'o>(res: &PointResponse, out: &'o mut [u8]) -> &'o mut [u8] {
    let total = 1 + 8 + GF2_8984_BYTES;
    assert!(
        out.len() >= total,
        "encode_point_response buffer too small"
    );
    let mut pos = 0;
    let idx = res.point_index.max(1);
    out[pos] = DIR_BIT
        | (idx & KIND_MASK)
        | match res.point_type {
            PointType::U => 0,
            PointType::V => TYPE_BIT,
        };
    pos += 1;
    put_u64_into(out, &mut pos, res.handshake_timestamp);
    put_gf2_into(out, &mut pos, &res.eval);
    &mut out[..pos]
}

pub fn decode_point_response(data: &[u8]) -> Result<PointResponse> {
    let total = 1 + 8 + GF2_8984_BYTES;
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
    let mut pos = 1;
    let handshake_timestamp = get_u64(data, &mut pos)?;
    let point_index = kind;
    let point_type = if header & TYPE_BIT != 0 {
        PointType::V
    } else {
        PointType::U
    };
    let eval = get_gf2(data, &mut pos)?;
    Ok(PointResponse {
        handshake_timestamp,
        point_index,
        point_type,
        eval,
    })
}

pub fn decode_packet(data: &[u8]) -> Result<Packet> {
    if data.is_empty() {
        return Err(Error::SerializationError);
    }
    let kind = data[0] & KIND_MASK;
    match kind {
        KIND_HANDSHAKE if data[0] & DIR_BIT == 0 => {
            decode_handshake_request(data).map(Packet::HandshakeRequest)
        }
        KIND_HANDSHAKE => decode_handshake_response(data).map(Packet::HandshakeResponse),
        _ if data[0] & DIR_BIT == 0 => decode_point_request(data).map(Packet::PointRequest),
        _ => decode_point_response(data).map(Packet::PointResponse),
    }
}

pub fn encode_packet<'o>(packet: &Packet, out: &'o mut [u8]) -> &'o mut [u8] {
    match packet {
        Packet::HandshakeRequest(req) => encode_handshake_request(req, out),
        Packet::HandshakeResponse(res) => encode_handshake_response(res, out),
        Packet::PointRequest(req) => encode_point_request(req, out),
        Packet::PointResponse(res) => encode_point_response(res, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_request_roundtrip() {
        let req = HandshakeRequest {
            hash_ek_kem: [0xAA; 32],
            timestamp: 12345,
        };
        let mut buf = [0u8; 128];
        let encoded = encode_handshake_request(&req, &mut buf);
        let decoded = decode_handshake_request(encoded).unwrap();
        assert_eq!(decoded.hash_ek_kem, req.hash_ek_kem);
        assert_eq!(decoded.timestamp, req.timestamp);
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        let res = HandshakeResponse {
            cookie: vec![1, 2, 3, 4, 5],
            salt: [0xBB; 16],
        };
        let mut buf = [0u8; 128];
        let encoded = encode_handshake_response(&res, &mut buf);
        let decoded = decode_handshake_response(encoded).unwrap();
        assert_eq!(decoded.cookie, res.cookie);
        assert_eq!(decoded.salt, res.salt);
    }
}
