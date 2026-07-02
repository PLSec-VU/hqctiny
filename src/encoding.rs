//! Custom binary packet encoding.

use crate::error::{Error, Result};
use crate::math::gf2_8984::{GF28984_NUM_U64, Gf2_8984};
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

const GF2_8984_BYTES: usize = GF28984_NUM_U64 * 8; // 1128

// ── Helpers ────────────────────────────────────────────────────────

fn put_u16_into(buf: &mut [u8], pos: &mut usize, v: u16) {
    buf[*pos..*pos + 2].copy_from_slice(&v.to_le_bytes());
    *pos += 2;
}

fn get_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > data.len() {
        return Err(Error::SerializationError);
    }
    let bytes: [u8; 2] = data[*pos..*pos + 2]
        .try_into()
        .map_err(|_| Error::SerializationError)?;
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

pub fn encode_handshake_request<'o>(
    req: &HandshakeRequest,
    out: &'o mut [u8],
) -> Result<&'o mut [u8]> {
    let total = 33;
    if out.len() < total {
        return Err(Error::SerializationError);
    }
    let mut pos = 0;
    out[pos] = 0x00; // c→s, handshake (all bits 0)
    pos += 1;
    out[pos..pos + 32].copy_from_slice(&req.hash_ek_kem);
    pos += 32;
    Ok(&mut out[..pos])
}

pub fn decode_handshake_request(data: &[u8]) -> Result<HandshakeRequest> {
    if data.len() < 33 {
        return Err(Error::SerializationError);
    }
    if data[0] != 0x00 {
        return Err(Error::SerializationError);
    }
    let mut pos = 1;
    let hash_ek_kem = get_array::<32>(data, &mut pos)?;
    Ok(HandshakeRequest { hash_ek_kem })
}

pub fn encode_handshake_response<'o>(
    res: &HandshakeResponse,
    out: &'o mut [u8],
) -> Result<&'o mut [u8]> {
    let cookie_len = res.cookie.len();
    let total = 1 + 2 + cookie_len + 16;
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
    put_u16_into(out, &mut pos, cookie_len as u16);
    out[pos..pos + cookie_len].copy_from_slice(&res.cookie);
    pos += cookie_len;
    out[pos..pos + 16].copy_from_slice(&res.salt);
    pos += 16;
    Ok(&mut out[..pos])
}

pub fn decode_handshake_response(data: &[u8]) -> Result<HandshakeResponse> {
    if data.len() < 19 {
        return Err(Error::SerializationError);
    }
    let header = data[0];
    if header & DIR_BIT == 0 || header & KIND_MASK != KIND_HANDSHAKE {
        return Err(Error::SerializationError);
    }
    let key_index = if header & KEY_BIT != 0 { 1 } else { 0 };
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
        key_index,
    })
}

pub fn encode_point_request<'o>(req: &PointRequest, out: &'o mut [u8]) -> Result<&'o mut [u8]> {
    let cookie_len = req.cookie.len();
    let total = 1 + 2 + cookie_len + GF2_8984_BYTES;
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
    put_u16_into(out, &mut pos, cookie_len as u16);
    out[pos..pos + cookie_len].copy_from_slice(&req.cookie);
    pos += cookie_len;
    put_gf2_into(out, &mut pos, &req.public_eval);
    Ok(&mut out[..pos])
}

pub fn decode_point_request(data: &[u8]) -> Result<PointRequest> {
    if data.len() < 1 + 2 + GF2_8984_BYTES {
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
    let cookie_len = get_u16(data, &mut pos)? as usize;
    if pos + cookie_len + GF2_8984_BYTES > data.len() {
        return Err(Error::SerializationError);
    }
    let mut cookie = vec![0u8; cookie_len];
    cookie.copy_from_slice(&data[pos..pos + cookie_len]);
    pos += cookie_len;
    let public_eval = get_gf2(data, &mut pos)?;
    Ok(PointRequest {
        cookie,
        key_index,
        point_index,
        point_type,
        public_eval,
    })
}

pub fn encode_point_response<'o>(res: &PointResponse, out: &'o mut [u8]) -> Result<&'o mut [u8]> {
    let total = 1 + GF2_8984_BYTES;
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
    let total = 1 + GF2_8984_BYTES;
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

pub fn encode_packet<'o>(pkt: &Packet, out: &'o mut [u8]) -> Result<&'o mut [u8]> {
    match pkt {
        Packet::HandshakeRequest(req) => encode_handshake_request(req, out),
        Packet::HandshakeResponse(res) => encode_handshake_response(res, out),
        Packet::PointRequest(req) => encode_point_request(req, out),
        Packet::PointResponse(res) => encode_point_response(res, out),
    }
}

pub fn decode_packet(data: &[u8]) -> Result<Packet> {
    if data.is_empty() {
        return Err(Error::SerializationError);
    }
    let header = data[0];
    let is_server = header & DIR_BIT != 0;
    let kind = header & KIND_MASK;

    if kind == KIND_HANDSHAKE {
        if is_server {
            let res = decode_handshake_response(data)?;
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
            let req = decode_point_request(data)?;
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
        };
        let mut buf = [0u8; 100];
        let enc = encode_handshake_request(&req, &mut buf).unwrap();
        assert_eq!(enc.len(), 33);
        let dec = decode_handshake_request(enc).unwrap();
        assert_eq!(dec.hash_ek_kem, req.hash_ek_kem);
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        let res = HandshakeResponse {
            cookie: vec![1, 2, 3, 4, 5],
            salt: [9; 16],
            key_index: 1,
        };
        let mut buf = [0u8; 100];
        let enc = encode_handshake_response(&res, &mut buf).unwrap();
        let dec = decode_handshake_response(enc).unwrap();
        assert_eq!(dec.cookie, res.cookie);
        assert_eq!(dec.salt, res.salt);
        assert_eq!(dec.key_index, res.key_index);
    }
}
