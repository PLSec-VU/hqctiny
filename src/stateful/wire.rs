use super::cookie::{COOKIE_BYTES, Cookie, cookie_nonce};
use crate::envelope::{self, Key, NONCE_BYTES, Nonce, TAG_BYTES};
use crate::error::{Error, Result};
use std::ops::Range;

pub const MAX_DATAGRAM_BYTES: usize = 1232;
pub const HELLO_NONCE_BYTES: usize = 8;
pub const CT_ID_BYTES: usize = 4;

const TAG_HELLO: u8 = 0x01;
const TAG_SERVER_HELLO: u8 = 0x02;
const TAG_KEY_FRAGMENT: u8 = 0x03;
const TAG_CT_FRAGMENT: u8 = 0x04;

pub const KIND_KEY_FRAGMENT: u8 = TAG_KEY_FRAGMENT;

const HELLO_HEADER_BYTES: usize = 2 + HELLO_NONCE_BYTES;
const SERVER_HELLO_BYTES: usize = 1 + NONCE_BYTES + COOKIE_BYTES + TAG_BYTES;
const KEY_FRAGMENT_HEADER_BYTES: usize = 2 + COOKIE_BYTES + 4;
const CT_FRAGMENT_HEADER_BYTES: usize = 2 + CT_ID_BYTES + 4;
const CT_FRAGMENT_OVERHEAD_BYTES: usize = CT_FRAGMENT_HEADER_BYTES + NONCE_BYTES + TAG_BYTES;
pub const KEY_FRAGMENT_OVERHEAD_BYTES: usize = KEY_FRAGMENT_HEADER_BYTES + TAG_BYTES;

pub const KEY_FRAGMENT_PAYLOAD_BYTES: usize = MAX_DATAGRAM_BYTES - KEY_FRAGMENT_OVERHEAD_BYTES;
pub const CT_FRAGMENT_PAYLOAD_BYTES: usize = MAX_DATAGRAM_BYTES - CT_FRAGMENT_OVERHEAD_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum Message<'a> {
    Hello {
        level: u8,
        nonce: [u8; HELLO_NONCE_BYTES],
        auth_request: &'a [u8],
    },
    ServerHello {
        nonce: Nonce,
        sealed_cookie: &'a [u8],
    },
    KeyFragment {
        level: u8,
        cookie: Cookie,
        index: u16,
        count: u16,
        header: &'a [u8],
        sealed: &'a [u8],
    },
    CtFragment {
        level: u8,
        ct_id: [u8; CT_ID_BYTES],
        index: u16,
        count: u16,
        header: &'a [u8],
        nonce: Nonce,
        sealed: &'a [u8],
    },
}

fn fragment_count(total_bytes: usize, fragment_bytes: usize) -> usize {
    total_bytes.div_ceil(fragment_bytes)
}

fn fragment_range(index: usize, total_bytes: usize, fragment_bytes: usize) -> Range<usize> {
    let start = index * fragment_bytes;
    start..(start + fragment_bytes).min(total_bytes)
}

pub fn key_fragment_count(total_bytes: usize) -> usize {
    fragment_count(total_bytes, KEY_FRAGMENT_PAYLOAD_BYTES)
}

pub fn key_fragment_range(index: usize, total_bytes: usize) -> Range<usize> {
    fragment_range(index, total_bytes, KEY_FRAGMENT_PAYLOAD_BYTES)
}

pub fn ct_fragment_count(total_bytes: usize) -> usize {
    fragment_count(total_bytes, CT_FRAGMENT_PAYLOAD_BYTES)
}

pub fn ct_fragment_range(index: usize, total_bytes: usize) -> Range<usize> {
    fragment_range(index, total_bytes, CT_FRAGMENT_PAYLOAD_BYTES)
}

fn array_at<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data[offset..offset + N].try_into().unwrap()
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(array_at(data, offset))
}

pub fn parse(data: &[u8]) -> Option<Message<'_>> {
    match *data.first()? {
        TAG_HELLO if data.len() >= HELLO_HEADER_BYTES => Some(Message::Hello {
            level: data[1],
            nonce: array_at(data, 2),
            auth_request: &data[HELLO_HEADER_BYTES..],
        }),
        TAG_SERVER_HELLO if data.len() == SERVER_HELLO_BYTES => Some(Message::ServerHello {
            nonce: array_at(data, 1),
            sealed_cookie: &data[1 + NONCE_BYTES..],
        }),
        TAG_KEY_FRAGMENT if data.len() >= KEY_FRAGMENT_OVERHEAD_BYTES => {
            Some(Message::KeyFragment {
                level: data[1],
                cookie: array_at(data, 2),
                index: u16_at(data, 2 + COOKIE_BYTES),
                count: u16_at(data, 4 + COOKIE_BYTES),
                header: &data[..KEY_FRAGMENT_HEADER_BYTES],
                sealed: &data[KEY_FRAGMENT_HEADER_BYTES..],
            })
        }
        TAG_CT_FRAGMENT if data.len() >= CT_FRAGMENT_OVERHEAD_BYTES => Some(Message::CtFragment {
            level: data[1],
            ct_id: array_at(data, 2),
            index: u16_at(data, 2 + CT_ID_BYTES),
            count: u16_at(data, 4 + CT_ID_BYTES),
            header: &data[..CT_FRAGMENT_HEADER_BYTES],
            nonce: array_at(data, CT_FRAGMENT_HEADER_BYTES),
            sealed: &data[CT_FRAGMENT_HEADER_BYTES + NONCE_BYTES..],
        }),
        _ => None,
    }
}

pub fn encode_hello(level: u8, nonce: &[u8; HELLO_NONCE_BYTES], auth_request: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG_HELLO, level];
    out.extend_from_slice(nonce);
    out.extend_from_slice(auth_request);
    out
}

fn seal_into(out: &mut Vec<u8>, key: &Key, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) {
    let start = out.len();
    out.extend_from_slice(plaintext);
    let tag = envelope::seal(key, nonce, aad, &mut out[start..]).expect("seal cannot fail");
    out.extend_from_slice(&tag);
}

fn open_sealed(key: &Key, nonce: &Nonce, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let split = sealed
        .len()
        .checked_sub(TAG_BYTES)
        .ok_or(Error::DecryptionError)?;
    let (ciphertext, tag) = sealed.split_at(split);
    let mut plaintext = ciphertext.to_vec();
    envelope::open(key, nonce, aad, &mut plaintext, tag)?;
    Ok(plaintext)
}

fn hello_digest(hello: &[u8]) -> [u8; 32] {
    *blake3::hash(hello).as_bytes()
}

pub fn encode_server_hello(key: &Key, nonce: &Nonce, hello: &[u8], cookie: &Cookie) -> Vec<u8> {
    let mut out = vec![TAG_SERVER_HELLO];
    out.extend_from_slice(nonce);
    seal_into(&mut out, key, nonce, &hello_digest(hello), cookie);
    out
}

pub fn open_server_hello(
    key: &Key,
    nonce: &Nonce,
    hello: &[u8],
    sealed_cookie: &[u8],
) -> Result<Cookie> {
    open_sealed(key, nonce, &hello_digest(hello), sealed_cookie)?
        .try_into()
        .map_err(|_| Error::SerializationError)
}

pub fn encode_key_fragment(
    key: &Key,
    level: u8,
    cookie: &Cookie,
    index: usize,
    public_key: &[u8],
) -> Vec<u8> {
    let mut out = vec![TAG_KEY_FRAGMENT, level];
    out.extend_from_slice(cookie);
    out.extend_from_slice(&(index as u16).to_le_bytes());
    out.extend_from_slice(&(key_fragment_count(public_key.len()) as u16).to_le_bytes());
    let header = out.clone();
    let nonce = envelope::request_nonce(cookie_nonce(cookie), KIND_KEY_FRAGMENT, index as u8);
    let piece = &public_key[key_fragment_range(index, public_key.len())];
    seal_into(&mut out, key, &nonce, &header, piece);
    out
}

pub fn open_key_fragment(
    key: &Key,
    cookie: &Cookie,
    index: u16,
    header: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let nonce = envelope::request_nonce(cookie_nonce(cookie), KIND_KEY_FRAGMENT, index as u8);
    open_sealed(key, &nonce, header, sealed)
}

pub fn encode_ct_fragment(
    key: &Key,
    nonce: &Nonce,
    level: u8,
    ct_id: &[u8; CT_ID_BYTES],
    index: usize,
    response: &[u8],
) -> Vec<u8> {
    let mut out = vec![TAG_CT_FRAGMENT, level];
    out.extend_from_slice(ct_id);
    out.extend_from_slice(&(index as u16).to_le_bytes());
    out.extend_from_slice(&(ct_fragment_count(response.len()) as u16).to_le_bytes());
    let header = out.clone();
    out.extend_from_slice(nonce);
    let piece = &response[ct_fragment_range(index, response.len())];
    seal_into(&mut out, key, nonce, &header, piece);
    out
}

pub fn open_ct_fragment(key: &Key, header: &[u8], nonce: &Nonce, sealed: &[u8]) -> Result<Vec<u8>> {
    open_sealed(key, nonce, header, sealed)
}

pub fn key_fragments(key: &Key, level: u8, cookie: &Cookie, public_key: &[u8]) -> Vec<Vec<u8>> {
    (0..key_fragment_count(public_key.len()))
        .map(|index| encode_key_fragment(key, level, cookie, index, public_key))
        .collect()
}
