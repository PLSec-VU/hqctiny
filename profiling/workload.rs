#![allow(dead_code)]

use HQCTiny::client::{Client, PointResult};
use HQCTiny::encoding::{Packet, decode_packet, encode_packet};
use HQCTiny::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCTiny::server::Server;
use HQCTiny::traits::*;
use rand::Rng;

#[derive(Clone)]
struct Entropy;
impl EntropyProvider for Entropy {
    fn random_bytes(&self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

#[derive(Clone, Default)]
struct NullSessionStore;
impl SessionStore for NullSessionStore {
    fn save_session(&self, _k_session: [u8; 32]) {}
}

pub fn run_round_trip<SCHEME: HqcScheme>() {
    let server = Server::<SCHEME, _, _>::new(NullSessionStore, Entropy);
    let client = Client::<SCHEME, _, _, _>::new(NullSessionStore, Entropy);

    let (client, req) = client.initialize();
    let mut buf = vec![0u8; 4096];
    let encoded = encode_packet::<SCHEME>(&Packet::HandshakeRequest(req), &mut buf).unwrap();
    let decoded_req = match decode_packet::<SCHEME>(encoded).unwrap() {
        Packet::HandshakeRequest(r) => r,
        _ => unreachable!(),
    };

    let res = server.handle_handshake(decoded_req).unwrap();
    let mut buf = vec![0u8; 4096];
    let encoded = encode_packet::<SCHEME>(&Packet::HandshakeResponse(res), &mut buf).unwrap();
    let decoded_res = match decode_packet::<SCHEME>(encoded).unwrap() {
        Packet::HandshakeResponse(r) => r,
        _ => unreachable!(),
    };

    let (mut client, point_reqs) = client.handle_handshake_response(decoded_res).unwrap();
    for req in point_reqs {
        let mut buf = vec![0u8; 8192];
        let encoded = encode_packet::<SCHEME>(&Packet::PointRequest(req), &mut buf).unwrap();
        let decoded_preq = match decode_packet::<SCHEME>(encoded).unwrap() {
            Packet::PointRequest(r) => r,
            _ => unreachable!(),
        };

        let point_res = server.handle_point_request(decoded_preq).unwrap();
        let mut buf = vec![0u8; 8192];
        let encoded = encode_packet::<SCHEME>(&Packet::PointResponse(point_res), &mut buf).unwrap();
        let decoded_pres = match decode_packet::<SCHEME>(encoded).unwrap() {
            Packet::PointResponse(r) => r,
            _ => unreachable!(),
        };

        match client.handle_point_response(decoded_pres).unwrap() {
            PointResult::Collecting(c) => client = *c,
            PointResult::Completed(_, _) => break,
        }
    }
}

pub fn run_all(iterations: usize) {
    for _ in 0..iterations {
        run_round_trip::<Hqc1>();
        run_round_trip::<Hqc3>();
        run_round_trip::<Hqc5>();
    }
}
