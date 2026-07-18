use HQCLethe::client::{Client, PointResult};
use HQCLethe::error::Error;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
mod test_utils;
use std::sync::{Arc, Mutex};
use test_utils::{MockEntropy, SharedSessionStore};

fn test_protocol_flow_generic<SCHEME: HqcScheme>(name: &str) {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let store = SharedSessionStore {
        sessions: sessions.clone(),
    };

    let server = Server::<SCHEME, _, _>::new(store, MockEntropy);

    let client = Client::<SCHEME, _, _, _>::new(
        SharedSessionStore {
            sessions: Arc::new(Mutex::new(Vec::new())),
        },
        MockEntropy,
    );

    let mut packets_sent = 0;
    let mut packets_received = 0;

    // 1. Initialize Handshake Request
    let (client, req) = client.initialize();

    // Serialize Handshake Request
    let mut buf = vec![0u8; 4096];
    let encoded_req = HQCLethe::encoding::encode_packet::<SCHEME>(
        &HQCLethe::encoding::Packet::HandshakeRequest(req),
        &mut buf,
    )
    .unwrap();
    packets_sent += 1;
    println!(
        "[{}] Client -> Server: HandshakeRequest ({} bytes)",
        name,
        encoded_req.len()
    );

    // Deserialize Handshake Request on the server side
    let decoded_req_pkt = HQCLethe::encoding::decode_packet::<SCHEME>(encoded_req).unwrap();
    let decoded_req = match decoded_req_pkt {
        HQCLethe::encoding::Packet::HandshakeRequest(r) => r,
        _ => panic!("Expected HandshakeRequest"),
    };

    // 2. Server handles Handshake Request
    let res = server.handle_handshake(decoded_req).unwrap();

    // Serialize Handshake Response
    let mut buf = vec![0u8; 4096];
    let encoded_res = HQCLethe::encoding::encode_packet::<SCHEME>(
        &HQCLethe::encoding::Packet::HandshakeResponse(res),
        &mut buf,
    )
    .unwrap();
    packets_received += 1;
    println!(
        "[{}] Server -> Client: HandshakeResponse ({} bytes)",
        name,
        encoded_res.len()
    );

    // Deserialize Handshake Response on the client side
    let decoded_res_pkt = HQCLethe::encoding::decode_packet::<SCHEME>(encoded_res).unwrap();
    let decoded_res = match decoded_res_pkt {
        HQCLethe::encoding::Packet::HandshakeResponse(r) => r,
        _ => panic!("Expected HandshakeResponse"),
    };

    // 3. Client handles Handshake Response
    let (client, point_reqs) = client.handle_handshake_response(decoded_res).unwrap();
    assert_eq!(point_reqs.len(), SCHEME::POINTS_NUM * 2);

    // 4. Point Stream
    let mut client = client;
    let mut client_key = None;
    for req in point_reqs {
        let req_index = req.point_index;
        let req_type = req.point_type;

        // Serialize Point Request
        let mut buf = vec![0u8; 8192];
        let encoded_preq = HQCLethe::encoding::encode_packet::<SCHEME>(
            &HQCLethe::encoding::Packet::PointRequest(req),
            &mut buf,
        )
        .unwrap();
        packets_sent += 1;
        println!(
            "[{}] Client -> Server: PointRequest (index={}, type={:?}, {} bytes)",
            name,
            req_index,
            req_type,
            encoded_preq.len()
        );

        // Deserialize Point Request on the server side
        let decoded_preq_pkt = HQCLethe::encoding::decode_packet::<SCHEME>(encoded_preq).unwrap();
        let decoded_preq = match decoded_preq_pkt {
            HQCLethe::encoding::Packet::PointRequest(r) => r,
            _ => panic!("Expected PointRequest"),
        };

        // Server processes Point Request
        let point_res = server.handle_point_request(decoded_preq).unwrap();

        // Serialize Point Response
        let mut buf = vec![0u8; 8192];
        let encoded_pres = HQCLethe::encoding::encode_packet::<SCHEME>(
            &HQCLethe::encoding::Packet::PointResponse(point_res),
            &mut buf,
        )
        .unwrap();
        packets_received += 1;
        println!(
            "[{}] Server -> Client: PointResponse (index={}, type={:?}, {} bytes)",
            name,
            req_index,
            req_type,
            encoded_pres.len()
        );

        // Deserialize Point Response on the client side
        let decoded_pres_pkt = HQCLethe::encoding::decode_packet::<SCHEME>(encoded_pres).unwrap();
        let decoded_pres = match decoded_pres_pkt {
            HQCLethe::encoding::Packet::PointResponse(r) => r,
            _ => panic!("Expected PointResponse"),
        };

        // Client processes Point Response
        match client.handle_point_response(decoded_pres).unwrap() {
            PointResult::Collecting(c) => client = *c,
            PointResult::Completed(_, key) => {
                client_key = Some(key);
                break;
            }
        }
    }

    let client_key = client_key.expect("Handshake should complete and return session key");
    assert!(
        !client_key.iter().all(|&b| b == 0),
        "Session key should not be all zeros"
    );

    // 5. Verify server has saved the identical session key
    let saved = sessions.lock().unwrap();
    assert_eq!(saved.len(), 1);
    let server_key = saved.iter().next().unwrap();

    assert_eq!(client_key.as_slice(), &server_key[..client_key.len()]);

    println!(
        "[{}] Protocol Flow Completed. Packets: {} sent, {} received.",
        name, packets_sent, packets_received
    );
}

#[test]
fn test_protocol_flow_hqc1() {
    test_protocol_flow_generic::<Hqc1>("HQC-1");
}

#[test]
fn test_protocol_flow_hqc3() {
    test_protocol_flow_generic::<Hqc3>("HQC-3");
}

#[test]
fn test_protocol_flow_hqc5() {
    test_protocol_flow_generic::<Hqc5>("HQC-5");
}

#[test]
fn test_cookie_key_rotation() {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let store = SharedSessionStore {
        sessions: sessions.clone(),
    };

    let server = Server::<Hqc1, _, _>::new(store, MockEntropy);

    let client = Client::<Hqc1, _, _, _>::new(
        SharedSessionStore {
            sessions: Arc::new(Mutex::new(Vec::new())),
        },
        MockEntropy,
    );

    // 1. Handshake
    let (client, req) = client.initialize();
    let res = server.handle_handshake(req).unwrap();

    // 2. Rotate keys in server twice (overwriting both slots so the old key is erased)
    server.rotate();
    server.rotate();

    // 3. Client attempts to process response and send point request
    let (_client, point_reqs) = client.handle_handshake_response(res).unwrap();
    let req = point_reqs[0];

    // 4. Server should fail to decrypt cookie (returns SessionExpired because key was overwritten/erased)
    let res = server.handle_point_request(req);
    assert!(matches!(
        res,
        Err(Error::SessionExpired) | Err(Error::DecryptionError)
    ));
}

#[test]
fn test_invalid_merkle_witness_rejected() {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let store = SharedSessionStore {
        sessions: sessions.clone(),
    };

    let server = Server::<Hqc1, _, _>::new(store, MockEntropy);

    let client = Client::<Hqc1, _, _, _>::new(
        SharedSessionStore {
            sessions: Arc::new(Mutex::new(Vec::new())),
        },
        MockEntropy,
    );

    // 1. Handshake
    let (client, req) = client.initialize();
    let res = server.handle_handshake(req).unwrap();

    // 2. Client processes response and generates point requests
    let (_client, point_reqs) = client.handle_handshake_response(res).unwrap();

    // Test Case 1: Corrupted public evaluation point
    let mut req_corrupted_val = point_reqs[0];
    req_corrupted_val.public_eval.data[0] ^= 1; // flip a bit
    let res_corrupted_val = server.handle_point_request(req_corrupted_val);
    assert_eq!(
        res_corrupted_val.unwrap_err(),
        Error::MerkleVerificationFailed
    );

    // Test Case 2: Corrupted witness bytes
    let mut req_corrupted_witness = point_reqs[0];
    if !req_corrupted_witness.witness.is_empty() {
        req_corrupted_witness.witness[0] ^= 1;
    }
    let res_corrupted_witness = server.handle_point_request(req_corrupted_witness);
    assert!(matches!(
        res_corrupted_witness,
        Err(Error::MerkleVerificationFailed) | Err(Error::InvalidWitness)
    ));
}

#[test]
fn test_invalid_merkle_root_rejected() {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let store = SharedSessionStore {
        sessions: sessions.clone(),
    };

    let server = Server::<Hqc1, _, _>::new(store, MockEntropy);

    let client = Client::<Hqc1, _, _, _>::new(
        SharedSessionStore {
            sessions: Arc::new(Mutex::new(Vec::new())),
        },
        MockEntropy,
    );

    // 1. Handshake
    let (client, req) = client.initialize();
    let res = server.handle_handshake(req).unwrap();

    // 2. Client processes response and generates point requests
    let (_client, point_reqs) = client.handle_handshake_response(res).unwrap();

    // Corrupt merkle_root in the point request
    let mut req_corrupted_root = point_reqs[0];
    req_corrupted_root.merkle_root[0] ^= 1;

    // Since merkle_root is used as AAD, changing it should make decryption fail
    let res_corrupted_root = server.handle_point_request(req_corrupted_root);
    assert_eq!(res_corrupted_root.unwrap_err(), Error::DecryptionError);
}

/// A silent MITM that forges Phase 2 point responses (injecting its own
/// ciphertext) makes the client decapsulate a different KEM secret. The
/// handshake confirmation tag is keyed on the genuine server's secret, so the
/// client's key confirmation must fail rather than exporting an attacker-known
/// key. We model the forgery as a one-bit tamper of a single point response.
#[test]
fn test_tampered_point_response_fails_key_confirmation() {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let server = Server::<Hqc1, _, _>::new(
        SharedSessionStore {
            sessions: sessions.clone(),
        },
        MockEntropy,
    );
    let client = Client::<Hqc1, _, _, _>::new(
        SharedSessionStore {
            sessions: Arc::new(Mutex::new(Vec::new())),
        },
        MockEntropy,
    );

    let (client, req) = client.initialize();
    let res = server.handle_handshake(req).unwrap();
    let (mut client, point_reqs) = client.handle_handshake_response(res).unwrap();

    let mut outcome = None;
    for (i, req) in point_reqs.into_iter().enumerate() {
        let mut pres = server.handle_point_request(req).unwrap();
        if i == 0 {
            // Attacker corrupts one evaluation on the insecure channel.
            pres.eval.data[0] ^= 1;
        }
        match client.handle_point_response(pres) {
            Ok(PointResult::Collecting(c)) => client = *c,
            Ok(PointResult::Completed(..)) => panic!("tampered stream must not confirm the key"),
            Err(e) => {
                outcome = Some(e);
                break;
            }
        }
    }
    assert_eq!(outcome, Some(Error::KeyConfirmationFailed));
}

/// If the confirmation tag itself is corrupted (which on a real deployment
/// would require breaking the handshake channel's authentication), the client
/// must reject even a genuine, untampered point stream.
#[test]
fn test_corrupted_handshake_tag_fails_key_confirmation() {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let server = Server::<Hqc1, _, _>::new(
        SharedSessionStore {
            sessions: sessions.clone(),
        },
        MockEntropy,
    );
    let client = Client::<Hqc1, _, _, _>::new(
        SharedSessionStore {
            sessions: Arc::new(Mutex::new(Vec::new())),
        },
        MockEntropy,
    );

    let (client, req) = client.initialize();
    let mut res = server.handle_handshake(req).unwrap();
    res.mac[0] ^= 1; // corrupt the confirmation tag
    let (mut client, point_reqs) = client.handle_handshake_response(res).unwrap();

    let mut outcome = None;
    for req in point_reqs {
        let pres = server.handle_point_request(req).unwrap();
        match client.handle_point_response(pres) {
            Ok(PointResult::Collecting(c)) => client = *c,
            Ok(PointResult::Completed(..)) => panic!("corrupted tag must not confirm the key"),
            Err(e) => {
                outcome = Some(e);
                break;
            }
        }
    }
    assert_eq!(outcome, Some(Error::KeyConfirmationFailed));
}
