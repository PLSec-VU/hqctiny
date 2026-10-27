use HQCLethe::auth::{ServerKeypair, shared_keypair};
use HQCLethe::client::{AwaitingHandshake, Client, Collecting, Initial, Progress};
use HQCLethe::encoding::{self, Header, Kind, MAX_UDP_PAYLOAD};
use HQCLethe::envelope::Key;
use HQCLethe::error::Error;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::session::run_in_process;
mod test_utils;
use std::sync::{Arc, Mutex};
use test_utils::{MockEntropy, ScriptedEntropy, SharedSessionStore};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

type TestServer<S> = Server<S, SharedSessionStore, MockEntropy>;
type TestClient<S, State> = Client<S, SharedSessionStore, MockEntropy, State>;
type RecordedSessions = Arc<Mutex<Vec<[u8; 32]>>>;

fn server_with_sessions<S: HqcScheme>() -> (TestServer<S>, RecordedSessions) {
    let store = SharedSessionStore::new();
    let sessions = store.sessions.clone();
    let server = Server::new(store, MockEntropy, shared_keypair::<S>().secret.clone());
    (server, sessions)
}

fn new_client<S: HqcScheme>() -> TestClient<S, Initial> {
    Client::new(SharedSessionStore::new(), MockEntropy)
}

fn serve<S: HqcScheme>(server: &TestServer<S>, request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, request, &mut out)?;
    Ok(out[..len].to_vec())
}

struct Rig<S: HqcScheme> {
    server: TestServer<S>,
    sessions: RecordedSessions,
    client: TestClient<S, Collecting>,
    handshake_request: Vec<u8>,
    handshake_response: Vec<u8>,
}

fn rig<S: HqcScheme>() -> Rig<S> {
    let (server, sessions) = server_with_sessions::<S>();
    let (client, handshake_request) = new_client::<S>().initialize(&shared_keypair::<S>().public);
    let handshake_response = serve(&server, &handshake_request).unwrap();
    let client = client
        .handle_handshake_response(&handshake_response)
        .unwrap();
    Rig {
        server,
        sessions,
        client,
        handshake_request,
        handshake_response,
    }
}

fn answers<S: HqcScheme>(rig: &Rig<S>) -> Vec<Vec<u8>> {
    rig.client
        .requests()
        .iter()
        .map(|request| serve(&rig.server, &request.bytes).unwrap())
        .collect()
}

fn flip_bit(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut copy = bytes.to_vec();
    copy[bit / 8] ^= 1 << (bit % 8);
    copy
}

fn flow<S: HqcScheme>() {
    let (server, sessions) = server_with_sessions::<S>();
    let keys = shared_keypair::<S>();
    let outcome = run_in_process(&server, new_client::<S>(), &keys.public).unwrap();
    assert_eq!(sessions.lock().unwrap().len(), 1);
    assert_eq!(outcome.session_key.as_slice(), &sessions.lock().unwrap()[0]);
    assert!(outcome.session_key.iter().any(|&b| b != 0));
    let u_chunks = encoding::uchunk_count::<S>();
    assert_eq!(outcome.packets.len(), 1 + u_chunks + S::CRT_MODULI.len());
}

#[test]
fn test_protocol_flow_hqc1() {
    flow::<Hqc1>();
}

#[test]
fn test_protocol_flow_hqc3() {
    flow::<Hqc3>();
}

#[test]
fn test_protocol_flow_hqc5() {
    flow::<Hqc5>();
}

/// Runs reference `HQC.Encaps` and the protocol with the same `m` and salt
/// and requires the same ciphertext bytes, and the same session key on both
/// sides.
fn matches_reference_encaps<S: HqcScheme>() {
    const ENTROPY_BYTES: usize = 48;
    let keygen_seed = [0x11u8; ENTROPY_BYTES];
    let encaps_seed = [0x22u8; ENTROPY_BYTES];

    let mut pk = vec![0u8; S::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; S::SECRET_KEY_BYTES];
    unsafe { S::keypair(&keygen_seed, &mut pk, &mut sk) };
    let mut reference_ct = vec![0u8; S::CIPHERTEXT_BYTES];
    let mut reference_ss = vec![0u8; S::SHARED_SECRET_BYTES];
    unsafe { S::enc(&encaps_seed, &mut reference_ct, &mut reference_ss, &pk) };

    const COOKIE_KEY_BYTES: usize = 64;
    let mut server_script = vec![0xAAu8; COOKIE_KEY_BYTES];
    let mut stream = vec![0u8; 256];
    S::reference_prng_stream(&encaps_seed, &mut stream);
    server_script.extend_from_slice(&stream);

    let store = SharedSessionStore::new();
    let sessions = store.sessions.clone();
    let server = Server::new(
        store,
        ScriptedEntropy::new(&server_script),
        shared_keypair::<S>().secret.clone(),
    );
    let client = Client::<S, _, _, _>::new(
        SharedSessionStore::new(),
        ScriptedEntropy::new(&keygen_seed),
    );
    let outcome = run_in_process(&server, client, &shared_keypair::<S>().public).unwrap();

    assert_eq!(outcome.ciphertext, reference_ct);
    assert_eq!(outcome.session_key.as_slice(), &sessions.lock().unwrap()[0]);

    let mut ss = vec![0u8; S::SHARED_SECRET_BYTES];
    assert_eq!(S::dec(&mut ss, &outcome.ciphertext, &sk), 0);
    assert_eq!(ss, reference_ss);
}

#[test]
fn test_ciphertext_matches_reference_encaps_hqc1() {
    matches_reference_encaps::<Hqc1>();
}

#[test]
fn test_ciphertext_matches_reference_encaps_hqc3() {
    matches_reference_encaps::<Hqc3>();
}

#[test]
fn test_ciphertext_matches_reference_encaps_hqc5() {
    matches_reference_encaps::<Hqc5>();
}

fn padding_and_size_invariants<S: HqcScheme>() {
    let (server, _) = server_with_sessions::<S>();
    let keys = shared_keypair::<S>();
    let outcome = run_in_process(&server, new_client::<S>(), &keys.public).unwrap();
    for packet in &outcome.packets {
        assert!(
            packet.request_bytes >= packet.response_bytes,
            "{:?} request {} < response {}",
            packet.kind,
            packet.request_bytes,
            packet.response_bytes
        );
        assert!(packet.request_bytes <= MAX_UDP_PAYLOAD);
        assert!(packet.response_bytes <= MAX_UDP_PAYLOAD);
        assert_eq!(
            packet.request_bytes,
            encoding::request_len::<S>(packet.kind)
        );
    }
}

#[test]
fn test_padding_and_size_invariants_hqc1() {
    padding_and_size_invariants::<Hqc1>();
}

#[test]
fn test_padding_and_size_invariants_hqc3() {
    padding_and_size_invariants::<Hqc3>();
}

#[test]
fn test_padding_and_size_invariants_hqc5() {
    padding_and_size_invariants::<Hqc5>();
}

fn server_rejects_wrong_lengths_and_dirty_padding<S: HqcScheme>() {
    let rig = rig::<S>();
    let mut requests: Vec<(Kind, Vec<u8>)> = vec![(Kind::Handshake, rig.handshake_request.clone())];
    requests.extend(
        rig.client
            .requests()
            .iter()
            .map(|r| (r.kind, r.bytes.clone())),
    );
    for (kind, request) in requests {
        assert!(serve(&rig.server, &request[..request.len() - 1]).is_err());
        let mut longer = request.clone();
        longer.push(0);
        assert!(serve(&rig.server, &longer).is_err());
        assert!(serve(&rig.server, &[]).is_err());
        if encoding::request_padding_len::<S>(kind) > 0 {
            let mut dirty = request.clone();
            *dirty.last_mut().unwrap() = 1;
            assert!(serve(&rig.server, &dirty).is_err());
        }
    }
}

#[test]
fn test_server_rejects_wrong_lengths_and_dirty_padding() {
    server_rejects_wrong_lengths_and_dirty_padding::<Hqc1>();
    server_rejects_wrong_lengths_and_dirty_padding::<Hqc3>();
    server_rejects_wrong_lengths_and_dirty_padding::<Hqc5>();
}

fn every_bit_flip_of_a_response_is_rejected<S: HqcScheme>() {
    let rig = rig::<S>();

    let (client, request) = new_client::<S>().initialize(&shared_keypair::<S>().public);
    let response = serve(&rig.server, &request).unwrap();
    for bit in 0..response.len() * 8 {
        assert!(
            client
                .verify_handshake_response(&flip_bit(&response, bit))
                .is_err(),
            "handshake response bit {bit}"
        );
    }
    assert!(client.verify_handshake_response(&response).is_ok());

    let mut client = rig.client;
    let responses: Vec<Vec<u8>> = client
        .requests()
        .to_vec()
        .iter()
        .map(|r| serve(&rig.server, &r.bytes).unwrap())
        .collect();
    for response in &responses {
        for bit in 0..response.len() * 8 {
            assert!(
                client.handle_response(&flip_bit(response, bit)).is_err(),
                "response bit {bit}"
            );
        }
    }
    let mut last = None;
    for response in &responses {
        last = Some(client.handle_response(response).unwrap());
    }
    assert!(matches!(last, Some(Progress::Complete(_))));
}

#[test]
fn test_every_bit_flip_of_a_response_is_rejected() {
    every_bit_flip_of_a_response_is_rejected::<Hqc1>();
    every_bit_flip_of_a_response_is_rejected::<Hqc3>();
    every_bit_flip_of_a_response_is_rejected::<Hqc5>();
}

fn every_bit_flip_of_a_phase_one_request_is_rejected<S: HqcScheme>() {
    let rig = rig::<S>();
    for kind in [Kind::UChunk, Kind::VResidue] {
        let request = rig
            .client
            .requests()
            .iter()
            .find(|r| r.kind == kind)
            .unwrap();
        for bit in 0..request.bytes.len() * 8 {
            assert!(
                serve(&rig.server, &flip_bit(&request.bytes, bit)).is_err(),
                "{kind:?} request bit {bit}"
            );
        }
        assert!(serve(&rig.server, &request.bytes).is_ok());
    }
}

#[test]
fn test_every_bit_flip_of_a_phase_one_request_is_rejected() {
    every_bit_flip_of_a_phase_one_request_is_rejected::<Hqc1>();
    every_bit_flip_of_a_phase_one_request_is_rejected::<Hqc3>();
    every_bit_flip_of_a_phase_one_request_is_rejected::<Hqc5>();
}

/// A flipped bit in the Phase-0 request either stops the server or leads to
/// a response the client refuses. Flips inside `ct_auth` make the server
/// decapsulate to an unrelated secret, so they are sampled: every bit would
/// cost one ML-KEM decapsulation each.
fn bit_flips_of_the_handshake_request_are_rejected<S: HqcScheme>() {
    let (server, _) = server_with_sessions::<S>();
    let (client, request) = new_client::<S>().initialize(&shared_keypair::<S>().public);
    let body_bits = (encoding::HEADER_BYTES + encoding::handshake_request_body_len::<S>()) * 8;
    let sampled_bits = (0..16)
        .chain((16..body_bits).step_by(61))
        .chain(body_bits - 1..request.len() * 8);
    for bit in sampled_bits {
        let outcome = serve(&server, &flip_bit(&request, bit))
            .map(|response| client.verify_handshake_response(&response));
        assert!(
            !matches!(outcome, Ok(Ok(_))),
            "handshake request bit {bit} accepted"
        );
    }
}

#[test]
fn test_bit_flips_of_the_handshake_request_are_rejected() {
    bit_flips_of_the_handshake_request_are_rejected::<Hqc1>();
    bit_flips_of_the_handshake_request_are_rejected::<Hqc3>();
    bit_flips_of_the_handshake_request_are_rejected::<Hqc5>();
}

fn reordered_duplicated_and_retransmitted<S: HqcScheme>() {
    let rig = rig::<S>();
    let first_batch: Vec<Vec<u8>> = rig
        .client
        .requests()
        .iter()
        .map(|r| r.bytes.clone())
        .collect();
    let responses = answers(&rig);
    let mut client = rig.client;

    let mut order: Vec<usize> = (0..responses.len()).collect();
    order.reverse();
    let mut completed = 0;
    for (step, &i) in order.iter().enumerate() {
        match client.handle_response(&responses[i]).unwrap() {
            Progress::Pending => assert!(step + 1 < responses.len()),
            Progress::Complete(_) => {
                assert_eq!(step + 1, responses.len());
                completed += 1;
            }
            Progress::Duplicate => panic!("first delivery reported as duplicate"),
        }
        if step + 1 < responses.len() {
            assert!(matches!(
                client.handle_response(&responses[i]).unwrap(),
                Progress::Duplicate
            ));
        }
    }
    assert_eq!(completed, 1);
    assert!(client.outstanding_requests().next().is_none());

    let current: Vec<Vec<u8>> = client.requests().iter().map(|r| r.bytes.clone()).collect();
    for (request, original) in current.iter().zip(&first_batch) {
        assert_eq!(request, original);
        let again = serve(&rig.server, request).unwrap();
        assert!(matches!(
            client.handle_response(&again).unwrap(),
            Progress::Duplicate
        ));
    }
    assert_eq!(rig.sessions.lock().unwrap().len(), 1);
}

#[test]
fn test_reordered_duplicated_and_retransmitted_packets() {
    reordered_duplicated_and_retransmitted::<Hqc1>();
    reordered_duplicated_and_retransmitted::<Hqc3>();
    reordered_duplicated_and_retransmitted::<Hqc5>();
}

#[test]
fn test_retransmitted_handshake_request_gets_a_valid_fresh_cookie() {
    let (server, sessions) = server_with_sessions::<Hqc1>();
    let (client, request) = new_client::<Hqc1>().initialize(&shared_keypair::<Hqc1>().public);
    let first = serve(&server, &request).unwrap();
    let second = serve(&server, &request).unwrap();
    assert_ne!(first, second);
    assert!(client.verify_handshake_response(&first).is_ok());
    assert!(client.verify_handshake_response(&second).is_ok());
    assert_eq!(sessions.lock().unwrap().len(), 2);
}

#[test]
fn test_cookie_key_rotation() {
    let rig = rig::<Hqc1>();
    rig.server.rotate();
    rig.server.rotate();
    let request = &rig.client.requests()[0];
    assert!(matches!(
        serve(&rig.server, &request.bytes),
        Err(Error::SessionExpired) | Err(Error::DecryptionError)
    ));
}

fn vresidue_request_with_payload(
    rig: &Rig<Hqc1>,
    sealing_key: &Key,
    edit: impl FnOnce(&mut Vec<u8>),
) -> Result<Vec<u8>, Error> {
    let original = rig
        .client
        .requests()
        .iter()
        .find(|r| r.kind == Kind::VResidue)
        .unwrap();
    let view = encoding::parse_request::<Hqc1>(&original.bytes).unwrap();
    let key = &rig.client.state.keys.client_to_server;
    let mut payload = vec![0u8; view.sealed.len()];
    encoding::open_request(&view, key, &mut payload).unwrap();
    edit(&mut payload);
    let mut forged = vec![0u8; MAX_UDP_PAYLOAD];
    let len = encoding::write_request::<Hqc1>(
        &mut forged,
        view.header,
        view.cookie,
        &payload,
        sealing_key,
    )
    .unwrap();
    serve(&rig.server, &forged[..len])
}

#[test]
fn test_chosen_residue_with_stolen_cookie_needs_k_auth() {
    let rig = rig::<Hqc1>();
    let client_key = rig.client.state.keys.client_to_server.clone();
    let attacker_key: Key = Key::new([0x5a; 32]);
    assert!(vresidue_request_with_payload(&rig, &client_key, |_| {}).is_ok());
    assert!(vresidue_request_with_payload(&rig, &attacker_key, |p| p[0] ^= 1).is_err());
}

#[test]
fn test_request_signed_under_wrong_direction_key_is_rejected() {
    let rig = rig::<Hqc1>();
    let original = &rig.client.requests()[0];
    let view = encoding::parse_request::<Hqc1>(&original.bytes).unwrap();
    let wrong_key = &rig.client.state.keys.server_to_client;
    let mut forged = vec![0u8; MAX_UDP_PAYLOAD];
    let len =
        encoding::write_request::<Hqc1>(&mut forged, view.header, view.cookie, &[], wrong_key)
            .unwrap();
    assert!(serve(&rig.server, &forged[..len]).is_err());
}

fn forged_response(
    rig: &Rig<Hqc1>,
    kind: Kind,
    index: u8,
    edit: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let honest_request = rig
        .client
        .requests()
        .iter()
        .find(|r| r.kind == kind && r.index == index)
        .unwrap();
    let honest = serve(&rig.server, &honest_request.bytes).unwrap();
    let view = encoding::parse_response::<Hqc1>(&honest).unwrap();
    let key = &rig.client.state.keys.server_to_client;
    let mut payload = vec![0u8; view.sealed.len()];
    encoding::open_response(&view, &[], key, &mut payload).unwrap();
    edit(&mut payload);
    let mut out = vec![0u8; MAX_UDP_PAYLOAD];
    encoding::response_payload_mut(&mut out, payload.len()).copy_from_slice(&payload);
    let len = encoding::finish_response(
        &mut out,
        Header::response(kind, 0, index),
        payload.len(),
        &[],
        key,
        view.nonce,
    )
    .unwrap();
    out.truncate(len);
    out
}

fn complete_with_one_forged(kind: Kind, index: u8) -> Error {
    let rig = rig::<Hqc1>();
    let forged = forged_response(&rig, kind, index, |p| p[0] ^= 1);
    let honest = answers(&rig);
    let mut client = rig.client;
    let target = client
        .requests()
        .iter()
        .position(|r| r.kind == kind && r.index == index)
        .unwrap();
    client.handle_response(&forged).unwrap();
    let mut outcome = None;
    for (i, response) in honest.iter().enumerate() {
        if i == target {
            continue;
        }
        match client.handle_response(response) {
            Ok(Progress::Complete(_)) => panic!("forged content confirmed"),
            Ok(_) => {}
            Err(e) => outcome = Some(e),
        }
    }
    outcome.expect("client must reject")
}

#[test]
fn test_forged_content_behind_valid_ae_fails_key_confirmation() {
    assert_eq!(
        complete_with_one_forged(Kind::VResidue, 1),
        Error::KeyConfirmationFailed
    );
    assert_eq!(
        complete_with_one_forged(Kind::UChunk, 0),
        Error::KeyConfirmationFailed
    );
}

#[test]
fn test_corrupted_gamma_fails_key_confirmation() {
    let (server, _) = server_with_sessions::<Hqc1>();
    let (client, request) = new_client::<Hqc1>().initialize(&shared_keypair::<Hqc1>().public);
    let response = serve(&server, &request).unwrap();
    let mut reply = client.verify_handshake_response(&response).unwrap();
    reply.gamma[0] ^= 1;
    let mut client = client.start_collecting(reply).unwrap();
    let mut outcome = None;
    for request in client.requests().to_vec() {
        let response = serve(&server, &request.bytes).unwrap();
        match client.handle_response(&response) {
            Ok(Progress::Complete(_)) => panic!("corrupted gamma must not confirm"),
            Ok(_) => {}
            Err(e) => outcome = Some(e),
        }
    }
    assert_eq!(outcome, Some(Error::KeyConfirmationFailed));
}

fn client_rejects_server_with_different_key<S: HqcScheme>() {
    let pinned = shared_keypair::<S>();
    let impostor_keys = ServerKeypair::<S>::generate();
    let impostor = Server::<S, _, _>::new(
        SharedSessionStore::new(),
        MockEntropy,
        impostor_keys.secret.clone(),
    );
    let (client, request) = new_client::<S>().initialize(&pinned.public);
    let response = serve(&impostor, &request).unwrap();
    assert_eq!(
        client.handle_handshake_response(&response).err(),
        Some(Error::ServerAuthenticationFailed)
    );
}

#[test]
fn test_client_rejects_server_with_different_key() {
    client_rejects_server_with_different_key::<Hqc1>();
    client_rejects_server_with_different_key::<Hqc3>();
    client_rejects_server_with_different_key::<Hqc5>();
}

#[test]
fn test_response_replayed_from_another_session_is_rejected() {
    let rig_a = rig::<Hqc1>();
    let (server, _) = server_with_sessions::<Hqc1>();
    let (client_b, request_b) = new_client::<Hqc1>().initialize(&shared_keypair::<Hqc1>().public);
    serve(&server, &request_b).unwrap();
    assert_eq!(
        client_b
            .handle_handshake_response(&rig_a.handshake_response)
            .err(),
        Some(Error::ServerAuthenticationFailed)
    );
}

#[test]
fn test_substituted_response_stream_is_rejected_after_authentic_handshake() {
    let mut rig_a = rig::<Hqc1>();
    let rig_b = rig::<Hqc1>();
    for response in answers(&rig_b) {
        assert!(rig_a.client.handle_response(&response).is_err());
    }
    assert!(rig_a.client.outstanding_requests().count() > 0);
}

#[test]
fn test_server_rejects_handshake_with_wrong_length_auth_ciphertext() {
    let (server, _) = server_with_sessions::<Hqc1>();
    let (_client, request) = new_client::<Hqc1>().initialize(&shared_keypair::<Hqc1>().public);
    assert!(serve(&server, &request[..request.len() - 7]).is_err());
}

#[test]
fn test_phase_zero_packets_use_the_documented_sizes() {
    fn check<S: HqcScheme>() {
        let rig = rig::<S>();
        assert_eq!(
            rig.handshake_request.len(),
            encoding::request_len::<S>(Kind::Handshake)
        );
        assert_eq!(
            rig.handshake_response.len(),
            encoding::response_len::<S>(Kind::Handshake, 0)
        );
    }
    check::<Hqc1>();
    check::<Hqc3>();
    check::<Hqc5>();
}

#[allow(dead_code)]
fn _state_types_are_public(_: Option<AwaitingHandshake>) {}
