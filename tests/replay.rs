use HQCLethe::auth::shared_keypair;
use HQCLethe::client::{Client, Collecting, Progress};
use HQCLethe::encoding::{self, Kind, MAX_UDP_PAYLOAD};
use HQCLethe::error::Error;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::limits::COOKIE_ROTATION_SECS;
use HQCLethe::replay::{DEFAULT_DUPLICATES, ReplayConfig};
use HQCLethe::server::Server;
mod test_utils;
use std::sync::Arc;
use test_utils::{ManualClock, MockEntropy, SharedSessionStore};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
const START_TIME: u32 = 1_800_000_000;
const TEST_RATE: u32 = 400;
const ANSWERS_PER_REQUEST: usize = DEFAULT_DUPLICATES as usize + 1;
const COPIES_PER_SECOND: usize = 3 * ANSWERS_PER_REQUEST;
const ROTATIONS_A_COOKIE_SURVIVES: usize = 1;
const OTHER_PAYLOADS: usize = 8;

type TestServer<S> = Server<S, SharedSessionStore, MockEntropy>;
type TestClient<S> = Client<S, SharedSessionStore, MockEntropy, Collecting>;

struct Rig<S: HqcScheme> {
    server: TestServer<S>,
    clock: Arc<ManualClock>,
    client: TestClient<S>,
}

fn config<S: HqcScheme>() -> ReplayConfig {
    ReplayConfig {
        max_rate: TEST_RATE,
        ..ReplayConfig::for_scheme::<S>()
    }
}

fn rig<S: HqcScheme>() -> Rig<S> {
    let clock = ManualClock::at(START_TIME);
    let keys = shared_keypair::<S>();
    let server = Server::new(SharedSessionStore::new(), MockEntropy, keys.secret.clone())
        .with_clock(clock.clone())
        .with_replay_filter(config::<S>().sizing().unwrap());
    let (client, request) =
        Client::<S, _, _, _>::new(SharedSessionStore::new(), MockEntropy).initialize(&keys.public);
    let reply = serve(&server, &request).unwrap();
    let client = client.handle_handshake_response(&reply).unwrap();
    Rig {
        server,
        clock,
        client,
    }
}

fn serve<S: HqcScheme>(server: &TestServer<S>, request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, request, &mut out)?;
    Ok(out[..len].to_vec())
}

fn request_of<S: HqcScheme>(client: &TestClient<S>, kind: Kind) -> Vec<u8> {
    client
        .requests()
        .iter()
        .find(|request| request.kind == kind)
        .unwrap()
        .bytes
        .clone()
}

fn reseal<S: HqcScheme>(client: &TestClient<S>, honest: &[u8], payload: &[u8]) -> Vec<u8> {
    let view = encoding::parse_request::<S>(honest).unwrap();
    let mut out = vec![0u8; MAX_UDP_PAYLOAD];
    let len = encoding::write_request::<S>(
        &mut out,
        view.header,
        view.cookie,
        payload,
        &client.state.keys.client_to_server,
    )
    .unwrap();
    out.truncate(len);
    out
}

fn requests_a_cookie_holder_can_seal<S: HqcScheme>(
    client: &TestClient<S>,
    kind: Kind,
) -> Vec<Vec<u8>> {
    let honest = request_of(client, kind);
    let honest_payload = opened_payload(client, &honest);
    let other_payload_count = if honest_payload.is_empty() {
        0
    } else {
        OTHER_PAYLOADS
    };
    let mut variants = vec![honest.clone()];
    for low_coefficients in (1..=u8::MAX).take(other_payload_count) {
        let mut payload = honest_payload.clone();
        payload[0] ^= low_coefficients;
        variants.push(reseal(client, &honest, &payload));
    }
    variants
}

fn opened_payload<S: HqcScheme>(client: &TestClient<S>, request: &[u8]) -> Vec<u8> {
    let view = encoding::parse_request::<S>(request).unwrap();
    let mut payload = vec![0u8; view.sealed.len()];
    encoding::open_request(&view, &client.state.keys.client_to_server, &mut payload).unwrap();
    payload
}

fn replayed_requests_are_dropped_after_the_duplicate_budget<S: HqcScheme>() {
    for kind in [Kind::UChunk, Kind::VResidue] {
        let rig = rig::<S>();
        let request = request_of(&rig.client, kind);
        for _ in 0..ANSWERS_PER_REQUEST {
            assert!(serve(&rig.server, &request).is_ok());
        }
        for _ in 0..10 {
            assert_eq!(
                serve(&rig.server, &request).unwrap_err(),
                Error::ReplayedRequest
            );
        }
    }
}

#[test]
fn replay_beyond_the_duplicate_budget_is_dropped() {
    replayed_requests_are_dropped_after_the_duplicate_budget::<Hqc1>();
    replayed_requests_are_dropped_after_the_duplicate_budget::<Hqc3>();
    replayed_requests_are_dropped_after_the_duplicate_budget::<Hqc5>();
}

#[test]
fn a_replay_does_not_reach_the_expensive_work() {
    let rig = rig::<Hqc1>();
    let request = request_of(&rig.client, Kind::VResidue);
    for _ in 0..ANSWERS_PER_REQUEST {
        serve(&rig.server, &request).unwrap();
    }
    let mut out = [0u8; 0];
    assert_eq!(
        rig.server.handle_packet(PEER, &request, &mut out),
        Err(Error::ReplayedRequest)
    );
}

fn answers_over_the_whole_cookie_life<S: HqcScheme>(kind: Kind) -> usize {
    let rig = rig::<S>();
    let variants = requests_a_cookie_holder_can_seal(&rig.client, kind);
    let mut answered = 0;
    for _ in 0..=ROTATIONS_A_COOKIE_SURVIVES {
        for second in 0..COOKIE_ROTATION_SECS {
            rig.clock.set(START_TIME + second);
            for variant in variants.iter().cycle().take(COPIES_PER_SECOND) {
                answered += usize::from(serve(&rig.server, variant).is_ok());
            }
        }
        rig.server.rotate();
    }
    for variant in &variants {
        assert_eq!(serve(&rig.server, variant), Err(Error::DecryptionError));
    }
    answered
}

#[test]
fn every_variant_of_a_request_shares_one_budget_for_the_whole_cookie_life() {
    fn check<S: HqcScheme>() {
        for kind in [Kind::UChunk, Kind::VResidue] {
            assert_eq!(
                answers_over_the_whole_cookie_life::<S>(kind),
                ANSWERS_PER_REQUEST,
                "{kind:?}"
            );
        }
    }
    check::<Hqc1>();
    check::<Hqc3>();
    check::<Hqc5>();
}

#[test]
fn the_variants_are_distinct_requests_the_server_would_answer() {
    let rig = rig::<Hqc1>();
    let variants = requests_a_cookie_holder_can_seal(&rig.client, Kind::VResidue);
    let distinct: std::collections::HashSet<_> = variants.iter().collect();
    assert_eq!(distinct.len(), 1 + OTHER_PAYLOADS);
    for variant in &variants {
        let fresh_worker = rig.server.clone();
        assert!(serve(&fresh_worker, variant).is_ok());
    }
}

#[test]
fn a_retransmit_is_byte_identical() {
    let rig = rig::<Hqc1>();
    for request in rig.client.requests() {
        let payload = opened_payload(&rig.client, &request.bytes);
        assert_eq!(reseal(&rig.client, &request.bytes, &payload), request.bytes);
    }
}

#[test]
fn the_budget_survives_the_rotation_that_retires_the_cookie_key() {
    let rig = rig::<Hqc1>();
    let request = request_of(&rig.client, Kind::UChunk);
    for _ in 0..ANSWERS_PER_REQUEST {
        serve(&rig.server, &request).unwrap();
    }
    rig.server.rotate();
    assert_eq!(serve(&rig.server, &request), Err(Error::ReplayedRequest));
}

#[test]
fn a_first_use_after_one_rotation_keeps_its_budget_until_the_cookie_dies() {
    let rig = rig::<Hqc1>();
    rig.server.rotate();
    let request = request_of(&rig.client, Kind::UChunk);
    for _ in 0..ANSWERS_PER_REQUEST {
        serve(&rig.server, &request).unwrap();
    }
    assert_eq!(serve(&rig.server, &request), Err(Error::ReplayedRequest));
    rig.server.rotate();
    assert_eq!(serve(&rig.server, &request), Err(Error::DecryptionError));
}

#[test]
fn a_request_with_an_expired_cookie_is_rejected_even_when_never_seen() {
    let rig = rig::<Hqc1>();
    rig.server.rotate();
    rig.server.rotate();
    for request in rig.client.requests() {
        assert_eq!(
            serve(&rig.server, &request.bytes),
            Err(Error::DecryptionError)
        );
    }
}

#[test]
fn a_cookie_still_opens_after_one_rotation() {
    let mut rig = rig::<Hqc1>();
    rig.server.rotate();
    let mut completed = false;
    for request in rig.client.requests().to_vec() {
        let reply = serve(&rig.server, &request.bytes).unwrap();
        completed |= matches!(
            rig.client.handle_response(&reply).unwrap(),
            Progress::Complete(_)
        );
    }
    assert!(completed);
}

#[test]
fn the_server_clock_does_not_matter_for_phase_one() {
    let rig = rig::<Hqc1>();
    let request = request_of(&rig.client, Kind::UChunk);
    rig.clock.set(0);
    assert!(serve(&rig.server, &request).is_ok());
    rig.clock.set(u32::MAX);
    assert!(serve(&rig.server, &request).is_ok());
}

fn distinct_requests_of_one_session_are_all_answered<S: HqcScheme>() {
    let mut rig = rig::<S>();
    let requests = rig.client.requests().to_vec();
    let mut completed = false;
    for request in &requests {
        let reply = serve(&rig.server, &request.bytes).unwrap();
        if let Progress::Complete(_) = rig.client.handle_response(&reply).unwrap() {
            completed = true;
        }
    }
    assert!(completed);
}

#[test]
fn distinct_requests_are_accepted() {
    distinct_requests_of_one_session_are_all_answered::<Hqc1>();
    distinct_requests_of_one_session_are_all_answered::<Hqc3>();
    distinct_requests_of_one_session_are_all_answered::<Hqc5>();
}

#[test]
fn many_sessions_do_not_collide() {
    let keys = shared_keypair::<Hqc1>();
    let server = Server::new(SharedSessionStore::new(), MockEntropy, keys.secret.clone())
        .with_replay_filter(config::<Hqc1>().sizing().unwrap());
    for _ in 0..40 {
        let (client, request) =
            Client::<Hqc1, _, _, _>::new(SharedSessionStore::new(), MockEntropy)
                .initialize(&keys.public);
        let reply = serve(&server, &request).unwrap();
        let client = client.handle_handshake_response(&reply).unwrap();
        for request in client.requests() {
            assert!(serve(&server, &request.bytes).is_ok());
        }
    }
}

#[test]
fn a_forged_request_fails_authentication_and_is_not_remembered() {
    let rig = rig::<Hqc1>();
    let request = request_of(&rig.client, Kind::UChunk);
    let tag_at = encoding::HEADER_BYTES + encoding::cookie_len::<Hqc1>();
    let mut forged = request.clone();
    forged[tag_at] ^= 1;
    for _ in 0..10 {
        assert_eq!(serve(&rig.server, &forged), Err(Error::DecryptionError));
    }
    for _ in 0..ANSWERS_PER_REQUEST {
        assert!(serve(&rig.server, &request).is_ok());
    }
}

#[test]
fn a_disabled_filter_accepts_repeats() {
    let keys = shared_keypair::<Hqc1>();
    let server = Server::new(SharedSessionStore::new(), MockEntropy, keys.secret.clone());
    let (client, request) = Client::<Hqc1, _, _, _>::new(SharedSessionStore::new(), MockEntropy)
        .initialize(&keys.public);
    let client = client
        .handle_handshake_response(&serve(&server, &request).unwrap())
        .unwrap();
    let request = request_of(&client, Kind::UChunk);
    for _ in 0..50 {
        assert!(serve(&server, &request).is_ok());
    }
    server.rotate();
    assert!(serve(&server, &request).is_ok());
}

#[test]
fn each_clone_of_a_server_has_its_own_filter() {
    let rig = rig::<Hqc1>();
    let other_worker = rig.server.clone();
    let request = request_of(&rig.client, Kind::UChunk);
    for _ in 0..ANSWERS_PER_REQUEST {
        serve(&rig.server, &request).unwrap();
    }
    assert!(serve(&rig.server, &request).is_err());
    for _ in 0..ANSWERS_PER_REQUEST {
        assert!(serve(&other_worker, &request).is_ok());
    }
    assert!(serve(&other_worker, &request).is_err());
}

#[test]
fn zero_duplicates_allow_one_answer_per_request() {
    let keys = shared_keypair::<Hqc1>();
    let sizing = ReplayConfig {
        duplicates: 0,
        ..config::<Hqc1>()
    }
    .sizing()
    .unwrap();
    let server = Server::new(SharedSessionStore::new(), MockEntropy, keys.secret.clone())
        .with_replay_filter(sizing);
    let (client, request) = Client::<Hqc1, _, _, _>::new(SharedSessionStore::new(), MockEntropy)
        .initialize(&keys.public);
    let client = client
        .handle_handshake_response(&serve(&server, &request).unwrap())
        .unwrap();
    let request = request_of(&client, Kind::UChunk);
    assert!(serve(&server, &request).is_ok());
    assert_eq!(serve(&server, &request), Err(Error::ReplayedRequest));
}

#[test]
fn a_filter_generation_holds_one_rotation_period_of_requests() {
    let config = ReplayConfig::for_scheme::<Hqc1>();
    let sizing = config.sizing().unwrap();
    assert_eq!(sizing.rotation_secs, COOKIE_ROTATION_SECS);
    assert_eq!(
        sizing.bloom.insertions,
        u64::from(config.max_rate) * u64::from(COOKIE_ROTATION_SECS)
    );
}
