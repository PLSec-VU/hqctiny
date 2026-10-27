use HQCLethe::auth::shared_keypair;
use HQCLethe::client::{AwaitingHandshake, Client, DEFAULT_MAX_PUZZLE_DIFFICULTY, Initial};
use HQCLethe::encoding::{self, HEADER_BYTES, Header, Kind, MAX_UDP_PAYLOAD};
use HQCLethe::error::Error;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::limits::{COOKIE_ROTATION_SECS, PUZZLE_MAX_AGE_SECS};
use HQCLethe::puzzle::{self, CHALLENGE_BYTES, Challenge, SOLUTION_BYTES};
use HQCLethe::replay::{DEFAULT_DUPLICATES, ReplayConfig};
use HQCLethe::server::Server;
use HQCLethe::session::run_in_process;
mod test_utils;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use test_utils::{ManualClock, MockEntropy, SharedSessionStore};

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const OTHER_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
const PEER_ON_DUAL_STACK_SOCKET: IpAddr = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
const OTHER_PEER_SAME_PREFIX: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

type TestServer<S> = Server<S, SharedSessionStore, MockEntropy>;
type TestClient<S, State> = Client<S, SharedSessionStore, MockEntropy, State>;
type RecordedSessions = Arc<Mutex<Vec<[u8; 32]>>>;

const START_TIME: u32 = 1_800_000_000;
const EASY: u8 = 8;
const MEDIUM: u8 = 14;
const HARD_ENOUGH_TO_REJECT_GUESSES: u8 = 20;

struct Rig<S: HqcScheme> {
    server: TestServer<S>,
    sessions: RecordedSessions,
    clock: Arc<ManualClock>,
}

fn rig<S: HqcScheme>(difficulty: u8) -> Rig<S> {
    let store = SharedSessionStore::new();
    let sessions = store.sessions.clone();
    let clock = ManualClock::at(START_TIME);
    let server = Server::new(store, MockEntropy, shared_keypair::<S>().secret.clone())
        .with_puzzle_difficulty(difficulty)
        .with_clock(clock.clone());
    Rig {
        server,
        sessions,
        clock,
    }
}

const ANSWERS_PER_SOLVED_PUZZLE: usize = DEFAULT_DUPLICATES as usize + 1;
const REPLAY_TEST_RATE: u32 = 400;

fn filtered_rig<S: HqcScheme>(difficulty: u8) -> Rig<S> {
    let rig = rig::<S>(difficulty);
    let sizing = ReplayConfig {
        max_rate: REPLAY_TEST_RATE,
        ..ReplayConfig::for_scheme::<S>()
    }
    .sizing()
    .unwrap();
    Rig {
        server: rig.server.with_replay_filter(sizing),
        ..rig
    }
}

fn cookie_of<S: HqcScheme>(client: &TestClient<S, AwaitingHandshake>, response: &[u8]) -> Vec<u8> {
    client.verify_handshake_response(response).unwrap().cookie
}

fn cookie_nonce(cookie: &[u8]) -> &[u8] {
    &cookie[..HQCLethe::envelope::NONCE_BYTES]
}

fn new_client<S: HqcScheme>() -> TestClient<S, Initial> {
    Client::new(SharedSessionStore::new(), MockEntropy)
}

fn serve_from<S: HqcScheme>(
    server: &TestServer<S>,
    peer: IpAddr,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(peer, request, &mut out)?;
    Ok(out[..len].to_vec())
}

fn serve<S: HqcScheme>(server: &TestServer<S>, request: &[u8]) -> Result<Vec<u8>, Error> {
    serve_from(server, PEER, request)
}

fn phase_zero<S: HqcScheme>() -> (TestClient<S, AwaitingHandshake>, Vec<u8>) {
    new_client::<S>().initialize(&shared_keypair::<S>().public)
}

struct Challenged<S: HqcScheme> {
    client: TestClient<S, AwaitingHandshake>,
    plain: Vec<u8>,
    challenge_packet: Vec<u8>,
    solved: Vec<u8>,
}

fn challenged<S: HqcScheme>(rig: &Rig<S>) -> Challenged<S> {
    let (client, plain) = phase_zero::<S>();
    let challenge_packet = serve(&rig.server, &plain).unwrap();
    let solved = client
        .solve_challenge(&challenge_packet, DEFAULT_MAX_PUZZLE_DIFFICULTY)
        .unwrap();
    Challenged {
        client,
        plain,
        challenge_packet,
        solved,
    }
}

fn challenge_of(packet: &[u8]) -> Challenge {
    encoding::parse_challenge_response(packet).unwrap().1
}

fn solved_with<S: HqcScheme>(
    plain: &[u8],
    key_index: u8,
    challenge: &Challenge,
    counter: u64,
) -> Vec<u8> {
    let mut out = vec![0u8; encoding::request_len::<S>(Kind::SolvedHandshake)];
    encoding::write_solved_handshake_request::<S>(&mut out, plain, key_index, challenge, counter)
        .unwrap();
    out
}

fn body_digest<S: HqcScheme>(plain: &[u8]) -> [u8; 32] {
    HQCLethe::kdf::request_digest(
        &plain[HEADER_BYTES..HEADER_BYTES + encoding::handshake_request_body_len::<S>()],
    )
}

fn first_wrong_counter(challenge: &Challenge, digest: &[u8; 32]) -> u64 {
    let peer = puzzle::peer_address(PEER);
    (0u64..)
        .find(|counter| !puzzle::is_solution(challenge, &peer, digest, *counter))
        .unwrap()
}

fn solution_offset<S: HqcScheme>() -> usize {
    HEADER_BYTES + encoding::handshake_request_body_len::<S>()
}

fn assert_refused_without_session<S: HqcScheme>(rig: &Rig<S>, request: &[u8], expected: Error) {
    assert_eq!(serve(&rig.server, request).err(), Some(expected));
    assert!(rig.sessions.lock().unwrap().is_empty());
}

fn challenge_round_trip<S: HqcScheme>() {
    let rig = rig::<S>(MEDIUM);
    let flow = challenged(&rig);

    let (key_index, challenge, peer) =
        encoding::parse_challenge_response(&flow.challenge_packet).unwrap();
    assert_eq!(key_index, 0);
    assert_eq!(peer, puzzle::peer_address(PEER));
    assert_eq!(challenge.difficulty, MEDIUM);
    assert_eq!(challenge.timestamp, START_TIME);
    assert!(rig.sessions.lock().unwrap().is_empty());

    let response = serve(&rig.server, &flow.solved).unwrap();
    assert_eq!(Header::decode(&response).unwrap().kind, Kind::Handshake);
    assert_eq!(
        response.len(),
        encoding::response_len::<S>(Kind::Handshake, 0)
    );
    assert!(flow.client.verify_handshake_response(&response).is_ok());
    assert_eq!(rig.sessions.lock().unwrap().len(), 1);
}

#[test]
fn test_challenge_round_trip_at_every_level() {
    challenge_round_trip::<Hqc1>();
    challenge_round_trip::<Hqc3>();
    challenge_round_trip::<Hqc5>();
}

fn full_session<S: HqcScheme>() {
    let rig = rig::<S>(MEDIUM);
    let outcome = run_in_process(
        &rig.server,
        new_client::<S>(),
        &shared_keypair::<S>().public,
    )
    .unwrap();
    let sessions = rig.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(outcome.session_key.as_slice(), &sessions[0]);

    let kinds: Vec<Kind> = outcome.packets.iter().map(|p| p.kind).collect();
    assert_eq!(kinds[0], Kind::Handshake);
    assert_eq!(kinds[1], Kind::SolvedHandshake);
    assert_eq!(
        outcome.packets.len(),
        2 + encoding::uchunk_count::<S>() + S::CRT_MODULI.len()
    );
    assert_eq!(
        outcome.packets[0].response_bytes,
        encoding::challenge_response_len()
    );
    assert!(
        outcome
            .packets
            .iter()
            .all(|p| p.response_bytes <= p.request_bytes)
    );
}

#[test]
fn test_full_session_completes_through_a_challenge() {
    full_session::<Hqc1>();
    full_session::<Hqc3>();
    full_session::<Hqc5>();
}

#[test]
fn test_difficulty_zero_issues_no_challenge() {
    let (_client, plain) = phase_zero::<Hqc1>();
    let answering = rig::<Hqc1>(0);
    let response = serve(&answering.server, &plain).unwrap();
    assert_eq!(Header::decode(&response).unwrap().kind, Kind::Handshake);
    assert_eq!(answering.sessions.lock().unwrap().len(), 1);
}

#[test]
fn test_solved_request_is_accepted_after_puzzles_are_switched_off() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    rig.server.set_puzzle_difficulty(0);
    let response = serve(&rig.server, &flow.solved).unwrap();
    assert!(flow.client.verify_handshake_response(&response).is_ok());
    assert_eq!(rig.sessions.lock().unwrap().len(), 1);
}

#[test]
fn test_solved_request_is_still_checked_after_puzzles_are_switched_off() {
    let rig = rig::<Hqc1>(HARD_ENOUGH_TO_REJECT_GUESSES);
    let flow = challenged(&rig);
    rig.server.set_puzzle_difficulty(0);

    let challenge = challenge_of(&flow.challenge_packet);
    let digest = body_digest::<Hqc1>(&flow.plain);
    let wrong = first_wrong_counter(&challenge, &digest);
    let wrong_counter = solved_with::<Hqc1>(&flow.plain, 0, &challenge, wrong);
    assert_refused_without_session(&rig, &wrong_counter, Error::InvalidPuzzleSolution);
    rig.clock.advance(PUZZLE_MAX_AGE_SECS + 1);
    assert_refused_without_session(&rig, &flow.solved, Error::StalePuzzle);
}

#[test]
fn test_difficulty_zero_session_has_no_puzzle_packets() {
    let rig = rig::<Hqc5>(0);
    let outcome = run_in_process(
        &rig.server,
        new_client::<Hqc5>(),
        &shared_keypair::<Hqc5>().public,
    )
    .unwrap();
    assert_eq!(
        outcome.packets.len(),
        1 + encoding::uchunk_count::<Hqc5>() + Hqc5::CRT_MODULI.len()
    );
    assert!(
        outcome
            .packets
            .iter()
            .all(|p| !Kind::PUZZLE.contains(&p.kind))
    );
}

#[test]
fn test_every_bit_of_the_challenge_mac_is_checked() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    let tag_start = solution_offset::<Hqc1>() + CHALLENGE_BYTES - puzzle::TAG_BYTES;
    for bit in 0..puzzle::TAG_BYTES * 8 {
        let mut forged = flow.solved.clone();
        forged[tag_start + bit / 8] ^= 1 << (bit % 8);
        assert_refused_without_session(&rig, &forged, Error::InvalidPuzzleMac);
    }
}

#[test]
fn test_forged_nonce_or_timestamp_fails_the_mac() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    rig.clock.advance(10);
    let challenge_start = solution_offset::<Hqc1>();
    let timestamp_start = challenge_start + puzzle::NONCE_BYTES + 1;
    for offset in [challenge_start, timestamp_start] {
        let mut forged = flow.solved.clone();
        forged[offset] ^= 1;
        assert_refused_without_session(&rig, &forged, Error::InvalidPuzzleMac);
    }
}

#[test]
fn test_challenge_from_another_server_is_refused() {
    let issuer = rig::<Hqc1>(EASY);
    let verifier = rig::<Hqc1>(EASY);
    let flow = challenged(&issuer);
    assert_refused_without_session(&verifier, &flow.solved, Error::InvalidPuzzleMac);
}

#[test]
fn test_stale_challenge_is_refused_and_the_boundary_is_inclusive() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);

    rig.clock.advance(PUZZLE_MAX_AGE_SECS);
    assert!(serve(&rig.server, &flow.solved).is_ok());
    assert_eq!(rig.sessions.lock().unwrap().len(), 1);

    rig.clock.advance(1);
    assert_eq!(
        serve(&rig.server, &flow.solved).err(),
        Some(Error::StalePuzzle)
    );
    assert_eq!(rig.sessions.lock().unwrap().len(), 1);
}

#[test]
fn test_challenge_dated_in_the_future_is_refused() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    rig.clock.set(START_TIME - 1);
    assert_refused_without_session(&rig, &flow.solved, Error::StalePuzzle);
}

#[test]
fn test_challenge_outlives_one_rotation_but_not_two() {
    assert_eq!(PUZZLE_MAX_AGE_SECS, COOKIE_ROTATION_SECS);
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    rig.server.rotate();
    assert!(serve(&rig.server, &flow.solved).is_ok());

    rig.server.rotate();
    assert_eq!(
        serve(&rig.server, &flow.solved).err(),
        Some(Error::InvalidPuzzleMac)
    );
    assert_eq!(rig.sessions.lock().unwrap().len(), 1);
}

#[test]
fn test_challenge_is_issued_under_the_active_key_index() {
    let rig = rig::<Hqc1>(EASY);
    rig.server.rotate();
    let flow = challenged(&rig);
    let (key_index, _, _) = encoding::parse_challenge_response(&flow.challenge_packet).unwrap();
    assert_eq!(key_index, 1);
    assert!(serve(&rig.server, &flow.solved).is_ok());
}

#[test]
fn test_challenge_below_the_current_difficulty_is_refused() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    rig.server.set_puzzle_difficulty(EASY + 1);
    assert_refused_without_session(&rig, &flow.solved, Error::InsufficientPuzzleDifficulty);
}

#[test]
fn test_challenge_above_the_current_difficulty_is_accepted() {
    let rig = rig::<Hqc1>(MEDIUM);
    let flow = challenged(&rig);
    rig.server.set_puzzle_difficulty(EASY);
    assert!(serve(&rig.server, &flow.solved).is_ok());
}

#[test]
fn test_client_cannot_lower_the_difficulty_in_the_challenge() {
    let rig = rig::<Hqc1>(MEDIUM);
    let flow = challenged(&rig);
    let mut easier = challenge_of(&flow.challenge_packet);
    easier.difficulty = EASY;
    let counter = puzzle::solve(
        &easier,
        &puzzle::peer_address(PEER),
        &HQCLethe::kdf::request_digest(
            &flow.plain
                [HEADER_BYTES..HEADER_BYTES + encoding::handshake_request_body_len::<Hqc1>()],
        ),
    );
    let forged = solved_with::<Hqc1>(&flow.plain, 0, &easier, counter);
    assert_refused_without_session(&rig, &forged, Error::InsufficientPuzzleDifficulty);
}

#[test]
fn test_solution_for_another_request_body_is_refused() {
    let rig = rig::<Hqc1>(HARD_ENOUGH_TO_REJECT_GUESSES);
    let first = challenged(&rig);
    let (_other_client, other_plain) = phase_zero::<Hqc1>();

    let challenge = challenge_of(&first.challenge_packet);
    let counter = u64::from_le_bytes(
        first.solved[solution_offset::<Hqc1>() + CHALLENGE_BYTES..][..8]
            .try_into()
            .unwrap(),
    );
    let transplanted = solved_with::<Hqc1>(&other_plain, 0, &challenge, counter);
    assert_refused_without_session(&rig, &transplanted, Error::InvalidPuzzleSolution);
    assert!(serve(&rig.server, &first.solved).is_ok());
}

#[test]
fn test_wrong_counter_is_refused() {
    let rig = rig::<Hqc1>(MEDIUM);
    let flow = challenged(&rig);
    let challenge = challenge_of(&flow.challenge_packet);
    let digest = HQCLethe::kdf::request_digest(
        &flow.plain[HEADER_BYTES..HEADER_BYTES + encoding::handshake_request_body_len::<Hqc1>()],
    );
    let wrong = first_wrong_counter(&challenge, &digest);
    let forged = solved_with::<Hqc1>(&flow.plain, 0, &challenge, wrong);
    assert_refused_without_session(&rig, &forged, Error::InvalidPuzzleSolution);
}

#[test]
fn test_solved_request_with_flipped_body_bit_is_refused_before_decapsulation() {
    let rig = rig::<Hqc1>(HARD_ENOUGH_TO_REJECT_GUESSES);
    let flow = challenged(&rig);
    let mut forged = flow.solved.clone();
    forged[HEADER_BYTES] ^= 1;
    assert_refused_without_session(&rig, &forged, Error::InvalidPuzzleSolution);
}

#[test]
fn test_unsolved_request_gets_only_a_challenge_even_with_garbage_ciphertext() {
    let rig = rig::<Hqc1>(EASY);
    let (_client, mut plain) = phase_zero::<Hqc1>();
    let last_body_byte = HEADER_BYTES + encoding::handshake_request_body_len::<Hqc1>() - 1;
    plain[last_body_byte] ^= 0xff;
    let reply = serve(&rig.server, &plain).unwrap();
    assert_eq!(Header::decode(&reply).unwrap().kind, Kind::Challenge);
    assert!(rig.sessions.lock().unwrap().is_empty());
}

#[test]
fn test_malformed_requests_get_no_challenge() {
    let rig = rig::<Hqc1>(EASY);
    let (_client, plain) = phase_zero::<Hqc1>();
    assert!(serve(&rig.server, &plain[..plain.len() - 1]).is_err());
    let mut with_trailing_byte = plain.clone();
    with_trailing_byte.push(1);
    assert!(serve(&rig.server, &with_trailing_byte).is_err());
}

#[test]
fn test_malformed_solved_requests_are_refused() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    assert!(serve(&rig.server, &flow.solved[..flow.solved.len() - 1]).is_err());
    let mut longer = flow.solved.clone();
    longer.push(0);
    assert!(serve(&rig.server, &longer).is_err());
    if encoding::request_padding_len::<Hqc1>(Kind::SolvedHandshake) > 0 {
        let mut dirty_padding = flow.solved.clone();
        *dirty_padding.last_mut().unwrap() = 1;
        assert!(serve(&rig.server, &dirty_padding).is_err());
    }
    let mut plain_with_trailer = flow.plain.clone();
    plain_with_trailer.extend_from_slice(&[0u8; SOLUTION_BYTES]);
    assert!(serve(&rig.server, &plain_with_trailer).is_err());
    assert!(rig.sessions.lock().unwrap().is_empty());
}

#[test]
fn test_server_does_not_accept_a_challenge_as_a_request() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    assert!(serve(&rig.server, &flow.challenge_packet).is_err());
}

#[test]
fn test_challenge_is_not_larger_than_the_request_and_solved_stays_in_the_datagram() {
    fn check<S: HqcScheme>() {
        let rig = rig::<S>(EASY);
        let flow = challenged(&rig);
        assert!(flow.challenge_packet.len() <= flow.plain.len());
        assert_eq!(
            flow.challenge_packet.len(),
            encoding::challenge_response_len()
        );
        assert!(flow.solved.len() <= MAX_UDP_PAYLOAD);
        let handshake_reply = serve(&rig.server, &flow.solved).unwrap();
        assert!(handshake_reply.len() <= flow.solved.len());
        assert_eq!(
            flow.solved.len(),
            encoding::request_len::<S>(Kind::SolvedHandshake)
        );
    }
    check::<Hqc1>();
    check::<Hqc3>();
    check::<Hqc5>();
}

#[test]
fn test_plain_request_length_is_unchanged_by_the_puzzle_feature() {
    fn check<S: HqcScheme>() {
        let unpadded = HEADER_BYTES + encoding::handshake_request_body_len::<S>();
        let reply = encoding::response_len::<S>(Kind::Handshake, 0);
        assert_eq!(
            encoding::request_len::<S>(Kind::Handshake),
            unpadded.max(reply)
        );
        assert_eq!(
            encoding::request_len::<S>(Kind::SolvedHandshake),
            (unpadded + SOLUTION_BYTES).max(reply)
        );
    }
    check::<Hqc1>();
    check::<Hqc3>();
    check::<Hqc5>();
}

#[test]
fn test_client_refuses_a_puzzle_above_its_limit() {
    let rig = rig::<Hqc1>(MEDIUM);
    let (client, plain) = phase_zero::<Hqc1>();
    let packet = serve(&rig.server, &plain).unwrap();
    assert_eq!(
        client.solve_challenge(&packet, MEDIUM - 1).err(),
        Some(Error::PuzzleTooHard)
    );
    assert!(client.solve_challenge(&packet, MEDIUM).is_ok());
}

#[test]
fn test_client_does_not_take_a_challenge_for_a_handshake_response() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    assert_eq!(
        flow.client
            .verify_handshake_response(&flow.challenge_packet)
            .err(),
        Some(Error::ServerAuthenticationFailed)
    );
}

#[test]
fn test_client_does_not_solve_a_handshake_response() {
    let rig = rig::<Hqc1>(0);
    let (client, plain) = phase_zero::<Hqc1>();
    let response = serve(&rig.server, &plain).unwrap();
    assert!(client.solve_challenge(&response, 255).is_err());
}

#[test]
fn test_each_challenge_has_a_fresh_nonce() {
    let rig = rig::<Hqc1>(EASY);
    let (_client, plain) = phase_zero::<Hqc1>();
    let first = challenge_of(&serve(&rig.server, &plain).unwrap());
    let second = challenge_of(&serve(&rig.server, &plain).unwrap());
    assert_ne!(first.nonce, second.nonce);
}

#[derive(Clone)]
struct CloneableStore;
impl HQCLethe::traits::SessionStore for CloneableStore {
    fn save_session(&self, _k_session: [u8; 32]) {}
}

#[derive(Clone)]
struct CloneableEntropy;
impl HQCLethe::traits::EntropyProvider for CloneableEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        MockEntropy.random_bytes(out);
    }
}

#[test]
fn test_difficulty_can_change_at_run_time_on_every_clone() {
    let server = Server::new(
        CloneableStore,
        CloneableEntropy,
        shared_keypair::<Hqc1>().secret.clone(),
    );
    let clone = server.clone();
    let (_client, plain) = phase_zero::<Hqc1>();
    let mut out = [0u8; MAX_UDP_PAYLOAD];

    clone.set_puzzle_difficulty(EASY);
    let len = server.handle_packet(PEER, &plain, &mut out).unwrap();
    assert_eq!(Header::decode(&out[..len]).unwrap().kind, Kind::Challenge);

    server.set_puzzle_difficulty(0);
    let len = clone.handle_packet(PEER, &plain, &mut out).unwrap();
    assert_eq!(Header::decode(&out[..len]).unwrap().kind, Kind::Handshake);
}

#[test]
fn test_retransmitted_solved_request_gets_an_equivalent_reply() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    let first = serve(&rig.server, &flow.solved).unwrap();
    let second = serve(&rig.server, &flow.solved).unwrap();
    assert_eq!(first.len(), second.len());
    assert!(flow.client.verify_handshake_response(&first).is_ok());
    assert!(flow.client.verify_handshake_response(&second).is_ok());
}

#[test]
fn test_solved_request_from_the_address_that_got_the_challenge_is_accepted() {
    let rig = rig::<Hqc1>(MEDIUM);
    let flow = challenged(&rig);
    let response = serve_from(&rig.server, PEER, &flow.solved).unwrap();
    assert!(flow.client.verify_handshake_response(&response).is_ok());
}

#[test]
fn test_solved_request_from_another_address_is_refused() {
    let rig = rig::<Hqc1>(MEDIUM);
    let flow = challenged(&rig);
    for stranger in [OTHER_PEER, OTHER_PEER_SAME_PREFIX] {
        assert_eq!(
            serve_from(&rig.server, stranger, &flow.solved).err(),
            Some(Error::InvalidPuzzleMac)
        );
    }
    assert!(rig.sessions.lock().unwrap().is_empty());
    assert!(serve_from(&rig.server, PEER, &flow.solved).is_ok());
}

#[test]
fn test_ipv4_address_and_its_mapped_ipv6_form_are_the_same_peer() {
    let rig = rig::<Hqc1>(MEDIUM);
    let (client, plain) = phase_zero::<Hqc1>();
    let challenge_packet = serve_from(&rig.server, PEER_ON_DUAL_STACK_SOCKET, &plain).unwrap();
    let solved = client
        .solve_challenge(&challenge_packet, DEFAULT_MAX_PUZZLE_DIFFICULTY)
        .unwrap();
    assert!(serve_from(&rig.server, PEER, &solved).is_ok());
}

#[test]
fn test_challenge_for_one_address_is_not_a_challenge_for_another() {
    let rig = rig::<Hqc1>(MEDIUM);
    let (_client, plain) = phase_zero::<Hqc1>();
    let for_peer = serve_from(&rig.server, PEER, &plain).unwrap();
    let for_other = serve_from(&rig.server, OTHER_PEER, &plain).unwrap();
    assert_ne!(challenge_of(&for_peer).tag, challenge_of(&for_other).tag);
}

#[test]
fn test_solution_computed_for_another_address_is_refused_even_with_a_valid_mac() {
    let rig = rig::<Hqc1>(HARD_ENOUGH_TO_REJECT_GUESSES);
    let (client, plain) = phase_zero::<Hqc1>();
    let mut challenge_packet = serve(&rig.server, &plain).unwrap();
    let echoed_address = challenge_packet.len() - puzzle::ADDRESS_BYTES;
    challenge_packet[echoed_address..].copy_from_slice(&puzzle::peer_address(OTHER_PEER));
    let solved = client
        .solve_challenge(&challenge_packet, HARD_ENOUGH_TO_REJECT_GUESSES)
        .unwrap();
    assert_refused_without_session(&rig, &solved, Error::InvalidPuzzleSolution);
}

fn decapsulations(rig: &Rig<impl HqcScheme>) -> usize {
    rig.sessions.lock().unwrap().len()
}

#[test]
fn test_one_solved_puzzle_buys_at_most_the_duplicate_budget_of_decapsulations() {
    let rig = filtered_rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    for _ in 0..ANSWERS_PER_SOLVED_PUZZLE {
        assert!(serve(&rig.server, &flow.solved).is_ok());
    }
    for _ in 0..3 * ANSWERS_PER_SOLVED_PUZZLE {
        assert_eq!(
            serve(&rig.server, &flow.solved).err(),
            Some(Error::ReplayedRequest)
        );
    }
    assert_eq!(decapsulations(&rig), ANSWERS_PER_SOLVED_PUZZLE);
}

#[test]
fn test_accepted_resends_of_one_solved_request_carry_the_same_cookie() {
    let rig = filtered_rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    let cookies: Vec<Vec<u8>> = (0..ANSWERS_PER_SOLVED_PUZZLE)
        .map(|_| cookie_of(&flow.client, &serve(&rig.server, &flow.solved).unwrap()))
        .collect();
    assert!(cookies.iter().all(|cookie| *cookie == cookies[0]));
}

#[test]
fn test_resends_without_a_filter_still_carry_the_same_cookie() {
    let rig = rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    let first = cookie_of(&flow.client, &serve(&rig.server, &flow.solved).unwrap());
    let second = cookie_of(&flow.client, &serve(&rig.server, &flow.solved).unwrap());
    assert_eq!(first, second);
}

#[test]
fn test_different_challenges_give_different_cookies() {
    let rig = filtered_rig::<Hqc1>(EASY);
    let first = challenged(&rig);
    let second = challenged(&rig);
    let first_cookie = cookie_of(&first.client, &serve(&rig.server, &first.solved).unwrap());
    let second_cookie = cookie_of(&second.client, &serve(&rig.server, &second.solved).unwrap());
    assert_ne!(cookie_nonce(&first_cookie), cookie_nonce(&second_cookie));
}

#[test]
fn test_plain_handshake_cookies_stay_random() {
    let rig = rig::<Hqc1>(0);
    let (client, plain) = phase_zero::<Hqc1>();
    let first = cookie_of(&client, &serve(&rig.server, &plain).unwrap());
    let second = cookie_of(&client, &serve(&rig.server, &plain).unwrap());
    assert_ne!(cookie_nonce(&first), cookie_nonce(&second));
}

#[test]
fn test_the_solved_puzzle_budget_spans_the_rotation_inside_the_challenge_life() {
    let rig = filtered_rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    let before = cookie_of(&flow.client, &serve(&rig.server, &flow.solved).unwrap());
    rig.server.rotate();
    let mut after_rotation = Vec::new();
    for _ in 1..ANSWERS_PER_SOLVED_PUZZLE {
        after_rotation.push(cookie_of(
            &flow.client,
            &serve(&rig.server, &flow.solved).unwrap(),
        ));
    }
    assert_eq!(
        serve(&rig.server, &flow.solved).err(),
        Some(Error::ReplayedRequest)
    );
    assert!(
        after_rotation
            .iter()
            .all(|cookie| cookie_nonce(cookie) == cookie_nonce(&before))
    );
    assert_eq!(decapsulations(&rig), ANSWERS_PER_SOLVED_PUZZLE);
}

#[test]
fn test_a_budget_spent_in_the_first_rotation_is_remembered_in_the_second() {
    let rig = filtered_rig::<Hqc1>(EASY);
    let flow = challenged(&rig);
    for _ in 0..ANSWERS_PER_SOLVED_PUZZLE {
        assert!(serve(&rig.server, &flow.solved).is_ok());
    }
    rig.server.rotate();
    rig.clock.advance(PUZZLE_MAX_AGE_SECS);
    assert_eq!(
        serve(&rig.server, &flow.solved).err(),
        Some(Error::ReplayedRequest)
    );
    rig.server.rotate();
    assert_eq!(
        serve(&rig.server, &flow.solved).err(),
        Some(Error::InvalidPuzzleMac)
    );
    assert_eq!(decapsulations(&rig), ANSWERS_PER_SOLVED_PUZZLE);
}

#[test]
fn test_a_refused_solution_spends_no_budget() {
    let rig = filtered_rig::<Hqc1>(HARD_ENOUGH_TO_REJECT_GUESSES);
    let flow = challenged(&rig);
    let challenge = challenge_of(&flow.challenge_packet);
    let digest = body_digest::<Hqc1>(&flow.plain);
    let wrong = solved_with::<Hqc1>(
        &flow.plain,
        0,
        &challenge,
        first_wrong_counter(&challenge, &digest),
    );
    for _ in 0..3 * ANSWERS_PER_SOLVED_PUZZLE {
        assert_refused_without_session(&rig, &wrong, Error::InvalidPuzzleSolution);
    }
    for _ in 0..ANSWERS_PER_SOLVED_PUZZLE {
        assert!(serve(&rig.server, &flow.solved).is_ok());
    }
}

#[test]
fn test_each_worker_has_its_own_budget_but_all_issue_the_same_cookie() {
    let rig = filtered_rig::<Hqc1>(EASY);
    let worker = rig.server.clone();
    let flow = challenged(&rig);
    let mut cookies = Vec::new();
    for server in [&rig.server, &worker] {
        for _ in 0..ANSWERS_PER_SOLVED_PUZZLE {
            cookies.push(cookie_of(
                &flow.client,
                &serve(server, &flow.solved).unwrap(),
            ));
        }
        assert_eq!(
            serve(server, &flow.solved).err(),
            Some(Error::ReplayedRequest)
        );
    }
    assert!(cookies.iter().all(|cookie| *cookie == cookies[0]));
    assert_eq!(decapsulations(&rig), 2 * ANSWERS_PER_SOLVED_PUZZLE);
}

#[test]
fn test_full_session_completes_through_a_challenge_with_the_replay_filter() {
    fn check<S: HqcScheme>() {
        let rig = filtered_rig::<S>(MEDIUM);
        let outcome = run_in_process(
            &rig.server,
            new_client::<S>(),
            &shared_keypair::<S>().public,
        )
        .unwrap();
        assert_eq!(outcome.packets[1].kind, Kind::SolvedHandshake);
        let sessions = rig.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(outcome.session_key.as_slice(), &sessions[0]);
    }
    check::<Hqc1>();
    check::<Hqc3>();
    check::<Hqc5>();
}
