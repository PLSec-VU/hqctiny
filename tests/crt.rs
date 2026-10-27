use HQCLethe::auth::shared_keypair;
use HQCLethe::client::{Client, Collecting, Initial, Progress};
use HQCLethe::encoding::{self, Header, Kind, MAX_UDP_PAYLOAD};
use HQCLethe::error::Error;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::server::Server;
use HQCLethe::session::run_in_process;
mod test_utils;
use test_utils::{MockEntropy, ScriptedEntropy, SharedSessionStore};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

type TestServer<S> = Server<S, SharedSessionStore, MockEntropy>;
type TestClient<S, State> = Client<S, SharedSessionStore, MockEntropy, State>;

fn new_server<S: HqcScheme>() -> TestServer<S> {
    Server::new(
        SharedSessionStore::new(),
        MockEntropy,
        shared_keypair::<S>().secret.clone(),
    )
}

fn new_client<S: HqcScheme>() -> TestClient<S, Initial> {
    Client::new(SharedSessionStore::new(), MockEntropy)
}

fn serve<S: HqcScheme>(server: &TestServer<S>, request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = [0u8; MAX_UDP_PAYLOAD];
    let len = server.handle_packet(PEER, request, &mut out)?;
    Ok(out[..len].to_vec())
}

fn collecting_client<S: HqcScheme>(server: &TestServer<S>) -> TestClient<S, Collecting> {
    let (client, request) = new_client::<S>().initialize(&shared_keypair::<S>().public);
    let response = serve(server, &request).unwrap();
    client.handle_handshake_response(&response).unwrap()
}

fn flip_bit(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut copy = bytes.to_vec();
    copy[bit / 8] ^= 1 << (bit % 8);
    copy
}

fn flow<S: HqcScheme>() {
    let store = SharedSessionStore::new();
    let sessions = store.sessions.clone();
    let server = Server::new(store, MockEntropy, shared_keypair::<S>().secret.clone());
    let outcome =
        run_in_process(&server, new_client::<S>(), &shared_keypair::<S>().public).unwrap();
    assert_eq!(outcome.session_key.as_slice(), &sessions.lock().unwrap()[0]);
    assert_eq!(
        outcome.packets.len(),
        1 + encoding::uchunk_count::<S>() + S::CRT_MODULI.len()
    );
    for packet in &outcome.packets {
        assert!(packet.request_bytes >= packet.response_bytes);
        assert!(packet.request_bytes <= MAX_UDP_PAYLOAD);
        assert_eq!(
            packet.request_bytes,
            encoding::request_len::<S>(packet.kind)
        );
    }
}

#[test]
fn crt_session_completes_and_respects_size_rules() {
    flow::<Hqc1>();
    flow::<Hqc3>();
    flow::<Hqc5>();
}

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
fn crt_ciphertext_matches_reference_encaps() {
    matches_reference_encaps::<Hqc1>();
    matches_reference_encaps::<Hqc3>();
    matches_reference_encaps::<Hqc5>();
}

fn crt_request<S: HqcScheme>(client: &TestClient<S, Collecting>, index: u8) -> Vec<u8> {
    client
        .requests()
        .iter()
        .find(|r| r.kind == Kind::VResidue && r.index == index)
        .unwrap()
        .bytes
        .clone()
}

fn every_bit_flip_is_rejected<S: HqcScheme>() {
    let server = new_server::<S>();
    let mut client = collecting_client::<S>(&server);
    let request = crt_request(&client, 0);
    for bit in 0..request.len() * 8 {
        assert!(
            serve(&server, &flip_bit(&request, bit)).is_err(),
            "request bit {bit}"
        );
    }
    let responses: Vec<Vec<u8>> = client
        .requests()
        .to_vec()
        .iter()
        .map(|r| serve(&server, &r.bytes).unwrap())
        .collect();
    let crt_response = responses.last().unwrap();
    for bit in 0..crt_response.len() * 8 {
        assert!(
            client
                .handle_response(&flip_bit(crt_response, bit))
                .is_err(),
            "response bit {bit}"
        );
    }
    let mut last = None;
    for response in &responses {
        last = Some(client.handle_response(response).unwrap());
    }
    assert!(matches!(last, Some(Progress::Complete(_))));
}

#[test]
fn crt_packets_reject_every_bit_flip() {
    every_bit_flip_is_rejected::<Hqc1>();
    every_bit_flip_is_rejected::<Hqc3>();
}

fn rejects_wrong_lengths_and_indices<S: HqcScheme>() {
    let server = new_server::<S>();
    let client = collecting_client::<S>(&server);
    let request = crt_request(&client, 0);
    assert!(serve(&server, &request[..request.len() - 1]).is_err());
    let mut longer = request.clone();
    longer.push(0);
    assert!(serve(&server, &longer).is_err());
    let mut out_of_range = request.clone();
    out_of_range[1] = S::CRT_MODULI.len() as u8;
    assert!(serve(&server, &out_of_range).is_err());
    assert_eq!(Header::decode(&request).unwrap().kind, Kind::VResidue);
}

#[test]
fn crt_server_rejects_malformed_requests() {
    rejects_wrong_lengths_and_indices::<Hqc1>();
    rejects_wrong_lengths_and_indices::<Hqc3>();
    rejects_wrong_lengths_and_indices::<Hqc5>();
}

#[test]
fn crt_request_and_reply_sizes() {
    for (name, sizes) in [
        ("hqc1", sizes::<Hqc1>()),
        ("hqc3", sizes::<Hqc3>()),
        ("hqc5", sizes::<Hqc5>()),
    ] {
        println!("{name} {sizes:?}");
    }
}

fn sizes<S: HqcScheme>() -> (usize, usize, usize) {
    (
        S::CRT_MODULI.len(),
        encoding::request_len::<S>(Kind::VResidue),
        (0..S::CRT_MODULI.len())
            .map(|i| encoding::response_len::<S>(Kind::VResidue, i))
            .max()
            .unwrap(),
    )
}

mod structure {
    use HQCLethe::blinding;
    use HQCLethe::crt::client::{residues_of, unreduced_from_residues};
    use HQCLethe::crt::params::{
        MAX_RESIDUE_WORDS, residue_bytes_from_words, words_from_residue_bytes,
    };
    use HQCLethe::crt::server::{QUOTIENT_MASK_CONTEXT, TRUNCATE_MASK_CONTEXT, masked_residue};
    use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcMessageParameters, HqcScheme};
    use HQCLethe::math::poly_mul::Backend;
    use rand::Rng;

    fn random_words(count: usize, bits: usize) -> Vec<u64> {
        let mut words: Vec<u64> = (0..count).map(|_| rand::rng().next_u64()).collect();
        words[bits / 64] &= (1u64 << (bits % 64)) - 1;
        words[bits / 64 + 1..].fill(0);
        words
    }

    fn xor_bits_at(dst: &mut [u64], src: &[u64], shift: usize) {
        for (i, &word) in src.iter().enumerate() {
            for bit in 0..64 {
                if word >> bit & 1 == 1 {
                    let at = shift + i * 64 + bit;
                    dst[at / 64] ^= 1u64 << (at % 64);
                }
            }
        }
    }

    fn expected_unreduced<S: HqcScheme>(s: &[u64], theta: &[u8], m: &[u8]) -> Vec<u64> {
        let n = S::PARAM_N;
        let n_words = S::VEC_N_SIZE_64;
        let message = S::partial_message_encaps_v(m, theta);
        let mut product = vec![0u64; 2 * n_words];
        Backend::fastest().multiply(s, message.r2(), &mut product, &mut vec![0u64; 4096]);
        let mut expected = product;
        xor_bits_at(&mut expected, message.e(), 0);
        let mut encoded = vec![0u64; n_words];
        S::code_encode(&mut encoded, m);
        xor_bits_at(&mut expected, &encoded, 0);
        let truncate = blinding::truncate_mask_word(theta, TRUNCATE_MASK_CONTEXT, n, S::PARAM_N1N2);
        xor_bits_at(&mut expected, &[truncate], S::PARAM_N1N2);
        let mut mu = vec![0u64; n_words];
        blinding::generate_quotient_mask(theta, QUOTIENT_MASK_CONTEXT, n, &mut mu);
        mu[(n - 1) / 64] &= !(1u64 << ((n - 1) % 64));
        xor_bits_at(&mut expected, &mu, 0);
        xor_bits_at(&mut expected, &mu, n);
        expected
    }

    fn server_unreduced<S: HqcScheme>(s: &[u64], theta: &[u8], m: &[u8]) -> Vec<u64> {
        let s_residues = residues_of::<S>(s);
        let replies: Vec<Vec<u8>> = S::CRT_MODULI
            .iter()
            .zip(&s_residues)
            .map(|(&modulus, residue)| {
                let mut s_words = [0u64; MAX_RESIDUE_WORDS];
                words_from_residue_bytes(residue, modulus, &mut s_words);
                let mut out = [0u64; MAX_RESIDUE_WORDS];
                masked_residue::<S>(theta, m, modulus, &s_words, &mut out);
                let mut bytes = vec![0u8; modulus.residue_bytes()];
                residue_bytes_from_words(&out, modulus, &mut bytes);
                bytes
            })
            .collect();
        unreduced_from_residues::<S>(&replies)
    }

    fn reply_is_the_masked_unreduced_value<S: HqcScheme>() {
        let theta: [u8; 32] = rand::random();
        let m: Vec<u8> = (0..S::PARAM_SECURITY_BYTES)
            .map(|_| rand::random())
            .collect();
        let s = random_words(S::VEC_N_SIZE_64, S::PARAM_N);
        let expected = expected_unreduced::<S>(&s, &theta, &m);
        let got = server_unreduced::<S>(&s, &theta, &m);
        assert_eq!(&got[..], &expected[..got.len()]);
        assert!(expected[got.len()..].iter().all(|&w| w == 0));
        let top_bit = 2 * S::PARAM_N - 1;
        assert!(got[top_bit / 64] >> (top_bit % 64) == 0);
    }

    #[test]
    fn replies_reconstruct_to_value_plus_quotient_and_truncate_masks() {
        reply_is_the_masked_unreduced_value::<Hqc1>();
        reply_is_the_masked_unreduced_value::<Hqc3>();
        reply_is_the_masked_unreduced_value::<Hqc5>();
    }
}

fn reordered_and_duplicated_replies_complete_the_session<S: HqcScheme>() {
    let server = new_server::<S>();
    let mut client = collecting_client::<S>(&server);
    let mut responses: Vec<Vec<u8>> = client
        .requests()
        .to_vec()
        .iter()
        .map(|r| serve(&server, &r.bytes).unwrap())
        .collect();
    responses.reverse();
    let first = responses[0].clone();
    assert!(matches!(
        client.handle_response(&first).unwrap(),
        Progress::Pending
    ));
    assert!(matches!(
        client.handle_response(&first).unwrap(),
        Progress::Duplicate
    ));
    let mut last = None;
    for response in &responses[1..] {
        last = Some(client.handle_response(response).unwrap());
    }
    assert!(matches!(last, Some(Progress::Complete(_))));
}

#[test]
fn crt_replies_may_arrive_reordered_and_duplicated() {
    reordered_and_duplicated_replies_complete_the_session::<Hqc1>();
    reordered_and_duplicated_replies_complete_the_session::<Hqc3>();
    reordered_and_duplicated_replies_complete_the_session::<Hqc5>();
}

#[test]
fn crt_retransmitted_request_gets_the_same_reply_content() {
    let server = new_server::<Hqc1>();
    let client = collecting_client::<Hqc1>(&server);
    let request = crt_request(&client, 2);
    let first = serve(&server, &request).unwrap();
    let second = serve(&server, &request).unwrap();
    assert_ne!(first, second);
    let payload_of = |packet: &[u8]| {
        let view = encoding::parse_response::<Hqc1>(packet).unwrap();
        let mut payload = vec![0u8; view.sealed.len()];
        encoding::open_response(
            &view,
            &[],
            &client.state.keys.server_to_client,
            &mut payload,
        )
        .unwrap();
        payload
    };
    assert_eq!(payload_of(&first), payload_of(&second));
}
