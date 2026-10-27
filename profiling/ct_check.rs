//! Constant-time check in the style of ctgrind. Run under
//! `valgrind --error-exitcode=9 --track-origins=yes`. The secrets live in
//! memory that Memcheck reports as uninitialised, so any branch or memory
//! address that depends on them is reported as an error.

use HQCLethe::auth::{AuthKem, AuthLevel, ServerSecretKey, shared_keypair};
use HQCLethe::client::{Client, Progress};
use HQCLethe::crt::MAX_RESIDUE_WORDS;
use HQCLethe::crt::server::masked_residue;
use HQCLethe::encoding::MAX_UDP_PAYLOAD;
use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use HQCLethe::math::poly_mul::{Backend, scratch_words};
use HQCLethe::server::Server;
use HQCLethe::traits::*;
use std::alloc::{Layout, alloc};

#[path = "valgrind_requests.rs"]
mod valgrind_requests;
use valgrind_requests::{classify, declassify};

const PEER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

#[derive(Clone)]
struct ZeroEntropy;
impl EntropyProvider for ZeroEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        out.fill(7);
    }
}

#[derive(Clone, Default)]
struct NullSessionStore;
impl SessionStore for NullSessionStore {
    fn save_session(&self, _k_session: [u8; 32]) {}
}

#[derive(Clone)]
struct ClassifiedEntropy;
impl EntropyProvider for ClassifiedEntropy {
    fn random_bytes(&self, out: &mut [u8]) {
        out.fill(7);
        classify(out);
    }
}

fn undefined_bytes(len: usize) -> &'static [u8] {
    let layout = Layout::array::<u8>(len).unwrap();
    unsafe { std::slice::from_raw_parts(alloc(layout), len) }
}

const MULTIPLY_WORDS: [usize; 4] = [8, 73, 141, 277];

fn undefined_words(len: usize) -> &'static [u64] {
    let layout = Layout::array::<u64>(len).unwrap();
    unsafe { std::slice::from_raw_parts(alloc(layout) as *const u64, len) }
}

fn check_poly_mul_backends() {
    for backend in Backend::available() {
        for words in MULTIPLY_WORDS {
            let secret = undefined_words(words);
            let public = vec![0x9E37_79B9_7F4A_7C15u64; words];
            let mut product = vec![0u64; 2 * words];
            let mut scratch = vec![0u64; scratch_words(words)];
            backend.multiply(secret, &public, &mut product, &mut scratch);
            backend.multiply(&public, secret, &mut product, &mut scratch);
            std::hint::black_box(&product);
        }
    }
}

fn check<SCHEME: HqcScheme>() {
    let theta = undefined_bytes(32);
    let m = undefined_bytes(SCHEME::PARAM_SECURITY_BYTES);
    let h_seed = [3u8; 32];

    let mut window = vec![0u8; 1190];
    SCHEME::compute_u_window(&h_seed, theta, 0, &mut window);
    std::hint::black_box(&window);
    check_residues::<SCHEME>(theta, m);
}

fn check_residues<SCHEME: HqcScheme>(theta: &[u8], m: &[u8]) {
    let public_residue = [0x9E37_79B9_7F4A_7C15u64; MAX_RESIDUE_WORDS];
    for &modulus in SCHEME::CRT_MODULI {
        let mut residue = [0u64; MAX_RESIDUE_WORDS];
        masked_residue::<SCHEME>(theta, m, modulus, &public_residue, &mut residue);
        std::hint::black_box(&residue);
    }
}

fn check_kem<SCHEME: HqcScheme>() {
    let mut pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    let mut ct = vec![0u8; SCHEME::CIPHERTEXT_BYTES];
    let mut ss = vec![0u8; SCHEME::SHARED_SECRET_BYTES];
    unsafe {
        SCHEME::keypair(&[7u8; 48], &mut pk, &mut sk);
        SCHEME::enc(&[9u8; 48], &mut ct, &mut ss, &pk);
    }

    let secret_entropy = undefined_bytes(48);
    let mut generated_pk = vec![0u8; SCHEME::PUBLIC_KEY_BYTES];
    let mut generated_sk = vec![0u8; SCHEME::SECRET_KEY_BYTES];
    unsafe {
        SCHEME::keypair(secret_entropy, &mut generated_pk, &mut generated_sk);
    }
    std::hint::black_box((&generated_pk, &generated_sk));

    let mut secret_key = undefined_bytes(SCHEME::SECRET_KEY_BYTES).to_vec();
    secret_key[..SCHEME::PUBLIC_KEY_BYTES].copy_from_slice(&pk);
    let mut decapsulated = vec![0u8; SCHEME::SHARED_SECRET_BYTES];
    SCHEME::dec(&mut decapsulated, &ct, &secret_key);
    std::hint::black_box(&decapsulated);

    unsafe {
        SCHEME::enc(secret_entropy, &mut ct, &mut ss, &pk);
    }
    std::hint::black_box((&ct, &ss));
}

/// An ML-KEM-768 secret key is dk_PKE || ek || H(ek) || z. Only dk_PKE and
/// the implicit-rejection seed z are secret; ek and H(ek) are public.
const MLKEM_DK_PKE_BYTES: usize = 1152;
const MLKEM_Z_BYTES: usize = 32;

fn classify_mlkem_secret_parts(secret_key: &mut [u8]) {
    let z_start = secret_key.len() - MLKEM_Z_BYTES;
    classify(&mut secret_key[..MLKEM_DK_PKE_BYTES]);
    classify(&mut secret_key[z_start..]);
}

fn check_mlkem_decapsulation<LEVEL: AuthLevel>() {
    let keys = shared_keypair::<LEVEL>();
    let secret_key = classified_secret_key(&keys.secret);
    let ciphertext = vec![5u8; LEVEL::Kem::CIPHERTEXT_BYTES];
    std::hint::black_box(secret_key.decapsulate(&ciphertext).unwrap());
}

fn classified_secret_key<LEVEL: AuthLevel>(key: &ServerSecretKey<LEVEL>) -> ServerSecretKey<LEVEL> {
    let mut bytes = key.as_bytes().to_vec();
    classify_mlkem_secret_parts(&mut bytes);
    ServerSecretKey::from_bytes(bytes).unwrap()
}

type ClassifiedServer<SCHEME> = Server<SCHEME, NullSessionStore, ClassifiedEntropy>;

fn serve<SCHEME: HqcScheme>(server: &ClassifiedServer<SCHEME>, request: &[u8]) -> Vec<u8> {
    let mut response = [0u8; MAX_UDP_PAYLOAD];
    let length = server.handle_packet(PEER, request, &mut response).unwrap();
    declassify(&response[..length]);
    response[..length].to_vec()
}

fn check_session<SCHEME: HqcScheme>() {
    let keys = shared_keypair::<SCHEME>();
    let server = ClassifiedServer::<SCHEME>::new(
        NullSessionStore,
        ClassifiedEntropy,
        classified_secret_key(&keys.secret),
    );
    let (client, request) = Client::new(NullSessionStore, ZeroEntropy).initialize(&keys.public);

    eprintln!("== stage: server handshake");
    let response = serve(&server, &request);
    let mut client = client.handle_handshake_response(&response).unwrap();
    classify(&mut client.state.sk);
    classify(&mut client.state.auth_secret[..]);

    let requests = client.requests().to_vec();
    for request in requests {
        eprintln!("== stage: server {:?} {}", request.kind, request.index);
        let response = serve(&server, &request.bytes);
        eprintln!(
            "== stage: client response {:?} {}",
            request.kind, request.index
        );
        if let Progress::Complete(session_key) = client.handle_response(&response).unwrap() {
            std::hint::black_box(&session_key);
        }
    }
}

fn branch_on_product_control() {
    let words = MULTIPLY_WORDS[0];
    let secret = undefined_words(words);
    let public = vec![0x9E37_79B9_7F4A_7C15u64; words];
    let mut product = vec![0u64; 2 * words];
    let mut scratch = vec![0u64; scratch_words(words)];
    Backend::fastest().multiply(secret, &public, &mut product, &mut scratch);
    if product[3] & 1 == 1 {
        std::hint::black_box(&product);
    }
}

fn classify_control() {
    let mut bytes = vec![1u8; 16];
    declassify(&bytes);
    if std::hint::black_box(bytes[0]) == 1 {
        std::hint::black_box(&bytes);
    }
    classify(&mut bytes);
    if std::hint::black_box(bytes[0]) == 1 {
        std::hint::black_box(&bytes);
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("control") {
        return branch_on_product_control();
    }
    match std::env::args().nth(1).as_deref() {
        Some("mlkem1") => return check_mlkem_decapsulation::<Hqc1>(),
        Some("mlkem3") => return check_mlkem_decapsulation::<Hqc3>(),
        Some("mlkem5") => return check_mlkem_decapsulation::<Hqc5>(),
        Some("session1") => return check_session::<Hqc1>(),
        Some("session3") => return check_session::<Hqc3>(),
        Some("session5") => return check_session::<Hqc5>(),
        Some("classify-control") => return classify_control(),
        _ => {}
    }
    check_poly_mul_backends();
    match std::env::args().nth(1).as_deref() {
        Some("kem1") => check_kem::<Hqc1>(),
        Some("kem3") => check_kem::<Hqc3>(),
        Some("kem5") => check_kem::<Hqc5>(),
        Some("1") => check::<Hqc1>(),
        Some("3") => check::<Hqc3>(),
        _ => check::<Hqc5>(),
    }
}
