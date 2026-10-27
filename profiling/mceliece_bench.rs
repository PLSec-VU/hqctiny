use pqcrypto_classicmceliece::ffi::*;
use std::time::Instant;

type Keypair = unsafe fn(*mut u8, *mut u8);
type Enc = unsafe fn(*mut u8, *mut u8, *const u8) -> i32;
type Dec = unsafe fn(*mut u8, *const u8, *const u8) -> i32;

struct Backend {
    name: &'static str,
    keypair: Keypair,
    enc: Enc,
    dec: Dec,
}

struct ParameterSet {
    name: &'static str,
    public_key_bytes: usize,
    secret_key_bytes: usize,
    ciphertext_bytes: usize,
    backends: Vec<Backend>,
}

const KEYGEN_RUNS: usize = 5;
const OPERATION_RUNS: usize = 41;

macro_rules! clean_backend {
    ($keypair:ident, $enc:ident, $dec:ident) => {
        Backend {
            name: "clean",
            keypair: |pk, sk| {
                unsafe { $keypair(pk, sk) };
            },
            enc: |ct, ss, pk| unsafe { $enc(ct, ss, pk) },
            dec: |ss, ct, sk| unsafe { $dec(ss, ct, sk) },
        }
    };
}

#[cfg(mceliece_vec)]
macro_rules! vec_backend {
    ($keypair:ident, $enc:ident, $dec:ident) => {
        Backend {
            name: "vec",
            keypair: |pk, sk| unsafe { HQCLethe::mceliece_ref::vec_ffi::$keypair(pk, sk) },
            enc: |ct, ss, pk| unsafe { HQCLethe::mceliece_ref::vec_ffi::$enc(ct, ss, pk) },
            dec: |ss, ct, sk| unsafe { HQCLethe::mceliece_ref::vec_ffi::$dec(ss, ct, sk) },
        }
    };
}

fn median_ms(mut times: Vec<f64>) -> f64 {
    times.sort_by(f64::total_cmp);
    times[times.len() / 2]
}

fn time_ms(runs: usize, mut operation: impl FnMut()) -> f64 {
    let times = (0..runs)
        .map(|_| {
            let start = Instant::now();
            operation();
            start.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    median_ms(times)
}

fn measure(set: &ParameterSet, backend: &Backend) {
    let mut pk = vec![0u8; set.public_key_bytes];
    let mut sk = vec![0u8; set.secret_key_bytes];
    let mut ct = vec![0u8; set.ciphertext_bytes];
    let mut ss = [0u8; 32];
    let keygen = time_ms(KEYGEN_RUNS, || unsafe {
        (backend.keypair)(pk.as_mut_ptr(), sk.as_mut_ptr())
    });
    let encaps = time_ms(OPERATION_RUNS, || {
        unsafe { (backend.enc)(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
    });
    let decaps = time_ms(OPERATION_RUNS, || {
        unsafe { (backend.dec)(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    });
    println!(
        "{} {} keygen_ms={keygen:.3} encaps_ms={encaps:.3} decaps_ms={decaps:.3}",
        set.name, backend.name
    );
}

fn parameter_sets() -> Vec<ParameterSet> {
    vec![
        ParameterSet {
            name: "mceliece348864",
            public_key_bytes: PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES,
            secret_key_bytes: PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES,
            ciphertext_bytes: PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES,
            backends: vec![
                clean_backend!(
                    PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair,
                    PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc,
                    PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec
                ),
                #[cfg(mceliece_vec)]
                vec_backend!(
                    mce348864vec_operation_keypair,
                    mce348864vec_operation_enc,
                    mce348864vec_operation_dec
                ),
            ],
        },
        ParameterSet {
            name: "mceliece460896",
            public_key_bytes: PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES,
            secret_key_bytes: PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES,
            ciphertext_bytes: PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES,
            backends: vec![
                clean_backend!(
                    PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair,
                    PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc,
                    PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec
                ),
                #[cfg(mceliece_vec)]
                vec_backend!(
                    mce460896vec_operation_keypair,
                    mce460896vec_operation_enc,
                    mce460896vec_operation_dec
                ),
            ],
        },
        ParameterSet {
            name: "mceliece6688128",
            public_key_bytes: PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES,
            secret_key_bytes: PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES,
            ciphertext_bytes: PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
            backends: vec![
                clean_backend!(
                    PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair,
                    PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc,
                    PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec
                ),
                #[cfg(mceliece_vec)]
                vec_backend!(
                    mce6688128vec_operation_keypair,
                    mce6688128vec_operation_enc,
                    mce6688128vec_operation_dec
                ),
            ],
        },
    ]
}

fn main() {
    for set in parameter_sets() {
        for backend in &set.backends {
            measure(&set, backend);
        }
    }
}
