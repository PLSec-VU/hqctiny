//! KEM work of the responder in two designs that HQCLethe is compared with,
//! plus the ML-KEM primitives for reference.
//!
//! Rosenpass responder: mceliece460896 decapsulation, mceliece460896
//! encapsulation to the initiator's static key, ML-KEM-512 encapsulation.
//! PQ-WireGuard responder: the same two McEliece operations and one lattice
//! encapsulation. Its IND-CPA Saber ("Dagger") is not available here, so
//! ML-KEM-768 encapsulation stands in for it. ML-KEM is libcrux, the
//! implementation HQCLethe uses.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

#[cfg(not(target_arch = "x86_64"))]
use HQCLethe::mceliece_ref::vec_ffi::{
    mce460896vec_operation_dec as mceliece_dec, mce460896vec_operation_enc as mceliece_enc,
    mce460896vec_operation_keypair as mceliece_keypair,
};
#[cfg(target_arch = "x86_64")]
use pqcrypto_classicmceliece::ffi::{
    PQCLEAN_MCELIECE460896_AVX2_crypto_kem_dec as mceliece_dec,
    PQCLEAN_MCELIECE460896_AVX2_crypto_kem_enc as mceliece_enc,
    PQCLEAN_MCELIECE460896_AVX2_crypto_kem_keypair as mceliece_keypair,
};
use pqcrypto_classicmceliece::ffi::{
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES as MCELIECE_CT_BYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES as MCELIECE_PK_BYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES as MCELIECE_SK_BYTES,
};

const SHARED_SECRET_BYTES: usize = 32;

struct McelieceKeys {
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
}

impl McelieceKeys {
    fn generate() -> Self {
        let mut pk = vec![0u8; MCELIECE_PK_BYTES];
        let mut sk = vec![0u8; MCELIECE_SK_BYTES];
        unsafe { mceliece_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        let mut ct = vec![0u8; MCELIECE_CT_BYTES];
        let mut ss = [0u8; SHARED_SECRET_BYTES];
        unsafe { mceliece_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
        Self { pk, sk, ct }
    }

    fn decapsulate(&self) -> [u8; SHARED_SECRET_BYTES] {
        let mut ss = [0u8; SHARED_SECRET_BYTES];
        unsafe { mceliece_dec(ss.as_mut_ptr(), self.ct.as_ptr(), self.sk.as_ptr()) };
        ss
    }

    fn encapsulate(&self) -> ([u8; SHARED_SECRET_BYTES], Vec<u8>) {
        let mut ct = vec![0u8; MCELIECE_CT_BYTES];
        let mut ss = [0u8; SHARED_SECRET_BYTES];
        unsafe { mceliece_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), self.pk.as_ptr()) };
        (ss, ct)
    }
}

const KEY_GENERATION_SEED: [u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE] = [7; 64];
const ENCAPSULATION_SEED: [u8; libcrux_ml_kem::ENCAPS_SEED_SIZE] = [9; 32];

/// A libcrux ML-KEM key pair and one ciphertext under it.
macro_rules! ml_kem_keys {
    ($name:ident, $module:ident, $key_pair:ident, $ciphertext:ident) => {
        struct $name {
            keys: libcrux_ml_kem::$module::$key_pair,
            ciphertext: libcrux_ml_kem::$module::$ciphertext,
        }

        impl $name {
            fn generate() -> Self {
                let keys = libcrux_ml_kem::$module::generate_key_pair(KEY_GENERATION_SEED);
                let (ciphertext, _) =
                    libcrux_ml_kem::$module::encapsulate(keys.public_key(), ENCAPSULATION_SEED);
                Self { keys, ciphertext }
            }

            fn encapsulate(&self) {
                black_box(libcrux_ml_kem::$module::encapsulate(
                    self.keys.public_key(),
                    black_box(ENCAPSULATION_SEED),
                ));
            }

            fn decapsulate(&self) {
                black_box(libcrux_ml_kem::$module::decapsulate(
                    self.keys.private_key(),
                    &self.ciphertext,
                ));
            }
        }
    };
}

ml_kem_keys!(MlKem512Keys, mlkem512, MlKem512KeyPair, MlKem512Ciphertext);
ml_kem_keys!(MlKem768Keys, mlkem768, MlKem768KeyPair, MlKem768Ciphertext);
ml_kem_keys!(
    MlKem1024Keys,
    mlkem1024,
    MlKem1024KeyPair,
    MlKem1024Ciphertext
);

fn bench_kem_comparison(c: &mut Criterion) {
    let mceliece = McelieceKeys::generate();
    let ml_kem_512 = MlKem512Keys::generate();
    let ml_kem_768 = MlKem768Keys::generate();
    let ml_kem_1024 = MlKem1024Keys::generate();

    c.bench_function("mceliece460896_decap", |b| {
        b.iter(|| black_box(mceliece.decapsulate()))
    });
    c.bench_function("mceliece460896_encap", |b| {
        b.iter(|| black_box(mceliece.encapsulate()))
    });
    c.bench_function("mlkem512_encap", |b| b.iter(|| ml_kem_512.encapsulate()));
    c.bench_function("mlkem512_decap", |b| b.iter(|| ml_kem_512.decapsulate()));
    c.bench_function("mlkem768_encap", |b| b.iter(|| ml_kem_768.encapsulate()));
    c.bench_function("mlkem768_decap", |b| b.iter(|| ml_kem_768.decapsulate()));
    c.bench_function("mlkem1024_encap", |b| b.iter(|| ml_kem_1024.encapsulate()));
    c.bench_function("mlkem1024_decap", |b| b.iter(|| ml_kem_1024.decapsulate()));

    c.bench_function("rosenpass_responder_kem", |b| {
        b.iter(|| {
            black_box(mceliece.decapsulate());
            black_box(mceliece.encapsulate());
            ml_kem_512.encapsulate();
        })
    });
    c.bench_function("pqwireguard_responder_kem_mlkem768_standin", |b| {
        b.iter(|| {
            black_box(mceliece.decapsulate());
            black_box(mceliece.encapsulate());
            ml_kem_768.encapsulate();
        })
    });
}

criterion_group!(benches, bench_kem_comparison);
criterion_main!(benches);
