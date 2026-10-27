use HQCLethe::hqc::{Hqc1, Hqc3, Hqc5, HqcScheme};
use std::fmt::Write as _;

const VECTORS_PER_LEVEL: u8 = 16;
const ENTROPY_BYTES: usize = 48;

struct Vector {
    level: u8,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn entropy(level: u8, index: u8, purpose: u8) -> [u8; ENTROPY_BYTES] {
    let mut bytes = [0u8; ENTROPY_BYTES];
    for (position, byte) in bytes.iter_mut().enumerate() {
        *byte = (position as u8)
            .wrapping_mul(31)
            .wrapping_add(level << 5 ^ index << 1 ^ purpose);
    }
    bytes
}

fn derive<S: HqcScheme>(level: u8, index: u8) -> Vector {
    let mut pk = vec![0u8; S::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; S::SECRET_KEY_BYTES];
    let mut ct = vec![0u8; S::CIPHERTEXT_BYTES];
    let mut ss = vec![0u8; S::SHARED_SECRET_BYTES];
    unsafe {
        assert_eq!(S::keypair(&entropy(level, index, 0), &mut pk, &mut sk), 0);
        assert_eq!(S::enc(&entropy(level, index, 1), &mut ct, &mut ss, &pk), 0);
    }
    Vector {
        level,
        pk,
        sk,
        ct,
        ss,
    }
}

fn derive_level(level: u8) -> Vec<Vector> {
    (0..VECTORS_PER_LEVEL)
        .map(|index| match level {
            1 => derive::<Hqc1>(level, index),
            3 => derive::<Hqc3>(level, index),
            _ => derive::<Hqc5>(level, index),
        })
        .collect()
}

fn decapsulate(vector: &Vector) -> Vec<u8> {
    let mut ss = vec![0u8; vector.ss.len()];
    let status = match vector.level {
        1 => Hqc1::dec(&mut ss, &vector.ct, &vector.sk),
        3 => Hqc3::dec(&mut ss, &vector.ct, &vector.sk),
        _ => Hqc5::dec(&mut ss, &vector.ct, &vector.sk),
    };
    assert_eq!(status, 0);
    ss
}

fn emit() {
    let mut text = String::new();
    for vector in [1, 3, 5].into_iter().flat_map(derive_level) {
        for field in [&vector.pk, &vector.sk, &vector.ct, &vector.ss] {
            write!(text, "{} ", hex::encode(field)).unwrap();
        }
        writeln!(text, "{}", vector.level).unwrap();
    }
    print!("{text}");
}

fn parse(line: &str) -> Vector {
    let mut fields = line.split(' ');
    let mut next_bytes = || hex::decode(fields.next().unwrap()).unwrap();
    let (pk, sk, ct, ss) = (next_bytes(), next_bytes(), next_bytes(), next_bytes());
    let level = fields.next().unwrap().parse().unwrap();
    Vector {
        level,
        pk,
        sk,
        ct,
        ss,
    }
}

fn verify(path: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    let foreign: Vec<Vector> = text.lines().map(parse).collect();
    let own: Vec<Vector> = [1, 3, 5].into_iter().flat_map(derive_level).collect();
    assert_eq!(foreign.len(), own.len());
    for (theirs, ours) in foreign.iter().zip(&own) {
        assert_eq!(theirs.pk, ours.pk, "HQC-{} public key", ours.level);
        assert_eq!(theirs.sk, ours.sk, "HQC-{} secret key", ours.level);
        assert_eq!(theirs.ct, ours.ct, "HQC-{} ciphertext", ours.level);
        assert_eq!(theirs.ss, ours.ss, "HQC-{} shared secret", ours.level);
        assert_eq!(
            decapsulate(theirs),
            theirs.ss,
            "HQC-{} decapsulation",
            ours.level
        );
    }
    println!("ok: {} vectors identical and decapsulated", own.len());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("emit") => emit(),
        Some("verify") => verify(&args[2]),
        _ => panic!("usage: backend-vectors emit | verify <file>"),
    }
}
