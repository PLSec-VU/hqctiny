const ROOT: &str = "hqc-addfft/hqc-fft";
const A72_POLYMUL_DIR: &str = "hqc-addfft/hqc-fft/lib/bitpolymul_a72";
const X86_POLYMUL_DIR: &str = "hqc-addfft/hqc-fft/lib/bitpolymul_x86";

pub const SYMBOLS: &[&str] = &[
    "ring_to_fftform",
    "ring_to_fftform_rlonly",
    "ring_mul_fftformx2",
    "ring_mul_fftform",
    "ring_mul",
    "ring_mul_x2",
    "ring_mul_x2_fftform",
    "vect_mul",
    "reduce",
    "schoolbook",
    "karat_mult_square",
    "karat_mult3",
    "toom_3_mult_arm",
    "a1_times_a2",
    "o256",
    "bloc64",
    "bit64",
    "__gf256_mulbase",
    "__gf256_mulbase_avx",
    "gf256v_generate_multabs_avx2",
    "gf256v_mul_scalar_avx2",
    "linearmap_8x8_ymm",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Multiplier {
    KroneckerCrt,
    ToomKaratsuba,
    FrobeniusAvx2,
}

const VARIANT_WITH_UNSOUND_KRONECKER_CRT: &str = "3";

pub fn multiplier(target_arch: &str, variant: &str) -> Option<Multiplier> {
    let enabled = |feature: &str| std::env::var_os(feature).is_some();
    if !enabled("CARGO_FEATURE_HQC_ADDFFT") {
        return None;
    }
    let toom = enabled("CARGO_FEATURE_HQC_ADDFFT_TOOM");
    match target_arch {
        "aarch64" if toom || variant == VARIANT_WITH_UNSOUND_KRONECKER_CRT => {
            Some(Multiplier::ToomKaratsuba)
        }
        "aarch64" => Some(Multiplier::KroneckerCrt),
        "x86_64" if !toom => Some(Multiplier::FrobeniusAvx2),
        _ => panic!(
            "the `hqc-addfft` feature supports aarch64 (and `hqc-addfft-toom` only there) and \
             x86_64 (target architecture is `{target_arch}`)"
        ),
    }
}

impl Multiplier {
    pub fn needs_avx2_defines(self) -> bool {
        self == Multiplier::FrobeniusAvx2
    }

    fn polymul_dir(self) -> Option<&'static str> {
        match self {
            Multiplier::FrobeniusAvx2 => Some(X86_POLYMUL_DIR),
            Multiplier::KroneckerCrt => Some(A72_POLYMUL_DIR),
            Multiplier::ToomKaratsuba => None,
        }
    }

    pub fn replaced_source(self, v: &str) -> String {
        match self {
            Multiplier::FrobeniusAvx2 => format!("hqc/src/x86_64/common/hqc-{v}/gf2x.c"),
            _ => "hqc/src/ref/gf2x.c".to_string(),
        }
    }

    fn include_dirs(self, v: &str) -> Vec<String> {
        let src = format!("{ROOT}/src");
        match self {
            Multiplier::KroneckerCrt => vec![
                A72_POLYMUL_DIR.to_string(),
                format!("{src}/cachekey"),
                format!("{src}/armv8"),
                format!("{src}/armv8/hqc-{v}"),
            ],
            Multiplier::ToomKaratsuba => vec![
                format!("{src}/a72"),
                format!("{src}/armv8"),
                format!("{src}/armv8/hqc-{v}"),
            ],
            Multiplier::FrobeniusAvx2 => vec![
                X86_POLYMUL_DIR.to_string(),
                format!("{src}/cachekey"),
                format!("hqc/src/x86_64/common/hqc-{v}"),
            ],
        }
    }

    fn source(self, v: &str) -> String {
        let src = format!("{ROOT}/src");
        match self {
            Multiplier::ToomKaratsuba => format!("{src}/a72/hqc-{v}/gf2x.c"),
            _ => format!("{src}/cachekey/gf2x.c"),
        }
    }

    pub fn compile_for_variant(self, v: &str) {
        let mut build = cc::Build::new();
        build.include("hqc/src/common");
        build.include(format!("hqc/src/common/hqc-{v}"));
        for dir in self.include_dirs(v) {
            build.include(dir);
        }
        build.file(super::per_thread_copy(&self.source(v), v));
        build.flag("-funroll-all-loops");
        build.flag_if_supported("-Wno-error=incompatible-pointer-types");
        build.warnings(false);
        build.opt_level(3);
        if self == Multiplier::FrobeniusAvx2 {
            build.define("HQC_ARCH_X86_64", "1");
            build.define("HQC_ARCH_X86_64_AVX256", "1");
            for flag in ["-mavx", "-mavx2", "-mbmi", "-mpclmul"] {
                build.flag(flag);
            }
        } else {
            build.define("NEW_CODE", None);
            build.flag("-flax-vector-conversions");
        }
        if self != Multiplier::ToomKaratsuba {
            build.define("TEST_CACHEKEY", None);
        }
        for symbol in SYMBOLS {
            build.define(symbol, Some(&*format!("hqc_{v}_{symbol}")));
        }
        build.compile(&format!("hqc{v}_multiplier"));
    }

    pub fn compile_shared_library(self) {
        let Some(dir) = self.polymul_dir() else {
            return;
        };
        let mut build = cc::Build::new();
        build.include(dir);
        build.opt_level(3);
        build.flag("-funroll-all-loops");
        build.warnings(false);
        if self == Multiplier::FrobeniusAvx2 {
            for flag in ["-mavx", "-mavx2", "-mbmi", "-mpclmul"] {
                build.flag(flag);
            }
        } else {
            build.flag("-flax-vector-conversions");
            build.define("NEW_CODE", None);
        }
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "c") {
                build.file(path);
            }
        }
        build.compile("addfft_polymul");
        println!("cargo:rerun-if-changed={dir}");
    }
}
