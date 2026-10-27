#[path = "build/addfft.rs"]
mod addfft;

const VARIANTS: [&str; 3] = ["1", "3", "5"];

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    // The `avx2` feature builds HQC's x86_64/avx256 sources in place of the
    // portable `ref` ones. They are x86-only and use real AVX2 intrinsics.
    let avx2 = std::env::var_os("CARGO_FEATURE_AVX2").is_some();
    assert!(
        !avx2 || matches!(target_arch.as_str(), "x86_64" | "x86"),
        "the `avx2` feature builds HQC's x86_64/avx256 sources, which require \
         an x86 target (target architecture is `{target_arch}`)"
    );

    let multipliers = VARIANTS.map(|variant| addfft::multiplier(&target_arch, variant));
    let avx2 = avx2 || multipliers.iter().flatten().any(|m| m.needs_avx2_defines());
    // Compile fips202 Keccak/SHA3 implementation once
    let mut fips_build = cc::Build::new();
    fips_build.include("hqc/lib/fips202");
    fips_build.file("hqc/lib/fips202/fips202.c");
    fips_build.compile("fips202");

    // The AVX2 sources need the genuine immintrin.h, and only ever build for x86.
    let immintrin_shim = if avx2 {
        None
    } else {
        non_x86_immintrin_shim(&target_arch)
    };

    // Compile HQC variants
    for (variant, multiplier) in VARIANTS.into_iter().zip(multipliers) {
        compile_variant(variant, avx2, multiplier, immintrin_shim.as_deref());
    }
    compile_shared_multiplier_libraries(&multipliers);

    println!("cargo::rustc-check-cfg=cfg(mceliece_vec)");
    if uses_mceliece_vec(&target_arch) && std::env::var_os("CARGO_FEATURE_MCELIECE_REF").is_some() {
        println!("cargo:rustc-cfg=mceliece_vec");
        for parameter_set in MCELIECE_VEC_PARAMETER_SETS {
            compile_mceliece_vec(parameter_set);
        }
    }

    println!("cargo:rerun-if-changed=third_party/mceliece-vec");
    println!("cargo:rerun-if-changed=hqc/src");
    println!("cargo:rerun-if-changed=hqc/lib/fips202");
    println!("cargo:rerun-if-changed=hqc-addfft/hqc-fft/src");
    println!("cargo:rerun-if-changed=build/addfft.rs");
}

/// The vendored HQC reference sources unconditionally `#include
/// <immintrin.h>`, even though the portable `HQC_ARCH_REF` path below calls
/// no AVX intrinsics (the `#define __IMMINTRIN_H` further down relies on the
/// header being a no-op once opened, not on skipping the `#include` itself).
/// On x86_64 that header always exists, so the no-op trick is enough. On other
/// architectures (e.g. aarch64, as in eval/'s Linux container) the
/// toolchain doesn't ship the file at all, so the `#include` fails before
/// the guard is ever reached. This synthesizes an empty stand-in and
/// places it ahead of the normal search path so it's found instead.
fn non_x86_immintrin_shim(target_arch: &str) -> Option<std::path::PathBuf> {
    if matches!(target_arch, "x86_64" | "x86") {
        return None;
    }
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let shim_dir = std::path::Path::new(&out_dir).join("immintrin_shim");
    std::fs::create_dir_all(&shim_dir).unwrap();
    std::fs::write(
        shim_dir.join("immintrin.h"),
        "// stub: this build never uses x86 intrinsics (see build.rs)\n",
    )
    .unwrap();
    Some(shim_dir)
}

const MCELIECE_VEC_PARAMETER_SETS: [&str; 3] = ["348864", "460896", "6688128"];

fn uses_mceliece_vec(target_arch: &str) -> bool {
    !matches!(target_arch, "x86_64" | "x86")
}

fn compile_shared_multiplier_libraries(multipliers: &[Option<addfft::Multiplier>]) {
    let mut compiled: Vec<addfft::Multiplier> = Vec::new();
    for multiplier in multipliers.iter().flatten() {
        if !compiled.contains(multiplier) {
            compiled.push(*multiplier);
            multiplier.compile_shared_library();
        }
    }
}

fn compile_mceliece_vec(parameter_set: &str) {
    let root = std::path::Path::new("third_party/mceliece-vec");
    let set_dir = root.join(parameter_set);
    let namespace = format!("mce{parameter_set}vec_");
    let mut build = cc::Build::new();
    build.include(&set_dir);
    build.include(root.join("include"));
    build.include(root.join("shim"));
    build.define("CRYPTO_NAMESPACE(x)", Some(&*format!("{namespace}##x")));
    build.define(
        "CRYPTO_SHARED_NAMESPACE(x)",
        Some(&*format!("{namespace}##x")),
    );
    build.opt_level(3);
    build.warnings(false);
    for entry in std::fs::read_dir(&set_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "c") {
            build.file(path);
        }
    }
    build.compile(&format!("mceliece{parameter_set}vec"));
}

fn compile_variant(
    v: &str,
    avx2: bool,
    addfft: Option<addfft::Multiplier>,
    immintrin_shim: Option<&std::path::Path>,
) {
    let mut build = cc::Build::new();

    // Set target architecture configuration, mirroring the upstream CMake build
    if avx2 {
        build.define("HQC_ARCH_X86_64", "1");
        build.define("HQC_ARCH_X86_64_AVX256", "1");
        for flag in ["-mavx", "-mavx2", "-mbmi", "-mpclmul", "-funroll-loops"] {
            build.flag(flag);
        }
    } else {
        build.define("HQC_ARCH_REF", "1");
        // Disable immintrin.h to avoid compilation errors on non-x86 architectures
        build.define("__IMMINTRIN_H", None);

        if let Some(dir) = immintrin_shim {
            build.include(dir);
        }
    }

    // Include directories
    build.include("hqc/src/common");
    build.include(format!("hqc/src/common/hqc-{}", v));
    if avx2 {
        build.include("hqc/src/x86_64/common");
        build.include(format!("hqc/src/x86_64/common/hqc-{}", v));
        build.include("hqc/src/x86_64/avx256");
        build.include(format!("hqc/src/x86_64/avx256/hqc-{}", v));
    } else {
        build.include("hqc/src/ref");
        build.include(format!("hqc/src/ref/hqc-{}", v));
    }
    build.include("hqc/lib/fips202");

    // Source files to compile
    let common_sources = &[
        "hqc/src/common/code.c",
        "hqc/src/common/crypto_memset.c",
        "hqc/src/common/fft.c",
        "hqc/src/common/kem.c",
        "hqc/src/common/symmetric.c",
    ];

    // The AVX2 build splits its sources in two: `x86_64/common` holds what is
    // shared by every x86 backend, `x86_64/avx256` the AVX2 kernels.
    let arch_sources: Vec<String> = if avx2 {
        vec![
            "hqc/src/x86_64/avx256/gf.c".into(),
            format!("hqc/src/x86_64/common/hqc-{}/gf2x.c", v),
            "hqc/src/x86_64/common/hqc.c".into(),
            "hqc/src/x86_64/common/parsing.c".into(),
            "hqc/src/x86_64/avx256/reed_muller.c".into(),
            format!("hqc/src/x86_64/avx256/hqc-{}/reed_solomon.c", v),
            "hqc/src/x86_64/avx256/vector.c".into(),
        ]
    } else {
        [
            "hqc/src/ref/gf.c",
            "hqc/src/ref/gf2x.c",
            "hqc/src/ref/hqc.c",
            "hqc/src/ref/parsing.c",
            "hqc/src/ref/reed_muller.c",
            "hqc/src/ref/reed_solomon.c",
            "hqc/src/ref/vector.c",
        ]
        .map(String::from)
        .to_vec()
    };

    let replaced_source = addfft.map(|multiplier| multiplier.replaced_source(v));
    let sources = common_sources
        .iter()
        .map(|src| src.to_string())
        .chain(arch_sources)
        .filter(|src| Some(src) != replaced_source.as_ref());
    for src in sources {
        build.file(per_thread_copy(&src, v));
    }

    // Prefix all global symbols to avoid conflicts between variants
    let symbols = &[
        "crypto_kem_keypair",
        "crypto_kem_enc",
        "crypto_kem_dec",
        "gf_generate",
        "gf_mul",
        "gf_square",
        "gf_inverse",
        "vect_mul",
        "hqc_pke_keygen",
        "hqc_pke_encrypt",
        "hqc_pke_decrypt",
        "hqc_dk_pke_from_string",
        "hqc_ek_pke_from_string",
        "hqc_c_kem_to_string",
        "hqc_c_kem_from_string",
        "vect_generate_random_support1",
        "vect_generate_random_support2",
        "vect_write_support_to_vector",
        "vect_sample_fixed_weight1",
        "vect_sample_fixed_weight2",
        "vect_set_random",
        "vect_add",
        "vect_compare",
        "vect_truncate",
        "vect_print",
        "reed_solomon_encode",
        "reed_solomon_decode",
        "reed_muller_encode",
        "reed_muller_decode",
        "fft",
        "fft_retrieve_error_poly",
        "prng_init",
        "prng_get_bytes",
        "xof_init",
        "xof_get_bytes",
        "hash_g",
        "hash_h",
        "hash_i",
        "hash_j",
        "memset_volatile",
        "code_encode",
        "code_decode",
        "shake256_prng_ctx",
        "encode",
        "hadamard",
        "expand_and_sum",
        "find_peaks",
        "compute_generator_poly",
        "compute_syndromes",
        "gf_reduce",
        "gf_carryless_mul",
    ];

    // Symbols that only exist in the AVX2 sources. `gf2x.c` keeps its scratch
    // space in file-scope globals, so these are data, not just functions —
    // without a prefix the three variants would share one buffer.
    let avx2_symbols: &[&str] = if avx2 {
        &[
            "gf_mul_vect",
            "toom_3_mult",
            "a1_times_a2",
            "o256",
            "tmp_reduce",
            "bloc64",
            "bit64",
        ]
    } else {
        &[]
    };

    for sym in symbols.iter().chain(avx2_symbols) {
        build.define(sym, Some(&*format!("hqc_{}_{}", v, sym)));
    }

    build.compile(&format!("hqc{}", v));
    if let Some(multiplier) = addfft {
        multiplier.compile_for_variant(v);
    }
}

const PER_THREAD_STORAGE: &str = "_Thread_local ";

const MUTABLE_FUNCTION_STATICS: [&str; 3] =
    ["static __m256i ", "static uint64_t ", "static int32_t d0;"];

const MUTABLE_GLOBALS: [&str; 7] = [
    "shake256incctx shake256_prng_ctx;",
    "__m256i a1_times_a2[",
    "__m256i o256[",
    "uint64_t a1_times_a2[",
    "uint64_t o256[",
    "uint64_t bloc64[",
    "uint64_t bit64[",
];

/// A global initialised with the address of a thread-local is not valid C,
/// so the pointer into `o256` becomes an expression.
const THREAD_LOCAL_ALIASES: [(&str, &str); 1] = [(
    "uint64_t *tmp_reduce = (uint64_t *)o256;",
    "#define tmp_reduce ((uint64_t *)o256)",
)];

fn is_function_static(line: &str) -> bool {
    let inside_a_function = line.starts_with(char::is_whitespace);
    let declaration = line.trim_start();
    inside_a_function
        && MUTABLE_FUNCTION_STATICS
            .iter()
            .any(|prefix| declaration.starts_with(prefix))
}

fn per_thread_line(line: &str) -> Option<String> {
    if is_function_static(line) {
        return Some(line.replacen("static ", &format!("static {PER_THREAD_STORAGE}"), 1));
    }
    let declaration = line.trim_start();
    if MUTABLE_GLOBALS
        .iter()
        .any(|global| declaration.starts_with(global))
    {
        return Some(format!("{PER_THREAD_STORAGE}{declaration}"));
    }
    THREAD_LOCAL_ALIASES
        .iter()
        .find(|(global, _)| line == *global)
        .map(|(_, alias)| alias.to_string())
}

/// Returns `source`, or a copy of it in OUT_DIR with its mutable globals and
/// function statics declared per thread.
pub fn per_thread_copy(source: &str, variant: &str) -> std::path::PathBuf {
    let original = std::path::PathBuf::from(source);
    let text = std::fs::read_to_string(&original).unwrap();
    let rewritten: Vec<Option<String>> = text.lines().map(per_thread_line).collect();
    if rewritten.iter().all(Option::is_none) {
        return original;
    }
    let lines = text
        .lines()
        .zip(&rewritten)
        .map(|(line, new)| new.as_deref().unwrap_or(line));
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap())
        .join("per_thread")
        .join(format!("hqc-{variant}"))
        .join(original.parent().unwrap());
    std::fs::create_dir_all(&out_dir).unwrap();
    let copy = out_dir.join(original.file_name().unwrap());
    std::fs::write(&copy, lines.collect::<Vec<_>>().join("\n") + "\n").unwrap();
    println!("cargo:rerun-if-changed={source}");
    copy
}
