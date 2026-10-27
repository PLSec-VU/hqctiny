#[cfg(target_arch = "x86_64")]
pub(crate) fn has_avx2_and_pclmulqdq() -> bool {
    is_x86_feature_detected!("avx2")
        && is_x86_feature_detected!("pclmulqdq")
        && is_x86_feature_detected!("bmi2")
}
