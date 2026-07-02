use crate::hqc::HqcScheme;
use crate::math::gf2_9009::Gf2_9009;

/// Multiplies the element by x^n + 1 where n is an argument
#[inline]
pub fn mul_by_x_n_plus_1(gf2: &mut Gf2_9009, n: usize) {
    let mut shifted = Gf2_9009::zero();
    gf2.mul_by_x_pow(n, &mut shifted);
    gf2.add(&shifted);
}

#[inline]
pub fn mul_by_modulus_point<T: HqcScheme>(gf2: &mut Gf2_9009, point_idx: usize) {
    let n = T::get_point_degree(point_idx);
    mul_by_x_n_plus_1(gf2, n);
}
