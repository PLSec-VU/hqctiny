use crate::math::gf2_8984::Gf2_8984;
use crate::hqc::HqcScheme;

/// Multiplies the element by x^n + 1 where n is an argument
#[inline]
pub fn mul_by_x_n_plus_1(gf2: &mut Gf2_8984, n: usize) {
    let mut shifted = Gf2_8984::zero();
    gf2.mul_by_x_pow(n, &mut shifted);
    gf2.add(&shifted);
}

#[inline]
pub fn mul_by_modulus_point<T: HqcScheme>(gf2: &mut Gf2_8984, point_idx: usize) {
    let n = T::get_point_degree(point_idx);
    mul_by_x_n_plus_1(gf2, n);
}
