use core::simd::u64x4;

/// In-place slice XOR: `dst[..src.len()] ^= src[..]` using portable SIMD.
#[inline(always)]
pub(crate) fn simd_xor_assign(dst: &mut [u64], src: &[u64]) {
    debug_assert!(dst.len() >= src.len());
    let len = src.len();
    let (dst_chunks, dst_tail) = dst[..len].as_chunks_mut::<4>();
    let (src_chunks, src_tail) = src.as_chunks::<4>();
    for (d, s) in dst_chunks.iter_mut().zip(src_chunks) {
        let vd = u64x4::from_array(*d);
        let vs = u64x4::from_array(*s);
        *d = (vd ^ vs).to_array();
    }
    for (d, s) in dst_tail.iter_mut().zip(src_tail) {
        *d ^= *s;
    }
}

/// XORs `src << shift` (as a bit string) into `acc`. `acc` must hold at
/// least `shift / 64 + src.len() + 1` words. Every index is derived from the
/// public `shift`.
#[inline(always)]
pub(crate) fn xor_shifted_into(acc: &mut [u64], src: &[u64], shift: usize) {
    let word_shift = shift / 64;
    let bit_shift = shift % 64;
    let window = &mut acc[word_shift..word_shift + src.len() + 1];
    if bit_shift == 0 {
        simd_xor_assign(window, src);
        return;
    }
    let inv_shift = 64 - bit_shift;
    let shift_hi = core::simd::u64x4::splat(bit_shift as u64);
    let shift_lo = core::simd::u64x4::splat(inv_shift as u64);
    let (chunks, tail) = src.as_chunks::<4>();
    for (c_idx, &src_arr) in chunks.iter().enumerate() {
        let base = c_idx * 4;
        let vs = core::simd::u64x4::from_array(src_arr);
        let hi = vs << shift_hi;
        let lo = vs >> shift_lo;

        let cur_lo = core::simd::u64x4::from_slice(&window[base..base + 4]);
        (cur_lo ^ hi).copy_to_slice(&mut window[base..base + 4]);

        let cur_hi = core::simd::u64x4::from_slice(&window[base + 1..base + 5]);
        (cur_hi ^ lo).copy_to_slice(&mut window[base + 1..base + 5]);
    }
    let processed = chunks.len() * 4;
    for (i, &w) in tail.iter().enumerate() {
        window[processed + i] ^= w << bit_shift;
        window[processed + i + 1] ^= w >> inv_shift;
    }
}
