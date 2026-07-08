//! Interpolation via precomputed inverse Vandermonde matrices.

use super::gf2_9009::{GF29009_NUM_U64, Gf2_9009, POLY_MUL_SCRATCH, poly_mul, reduce};

/// Load a precomputed matrix from embedded binary data.
///
/// Format: 4 bytes (m as little-endian u32), then m*m blocks of
/// 141 u64s (= 1128 bytes) each, stored in the native `Gf2_9009`
/// internal representation.
pub fn load_matrix<const M: usize>(data: &[u8]) -> Box<[[Gf2_9009; M]; M]> {
    let m = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    assert_eq!(m, M, "matrix data size mismatch: expected {M}, got {m}");
    let entry_size = GF29009_NUM_U64 * 8;
    let expected_len = 4 + m * m * entry_size;
    assert_eq!(
        data.len(),
        expected_len,
        "matrix data size mismatch: expected {}, got {}",
        expected_len,
        data.len()
    );

    // Allocate the matrix directly on the heap as a Box.
    // We use unsafe to initialize it from raw bytes.
    let layout = std::alloc::Layout::array::<[Gf2_9009; M]>(M).expect("matrix layout invalid");
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) as *mut [Gf2_9009; M] };
    let matrix_slice: &mut [[Gf2_9009; M]] = unsafe { std::slice::from_raw_parts_mut(ptr, M) };

    let mut offset = 4;
    for row in matrix_slice.iter_mut().take(M) {
        for field_val in row.iter_mut().take(M) {
            let mut field_data = [0u64; GF29009_NUM_U64];
            for (j, f) in field_data.iter_mut().enumerate() {
                let start = offset + j * 8;
                *f = u64::from_le_bytes(data[start..start + 8].try_into().unwrap());
            }
            *field_val = Gf2_9009::new(field_data);
            offset += entry_size;
        }
    }

    unsafe { Box::from_raw(ptr as *mut [[Gf2_9009; M]; M]) }
}

/// Multiply an m×m matrix by a length-m vector over GF(2^9009).
///
/// Accumulates all M unreduced products per row in a single 2n-word buffer,
/// then reduces once per row — saving M²−M reduction passes vs. the naive
/// reduce-after-each-mul approach.
fn mat_vec_mul<const M: usize>(matrix: &[[Gf2_9009; M]; M], vec: &[Gf2_9009; M]) -> [Gf2_9009; M] {
    let mut result = [Gf2_9009::zero(); M];
    let mut prod = [0u64; 2 * GF29009_NUM_U64];
    let mut scratch = [0u64; POLY_MUL_SCRATCH];

    for j in 0..M {
        let mut acc = [0u64; 2 * GF29009_NUM_U64];
        for i in 0..M {
            prod.fill(0);
            poly_mul(&matrix[j][i].data, &vec[i].data, &mut prod, &mut scratch);
            for (a, p) in acc.iter_mut().zip(prod.iter()) {
                *a ^= *p;
            }
        }
        reduce(&mut acc, &mut result[j]);
    }
    result
}

// ── Public API ─────────────────────────────────────────────────────────

/// Interpolate `M` GF(2^9009) evaluation points into
/// `M` coefficients.
pub fn interpolate<const M: usize>(
    matrix: &[[Gf2_9009; M]; M],
    evals: &[Gf2_9009; M],
) -> [Gf2_9009; M] {
    mat_vec_mul::<M>(matrix, evals)
}
