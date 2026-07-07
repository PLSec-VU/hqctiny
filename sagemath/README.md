# SageMath Scripts

This directory contains SageMath scripts used to generate mathematical structures and test vectors for HQCTiny.

## Scripts

- **`generate_test_vectors.sage`**: Generates test vectors for arithmetic and polynomial operations in $\text{GF}(2^{9009})$ with modulus $x^{9009} + x^{29} + 1$. Output is saved to `src/math/test_vectors.json`.
- **`save_matrices_bin.sage`**: Generates the binary interpolation matrices for the Vandermonde system over $\text{GF}(2^{9009})$ for HQC parameter sets ($n = 17669, 35851, 57637$). Output files are saved to `src/math/interpolate_matrix_{n}.bin`.

## Running the Scripts

To execute either script, run:

```bash
sage sagemath/generate_test_vectors.sage
sage sagemath/save_matrices_bin.sage
```
