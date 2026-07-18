# SageMath Scripts

This directory contains SageMath scripts used to generate mathematical structures and test vectors for HQCLethe.

## Scripts

- **`generate_test_vectors.sage`**: Generates test vectors for arithmetic and polynomial operations in $\text{GF}(2^{9009})$ with modulus $x^{9009} + x^{29} + 1$. Output is saved to `src/math/test_vectors.json`.
- **`save_newton_weights_bin.sage`**: Generates the binary Newton divided-difference weight files for the three HQC parameter sets ($n = 17669, 35851, 57637$). Output files are saved to `src/math/newton_weights_{n}.bin`.

## Running the Scripts

To execute either script, run:

```bash
sage sagemath/generate_test_vectors.sage
sage sagemath/save_newton_weights_bin.sage
```
