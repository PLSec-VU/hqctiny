# HQC-Tiny SSProve Proof

| File | Contents |
|------|----------|
| `Tuple.v` | Bijections between tuples and finite ordinals; used to sample structured randomness |
| `Interpolate.v` | Kronecker segmentation and polynomial interpolation |
| `HQC.v` | Ring Rq = F₂[X]/(Xⁿ−1), the HQC encryption scheme, and the three concrete parameter sets (HQC1/3/5) |
| `HQCTiny.v` | The main security theorem for HQC-Tiny |

## Proof structure

HQC-Tiny is a variant of HQC where the public key is represented in *point-value form*:
instead of sending ring elements h, s ∈ Rq directly, the sender evaluates
them at npoints points in K = GF(2^d) and transmits the evaluation sequence.

The main theorem (`hqctiny_indistinguishable` in `HQCTiny.v`) states that the
HQC-Tiny encryption package is perfectly indistinguishable from a composed
simulator applied to the standard HQC encryption package:

```
hqctiny_encrypt ≈₀ (Sim ∘ hqc_encrypt)
```

This proves that `hqctiny_encrypt` does not leak anymore information than
`hqc_encrypt`.

The proof is parametric throughout. `HQCTinyParams` extends `HQCParams` with
the point-field parameters (d, gen_K, W, nblocks, npoints). Each of the three
concrete parameter sets instantiates this signature:

| Parameter Module | Scheme | $n$ | $d$ | $W$ | `nblocks` | `npoints` |
|------------------|---------|-----|-----|-----|-----------|-----------|
| `HQCTiny1Params`  | HQC-128 | 17669 | 9009 | 4505 | 4 | 7 |
| `HQCTiny3Params`  | HQC-192 | 35851 | 9009 | 4505 | 8 | 15 |
| `HQCTiny5Params`  | HQC-256 | 57637 | 9009 | 4505 | 13 | 25 |


## Axioms

One axiom remains open:

- **`gen_K_irreducible`** — irreducibility of X^9009 + X^29 + 1 over GF(2).
  This is a standard mathematical fact (the polynomial defines GF(2^9009)),
  but proving it in Rocq requires formalizing Rabin's irreducibility test.
  MathComp's `irreducibleb` is a boolean decision procedure but is infeasible
  at this degree (it enumerates 2^9009 polynomials). See the comment in
  `HQCTiny.v` for the full explanation.

## Dependencies

- [SSProve](https://github.com/SSProve/ssprove)