# HQC-Tiny Protocol

A stateless, non-interactive post-quantum key-exchange protocol built on
**Hamming Quasi-Cyclic (HQC)** encryption.

We use the following primitives:
- MAC / KDF: BLAKE3
- AEAD: XChaCha20-Poly1305

```
[CLIENT]                                                                   [SERVER]
Generates: Ephemeral HQC Keypair (h, s)                                    Holds: Bounded RAM Table (table[hash_ek_kem])
                                                                           Holds: Windowed Symmetric Cookie Key Pool (2 keys)

========================================================================================================
                          PHASE 1: ENTROPY ESTABLISHMENT (HANDSHAKE)
========================================================================================================

  1. ephem_pk, ephem_sk <- keypair()
  2. hash_ek_kem <- hash(ephem_pk)
  3. Generate all client evaluation points and compute Merkle tree root hash (`merkle_root`)

     [Packet 1: Handshake Request] 
     -------------------------------------------------------------------->
      | 0x00 | hash_ek_kem (32 B) | merkle_root (32 B) |

                                                 1. REPLAY CHECK: If table[hash_ek_kem] already exists, DROP.
                                                 2. Generate random m (PARAM_SECURITY_BYTES) and salt (16 B).
                                                 3. K_session, theta <- derive_shared_secret(m, salt, hash_ek_kem).
                                                 4. OVERWRITE RAM: table[hash_ek_kem] = {K_session}.
                                                 5. Fetch current key_index (0 or 1) and active key from pool.
                                                    Encrypt Cookie = AEAD_{ActiveKey}(theta || m) with AAD = merkle_root and a random 24‑byte nonce.

     [Packet 2: Handshake Response] 
     <--------------------------------------------------------------------
      | Tag | cookie_len (2 B LE) | Cookie | Salt (16 B)
      
      Tag encodes direction (s→c), handshake kind, and the key_index bit (0x80 or 0xA0).

  1. Store cookie, salt, and key_index.

> [!NOTE]
> To avoid invading the HQC reference implementation (which internally computes
`hash_ek_kem = hash(ek_pke)`) and prevent code duplication of the decapsulation
math, this implementation sends `hash_ek_kem` and the Merkle tree root
(`merkle_root`) as separate things instead. In a real/production implementation
where modifying the reference code is permitted, one can opt to just use the
Merkle tree root directly as the `hash_ek_kem`.


========================================================================================================
                          PHASE 2: STATELESS POINT-ON-DEMAND STREAM
========================================================================================================
  (Client loops this process for all evaluation points x_i asynchronously, no
  waiting is required between requests, and the server can respond in any order.)

     [Packet 3: Point Request] 
     -------------------------------------------------------------------->
      | Tag | cookie_len (2 B LE) | Cookie | h(x_i) or s(x_i) (limbs*8) | merkle_root (32 B) | witness_len (2 B LE) | Witness |
      
      Tag encodes direction (c→s), point_type (U/V), key_index, and point_index.

                                                   1. Parse key_index from Tag.
                                                   2. Decrypt Cookie using key at key_index and AAD = merkle_root → extract theta and m. If key was rotated/overwritten or decryption fails, DROP.
                                                   3. Verify that h(x_i) or s(x_i) belongs to the Merkle tree with root merkle_root using Witness. If verification fails, DROP.
                                                   4. Gen random quotient-blinding mask.
                                                   For Type u:
                                                    5. Load r1(x_i), r2(x_i) from theta, m.
                                                    6. Compute: u_eval = r1 + [h(x_i)]*r2 + mask*(x_i^d_i + 1).
                                                   For Type v:
                                                    5. Load e(x_i), r2(x_i) from theta, m.
                                                    6. Gen random truncate-blinding mask T(x) over [n1n2, n-1] from theta.
                                                    7. Compute: v_eval = encode(m) + [s(x_i)]*r2 + e + T(x_i) + mask*(x_i^d_i + 1).

     [Packet 4: Point Response] 
     <--------------------------------------------------------------------
      | Tag | u_eval / v_eval (1128 B) |
      
      Tag encodes direction (s→c), point_type, and point_index.

  1. Save (x_i, u_eval) or (x_i, v_eval) for later interpolation.

========================================================================================================
                          PHASE 3: DEFERRED DECRYPTION
========================================================================================================

  1. Interpolate the collected 'u' and 'v' evaluations.
  2. Reduce modulo (x^n - 1) to vanish the blinding mask polynomials.
  3. Truncate the resulting v(x) modulo x^n1n2 (discarding the randomized truncate mask coefficients).
  4. Decode HQC ciphertext -> Extract K_session.
```

## Cookie Key Rotation
Time validation is handled implicitly through **Windowed Symmetric Cookie Key Rotation**:
- **Symmetric Cookie Pool:** The server keeps a local pool of exactly 2 symmetric keys ($s_0, s_1$).
- **Implicit Expiry:** A background process rotates the keys every 90 seconds (1.5 minute). It generates a new active key and overwrites the older slot, yielding an effective session lifetime of 2 to 3 minutes.
- **Validation Check:** Every `PointRequest` transmits the `key_index` (0 or 1) in its tag byte. The server attempts to decrypt the cookie using the corresponding key. If that slot was already overwritten by the rotation process, decryption fails automatically.

## Wire Format

Every packet starts with a single **tag byte** that encodes direction, point type, key index, and kind:

| Bit 7 (MSB) | Bit 6       | Bit 5       | Bits 4–0       |
|-------------|-------------|-------------|-----------------|
| Direction   | Point type  | Key index   | Kind            |

- **Direction**: `0` = client → server, `1` = server → client.
- **Point type**: `0` = U, `1` = V. Ignored when Kind = 0 (handshake).
- **Key index**: `0` or `1`. Ignored for HandshakeRequest, used in HandshakeResponse and PointRequest.
- **Kind**: `0` = handshake, `1`–`31` = point index.

All fields are packed sequentially after the tag byte. 

### Packet Layouts

> `LE` = little‑endian. `Gf2_8984` = 141 × 8 = **1128 bytes**.
> `Cookie` = 24‑byte nonce + (32‑byte `theta` + `PARAM_SECURITY_BYTES` `m` + 16‑byte tag) = **72 + PARAM_SECURITY_BYTES** bytes.

#### HandshakeRequest (tag `0x00`)

```
┌───────┬──────────────────────┬──────────────────────┐
│ 1 B   │ 32 B                 │ 32 B                 │
│ 0x00  │ hash_ek_kem          │ merkle_root          │
└───────┴──────────────────────┴──────────────────────┘
```

Fixed size: **65 bytes**.

#### HandshakeResponse (tag `0x80` or `0xA0`)

```
┌───────┬────────────────┬──────────┬────────┐
│ 1 B   │ 2 B            │ Var B    │ 16 B   │
│ Tag   │ cookie_len LE  │ cookie   │ salt   │
└───────┴────────────────┴──────────┴────────┘
```

Size: **19 + cookie_len bytes**.

#### PointRequest (tag = `idx | (if V { 0x40 }) | (if key_index == 1 { 0x20 })`)

```
┌───────┬────────────────┬──────────┬─────────────┬─────────────┬────────────────┬───────────┐
│ 1 B   │ 2 B            │ Var B    │ Var B       │ 32 B        │ 2 B            │ Var B     │
│ Tag   │ cookie_len LE  │ cookie   │ public_eval │ merkle_root │ witness_len LE │ witness   │
│ (c→s) │                │          │ (segmented) │             │                │           │
└───────┴────────────────┴──────────┴─────────────┴─────────────┴────────────────┴───────────┘
```

Size: **5 + cookie_len + (limbs * 8) + 32 + witness_len bytes**.

Because the public key is segmented using Kronecker segmentation, the segment coefficients by design cannot exceed degree `W = n/2 = 4492` (where `n = 8984` is the field degree). Thus, the resulting `public_eval` evaluated segmented polynomial has degree `< n/2 + epsilon` and most of its high-order coefficients are empty (zeros). It is only in the response, where the server multiplies two points, that the degree adds up to around `8984`. To optimize network bandwidth, only the active (non-zero) little-endian `u64` limbs of `public_eval` are serialized in the request.

The number of limbs transmitted is calculated as:
`limbs = ceil((4492 + point_index * (num_blocks - 1)) / 64)`

where `num_blocks` is the number of segmented blocks for the HQC variant (4 for HQC-1, 8 for HQC-3, and 13 for HQC-5).

#### PointResponse (tag = `0x80 | idx | (if V { 0x40 })`)

```
┌──────────────┬────────────────┐
│ 1 B          │ 1128 B         │
│ Tag          │ eval           │
│ (s→c)        │ (Gf2_8984 LE)  │
└──────────────┴────────────────┘
```

Fixed size: **1129 bytes**.

### Gf2_8984 Encoding

Each `Gf2_8984` element (a polynomial in GF(2)[x] / (x^8984 + x^9 + x^8 + x^6 + 1)) is normally serialized as 141 consecutive `u64` limbs, each in little‑endian byte order. For `PointRequest` packets, this is optimized to transmit only the active limbs as described above.

### Security Warning

This implementation is for educational and research purposes only. It is not suitable for production or secure communication.

## Requirements

- [Rust](https://www.rust-lang.org/) (nightly)
