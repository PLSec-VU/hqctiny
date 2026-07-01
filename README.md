# HQC-Tiny Protocol

A stateless, non-interactive post-quantum key-exchange protocol built on
**Hamming Quasi-Cyclic (HQC)** encryption.

We use the following primitives:
- MAC / KDF: BLAKE3
- AEAD: XChaCha20-Poly1305

```
[CLIENT]                                                                   [SERVER]
Generates: Ephemeral HQC Keypair (h, s)                                    Holds: Bounded RAM Table (table[hash_ek_kem])
                                                                           Holds: Ephemeral ServerKey for encrypting cookies

========================================================================================================
                          PHASE 1: ENTROPY ESTABLISHMENT (HANDSHAKE)
========================================================================================================

  1. ephem_pk, ephem_sk <- keypair()
  2. hash_ek_kem <- hash(ephem_pk)
  3. timestamp <- now()

     [Packet 1: Handshake Request] 
     -------------------------------------------------------------------->
      | 0x00 | hash_ek_kem (32 B) | timestamp (8 B LE)

                                                1. TIME CHECK: If timestamp <= table[hash_ek_kem].time or timestamp < now - timeout, DROP.
                                                2. Generate random m (PARAM_SECURITY_BYTES) and salt (16 B).
                                                3. K_session, theta <- derive_shared_secret(m, salt, hash_ek_kem).
                                                4. OVERWRITE RAM: table[hash_ek_kem] = {K_session, timestamp}.
                                                5. Encrypt Cookie = AEAD_{ServerKey}(theta || m) with a random 24‑byte nonce and timestamp as Associated Authenticated Data (AAD).

     [Packet 2: Handshake Response] 
     <--------------------------------------------------------------------
      | 0x80 | cookie_len (2 B LE) | Cookie | Salt (16 B)

  1. Store cookie and salt.


========================================================================================================
                          PHASE 2: STATELESS POINT-ON-DEMAND STREAM
========================================================================================================
  (Client loops this process for all evaluation points x_i asynchronously, no
  waiting is required between requests, and the server can respond in any order.
  The Client appends the original plaintext Handshake_Timestamp from Phase 1)

     [Packet 3: Point Request] 
     -------------------------------------------------------------------->
      | Header | cookie_len (2 B LE) | Cookie | Handshake_Timestamp (8 B LE) | h(x_i) or s(x_i) (1128 B) |
      
      Header encodes direction (c→s), point_type (U/V), and point_index in a single byte.

                                                   1. TTL CHECK: If (Current_Time - Handshake_Timestamp) > timeout, DROP.
                                                   2. Decrypt Cookie using ServerKey and Handshake_Timestamp as Associated Authenticated Data (AAD) → extract theta and m.
                                                   3. Gen random quotient-blinding mask.
                                                   For Type u:
                                                    4. Load r1(x_i), r2(x_i) from theta, m.
                                                    5. Compute: u_eval = r1 + [h(x_i)]*r2 + mask*(x_i^d_i + 1).
                                                   For Type v:
                                                    4. Load e(x_i), r2(x_i) from theta, m.
                                                    5. Gen random truncate-blinding mask T(x) over [n1n2, n-1] from theta.
                                                    6. Compute: v_eval = encode(m) + [s(x_i)]*r2 + e + T(x_i) + mask*(x_i^d_i + 1).

     [Packet 4: Point Response] 
     <--------------------------------------------------------------------
      | Header | Handshake_Timestamp (8 B LE) | u_eval / v_eval (1128 B) |
      
      Header encodes direction (s→c), point_type, and point_index.

  1. Verify Handshake_Timestamp matches Phase 1.
  2. Save (x_i, u_eval) or (x_i, v_eval) for later interpolation.

========================================================================================================
                          PHASE 3: DEFERRED DECRYPTION
========================================================================================================

  1. Interpolate the collected 'u' and 'v' evaluations.
  2. Reduce modulo (x^n - 1) to vanish the blinding mask polynomials.
  3. Truncate the resulting v(x) modulo x^n1n2 (discarding the upper randomized truncate mask coefficients).
  4. Decode HQC ciphertext -> Extract K_session.
```

## Wire Format

Every packet starts with a single **tag byte** that encodes direction, point type, and the packet kind:

| Bit 7 (MSB) | Bit 6       | Bits 5–0       |
|-------------|-------------|-----------------|
| Direction   | Point type  | Kind            |

- **Direction**: `0` = client → server, `1` = server → client.
- **Point type**: `0` = U, `1` = V. Ignored when Kind = 0 (handshake).
- **Kind**: `0` = handshake, `1`–`63` = point index.

All fields are packed sequentially after the tag byte. 

### Packet Layouts

> `LE` = little‑endian. `Gf2_8984` = 141 × 8 = **1128 bytes**.
> `Cookie` = 24‑byte nonce + (32‑byte `theta` + `PARAM_SECURITY_BYTES` `m` + 16‑byte tag) = **72 + PARAM_SECURITY_BYTES** bytes.

#### HandshakeRequest (tag `0x00`)

```
┌───────┬──────────────────────┬─────────────────┐
│ 1 B   │ 32 B                 │ 8 B             │
│ 0x00  │ hash_ek_kem          │ timestamp (u64) │
└───────┴──────────────────────┴─────────────────┘
```

Fixed size: **41 bytes**.

#### HandshakeResponse (tag `0x80`)

```
┌───────┬────────────────┬──────────┬────────┐
│ 1 B   │ 2 B            │ Var B    │ 16 B   │
│ 0x80  │ cookie_len LE  │ cookie   │ salt   │
└───────┴────────────────┴──────────┴────────┘
```

Size: **19 + cookie_len bytes**.

#### PointRequest (tag = `T | idx`, direction = 0)

```
┌──────────────┬────────────────┬──────────┬───────────────────────┬────────────────┐
│ 1 B          │ 2 B            │ Var B    │ 8 B                   │ 1128 B         │
│ 0 | T | idx  │ cookie_len LE  │ cookie   │ handshake_timestamp   │ public_eval    │
│ (c→s)        │                │          │ (u64 LE)              │ (Gf2_8984 LE)  │
└──────────────┴────────────────┴──────────┴───────────────────────┴────────────────┘
```

- `T` = point type (`0` = U, `1` = V).
- `idx` = point index (`1`–`63`, 6 bits).

Size: **1139 + cookie_len bytes**.

#### PointResponse (tag = `1 | T | idx`)

```
┌──────────────┬───────────────────────┬────────────────┐
│ 1 B          │ 8 B                   │ 1128 B         │
│ 1 | T | idx  │ handshake_timestamp   │ eval           │
│ (s→c)        │ (u64 LE)              │ (Gf2_8984 LE)  │
└──────────────┴───────────────────────┴────────────────┘
```

- `T` = point type (`0` = U, `1` = V).
- `idx` = point index (`1`–`63`, 6 bits).

Fixed size: **1137 bytes**.

### Gf2_8984 Encoding

Each `Gf2_8984` element (a polynomial in GF(2)[x] / (x^8984 + x^9 + x^8 + x^6 + 1)) is serialized as 141 consecutive `u64` limbs, each in little‑endian byte order.

### Security Warning

This implementation is for educational and research purposes only. It is not suitable for production or secure communication.

## Requirements

- [Rust](https://www.rust-lang.org/) (nightly)
