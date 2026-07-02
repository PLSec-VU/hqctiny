# HQC-Tiny Protocol

A server-stateless post-quantum key-exchange protocol built on the
**Hamming Quasi-Cyclic (HQC)** KEM.

We use the following primitives:
- Hash / MAC / KDF: BLAKE3
- AEAD: XChaCha20-Poly1305

# Phase 1: Entropy establishment (Handshake)
```
[CLIENT]                                                                   [SERVER]
Generates: Ephemeral HQC Keypair (h, s)                                    Holds: Bounded RAM Table (table[hash_ek_kem])
                                                                            Holds: Windowed Symmetric Cookie Key Pool (2 keys)

  1. ephem_pk, ephem_sk <- keypair()
  2. hash_ek_kem <- hash(ephem_pk)
  3. Generate all client evaluation points and compute Merkle tree root hash (`merkle_root`)

     [Packet 1: Handshake Request] 
     -------------------------------------------------------------------->
      | 0x00 | hash_ek_kem (32 B) | merkle_root (32 B) |

                                                 1. Generate random m (PARAM_SECURITY_BYTES) and salt (16 B).
                                                 2. K_session, theta <- derive_shared_secret(m, salt, hash_ek_kem).
                                                 3. K_session is ready for future use.
                                                 4. Fetch current key_index (0 or 1) and active key from pool.
                                                    Encrypt Cookie = AEAD_{ActiveKey}(theta || m) with AAD = merkle_root and a random 24‑byte nonce.

     [Packet 2: Handshake Response] 
     <--------------------------------------------------------------------
      | Tag | Cookie | Salt (16 B)
      
      Tag encodes direction (s→c), handshake kind, and the key_index bit (0x80 or 0xA0).

  1. Store cookie, salt, and key_index.
```

> [!NOTE]
> To avoid invading the HQC reference implementation (which internally computes
> `hash_ek_kem = hash(ek_pke)`) and prevent code duplication of the decapsulation
> math, this implementation sends `hash_ek_kem` and the Merkle tree root
> (`merkle_root`) as separate things instead. In a real/production implementation
> where modifying the reference code is permitted, one can opt to just use the
> Merkle tree root directly as the `hash_ek_kem`.

# Phase 2: Stateless point-on-demand stream
```
  (Client loops this process for all evaluation points x_i asynchronously, no
  waiting is required between requests, and the server can respond in any order.)

     [Packet 3: Point Request] 
     -------------------------------------------------------------------->
      | Tag | Cookie | h(x_i) or s(x_i) (limbs*8) | merkle_root (32 B) | Witness |
      
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
```

# Phase 3: Client-side decapsulation
```
  1. Interpolate the collected 'u' and 'v' evaluations.
  2. Reduce modulo (x^n - 1) to vanish the blinding mask polynomials.
  3. Truncate the resulting v(x) modulo x^n1n2 (discarding the randomized truncate mask coefficients).
  4. Decode HQC ciphertext -> Extract K_session.
```

## Cookie Key Rotation
Time validation is handled implicitly through **Windowed Symmetric Cookie Key Rotation**:
- **Symmetric Cookie Pool:** The server keeps a local pool of exactly 2 symmetric keys ($s_0, s_1$).
- **Implicit Expiry:** A background process rotates the keys every 90 seconds (1.5 minute). It generates a new active key and overwrites the older slot, yielding an effective session lifetime of 2-3 minutes.
- **Validation Check:** Every `PointRequest` transmits the `key_index` (0 or 1) in its tag byte. The server attempts to decrypt the cookie using the corresponding key. If that slot was already overwritten, the request is rejected.

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

### HandshakeRequest (tag `0x00`)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 B | 0x00 | Tag byte |
| 1 | 32 B | hash_ek_kem | Hash of ephemeral public key |
| 33 | 32 B | merkle_root | Merkle tree root of evaluation points |

### HandshakeResponse (tag `0x80` or `0xA0`)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 B | Tag | Tag byte (encodes key_index: 0x80 or 0xA0) |
| 1 | 24 B | nonce | XChaCha20 nonce |
| 25 | 32 + SecParam B | ciphertext | AEAD ciphertext (encrypts `theta \|\| m`) |
| 57 + SecParam | 16 B | auth_tag | Poly1305 authentication tag |
| 73 + SecParam | 16 B | salt | Random salt for key derivation |

**Where SecParam = PARAM_SECURITY_BYTES:**
- 16 B for HQC-1
- 24 B for HQC-3
- 32 B for HQC-5

### PointRequest

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 B | Tag | Tag byte (c→s, encodes point type and key_index) |
| 1 | 24 B | nonce | XChaCha20 nonce |
| 25 | 32 + SecParam B | ciphertext | AEAD ciphertext (encrypts `theta \|\| m`) |
| 57 + SecParam | 16 B | auth_tag | Poly1305 authentication tag |
| 73 + SecParam | limbs * 8 B | public_eval | Segmented public key evaluation result |
| 73 + SecParam + limbs*8 | 32 B | merkle_root | Merkle tree root for verification |
| 105 + SecParam + limbs*8 | Variable | witness | Merkle proof (at most 160-192 B) |

**Limbs calculation:**

Because the public key is segmented using Kronecker segmentation, the segment coefficients by design cannot exceed degree `W = n/2 = 4504` (where `n = 9009` is the field degree). The limb count is:

`limbs = ceil((4504 + POINTS_NUM * (num_blocks - 1)) / 64)`

Where:
- `POINTS_NUM` is the number of evaluation points (7 for HQC-1, 15 for HQC-3, 25 for HQC-5)
- `num_blocks` is the number of segmented blocks (4 for HQC-1, 8 for HQC-3, 13 for HQC-5)

This yields:
- **HQC-1**: 71 limbs (568 bytes)
- **HQC-3**: 73 limbs (584 bytes)
- **HQC-5**: 76 limbs (608 bytes)

### PointResponse (tag = `0x80 | idx | (if V { 0x40 })`)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 B | Tag | Tag byte (s→c, encodes point type and index) |
| 1 | 1128 B | eval | Evaluation result in Gf2_9009 (LE, 141 u64 limbs) |

## Packet Sizes

| Packet Type | HQC-1 (128-bit) | HQC-3 (192-bit) | HQC-5 (256-bit) | Size Formula / Components |
|-------------|-----------------|-----------------|-----------------|---------------------------|
| **HandshakeRequest** | 65 B | 65 B | 65 B | `1 + 32 (hash_ek_kem) + 32 (merkle_root)` |
| **HandshakeResponse** | 105 B | 113 B | 121 B | `1 (tag) + (24 + 32 + SecParam + 16) (cookie) + 16 (salt)` |
| **PointRequest** (Max) | 817 B | 865 B | 937 B | `1 (tag) + (24 + 32 + SecParam + 16) (cookie) + (limbs * 8) (public_eval) + 32 (merkle_root) + Witness` |
| **PointResponse** | 1129 B | 1129 B | 1129 B | `1 + 1128 (Gf2_9009)` |

**Size key:**
- `SecParam` = `PARAM_SECURITY_BYTES`: 16 B for HQC-1, 24 B for HQC-3, 32 B for HQC-5
- **Witness** (Merkle proof): at most 128 bytes for HQC-1 (tree depth 4), 160 bytes for HQC-3 (tree depth 5), and 192 bytes for HQC-5 (tree depth 6)

## Protocol Statistics

The table below shows the total number of round trips (request-response pairs) and the total data exchanged by the client during a complete protocol flow execution:

| Variant | Total Round Trips | Total Sent (Client) | Total Received (Client) |
|---------|-------------------|---------------------|-------------------------|
| **HQC-1** | 15 | 11,439 B (~11.4 KB) | 15,911 B (~15.9 KB) |
| **HQC-3** | 31 | 25,951 B (~26.0 KB) | 33,983 B (~34.0 KB) |
| **HQC-5** | 51 | 46,675 B (~46.7 KB) | 56,571 B (~56.6 KB) |

*Note: Since the point-on-demand stream is asynchronous and stateless, the client can stream all point requests concurrently once it receives the handshake cookie. Under parallel execution, the entire protocol (handshake + streaming) completes in exactly **2 network round-trip times (RTT)**.*

## Gf2_9009 Encoding

Each `Gf2_9009` element (a polynomial in $F_2[z] / (z^{9009} + z^{29} + 1)$) is serialized as 141 consecutive `u64` limbs (1128 bytes) in little‑endian byte order.

### Design Rationale

1. **MTU Alignment**: Assuming a standard internet/IPv6 minimum MTU of **1280
bytes**, all `PointRequest` packets fit entirely within a single MTU. Bigger
field degrees are of no benefit because they do not reduce the number of
evaluation points that must be sent for the three HQC security parameters
without going above the MTU limit.
2. **Computational Efficiency**: We use the irreducible trinomial $x^{9009} +
x^{29} + 1$. Reducing modulo a low-weight polynomial especially a trinomial
avoids extra XOR operations, and the small exponent (29) allows modular
reduction to be implemented extremely quickly using simple shifts and XOR
operations on machine words.
