# HQC-Tiny Protocol

A stateless, non-interactive post-quantum key-exchange protocol built on
**Hamming Quasi-Cyclic (HQC)** encryption, with mutual authentication via
**MAYO** signatures.

We use the following primitives:
- MAC: BLAKE3
- AEAD: ChaCha20-Poly1305
- Signatures: MAYO

```
[CLIENT]                                                                   [SERVER]
Holds: Static signature Keypair (Identity)                                 Holds: Static signature Keypair (Identity)
Generates: Ephemeral HQC Keypair (h, s)                                    Holds: Bounded RAM Table (table[ID])
                                                                           Holds: Ephemeral ServerKey for encrypting cookies

========================================================================================================
                          PHASE 1: AUTHENTICATED ENTROPY ESTABLISHMENT
========================================================================================================

  1. Generate 'Client_Nonce' (Timestamp + Random)
  2. Sign: Signature(Client_ID + Nonce)

     [Packet 1: Handshake Request] 
     -------------------------------------------------------------------->
      | Client_ID | Client_Nonce | Client_Sig

                                                1. Verify Client_Sig. (Drops if bad).
                                                2. TIME CHECK: If Client_Nonce.Timestamp <= table[ID].time or Client_Nonce.Timestamp < now - timeout, DROP.
                                                3. Generate HQC Seed (θ).
                                                4. Derive Session Key (K_session) from θ.
                                                5. OVERWRITE RAM: table[Client_ID] = {K_session, new_timestamp}.
                                                6. Compute Transcript_MAC = MAC_{K_session}(History).
                                                7. Derive per-session encryption key = KDF(ServerKey, Client_Nonce.Timestamp).
                                                   Encrypt Cookie = AEAD_{derived_key}(θ) with a random 12‑byte nonce.
                                                8. Sign: Signature(Cookie + Transcript_MAC).

     [Packet 2: Handshake Response] 
     <--------------------------------------------------------------------
      | Cookie | Transcript_MAC | Server_Sig

  1. Verify Server_Sig.
  2. Save Transcript_MAC for later.


========================================================================================================
                          PHASE 2: STATELESS POINT-ON-DEMAND STREAM
========================================================================================================
  (Client loops this process for all evaluation points x_i asynchronously, no
  waiting is required between requests, and the server can respond in any order.
  The Client appends the original plaintext Handshake_Timestamp from Phase 1)

  -- [ REQ TYPE 0: 'u' POLYNOMIAL POINTS ] --

     [Packet 3: Request 'u/v' Point] 
     -------------------------------------------------------------------->
      | Cookie | Handshake_Timestamp | h(x_i) or s(x_i) |
      
      Header encodes direction (c→s), point_type (U/V), and point_index in a single byte.

                                                  1. TTL CHECK: If (Current_Time - Handshake_Timestamp) > timeout, DROP.
                                                  2. Derive per-session encryption key = KDF(ServerKey, Handshake_Timestamp).
                                                     Decrypt Cookie → extract θ.
                                                     (If the timestamp was tampered with, the derived key is wrong and decryption fails).
                                                  3. Gen random quotient-blinding mask = k*(X^n-1) for random k.
                                                  For Type u:
                                                   4. Parse Type (U) -> load r1(x_i), r2(x_i) from θ.
                                                   5. Compute: u_eval = r1 + [h(x_i)]*r2 + mask.
                                                  For Type v:
                                                   4. Parse Type (V) -> load e(x_i), r2(x_i), K_session from θ.
                                                   5. Compute: v_eval = K_session + [s(x_i)]*r2 + e + mask.

     [Packet 4: Response 'u/v' Point] 
     <--------------------------------------------------------------------
      | Handshake_Timestamp | u_eval / v_eval |
      
      Header encodes direction (s→c), point_type, and point_index.

  1. Verify Handshake_Timestamp = Client_Nonce.Timestamp (from Phase 1).
  2. Save (x_i, u_eval) or (x_i, v_eval) for later interpolation.

========================================================================================================
                          PHASE 3: DEFERRED KEY CONFIRMATION & SECURE TUNNEL
========================================================================================================

  1. Interpolate the collected 'u' and 'v' points.
  3. Reduce modulo (X^n - 1) to vanish the blinding polynomials.
  4. Decode HQC ciphertext -> Extract K_session.
  5. Verify Transcript_MAC (from Packet 2) using the newly decoded K_session.
  6. Tunnel is now active, K_session is used for encrypting application data with AEAD.
```

## Wire Format

Every packet starts with a single **tag byte** that encodes direction, point type,
and the packet kind:

| Bit 7 (MSB) | Bit 6       | Bits 5–0       |
|-------------|-------------|-----------------|
| Direction   | Point type  | Kind            |

- **Direction**: `0` = client → server, `1` = server → client
- **Point type**: `0` = U, `1` = V. Ignored when Kind = 0 (handshake).
- **Kind**: `0` = handshake, `1`–`63` = point index

All fixed‑length fields are packed sequentially after the tag byte.
Variable‑length signatures (`Vec<u8>`) always appear at the very end
and consume the remainder of the packet — no length prefix is needed.

### Packet layouts

> `LE` = little‑endian. `Gf2_8984` = 141 × 8 = **1128 bytes**.
> `Cookie` = 12‑byte nonce + 56‑byte AEAD ciphertext = **68 bytes**.

#### HandshakeRequest (tag `0x00`)

```
┌────────┬───────────────┬──────────────────┬────────────────┬───────────────┐
│ 1 B    │ 32 B          │ 8 B              │ 16 B           │ …             │
│ 0x00   │ client_id     │ timestamp (u64)  │ random         │ client_sig    │
└────────┴───────────────┴──────────────────┴────────────────┴───────────────┘
```

Minimum size: 57 bytes + signature.

#### HandshakeResponse (tag `0x80`)

```
┌────────┬─────────────┬───────────────────┬──────────────┐
│ 1 B    │ 68 B        │ 32 B              │ …            │
│ 0x80   │ cookie      │ transcript_mac    │ server_sig   │
└────────┴─────────────┴───────────────────┴──────────────┘
```

Minimum size: 101 bytes + signature.

#### PointRequest (tag = `T | idx`, direction = 0)

```
┌──────────────┬─────────────┬───────────────────────┬──────────────────┐
│ 1 B          │ 68 B        │ 8 B                   │ 1128 B           │
│ 0 | T | idx  │ cookie      │ handshake_timestamp   │ public_eval      │
│ (c→s)        │             │ (u64 LE)              │ (Gf2_8984 LE)    │
└──────────────┴─────────────┴───────────────────────┴──────────────────┘
```

- `T` = point type (`0` = U, `1` = V)
- `idx` = point index (`1`–`63`, 6 bits)

Total fixed size: **1205 bytes**.

#### PointResponse (tag = `1 | T | idx`)

```
┌──────────────┬───────────────────────┬──────────────────┐
│ 1 B          │ 8 B                   │ 1128 B           │
│ 1 | T | idx  │ handshake_timestamp   │ eval             │
│ (s→c)        │ (u64 LE)              │ (Gf2_8984 LE)    │
└──────────────┴───────────────────────┴──────────────────┘
```

- `T` = point type (`0` = U, `1` = V)
- `idx` = point index (`1`–`63`, 6 bits)

Total fixed size: **1137 bytes**.

### Gf2_8984 encoding

Each `Gf2_8984` element (a polynomial in GF(2)[x] / (x^8984 + x^9 + x^8 + x^6 + 1))
is serialized as 141 consecutive `u64` limbs, each in little‑endian byte order.

### Security Warning

This implementation is for educational and research purposes only. It is
not suitable for production or secure communication.

## Requirements

- [Rust](https://www.rust-lang.org/) (nightly)
- [SageMath](https://www.sagemath.org/) (for the reference implementation in `sagemath/`)

## Quick start (`hqctiny-net` CLI)

The `hqctiny-network` crate provides a UDP server/client for running the
protocol on real networks.

```bash
# Terminal 1 — start the server
cargo run -p hqctiny-network -- server --bind 0.0.0.0:9000

# Terminal 2 — connect a client (session key printed to stdout as hex)
cargo run -p hqctiny-network -- client --server 127.0.0.1:9000
```

| Flag | Description |
|---|---|
| `server --bind <ADDR>` | UDP listen address (default `0.0.0.0:9000`) |
| `server --server-key <HEX>` | 32‑byte static server key as hex (64 chars) |
| `client --server <ADDR>` | Server address (default `127.0.0.1:9000`) |
