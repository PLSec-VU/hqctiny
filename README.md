# HqcLethe

HqcLethe is a post-quantum key exchange in which the server keeps no state for a
client. HQC gives the ephemeral key, and ML-KEM-768 authenticates the server. The
server receives the client's HQC public key and returns the ciphertext in
packet-sized pieces. It handles each piece on its own and then forgets it.

This repository holds the implementation, the proofs, and the scripts that make
the measurements. This file tells you where each part is.

## Where to look

### Protocol

| Path | Content |
|---|---|
| `src/server.rs` | The stateless server: request handlers, cookie keys and their rotation |
| `src/client.rs` | The client |
| `src/crt/` | The Chinese-remainder construction for `v`: the moduli (`params.rs`), the server residues (`server.rs`), and the client rebuild with Garner's algorithm (`client.rs`) |
| `src/blinding.rs` | Reduction modulo `X^n - 1` and the masks that hide the unreduced product |
| `src/auth.rs` | Server authentication with ML-KEM-768 |
| `src/encoding.rs` | Wire format: packet layouts, lengths and padding |
| `src/envelope.rs` | Authenticated encryption of every packet after the first exchange |
| `src/kdf.rs` | Derivation of the session key |
| `src/replay.rs` | Replay filter: a Bloom filter that answers each request at most four times per worker |
| `src/puzzle.rs` | Optional client puzzle in front of the ML-KEM decapsulation |
| `src/hqc/` | Rust interface to the HQC C code |
| `src/math/` | Carry-less polynomial multiplication over GF(2) |
| `hqclethe-server/`, `hqclethe-client/` | The UDP server and client programs. The client program also holds `keygen`, `bandwidth-report` and the flood modes. |
| `hqc/` | Official HQC reference implementation (git submodule) |
| `hqc-addfft/` | HQC polynomial multiplier for ARM without crypto extensions (git submodule, `hqc-addfft` feature) |

### Stateful baseline

The baseline server buffers the client's public key until all fragments arrive.
The code is in `src/stateful/`. The table of pending uploads is in
`src/stateful/table.rs`. The programs are in `hqclethe-stateful/`. The baseline
uses the same key files and command-line options as HqcLethe.

### Proofs

| Path | Content |
|---|---|
| `ssprove/HQCLethe.v` | Rocq/SSProve proof that the masked residues reveal nothing more than a plain HQC ciphertext. Theorem: `hqclethe_indistinguishable`. |
| `ssprove/DerivedMasks.v` | The same result when the masks come from the session seed. Theorem: `seeded_masks_simulatable`. |
| `ssprove/HQC.v`, `ssprove/Tuple.v` | HQC encryption and the helper lemmas that the proofs use |
| `ssprove/Assumptions.v` | Prints every assumption of the main theorems |
| `proofs/proverif/hqclethe.pv` | ProVerif model of the whole protocol: secrecy, server authentication, forward secrecy, replay, and puzzle binding |
| `proofs/proverif/variants/` | One file per variant of the model: a key compromise, a removed server check, or the puzzle on |
| `scripts/check_crt_moduli.py`, `scripts/check_crt_moduli.sage` | Check that the moduli in `src/crt/params.rs` satisfy the hypotheses of the Rocq proof |
| `tests/crt_masking.rs`, `scripts/crt_masking_toy.py` | Exhaustive check of the masking argument for a small ring (n = 7) |

### Tests and benchmarks

| Path | Content |
|---|---|
| `tests/protocol_flow.rs` | Full sessions at all levels. The rebuilt `(u, v)` must equal the reference HQC ciphertext. Also tampered, reordered and resent packets. |
| `tests/zero_alloc.rs` | The server makes no heap allocation after start-up |
| `tests/replay.rs`, `tests/puzzle.rs`, `tests/workers.rs` | Replay filter, client puzzle, multi-worker server |
| `tests/stateful_*.rs` | The stateful baseline |
| `benches/protocol_phases.rs` | Server cost of each request kind (Criterion) |
| `benches/puzzle.rs`, `benches/replay.rs`, `benches/stateful_baseline.rs` | Puzzle, replay filter and baseline costs |
| `profiling/ct_check.rs` | Program that Valgrind runs to check that the server code does not branch on secrets or use them as addresses |

### Measurements

| Path | Content |
|---|---|
| `eval/` | Measurement harness for x86. It runs in Docker (`eval/Dockerfile`). |
| `artifact/x86/` | The x86 campaigns. Each stage list in `artifact/x86/stages/` names the harness runs of one campaign. |
| `eval/arm/` | The Raspberry Pi campaign |
| `eval/arm/memcap/` | Smallest memory limit under which each server still completes every session |
| `artifact/mctiny/` | Build of McTiny for the comparison |
| `artifact/tables/` | Scripts that turn raw results into tables |
| `artifact/env/collect_env.sh` | Records the software and hardware of a machine |

## Build and test

Get the submodules first. They are pinned to the exact revisions that we
measured.

```sh
git submodule update --init
```

`rust-toolchain.toml` pins the Rust toolchain (nightly-2026-06-15). `rustup`
installs it on the first build.

```sh
cargo build --release                        # portable HQC code, any machine
cargo build --release --features avx2        # HQC AVX2 code, x86-64 with AVX2, BMI1 and PCLMULQDQ
cargo build --release --features hqc-addfft  # aarch64 without crypto extensions (Raspberry Pi 3B+)
cargo test --release
```

All builds give the same keys, ciphertexts and session keys. The features change
only the speed. Always build with `--release`. Without it, the C code is built
without optimization and is very slow.

To run a server and a client:

```sh
target/release/hqclethe-client keygen --variant hqc5      # writes server-hqc5.pk and server-hqc5.sk
target/release/hqclethe-server --variant hqc5 --key server-hqc5.sk
target/release/hqclethe-client client --variant hqc5 --server-key server-hqc5.pk
```

To turn on the client puzzle, add `--puzzle-difficulty N` to the server. `N` is
the number of leading zero bits that the client's hash must have. To run N
server threads on one port, add `--workers N`.

## Check the proofs

The Rocq proofs need Rocq 9.0 or newer and SSProve:

```sh
opam repo add coq-released https://coq.inria.fr/opam/released
opam install coq-ssprove
cd ssprove
rocq makefile -f _CoqProject -o Makefile
make -j"$(nproc)"
make validate        # check the proof terms again with rocqchk
```

The opam install builds SSProve from source and can take more than an hour. The
proofs keep the moduli and the HQC message encoding as parameters. The moduli
must have degree at least 1, be pairwise coprime, and have degrees that add up to
at least `2n - 1`. `python3 scripts/check_crt_moduli.py` checks this for the
moduli in the code.

The ProVerif model needs ProVerif 2.05:

```sh
cd proofs/proverif
proverif hqclethe.pv      # the base model
./run.sh OUT_DIR          # every variant, 900 s limit for each
```

## Repeat the measurements

### Hardware

- x86: an AMD Ryzen 7 5800H with Linux, Docker with Compose, and root access.
  The scripts pin work to cpus 0, 2, 4, 10 and 12 to 15, so the machine needs at
  least 16 logical CPUs. `eval/scripts/container/placement.py` sets the pins.
- ARM: a Raspberry Pi 3 Model B Plus on the same LAN as the x86 machine. The x86
  machine cross-builds the Pi programs and sends the floods.
- Disk: about 20 GB for the Docker image and the builds.

`eval/scripts/host/measurement_on.sh` puts the x86 machine into the measurement
state: the `performance` governor, boost off, the hyperthreading sibling of the
server core offline, and interrupts moved off the measured cores. If the clock
is more than 2 % away from 3169 MHz, the script stops. `measurement_off.sh`
undoes the changes.

### x86

`eval/run_all.sh` runs the harness. `--categories` selects the measurements, and
`--variant hqc1|hqc3|hqc5` selects one level. Each run writes
`eval/results/<UTC time>/`. Run `eval/run_all.sh --smoke` first. It takes a few
minutes and checks the setup.

| Category | Measurement |
|---|---|
| 1 | Resident memory, idle and after sessions |
| 2 | Packet sizes and bytes per session |
| 3 | Server cost of each request kind (Criterion) |
| 4 | Floods: legitimate clients during each kind of flood, and filling the baseline's table |
| 5 | Session time over a network path |
| 6 | Server CPU per session |
| 7 | Smallest stack limit under which a session completes |
| 8 | Session time under emulated delay and loss (`tc netem`) |
| 9 | Valgrind check for secret-dependent branches and addresses |

Each category measures HqcLethe and the stateful baseline. The campaign scripts
run the categories in the order and with the repetitions that we used:

```sh
export CAMPAIGN_OUT=$HOME/campaign-out
export MEASURE_LOCK=$HOME/measure.lock
artifact/x86/campaign_final.sh       # HqcLethe and the baseline, about 10 hours
artifact/x86/campaign_part3.sh       # McTiny under loss, about 4 hours
```

Build McTiny first with `artifact/mctiny/build_x86.sh`. It downloads McTiny
20200804 and SUPERCOP 20200702 and adds one file,
`artifact/mctiny/mctiny_keygen_decap_bench.c`, that times key generation and
decapsulation.

### Raspberry Pi

```sh
export PI=user@host PLAY=x86-host
eval/arm/run_all.sh REV
```

`REV` is the git revision to build. The script cross-builds it on the x86 host,
installs it on the Pi, and runs the tests and Valgrind on the Pi. Then it
measures server CPU, client CPU, memory, floods over the LAN, and session time
over the LAN. `eval/arm/config.sh` holds the other settings. To size the replay
filter for the Pi, set `STATELESS_REPLAY_RATES=hqc1=R1,hqc3=R3,hqc5=R5`.
`eval/arm/item6_multicore_hello.sh` measures how the server scales with four
cores. `eval/arm/memcap/run.sh` searches for the smallest memory limit of each
server inside a Linux control group. Run it with `--smoke` first.

### Tables

```sh
export RESULTS_DIR=$HOME/results
artifact/tables/build_tables.sh $RESULTS_DIR OUT_DIR
```

`RESULTS_DIR` holds one directory for each campaign (`part1`, `part2`, `part3`,
`final-x86`, `arm-final`). `artifact/x86/fetch_results.sh` copies the results of
a campaign there. The table scripts name the result directories that they read
at the top of `make_tables_final.py` and `make_tables_dos.py`. After a new run,
change these names to your directories.

Absolute times depend on the machine. On other hardware, expect other absolute
values but similar ratios.

## Third-party code

| Code | Version | Licence | Use |
|---|---|---|---|
| HQC reference implementation, https://gitlab.com/pqc-hqc/hqc | `161cd4f` | Public domain | submodule `hqc/` |
| addFFT HQC multiplier (Chen, Chiu, Peng, Yang), https://github.com/ChunTaoPengim/HQC_with_addFFT_tches2026 | `c94c84d` | CC0 1.0 and Unlicense | submodule `hqc-addfft/` |
| libcrux ML-KEM | crate `libcrux-ml-kem` 0.0.11 | Apache-2.0 | server authentication |
| libmceliece `vec` code | 20230612 | Public domain | `third_party/mceliece-vec/`, Classic McEliece on non-x86 targets (`mceliece-ref` feature) |
| McTiny, https://mctiny.org | 20200804 | Public domain | downloaded by `artifact/mctiny/build_x86.sh` |
| SUPERCOP | 20200702 | Public domain or similar | downloaded with McTiny |
| SSProve | opam package `coq-ssprove` | MIT | proofs |
| Other Rust crates | `Cargo.lock` | MIT or Apache-2.0 | Cargo |
