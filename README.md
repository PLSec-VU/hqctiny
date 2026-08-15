# HQCLethe

A server-stateless post-quantum key-exchange protocol built on the
**Hamming Quasi-Cyclic (HQC)** KEM. The protocol design, security
argument, and evaluation results are described in full in the accompanying
paper; this README covers only what a reviewer needs to build the code and
reproduce its numbers.

## Requirements

- **Docker + Docker Compose** — everything the evaluation suite needs
  (Rust nightly, `strace`, `valgrind`, `iproute2`, `procps`) is installed
  inside the container by `eval/Dockerfile`; nothing else needs to be
  installed on the host to reproduce the paper's numbers.
- **`python3`** on the host, to drive `eval/run.py`.
- To build outside Docker instead (e.g. for development), a Rust nightly
  toolchain is required; `rust-toolchain.toml` pins the exact one used for
  the paper's numbers and `rustup` will install it automatically on first
  `cargo build`.
- The `avx2` Cargo feature (used for every main-body measurement in the
  paper — see below) requires an x86\_64 CPU with AVX2, BMI1, and
  PCLMULQDQ, and only builds on x86\_64. The portable build has no such
  requirement and runs anywhere.

## Project Structure

| Path | Contents |
|------|----------|
| `src/` | The Rust protocol implementation (client, server, wire encoding, HQC bindings, field math) |
| `hqc/` | The [official HQC reference implementation](https://gitlab.com/pqc-hqc/hqc.git), built by `build.rs` |
| `hqclethe-client/` | The UDP client binary, plus `bandwidth-report`/`flood-client` measurement helpers |
| `hqclethe-server/` | The UDP server binary, used for static-size/stack-depth/strace measurements |
| `benches/` | Criterion and iai-callgrind benchmarks (feed Table 3 / the callgrind cycle counts) |
| `profiling/` | Dev-loop profiling: heap (dhat), CPU flamegraphs, a stack-depth probe — see `profiling/README.md` |
| `eval/` | The evaluation suite that reproduces the paper's measurements — see `eval/README.md` |
| `sagemath/` | SageMath scripts used to generate precomputation artifacts (Newton weights, test vectors) — see `sagemath/README.md` |
| `ssprove/`, `proofs/` | The mechanized Coq/SSProve confidentiality proof (Appendix on trace confidentiality) |
| `tests/` | Integration tests exercising the full protocol flow |

## Fetching HQC (Required for Building)

The build script (`build.rs`) compiles the C sources from the official HQC reference implementation inside `hqc/`. If the `hqc/` directory is empty or missing, clone it directly into the repository root before building:

```sh
git clone https://gitlab.com/pqc-hqc/hqc.git hqc
```

## Building

```sh
cargo build --release                    # portable HQC backend, runs anywhere
cargo build --release --features avx2    # AVX2 HQC backend; needs AVX2/BMI1/PCLMULQDQ
```

Both produce identical keys, ciphertexts, and shared secrets — `avx2` is a
performance-only opt-in (roughly 50-90x faster keygen, 40-70x faster
decapsulation), not a correctness or wire-format change. The evaluation
suite (below) builds with `avx2` automatically for the categories that use
it; you don't need to pass the flag yourself when reproducing paper numbers.

## Checking the Proofs

The mechanized confidentiality proofs (Appendix on trace confidentiality) are formalized in Rocq / Coq using the [SSProve](https://github.com/SSProve/ssprove) foundational framework and MathComp in `ssprove/`.

### Requirements

- **Rocq / Coq** (version 9.0+) with `rocq-mathcomp-ssreflect`, `rocq-mathcomp-algebra`, and `ssprove` installed (via `opam`).

### Verifying Proofs

To compile and verify all proof scripts (`Tuple.v`, `Interpolate.v`, `HQC.v`, `HQCLethe.v`):

```sh
make -C ssprove
```

To run the standalone proof checker kernel (`rocqchk`):

```sh
make -C ssprove validate
```

See [`ssprove/README.md`](file:///Users/octeep/workspace/hqctiny/ssprove/README.md) for details on the proof structure, parameter sets, and axioms.

## Reproducing the Paper's Evaluation

`eval/run.py` builds a Docker measurement environment and drives all five
evaluation categories:

| Category | Paper section | What it measures |
|---|---|---|
| 1 | §7.1 RAM Consumption | Binary size, stack depth, startup/steady-state memory (`strace`) |
| 2 | §7.2 Network Usage | Packet sizes and per-session bandwidth (protocol-intrinsic, host-independent) |
| 3 | §7.3 CPU Usage | Criterion micro/macrobenchmarks, FFI-vs-protocol timing breakdown, iai-callgrind cycle counts (Table 3) |
| 4 | §7.4 CPU/Memory Overload Attacks | Flood resilience under handshake and point-request DoS (Table 4) |
| 5 | §7.5 Latency on a Real Network Path | Client/server session latency, optionally under injected loss (Table 5) |

Full usage, flags, and output layout are in `eval/README.md`; the short
version:

```sh
eval/run.py                       # all 5 categories, all 3 variants, local WAN profile
eval/run.py --categories 1,3,4    # just the AVX2 host measurements (fast, no WAN/remote setup)
eval/run.py --dos-reps 20 --wan-reps 50   # tighter CIs, matching the paper-final run
```

Each run writes `eval/results/<UTC timestamp>/report.md` plus the raw logs
and JSON it was built from.

**Categories 1, 3, and 4 build with the `avx2` feature** (the eval scripts
pass `--features avx2` to every `cargo build`/`cargo bench` invocation),
matching the AVX2 host used for the paper's main-body numbers. **Category
2** is protocol-intrinsic and unaffected by the crypto backend. **Category
5 (WAN)** run locally (the default) exercises the same retransmission and
congestion-handling logic as the paper's real Hong Kong–Amsterdam
measurement, but will not reproduce those exact numbers — that path was
run against a specific (since-decommissioned) remote deployment. Point
`--remote host:port` at your own two-host setup, or use `--wan-profile` to
approximate a WAN path's RTT/loss locally via `netem`, to get comparable
(not identical) latency numbers.

### Appendix A: The McTiny Comparison

Appendix A's numbers are **not** produced by this repo or by `eval/run.py`
— they come from benchmarking the public
[McTiny](https://mctiny.cr.yp.to/) reference release
(`mctiny-20200804` with `supercop-20200702`) directly, built with its AVX2
Classic McEliece (`mceliece6960119`) backend, alongside a same-host AVX2
build of this repo. To redo that comparison:

1. Fetch and build `mctiny-20200804` + `supercop-20200702` per McTiny's own
   instructions, on the same machine you'll build this repo's `avx2`
   feature on.
2. Client/server keygen, encap, decap medians come from a small custom
   `mctiny-bench.c` harness (median of 20 reps, calling McTiny's own
   `mctiny_keypair`/`mctiny_enc`/`mctiny_dec`) dropped into the McTiny
   source tree, and from this repo's `cargo bench --features avx2`
   (Criterion medians), respectively.
3. Per-session server CPU for both systems is measured directly from
   server process CPU time (`/usr/bin/time -v`) across N repeated
   sessions on localhost.
4. The two WAN rows are carried over unchanged from Category 5's real
   Hong Kong–Amsterdam measurement and are not re-derived on the AVX2 host.

