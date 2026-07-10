# Heap profiling

This is done with [dhat](https://github.com/nnethercote/dhat-rs).

```sh
cargo run --release --features dhat-heap --bin dhat-heap [iterations]
```

`iterations` defaults to 20. This writes `dhat-heap.json` in the working
directory; open it at https://nnethercote.github.io/dhat/dhat.html to
view the allocation graph.

# CPU flamegraphs

This is done with [flamegraph](https://github.com/flamegraph-rs/flamegraph).

```sh
cargo install flamegraph
cargo flamegraph --profile profiling --bin flamegraph-workload -- 20000
```

`iterations` defaults to 20,000.  Output is written to `flamegraph.svg`.

# FFI vs protocol-layer timing breakdown

```sh
cargo run --release --bin timing-breakdown [iterations]
```

`iterations` defaults to 3000. Prints, per variant, the share of a full
round trip spent in the raw HQC FFI calls (`keypair`/`dec`) vs everything
else in the protocol layer.

# Stack depth probe

```sh
cargo run --profile tiny-release --bin stack-test
```

Runs one full HQC-5 client+server round trip and exits 0. Used by
`eval/scripts/container/stack_search.py` under a constrained `ulimit -s`
to binary-search the implementation's minimum stack requirement.
