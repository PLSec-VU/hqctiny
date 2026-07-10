# HQCTiny evaluation suite

Reproduces the measurements in the paper.

## Requirements

- Docker Compose.
- `python3` on the *host*.

Everything else (Rust nightly toolchain, `strace`, `iproute2`, `valgrind`,
`procps`) is installed in `eval/Dockerfile` and does not need to exist on
the host.

## Running it

```sh
eval/run.py  # all 5 categories, all 3 variants, local WAN profile
eval/run.py --categories 1,2 # just memory + bandwidth (fast, no flood/WAN)
eval/run.py --variant hqc1 # restrict to one parameter set
eval/run.py --categories 5 --wan-profile transatlantic
eval/run.py --categories 5 --remote 203.0.113.4:12345 # real remote host instead of netem
eval/run.py --categories 4 --dos-reps 3 # fast iteration (default is 10 reps)
eval/run.py --dos-reps 20 --wan-reps 50 # tighter CIs for a paper-final run
```

Each run writes `eval/results/<UTC timestamp>/`.