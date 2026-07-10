# Pinned by digest (multi-arch index -- resolves correctly on both amd64
# eval hosts and arm64 dev machines) rather than the floating `bookworm`
# tag, so apt package versions (valgrind, strace, ...) don't silently shift
# between paper runs. `rust-toolchain.toml` pins the actual Rust nightly
# separately; this only fixes the Debian base. Re-resolve deliberately with
# `docker buildx imagetools inspect rust:bookworm` when you want to bump it.
FROM rust:bookworm@sha256:7d0723df719e7f213b69dc7c8c595985c3f4b060cfbee4f7bc0e347a86fe3b6a

# The base image's own /etc/apt/sources.list.d/debian.sources points at the
# live deb.debian.org mirror (only its comment records which
# snapshot.debian.org timestamp the image itself was built from), so
# `apt-get install` below would otherwise pull whatever strace/valgrind/etc
# versions happen to be current *at image-build time* -- drifting between
# paper runs even with the base image digest pinned above. Repointing at
# that exact recorded snapshot freezes it. `Check-Valid-Until "false"`:
# snapshot Release files are deliberately old, so apt's normal
# expiry check would otherwise refuse them.
RUN sed -i \
    -e 's|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20260623T000000Z|' \
    -e 's|URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20260623T000000Z|' \
    /etc/apt/sources.list.d/debian.sources \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    strace \
    iproute2 \
    iputils-ping \
    valgrind \
    procps \
    python3 \
    time \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN cd /tmp && rustup show
RUN cargo install iai-callgrind-runner --version 0.14.2 --locked

WORKDIR /work
