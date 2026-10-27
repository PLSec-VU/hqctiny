#!/bin/sh -e
# usage: build_x86.sh [MCTINY_BUILD] [MCTINY_STATE]
# Builds McTiny 20200804 with SUPERCOP 20200702 for the host CPU and creates the server key state.
# Needs AVX2, gcc, make, python3, xsltproc, wget and about 1 GB of disk space.
MCTINY_BUILD=${1:-${MCTINY_BUILD:-$HOME/mctiny_build}}
MCTINY_STATE=${2:-${MCTINY_STATE:-$HOME/mctiny_state}}
MCTINY_URL=${MCTINY_URL:-https://mctiny.org/mctiny-20200804.tar.gz}
MCTINY_SHA256=d59402bcabf15186889418dd3e8f1088aacdfb5c932d54602f8bd09bb4fe747a
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$MCTINY_BUILD"
cd "$MCTINY_BUILD"
[ -f mctiny-20200804.tar.gz ] || wget -q "$MCTINY_URL"
echo "$MCTINY_SHA256  mctiny-20200804.tar.gz" | sha256sum -c
tar -xzf mctiny-20200804.tar.gz
cd mctiny-20200804
./supercop-download
./supercop-build
make
cp "$HERE/mctiny_keygen_decap_bench.c" .
gcc -march=native -mtune=native -O3 -fwrapv -fPIC -fPIE -I supercop/me/include -I supercop/me/include/myabi \
  -o mctiny_keygen_decap_bench mctiny_keygen_decap_bench.c hash.o mctiny_cfun.o mctiny_sfun.o \
  supercop/me/lib/myabi/fastrandombytes.o supercop/me/lib/myabi/kernelrandombytes.o supercop/me/lib/myabi/cpucycles.o \
  supercop/me/lib/myabi/libsupercop.a supercop/me/lib/myabi/libkeccak.a
[ -d "$MCTINY_STATE/public" ] || ./mctiny-master "$MCTINY_STATE"
echo "McTiny binaries: $PWD"
echo "McTiny state:    $MCTINY_STATE"
