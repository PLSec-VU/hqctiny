#!/bin/sh -e
# usage: build.sh COMMIT
# Builds from COMMIT, in one playground lock hold: the aarch64 binaries (HQCLethe servers and clients, benches, McTiny with
# portable McEliece), the x86 flood clients, the aarch64 test binaries, ct-check and backend-vectors, and the x86 test suites.
# Then copies the aarch64 files to the Pi.
. "$(dirname "$0")/config.sh"
"$ARM_SCRIPTS/sync_src.sh" "$1"
ssh $PLAY "mkdir -p ~/$BUILD_DIR/build ~/$BUILD_DIR/mct"
rsync -a "$ARM_SCRIPTS/build/" $PLAY:$BUILD_DIR/build/
rsync -a "$ARM_SCRIPTS/build/mctshim" $PLAY:$BUILD_DIR/mct/
ssh $PLAY "cd ~/$BUILD_DIR/mct && S=$MCTINY_BUILD/supercop-20200702 && M=$MCTINY_BUILD/mctiny-20200804 &&
  [ -d mctiny ] || { mkdir -p mctiny sc && cp \$M/*.c \$M/*.h mctiny/ && sed -i 's/#define ITERS 30/#define ITERS 10/' mctiny/mctiny_keygen_decap_bench.c &&
  cp -r \$S/crypto_kem/mceliece6960119/vec sc/vec &&
  for p in crypto_stream/xsalsa20/ref crypto_stream/salsa20/ref crypto_core/salsa20/ref crypto_core/hsalsa20/ref crypto_verify/32/ref crypto_verify/16/ref crypto_onetimeauth/poly1305/ref crypto_sort/int32/portable4 crypto_hash/shake256/gil/singlefile; do mkdir -p sc/\$p; cp \$S/\$p/* sc/\$p/; done &&
  mkdir -p inc && cp \$M/supercop/me/include/myabi/crypto_int*.h \$M/supercop/me/include/myabi/crypto_uint*.h inc/; }"
ssh $PLAY "cd ~/$BUILD_DIR && nice env BUILD_DIR=$BUILD_DIR BUILD_CPUS=$BUILD_CPUS flock $PLAY_LOCK sh build/remote_all.sh"
"$ARM_SCRIPTS/install_pi.sh" "$1"
