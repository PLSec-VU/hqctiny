set -e
cd /work/mct
CC="aarch64-linux-gnu-gcc -march=armv8-a -mtune=cortex-a53 -O3 -fwrapv -fPIC -fPIE -w -Iinc"
B=build; rm -rf $B; mkdir $B
SH=mctshim
IMPL=""
c() { out=$1; shift; $CC "$@" -c -o $B/$out; }
# McEliece vec
for f in sc/vec/*.c; do
  n=$(basename $f .c)
  c vec_$n.o -Isc/vec -I$SH/gen -I$SH/inc -I$SH/gen \
    -Dcrypto_kem_keypair=crypto_kem_mceliece6960119_vec_keypair -Dcrypto_kem_enc=crypto_kem_mceliece6960119_vec_enc -Dcrypto_kem_dec=crypto_kem_mceliece6960119_vec_dec $f
done
c keccaksponge.o -I$SH/inc $SH/keccaksponge.c
c aes256ctr.o -I$SH/inc $SH/aes256ctr.c
c randombytes.o $SH/randombytes.c
c cpucycles.o $SH/cpucycles.c
# primitives
S=sc
c hsalsa.o -I$SH/gen -Dcrypto_core=crypto_core_hsalsa20 $S/crypto_core/hsalsa20/ref/core.c
c salsa.o -I$SH/gen -Dcrypto_core=crypto_core_salsa20 $S/crypto_core/salsa20/ref/core.c
c s20stream.o -I$SH/gen -Dcrypto_stream=crypto_stream_salsa20 $S/crypto_stream/salsa20/ref/stream.c
c s20xor.o -I$SH/gen -Dcrypto_stream_xor=crypto_stream_salsa20_xor $S/crypto_stream/salsa20/ref/xor.c
c xs20stream.o -I$SH/gen -Dcrypto_stream=crypto_stream_xsalsa20 $S/crypto_stream/xsalsa20/ref/stream.c
c xs20xor.o -I$SH/gen -Dcrypto_stream_xor=crypto_stream_xsalsa20_xor $S/crypto_stream/xsalsa20/ref/xor.c
c verify32.o -I$SH/gen -Dcrypto_verify=crypto_verify_32 $S/crypto_verify/32/ref/verify.c
c verify16.o -I$SH/gen -Dcrypto_verify=crypto_verify_16 $S/crypto_verify/16/ref/verify.c
c poly.o -I$SH/gen -I$SH/inc -Dcrypto_onetimeauth=crypto_onetimeauth_poly1305 $S/crypto_onetimeauth/poly1305/ref/auth.c
c polyv.o -I$SH/gen -I$SH/inc -Dcrypto_onetimeauth=crypto_onetimeauth_poly1305 -Dcrypto_onetimeauth_verify=crypto_onetimeauth_poly1305_verify $S/crypto_onetimeauth/poly1305/ref/verify.c
c sort.o -I$SH/gen -I$SH/inc -Dcrypto_sort=crypto_sort_int32 $S/crypto_sort/int32/portable4/sort.c
c shake.o -I$SH/genhash -I$S/crypto_hash/shake256/gil/singlefile -Dcrypto_hash=crypto_hash_shake256 $S/crypto_hash/shake256/gil/singlefile/keccak-tiny.c
LIBOBJS=$(ls $B/*.o)
ar rcs $B/libsc.a $LIBOBJS
LINK="$B/libsc.a"
M=mctiny
for p in server client master rotate; do
  $CC -I$SH/inc -c $M/mctiny-$p.c -o $B/mt_$p.o
done
$CC -I$SH/inc -c $M/mctiny_keygen_decap_bench.c -o $B/mt_bench.o
for f in hash packet pacing mctiny_cfun mctiny_sfun; do $CC -I$SH/inc -c $M/$f.c -o $B/m_$f.o; done
$CC -o $B/mctiny-server $B/mt_server.o $B/m_packet.o $B/m_mctiny_sfun.o $B/m_hash.o $LINK
$CC -o $B/mctiny-client $B/mt_client.o $B/m_mctiny_cfun.o $B/m_hash.o $B/m_packet.o $B/m_pacing.o $LINK
$CC -o $B/mctiny-master $B/mt_master.o $B/m_hash.o $LINK
$CC -o $B/mctiny-rotate $B/mt_rotate.o $B/m_hash.o $LINK
$CC -o $B/mctiny_keygen_decap_bench $B/mt_bench.o $B/m_mctiny_cfun.o $B/m_mctiny_sfun.o $B/m_hash.o $B/m_packet.o $LINK
mkdir -p /out/mctiny && cp $B/mctiny-server $B/mctiny-client $B/mctiny-master $B/mctiny-rotate $B/mctiny_keygen_decap_bench /out/mctiny/
file /out/mctiny/* 2>/dev/null || true
