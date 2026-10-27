# Classic McEliece `vec` implementations

Source: libmceliece 20230612, https://lib.mceliece.org/libmceliece-20230612.tar.gz
SHA-256 of the tarball: 6603d08888b39b5abbe96d75ee9393920acc4e077461d4f6c6910b7df0574ff7

Directories 348864, 460896 and 6688128 are copies of `crypto_kem/<set>/vec`
from that tarball. The `wrap_*.c` files are left out.
The directory `include` holds the libmceliece integer and declassify headers
(`crypto_int{8,16,32,64}.h`, `crypto_uint{8,16,32,64}.h`, `crypto_declassify.h`).
They are the output of the libmceliece `configure` step, not code of ours:
`crypto_declassify.h` is `include-build/crypto_declassify.h` from the tarball,
and `crypto_intN.h` and `crypto_uintN.h` are `inttypes/crypto_intN.h`
(SHA-256 956973f1...fb48) and `inttypes/crypto_uintN.h` (SHA-256
6affc998...c50f) with every `N` replaced by 8, 16, 32 or 64, as in `configure`
(`re.sub('N', str(bits), template)`).
The directory `shim` holds two adapters, not mask code: `crypto_xof_shake256.h`
calls SHAKE256 of the HQC `fips202.c`, and `randombytes.h` calls the Rust
random number generator.

Licence: public domain, see LICENSE.md.
The `vec` code is the portable bitsliced constant-time implementation of the
Classic McEliece authors (Tung Chou and others).
