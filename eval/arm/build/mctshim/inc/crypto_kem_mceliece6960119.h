#ifndef crypto_kem_mceliece6960119_H
#define crypto_kem_mceliece6960119_H
#define crypto_kem_mceliece6960119_PUBLICKEYBYTES 1047319
#define crypto_kem_mceliece6960119_SECRETKEYBYTES 13908
#define crypto_kem_mceliece6960119_CIPHERTEXTBYTES 226
#define crypto_kem_mceliece6960119_BYTES 32
extern int crypto_kem_mceliece6960119_vec_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece6960119_vec_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece6960119_vec_dec(unsigned char *,const unsigned char *,const unsigned char *);
#define crypto_kem_mceliece6960119_keypair crypto_kem_mceliece6960119_vec_keypair
#define crypto_kem_mceliece6960119_enc crypto_kem_mceliece6960119_vec_enc
#define crypto_kem_mceliece6960119_dec crypto_kem_mceliece6960119_vec_dec
#endif
