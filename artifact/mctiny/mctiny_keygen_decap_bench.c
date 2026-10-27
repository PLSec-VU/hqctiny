#include <stdio.h>
#include <string.h>
#include "mctiny.h"
#include "cpucycles.h"

#define ITERS 30

static unsigned char pk[mctiny_PUBLICKEYBYTES];
static unsigned char sk[mctiny_SECRETKEYBYTES];
static unsigned char ciphertext[mctiny_CIPHERTEXTBYTES];
static unsigned char k_enc[mctiny_SESSIONKEYBYTES];
static unsigned char k_dec[mctiny_SESSIONKEYBYTES];

int main(void)
{
  long long keypair_cycles[ITERS];
  long long dec_cycles[ITERS];
  long long t0, t1;
  int i;

  for (i = 0; i < ITERS; ++i) {
    t0 = cpucycles();
    if (mctiny_keypair(pk, sk) != 0) {
      fprintf(stderr, "keygen failed\n");
      return 111;
    }
    t1 = cpucycles();
    keypair_cycles[i] = t1 - t0;

    if (mctiny_enc(ciphertext, k_enc, pk) != 0) {
      fprintf(stderr, "enc failed\n");
      return 111;
    }

    t0 = cpucycles();
    mctiny_dec(k_dec, ciphertext, sk);
    t1 = cpucycles();
    dec_cycles[i] = t1 - t0;

    if (memcmp(k_enc, k_dec, sizeof k_enc) != 0) {
      fprintf(stderr, "dec mismatch at iter %d\n", i);
      return 111;
    }
  }

  printf("cpucycles_persecond %lld\n", cpucycles_persecond());
  printf("iters %d\n", ITERS);
  printf("keypair_cycles");
  for (i = 0; i < ITERS; ++i) printf(" %lld", keypair_cycles[i]);
  printf("\n");
  printf("dec_cycles");
  for (i = 0; i < ITERS; ++i) printf(" %lld", dec_cycles[i]);
  printf("\n");
  return 0;
}
