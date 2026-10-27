#include <stdint.h>
#include <string.h>
#include "libkeccak.a.headers/KeccakSpongeWidth1600.h"
static const uint64_t RC[24] = {
0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int ROT[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int PI[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
#define ROL(x,n) (((x) << (n)) | ((x) >> (64 - (n))))
static void keccakf(uint64_t s[25])
{
  for (int r = 0; r < 24; r++) {
    uint64_t c[5], t;
    for (int i = 0; i < 5; i++) c[i] = s[i]^s[i+5]^s[i+10]^s[i+15]^s[i+20];
    for (int i = 0; i < 5; i++) { t = c[(i+4)%5] ^ ROL(c[(i+1)%5],1); for (int j = 0; j < 25; j += 5) s[j+i] ^= t; }
    t = s[1];
    for (int i = 0; i < 24; i++) { int j = PI[i]; uint64_t b = s[j]; s[j] = ROL(t, ROT[i]); t = b; }
    for (int j = 0; j < 25; j += 5) { for (int i = 0; i < 5; i++) c[i] = s[j+i]; for (int i = 0; i < 5; i++) s[j+i] ^= (~c[(i+1)%5]) & c[(i+2)%5]; }
    s[0] ^= RC[r];
  }
}
static void xorbytes(uint64_t s[25], const unsigned char *in, unsigned n)
{
  for (unsigned i = 0; i < n; i++) s[i/8] ^= (uint64_t) in[i] << (8*(i%8));
}
int KeccakWidth1600_Sponge(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long inlen, unsigned char suffix, unsigned char *output, unsigned long long outlen)
{
  uint64_t s[25];
  unsigned char block[200];
  unsigned rb = rate / 8;
  (void) capacity;
  memset(s, 0, sizeof s);
  while (inlen >= rb) { xorbytes(s, input, rb); keccakf(s); input += rb; inlen -= rb; }
  memset(block, 0, sizeof block);
  memcpy(block, input, inlen);
  block[inlen] ^= suffix;
  block[rb-1] ^= 0x80;
  xorbytes(s, block, rb);
  keccakf(s);
  while (outlen > 0) {
    unsigned n = outlen < rb ? (unsigned) outlen : rb;
    for (unsigned i = 0; i < n; i++) output[i] = (unsigned char)(s[i/8] >> (8*(i%8)));
    output += n; outlen -= n;
    if (outlen > 0) keccakf(s);
  }
  return 0;
}
