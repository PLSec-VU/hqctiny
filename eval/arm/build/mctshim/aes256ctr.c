#include <stdint.h>
#include <string.h>
#include "crypto_stream_aes256ctr.h"
static uint8_t sbox[256];
static int ready;
static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }
static void init_sbox(void)
{
  uint8_t p = 1, q = 1;
  do {
    p = p ^ (uint8_t)(p << 1) ^ ((p & 0x80) ? 0x1b : 0);
    q ^= q << 1; q ^= q << 2; q ^= q << 4; if (q & 0x80) q ^= 0x09;
    uint8_t x = q ^ (uint8_t)((q << 1) | (q >> 7)) ^ (uint8_t)((q << 2) | (q >> 6)) ^ (uint8_t)((q << 3) | (q >> 5)) ^ (uint8_t)((q << 4) | (q >> 4));
    sbox[p] = x ^ 0x63;
  } while (p != 1);
  sbox[0] = 0x63;
  ready = 1;
}
static void expand(uint8_t rk[240], const uint8_t key[32])
{
  uint8_t rcon = 1;
  memcpy(rk, key, 32);
  for (int i = 32; i < 240; i += 4) {
    uint8_t t[4];
    memcpy(t, rk + i - 4, 4);
    if (i % 32 == 0) {
      uint8_t a = t[0];
      t[0] = sbox[t[1]] ^ rcon; t[1] = sbox[t[2]]; t[2] = sbox[t[3]]; t[3] = sbox[a];
      rcon = xtime(rcon);
    } else if (i % 32 == 16) {
      for (int k = 0; k < 4; k++) t[k] = sbox[t[k]];
    }
    for (int k = 0; k < 4; k++) rk[i + k] = rk[i - 32 + k] ^ t[k];
  }
}
static void encrypt(uint8_t out[16], const uint8_t in[16], const uint8_t rk[240])
{
  uint8_t s[16];
  for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
  for (int r = 1; r <= 14; r++) {
    uint8_t t[16];
    for (int i = 0; i < 16; i++) t[i] = sbox[s[i]];
    static const int shift[16] = {0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};
    for (int i = 0; i < 16; i++) s[i] = t[shift[i]];
    if (r != 14) {
      for (int c = 0; c < 4; c++) {
        uint8_t *a = s + 4*c, a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], all = a0^a1^a2^a3;
        a[0] ^= all ^ xtime(a0 ^ a1);
        a[1] ^= all ^ xtime(a1 ^ a2);
        a[2] ^= all ^ xtime(a2 ^ a3);
        a[3] ^= all ^ xtime(a3 ^ a0);
      }
    }
    for (int i = 0; i < 16; i++) s[i] ^= rk[16*r + i];
  }
  memcpy(out, s, 16);
}
int crypto_stream_aes256ctr(unsigned char *out, unsigned long long outlen, const unsigned char *nonce, const unsigned char *key)
{
  uint8_t rk[240], ctr[16], block[16];
  if (!ready) init_sbox();
  expand(rk, key);
  memcpy(ctr, nonce, 16);
  while (outlen > 0) {
    unsigned long long n = outlen < 16 ? outlen : 16;
    encrypt(block, ctr, rk);
    memcpy(out, block, n);
    out += n; outlen -= n;
    for (int i = 15; i >= 0; i--) if (++ctr[i] != 0) break;
  }
  return 0;
}
