#ifndef crypto_xof_shake256_h
#define crypto_xof_shake256_h

#include <stddef.h>
#include <stdint.h>

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

static inline int crypto_xof_shake256(unsigned char *out, long long outlen, const unsigned char *in, long long inlen)
{
  shake256(out, (size_t)outlen, in, (size_t)inlen);
  return 0;
}

#endif
