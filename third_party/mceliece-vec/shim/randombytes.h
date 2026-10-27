#ifndef randombytes_h
#define randombytes_h

#include <stddef.h>

int PQCRYPTO_RUST_randombytes(unsigned char *buffer, size_t length);

static inline void randombytes(unsigned char *buffer, unsigned long long length)
{
  PQCRYPTO_RUST_randombytes(buffer, (size_t)length);
}

#endif
