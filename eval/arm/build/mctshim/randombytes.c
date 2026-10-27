#include <sys/random.h>
#include <stdlib.h>
void randombytes(unsigned char *x, unsigned long long xlen)
{
  while (xlen > 0) {
    ssize_t got = getrandom(x, xlen > 256 ? 256 : xlen, 0);
    if (got <= 0) abort();
    x += got; xlen -= got;
  }
}
