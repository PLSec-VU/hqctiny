#ifndef crypto_int64_h
#define crypto_int64_h

#include <inttypes.h>
#define crypto_int64 int64_t

__attribute__((unused))
static crypto_int64 crypto_int64_negative_mask(crypto_int64 crypto_int64_x)
{
  return crypto_int64_x >> (64-1);
}

__attribute__((unused))
static crypto_int64 crypto_int64_nonzero_mask(crypto_int64 crypto_int64_x)
{
  return crypto_int64_negative_mask(crypto_int64_x) | crypto_int64_negative_mask(-crypto_int64_x);
}

__attribute__((unused))
static crypto_int64 crypto_int64_zero_mask(crypto_int64 crypto_int64_x)
{
  return ~crypto_int64_nonzero_mask(crypto_int64_x);
}

__attribute__((unused))
static crypto_int64 crypto_int64_positive_mask(crypto_int64 crypto_int64_x)
{
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  return crypto_int64_negative_mask(crypto_int64_z);
}

__attribute__((unused))
static crypto_int64 crypto_int64_unequal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y)
{
  crypto_int64 crypto_int64_xy = crypto_int64_x ^ crypto_int64_y;
  return crypto_int64_nonzero_mask(crypto_int64_xy);
}

__attribute__((unused))
static crypto_int64 crypto_int64_equal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y)
{
  return ~crypto_int64_unequal_mask(crypto_int64_x,crypto_int64_y);
}

__attribute__((unused))
static crypto_int64 crypto_int64_smaller_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y)
{
  crypto_int64 crypto_int64_xy = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_xy & (crypto_int64_z ^ crypto_int64_x);
  return crypto_int64_negative_mask(crypto_int64_z);
}

__attribute__((unused))
static crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y)
{
  crypto_int64 crypto_int64_xy = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_xy & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_xy;
  return crypto_int64_x ^ crypto_int64_z;
}

__attribute__((unused))
static crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y)
{
  crypto_int64 crypto_int64_xy = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_xy & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_xy;
  return crypto_int64_y ^ crypto_int64_z;
}

__attribute__((unused))
static void crypto_int64_minmax(crypto_int64 *crypto_int64_a,crypto_int64 *crypto_int64_b)
{
  crypto_int64 crypto_int64_x = *crypto_int64_a;
  crypto_int64 crypto_int64_y = *crypto_int64_b;
  crypto_int64 crypto_int64_xy = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_xy & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_xy;
  *crypto_int64_a = crypto_int64_x ^ crypto_int64_z;
  *crypto_int64_b = crypto_int64_y ^ crypto_int64_z;
}

#endif
