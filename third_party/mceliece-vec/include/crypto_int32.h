#ifndef crypto_int32_h
#define crypto_int32_h

#include <inttypes.h>
#define crypto_int32 int32_t

__attribute__((unused))
static crypto_int32 crypto_int32_negative_mask(crypto_int32 crypto_int32_x)
{
  return crypto_int32_x >> (32-1);
}

__attribute__((unused))
static crypto_int32 crypto_int32_nonzero_mask(crypto_int32 crypto_int32_x)
{
  return crypto_int32_negative_mask(crypto_int32_x) | crypto_int32_negative_mask(-crypto_int32_x);
}

__attribute__((unused))
static crypto_int32 crypto_int32_zero_mask(crypto_int32 crypto_int32_x)
{
  return ~crypto_int32_nonzero_mask(crypto_int32_x);
}

__attribute__((unused))
static crypto_int32 crypto_int32_positive_mask(crypto_int32 crypto_int32_x)
{
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  return crypto_int32_negative_mask(crypto_int32_z);
}

__attribute__((unused))
static crypto_int32 crypto_int32_unequal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y)
{
  crypto_int32 crypto_int32_xy = crypto_int32_x ^ crypto_int32_y;
  return crypto_int32_nonzero_mask(crypto_int32_xy);
}

__attribute__((unused))
static crypto_int32 crypto_int32_equal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y)
{
  return ~crypto_int32_unequal_mask(crypto_int32_x,crypto_int32_y);
}

__attribute__((unused))
static crypto_int32 crypto_int32_smaller_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y)
{
  crypto_int32 crypto_int32_xy = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_xy & (crypto_int32_z ^ crypto_int32_x);
  return crypto_int32_negative_mask(crypto_int32_z);
}

__attribute__((unused))
static crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y)
{
  crypto_int32 crypto_int32_xy = crypto_int32_y ^ crypto_int32_x;
  crypto_int32 crypto_int32_z = crypto_int32_y - crypto_int32_x;
  crypto_int32_z ^= crypto_int32_xy & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_xy;
  return crypto_int32_x ^ crypto_int32_z;
}

__attribute__((unused))
static crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y)
{
  crypto_int32 crypto_int32_xy = crypto_int32_y ^ crypto_int32_x;
  crypto_int32 crypto_int32_z = crypto_int32_y - crypto_int32_x;
  crypto_int32_z ^= crypto_int32_xy & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_xy;
  return crypto_int32_y ^ crypto_int32_z;
}

__attribute__((unused))
static void crypto_int32_minmax(crypto_int32 *crypto_int32_a,crypto_int32 *crypto_int32_b)
{
  crypto_int32 crypto_int32_x = *crypto_int32_a;
  crypto_int32 crypto_int32_y = *crypto_int32_b;
  crypto_int32 crypto_int32_xy = crypto_int32_y ^ crypto_int32_x;
  crypto_int32 crypto_int32_z = crypto_int32_y - crypto_int32_x;
  crypto_int32_z ^= crypto_int32_xy & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_xy;
  *crypto_int32_a = crypto_int32_x ^ crypto_int32_z;
  *crypto_int32_b = crypto_int32_y ^ crypto_int32_z;
}

#endif
