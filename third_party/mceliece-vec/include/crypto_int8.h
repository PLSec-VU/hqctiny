#ifndef crypto_int8_h
#define crypto_int8_h

#include <inttypes.h>
#define crypto_int8 int8_t

__attribute__((unused))
static crypto_int8 crypto_int8_negative_mask(crypto_int8 crypto_int8_x)
{
  return crypto_int8_x >> (8-1);
}

__attribute__((unused))
static crypto_int8 crypto_int8_nonzero_mask(crypto_int8 crypto_int8_x)
{
  return crypto_int8_negative_mask(crypto_int8_x) | crypto_int8_negative_mask(-crypto_int8_x);
}

__attribute__((unused))
static crypto_int8 crypto_int8_zero_mask(crypto_int8 crypto_int8_x)
{
  return ~crypto_int8_nonzero_mask(crypto_int8_x);
}

__attribute__((unused))
static crypto_int8 crypto_int8_positive_mask(crypto_int8 crypto_int8_x)
{
  crypto_int8 crypto_int8_z = -crypto_int8_x;
  crypto_int8_z ^= crypto_int8_x & crypto_int8_z;
  return crypto_int8_negative_mask(crypto_int8_z);
}

__attribute__((unused))
static crypto_int8 crypto_int8_unequal_mask(crypto_int8 crypto_int8_x,crypto_int8 crypto_int8_y)
{
  crypto_int8 crypto_int8_xy = crypto_int8_x ^ crypto_int8_y;
  return crypto_int8_nonzero_mask(crypto_int8_xy);
}

__attribute__((unused))
static crypto_int8 crypto_int8_equal_mask(crypto_int8 crypto_int8_x,crypto_int8 crypto_int8_y)
{
  return ~crypto_int8_unequal_mask(crypto_int8_x,crypto_int8_y);
}

__attribute__((unused))
static crypto_int8 crypto_int8_smaller_mask(crypto_int8 crypto_int8_x,crypto_int8 crypto_int8_y)
{
  crypto_int8 crypto_int8_xy = crypto_int8_x ^ crypto_int8_y;
  crypto_int8 crypto_int8_z = crypto_int8_x - crypto_int8_y;
  crypto_int8_z ^= crypto_int8_xy & (crypto_int8_z ^ crypto_int8_x);
  return crypto_int8_negative_mask(crypto_int8_z);
}

__attribute__((unused))
static crypto_int8 crypto_int8_min(crypto_int8 crypto_int8_x,crypto_int8 crypto_int8_y)
{
  crypto_int8 crypto_int8_xy = crypto_int8_y ^ crypto_int8_x;
  crypto_int8 crypto_int8_z = crypto_int8_y - crypto_int8_x;
  crypto_int8_z ^= crypto_int8_xy & (crypto_int8_z ^ crypto_int8_y);
  crypto_int8_z = crypto_int8_negative_mask(crypto_int8_z);
  crypto_int8_z &= crypto_int8_xy;
  return crypto_int8_x ^ crypto_int8_z;
}

__attribute__((unused))
static crypto_int8 crypto_int8_max(crypto_int8 crypto_int8_x,crypto_int8 crypto_int8_y)
{
  crypto_int8 crypto_int8_xy = crypto_int8_y ^ crypto_int8_x;
  crypto_int8 crypto_int8_z = crypto_int8_y - crypto_int8_x;
  crypto_int8_z ^= crypto_int8_xy & (crypto_int8_z ^ crypto_int8_y);
  crypto_int8_z = crypto_int8_negative_mask(crypto_int8_z);
  crypto_int8_z &= crypto_int8_xy;
  return crypto_int8_y ^ crypto_int8_z;
}

__attribute__((unused))
static void crypto_int8_minmax(crypto_int8 *crypto_int8_a,crypto_int8 *crypto_int8_b)
{
  crypto_int8 crypto_int8_x = *crypto_int8_a;
  crypto_int8 crypto_int8_y = *crypto_int8_b;
  crypto_int8 crypto_int8_xy = crypto_int8_y ^ crypto_int8_x;
  crypto_int8 crypto_int8_z = crypto_int8_y - crypto_int8_x;
  crypto_int8_z ^= crypto_int8_xy & (crypto_int8_z ^ crypto_int8_y);
  crypto_int8_z = crypto_int8_negative_mask(crypto_int8_z);
  crypto_int8_z &= crypto_int8_xy;
  *crypto_int8_a = crypto_int8_x ^ crypto_int8_z;
  *crypto_int8_b = crypto_int8_y ^ crypto_int8_z;
}

#endif
