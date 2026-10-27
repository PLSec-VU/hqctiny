#ifndef crypto_uint8_h
#define crypto_uint8_h

#include <inttypes.h>
#define crypto_uint8 uint8_t
#define crypto_uint8_signed int8_t

__attribute__((unused))
static crypto_uint8_signed crypto_uint8_signed_negative_mask(crypto_uint8_signed crypto_uint8_signed_x)
{
  return crypto_uint8_signed_x >> (8-1);
}

__attribute__((unused))
static crypto_uint8 crypto_uint8_nonzero_mask(crypto_uint8 crypto_uint8_x)
{
  return crypto_uint8_signed_negative_mask(crypto_uint8_x) | crypto_uint8_signed_negative_mask(-crypto_uint8_x);
}

__attribute__((unused))
static crypto_uint8 crypto_uint8_zero_mask(crypto_uint8 crypto_uint8_x)
{
  return ~crypto_uint8_nonzero_mask(crypto_uint8_x);
}

__attribute__((unused))
static crypto_uint8 crypto_uint8_unequal_mask(crypto_uint8 crypto_uint8_x,crypto_uint8 crypto_uint8_y)
{
  crypto_uint8 crypto_uint8_xy = crypto_uint8_x ^ crypto_uint8_y;
  return crypto_uint8_nonzero_mask(crypto_uint8_xy);
}

__attribute__((unused))
static crypto_uint8 crypto_uint8_equal_mask(crypto_uint8 crypto_uint8_x,crypto_uint8 crypto_uint8_y)
{
  return ~crypto_uint8_unequal_mask(crypto_uint8_x,crypto_uint8_y);
}

__attribute__((unused))
static crypto_uint8 crypto_uint8_smaller_mask(crypto_uint8 crypto_uint8_x,crypto_uint8 crypto_uint8_y)
{
  crypto_uint8 crypto_uint8_xy = crypto_uint8_x ^ crypto_uint8_y;
  crypto_uint8 crypto_uint8_z = crypto_uint8_x - crypto_uint8_y;
  crypto_uint8_z ^= crypto_uint8_xy & (crypto_uint8_z ^ crypto_uint8_x ^ (((crypto_uint8) 1) << (8-1)));
  return crypto_uint8_signed_negative_mask(crypto_uint8_z);
}

__attribute__((unused))
static crypto_uint8 crypto_uint8_min(crypto_uint8 crypto_uint8_x,crypto_uint8 crypto_uint8_y)
{
  crypto_uint8 crypto_uint8_xy = crypto_uint8_y ^ crypto_uint8_x;
  crypto_uint8 crypto_uint8_z = crypto_uint8_y - crypto_uint8_x;
  crypto_uint8_z ^= crypto_uint8_xy & (crypto_uint8_z ^ crypto_uint8_y ^ (((crypto_uint8) 1) << (8-1)));
  crypto_uint8_z = crypto_uint8_signed_negative_mask(crypto_uint8_z);
  crypto_uint8_z &= crypto_uint8_xy;
  return crypto_uint8_x ^ crypto_uint8_z;
}

__attribute__((unused))
static crypto_uint8 crypto_uint8_max(crypto_uint8 crypto_uint8_x,crypto_uint8 crypto_uint8_y)
{
  crypto_uint8 crypto_uint8_xy = crypto_uint8_y ^ crypto_uint8_x;
  crypto_uint8 crypto_uint8_z = crypto_uint8_y - crypto_uint8_x;
  crypto_uint8_z ^= crypto_uint8_xy & (crypto_uint8_z ^ crypto_uint8_y ^ (((crypto_uint8) 1) << (8-1)));
  crypto_uint8_z = crypto_uint8_signed_negative_mask(crypto_uint8_z);
  crypto_uint8_z &= crypto_uint8_xy;
  return crypto_uint8_y ^ crypto_uint8_z;
}

__attribute__((unused))
static void crypto_uint8_minmax(crypto_uint8 *crypto_uint8_a,crypto_uint8 *crypto_uint8_b)
{
  crypto_uint8 crypto_uint8_x = *crypto_uint8_a;
  crypto_uint8 crypto_uint8_y = *crypto_uint8_b;
  crypto_uint8 crypto_uint8_xy = crypto_uint8_y ^ crypto_uint8_x;
  crypto_uint8 crypto_uint8_z = crypto_uint8_y - crypto_uint8_x;
  crypto_uint8_z ^= crypto_uint8_xy & (crypto_uint8_z ^ crypto_uint8_y ^ (((crypto_uint8) 1) << (8-1)));
  crypto_uint8_z = crypto_uint8_signed_negative_mask(crypto_uint8_z);
  crypto_uint8_z &= crypto_uint8_xy;
  *crypto_uint8_a = crypto_uint8_x ^ crypto_uint8_z;
  *crypto_uint8_b = crypto_uint8_y ^ crypto_uint8_z;
}

#endif
