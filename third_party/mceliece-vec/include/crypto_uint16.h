#ifndef crypto_uint16_h
#define crypto_uint16_h

#include <inttypes.h>
#define crypto_uint16 uint16_t
#define crypto_uint16_signed int16_t

__attribute__((unused))
static crypto_uint16_signed crypto_uint16_signed_negative_mask(crypto_uint16_signed crypto_uint16_signed_x)
{
  return crypto_uint16_signed_x >> (16-1);
}

__attribute__((unused))
static crypto_uint16 crypto_uint16_nonzero_mask(crypto_uint16 crypto_uint16_x)
{
  return crypto_uint16_signed_negative_mask(crypto_uint16_x) | crypto_uint16_signed_negative_mask(-crypto_uint16_x);
}

__attribute__((unused))
static crypto_uint16 crypto_uint16_zero_mask(crypto_uint16 crypto_uint16_x)
{
  return ~crypto_uint16_nonzero_mask(crypto_uint16_x);
}

__attribute__((unused))
static crypto_uint16 crypto_uint16_unequal_mask(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_x ^ crypto_uint16_y;
  return crypto_uint16_nonzero_mask(crypto_uint16_xy);
}

__attribute__((unused))
static crypto_uint16 crypto_uint16_equal_mask(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  return ~crypto_uint16_unequal_mask(crypto_uint16_x,crypto_uint16_y);
}

__attribute__((unused))
static crypto_uint16 crypto_uint16_smaller_mask(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_x ^ crypto_uint16_y;
  crypto_uint16 crypto_uint16_z = crypto_uint16_x - crypto_uint16_y;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_x ^ (((crypto_uint16) 1) << (16-1)));
  return crypto_uint16_signed_negative_mask(crypto_uint16_z);
}

__attribute__((unused))
static crypto_uint16 crypto_uint16_min(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_y ^ crypto_uint16_x;
  crypto_uint16 crypto_uint16_z = crypto_uint16_y - crypto_uint16_x;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_y ^ (((crypto_uint16) 1) << (16-1)));
  crypto_uint16_z = crypto_uint16_signed_negative_mask(crypto_uint16_z);
  crypto_uint16_z &= crypto_uint16_xy;
  return crypto_uint16_x ^ crypto_uint16_z;
}

__attribute__((unused))
static crypto_uint16 crypto_uint16_max(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_y ^ crypto_uint16_x;
  crypto_uint16 crypto_uint16_z = crypto_uint16_y - crypto_uint16_x;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_y ^ (((crypto_uint16) 1) << (16-1)));
  crypto_uint16_z = crypto_uint16_signed_negative_mask(crypto_uint16_z);
  crypto_uint16_z &= crypto_uint16_xy;
  return crypto_uint16_y ^ crypto_uint16_z;
}

__attribute__((unused))
static void crypto_uint16_minmax(crypto_uint16 *crypto_uint16_a,crypto_uint16 *crypto_uint16_b)
{
  crypto_uint16 crypto_uint16_x = *crypto_uint16_a;
  crypto_uint16 crypto_uint16_y = *crypto_uint16_b;
  crypto_uint16 crypto_uint16_xy = crypto_uint16_y ^ crypto_uint16_x;
  crypto_uint16 crypto_uint16_z = crypto_uint16_y - crypto_uint16_x;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_y ^ (((crypto_uint16) 1) << (16-1)));
  crypto_uint16_z = crypto_uint16_signed_negative_mask(crypto_uint16_z);
  crypto_uint16_z &= crypto_uint16_xy;
  *crypto_uint16_a = crypto_uint16_x ^ crypto_uint16_z;
  *crypto_uint16_b = crypto_uint16_y ^ crypto_uint16_z;
}

#endif
