#ifndef crypto_uint32_h
#define crypto_uint32_h

#include <inttypes.h>
#define crypto_uint32 uint32_t
#define crypto_uint32_signed int32_t

__attribute__((unused))
static crypto_uint32_signed crypto_uint32_signed_negative_mask(crypto_uint32_signed crypto_uint32_signed_x)
{
  return crypto_uint32_signed_x >> (32-1);
}

__attribute__((unused))
static crypto_uint32 crypto_uint32_nonzero_mask(crypto_uint32 crypto_uint32_x)
{
  return crypto_uint32_signed_negative_mask(crypto_uint32_x) | crypto_uint32_signed_negative_mask(-crypto_uint32_x);
}

__attribute__((unused))
static crypto_uint32 crypto_uint32_zero_mask(crypto_uint32 crypto_uint32_x)
{
  return ~crypto_uint32_nonzero_mask(crypto_uint32_x);
}

__attribute__((unused))
static crypto_uint32 crypto_uint32_unequal_mask(crypto_uint32 crypto_uint32_x,crypto_uint32 crypto_uint32_y)
{
  crypto_uint32 crypto_uint32_xy = crypto_uint32_x ^ crypto_uint32_y;
  return crypto_uint32_nonzero_mask(crypto_uint32_xy);
}

__attribute__((unused))
static crypto_uint32 crypto_uint32_equal_mask(crypto_uint32 crypto_uint32_x,crypto_uint32 crypto_uint32_y)
{
  return ~crypto_uint32_unequal_mask(crypto_uint32_x,crypto_uint32_y);
}

__attribute__((unused))
static crypto_uint32 crypto_uint32_smaller_mask(crypto_uint32 crypto_uint32_x,crypto_uint32 crypto_uint32_y)
{
  crypto_uint32 crypto_uint32_xy = crypto_uint32_x ^ crypto_uint32_y;
  crypto_uint32 crypto_uint32_z = crypto_uint32_x - crypto_uint32_y;
  crypto_uint32_z ^= crypto_uint32_xy & (crypto_uint32_z ^ crypto_uint32_x ^ (((crypto_uint32) 1) << (32-1)));
  return crypto_uint32_signed_negative_mask(crypto_uint32_z);
}

__attribute__((unused))
static crypto_uint32 crypto_uint32_min(crypto_uint32 crypto_uint32_x,crypto_uint32 crypto_uint32_y)
{
  crypto_uint32 crypto_uint32_xy = crypto_uint32_y ^ crypto_uint32_x;
  crypto_uint32 crypto_uint32_z = crypto_uint32_y - crypto_uint32_x;
  crypto_uint32_z ^= crypto_uint32_xy & (crypto_uint32_z ^ crypto_uint32_y ^ (((crypto_uint32) 1) << (32-1)));
  crypto_uint32_z = crypto_uint32_signed_negative_mask(crypto_uint32_z);
  crypto_uint32_z &= crypto_uint32_xy;
  return crypto_uint32_x ^ crypto_uint32_z;
}

__attribute__((unused))
static crypto_uint32 crypto_uint32_max(crypto_uint32 crypto_uint32_x,crypto_uint32 crypto_uint32_y)
{
  crypto_uint32 crypto_uint32_xy = crypto_uint32_y ^ crypto_uint32_x;
  crypto_uint32 crypto_uint32_z = crypto_uint32_y - crypto_uint32_x;
  crypto_uint32_z ^= crypto_uint32_xy & (crypto_uint32_z ^ crypto_uint32_y ^ (((crypto_uint32) 1) << (32-1)));
  crypto_uint32_z = crypto_uint32_signed_negative_mask(crypto_uint32_z);
  crypto_uint32_z &= crypto_uint32_xy;
  return crypto_uint32_y ^ crypto_uint32_z;
}

__attribute__((unused))
static void crypto_uint32_minmax(crypto_uint32 *crypto_uint32_a,crypto_uint32 *crypto_uint32_b)
{
  crypto_uint32 crypto_uint32_x = *crypto_uint32_a;
  crypto_uint32 crypto_uint32_y = *crypto_uint32_b;
  crypto_uint32 crypto_uint32_xy = crypto_uint32_y ^ crypto_uint32_x;
  crypto_uint32 crypto_uint32_z = crypto_uint32_y - crypto_uint32_x;
  crypto_uint32_z ^= crypto_uint32_xy & (crypto_uint32_z ^ crypto_uint32_y ^ (((crypto_uint32) 1) << (32-1)));
  crypto_uint32_z = crypto_uint32_signed_negative_mask(crypto_uint32_z);
  crypto_uint32_z &= crypto_uint32_xy;
  *crypto_uint32_a = crypto_uint32_x ^ crypto_uint32_z;
  *crypto_uint32_b = crypto_uint32_y ^ crypto_uint32_z;
}

#endif
