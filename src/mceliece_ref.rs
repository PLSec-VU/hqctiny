//! Classic McEliece reference code, kept for the comparison microbenchmarks.

#[cfg(mceliece_vec)]
pub mod vec_ffi {
    macro_rules! vec_externs {
        ($($keypair:ident $enc:ident $dec:ident)*) => {
            unsafe extern "C" {
                $(
                    pub fn $keypair(pk: *mut u8, sk: *mut u8);
                    pub fn $enc(ct: *mut u8, key: *mut u8, pk: *const u8) -> i32;
                    pub fn $dec(key: *mut u8, ct: *const u8, sk: *const u8) -> i32;
                )*
            }
        };
    }

    vec_externs! {
        mce348864vec_operation_keypair mce348864vec_operation_enc mce348864vec_operation_dec
        mce460896vec_operation_keypair mce460896vec_operation_enc mce460896vec_operation_dec
        mce6688128vec_operation_keypair mce6688128vec_operation_enc mce6688128vec_operation_dec
    }
}
