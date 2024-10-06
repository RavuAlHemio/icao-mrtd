//! Cryptographic functionality for PACE.


pub(crate) mod dh;
pub(crate) mod elliptic;


use crypto_bigint::BoxedUint;


pub(crate) fn boxed_uint_from_be_slice(slice: &[u8]) -> BoxedUint {
    let bits: u32 = (8 * slice.len()).try_into().unwrap();
    BoxedUint::from_be_slice(slice, bits).unwrap()
}
