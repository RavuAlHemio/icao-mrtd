//! Cryptographic functionality.


pub mod dh;
pub mod elliptic;


use crypto_bigint::BoxedUint;
use elliptic::AffinePoint;
use zeroize::Zeroizing;
use zeroize_derive::ZeroizeOnDrop;

use crate::crypt::dh::DiffieHellmanParams;
use crate::crypt::elliptic::PrimeWeierstrassCurve;


/// A key exchange method.
///
/// Private keys are assumed to always be unsigned integers; if serialized, they appear in
/// big-endian byte order, generally in the shortest encoding available.
///
/// The representation of public and secret keys differs according to the key exchange method.
///
/// For classic Diffie-Hellman, public and secret keys are represented as unsigned integers in
/// big-endian byte order, generally in the shortest encoding available.
///
/// For elliptic-curve Diffie-Hellman, public and secret keys are represented as affine coordinates
/// of a point on the curve. They are serialized in the following sequence:
/// 1. the byte `0x04` to signify uncompressed coordinates
/// 2. the x coordinate as an unsigned integer in big-endian byte order
/// 3. the y coordinate as an unsigned integer in big-endian byte order
/// Both coordinates are encoded in the same number of bytes as the expected length of a private key
/// on the curve; the coordinates can be extracted by stripping the leading `0x04` byte and
/// splitting the resulting byte string in the middle.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub enum KeyExchange {
    DiffieHellman(DiffieHellmanParams),
    PrimeWeierstrassEllipticDiffieHellman(PrimeWeierstrassCurve),
}
impl KeyExchange {
    /// Returns the recommended number of bytes for a private key using this key exchange method.
    pub fn private_key_len_bytes(&self) -> usize {
        match self {
            Self::DiffieHellman(dhp) => dhp.subgroup_size_bytes(),
            Self::PrimeWeierstrassEllipticDiffieHellman(curve) => curve.private_key_len_bytes(),
        }
    }

    /// Calculates a public key for the given private key, returning it serialized to bytes.
    ///
    /// For classic Diffie-Hellman, the public key is serialized as an unsigned integer in
    /// big-endian byte order, generally in the shortest encoding available.
    ///
    /// For elliptic-curve Diffie-Hellman, the public key is represented as affine coordinates of a
    /// point on the curve. It is serialized in the following sequence:
    /// 1. the byte `0x04` to signify uncompressed coordinates
    /// 2. the x coordinate as an unsigned integer in big-endian byte order
    /// 3. the y coordinate as an unsigned integer in big-endian byte order
    /// Both coordinates are encoded in the same number of bytes as the expected length of a private
    /// key on the curve; the coordinates can be extracted by stripping the leading `0x04` byte and
    /// splitting the resulting byte string in the middle.
    pub fn calculate_public_key(&self, private_key: &BoxedUint) -> Zeroizing<Vec<u8>> {
        match self {
            Self::DiffieHellman(dhp) => {
                let public_key_int = dhp.calculate_public_key(private_key);
                Zeroizing::new(public_key_int.to_be_bytes().into_vec())
            },
            Self::PrimeWeierstrassEllipticDiffieHellman(curve) => {
                let public_key_point = curve.calculate_public_key(private_key);
                public_key_point.to_be_bytes(curve.private_key_len_bytes())
            },
        }
    }

    /// Performs the key exchange using the given private key and the other party's public key,
    /// generating a shared secret.
    ///
    /// For classic Diffie-Hellman, the shared secret is serialized as an unsigned integer in
    /// big-endian byte order, generally in the shortest encoding available.
    ///
    /// For elliptic-curve Diffie-Hellman, the shared secret is represented as affine coordinates of a
    /// point on the curve. Only the x coordinate is serialized as an unsigned integer in big-endian
    /// byte order, generally in the shortest encoding available.
    pub fn exchange_keys(&self, private_key: &BoxedUint, other_public_key: &[u8]) -> Zeroizing<Vec<u8>> {
        match self {
            Self::DiffieHellman(dhp) => {
                let other_public_key_int = Zeroizing::new(boxed_uint_from_be_slice(other_public_key));
                let shared_secret = dhp.diffie_hellman(private_key, &other_public_key_int);
                Zeroizing::new(shared_secret.to_be_bytes().into_vec())
            },
            Self::PrimeWeierstrassEllipticDiffieHellman(curve) => {
                let other_public_key_point = AffinePoint::try_from_be_bytes(other_public_key).unwrap();
                let shared_secret_point = curve.diffie_hellman(private_key, &other_public_key_point).unwrap();
                Zeroizing::new(shared_secret_point.x().to_be_bytes().into_vec())
            },
        }
    }

    /// Derives a new key exchange method using generic mapping.
    ///
    /// The generic mapping process keeps the same parameters but derives a new generator using a
    /// given nonce and a shared secret derived from the given private key and the other party's
    /// public key using the current key exchange method.
    ///
    /// Since the derivation requires both coordinates of the secret key with elliptic-curve
    /// Diffie-Hellman, the key exchange step is integrated into this function, as
    /// [`Self::exchange_keys`] only returns the x coordinate.
    pub fn derive_generic_mapping(&self, nonce: &BoxedUint, private_key: &BoxedUint, other_public_key: &[u8]) -> Self {
        match self {
            Self::DiffieHellman(dhp) => {
                let other_public_key_int = Zeroizing::new(boxed_uint_from_be_slice(other_public_key));
                let shared_secret = dhp.diffie_hellman(private_key, &other_public_key_int);
                Self::DiffieHellman(dhp.derive_generic_mapping(nonce, &*shared_secret))
            },
            Self::PrimeWeierstrassEllipticDiffieHellman(curve) => {
                let other_public_key_point = AffinePoint::try_from_be_bytes(other_public_key).unwrap();
                let shared_secret_point = curve.diffie_hellman(private_key, &other_public_key_point).unwrap();
                Self::PrimeWeierstrassEllipticDiffieHellman(curve.derive_generic_mapping_session_curve(nonce, &shared_secret_point))
            },
        }
    }

    /// The ASN.1 tag representing this type of public key.
    pub fn public_key_tag(&self) -> u8 {
        match self {
            Self::DiffieHellman(_) => 0x84, // Diffie-Hellman public key
            Self::PrimeWeierstrassEllipticDiffieHellman(_) => 0x86, // elliptic curve point
        }
    }
}


pub fn boxed_uint_from_be_slice(slice: &[u8]) -> BoxedUint {
    let bits: u32 = (8 * slice.len()).try_into().unwrap();
    BoxedUint::from_be_slice(slice, bits).unwrap()
}
