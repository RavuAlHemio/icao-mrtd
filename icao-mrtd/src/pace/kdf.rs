//! Key Derivation Functions for PACE.


use digest::Digest;
use sha1::Sha1;
use sha2::Sha256;


/// A key derivation function.
pub trait Kdf<K> {
    /// The key derivation function itself.
    fn derive_key(key_seed: &[u8], counter: u32) -> K;

    /// The key derivation function for encryption purposes.
    fn derive_encryption_key(key_seed: &[u8]) -> K {
        Self::derive_key(key_seed, 1)
    }

    /// The key derivation function for message authentication purposes.
    fn derive_mac_key(key_seed: &[u8]) -> K {
        Self::derive_key(key_seed, 2)
    }

    /// The password-to-key derivation function.
    fn derive_key_from_password(password: &[u8]) -> K {
        Self::derive_key(password, 3)
    }
}

/// Key derivation function for 3DES.
///
/// PACE uses 3DES in EDE two-key mode, i.e. `K3 = K1`.
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha1(key || counter)[0..16]
/// ```
/// whereupon
/// ```plain
/// K1 = keydata[0..8]
/// K2 = keydata[8..16]
/// ```
pub struct Kdf3Des;
impl Kdf<[u8; 16]> for Kdf3Des {
    fn derive_key(key_seed: &[u8], counter: u32) -> [u8; 16] {
        let mut hasher = Sha1::new();
        hasher.update(key_seed);
        hasher.update(&counter.to_be_bytes());
        let result = hasher.finalize();
    
        let mut keydata = [0u8; 16];
        keydata.copy_from_slice(&result[0..16]);
        keydata
    }
}


/// Key derivation function for AES-128.
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha1(key || counter)[0..16]
/// ```
pub struct KdfAes128;
impl Kdf<[u8; 16]> for KdfAes128 {
    fn derive_key(key_seed: &[u8], counter: u32) -> [u8; 16] {
        let mut hasher = Sha1::new();
        hasher.update(key_seed);
        hasher.update(&counter.to_be_bytes());
        let result = hasher.finalize();

        let mut keydata = [0u8; 16];
        keydata.copy_from_slice(&result[0..16]);
        keydata
    }
}


/// Key derivation function for AES-192.
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)[0..24]
/// ```
pub struct KdfAes192;
impl Kdf<[u8; 24]> for KdfAes192 {
    fn derive_key(key_seed: &[u8], counter: u32) -> [u8; 24] {
        let mut hasher = Sha256::new();
        hasher.update(key_seed);
        hasher.update(&counter.to_be_bytes());
        let result = hasher.finalize();

        let mut keydata = [0u8; 24];
        keydata.copy_from_slice(&result[0..24]);
        keydata
    }
}


/// Key derivation function for AES-256.
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)
/// ```
pub struct KdfAes256;
impl Kdf<[u8; 32]> for KdfAes256 {
    fn derive_key(key_seed: &[u8], counter: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(key_seed);
        hasher.update(&counter.to_be_bytes());
        let result = hasher.finalize();

        let mut keydata = [0u8; 32];
        keydata.copy_from_slice(&result[0..32]);
        keydata
    }
}
