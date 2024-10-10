//! Cipher and MAC (message authentication code) combinations.


use aes::{Aes128, Aes192, Aes256};
use block_padding::NoPadding;
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use cmac::Cmac;
use crypto_bigint::{BoxedUint, NonZero};
use des::{Des, TdesEde2};
use digest::{Digest, DynDigest, KeyInit, Mac};
use hex_literal::hex;
use retail_mac::RetailMac;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::iso7816::card::SmartCard;
use crate::secure_messaging::{Sm3Des, SmAes128, SmAes192, SmAes256};


/// A combination of cipher, MAC and KDF (key derivation function) usable during authentication and
/// Secure Messaging.
pub trait CipherAndMac {
    /// Size of the cipher key in bytes.
    fn cipher_key_size(&self) -> usize;

    /// Block size of the cipher in bytes.
    fn cipher_block_size(&self) -> usize;

    /// Block size of the MAC in bytes.
    ///
    /// Note that this is only used when establishing Secure Messaging. Once it is established,
    /// decisions about padding are made depending on [`CipherAndMac::cipher_block_size`] instead.
    fn mac_block_size(&self) -> usize;

    /// The key derivation function.
    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>>;

    /// The key derivation function for encryption purposes.
    fn derive_encryption_key(&self, key_seed: &[u8]) -> Zeroizing<Vec<u8>> {
        self.derive_key(key_seed, 1)
    }

    /// The key derivation function for message authentication purposes.
    fn derive_mac_key(&self, key_seed: &[u8]) -> Zeroizing<Vec<u8>> {
        self.derive_key(key_seed, 2)
    }

    /// The password-to-key derivation function.
    fn derive_key_from_password(&self, password: &[u8]) -> Zeroizing<Vec<u8>> {
        self.derive_key(password, 3)
    }

    /// Decrypts data in-place using the given key and CBC IV.
    ///
    /// Does not strip padding.
    fn decrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]);

    /// Encrypts pre-padded data in-place using the given key and CBC IV.
    fn encrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]);

    /// Generates a MAC (message authentication code) for the given pre-padded data and key.
    fn mac_padded_data(&self, data: &[u8], key: &[u8]) -> Zeroizing<Vec<u8>>;

    /// Verifies whether the given data fits the given MAC (message authentication code).
    fn verify_mac_padded_data(&self, data: &[u8], key: &[u8], expected_mac: &[u8]) -> bool {
        let computed_mac = self.mac_padded_data(data, key);
        computed_mac.ct_eq(expected_mac).into()
    }

    /// Creates an object that manages secure messaging with this cipher and MAC over the given card
    /// with the given keys.
    fn create_secure_messaging(
        &self,
        card: Box<dyn SmartCard>,
        k_session_enc: &[u8],
        k_session_mac: &[u8],
        send_sequence_counter: &[u8],
    ) -> Box<dyn SmartCard>;

    /// The pseudorandom function used for Integrated Mapping.
    fn integrated_mapping_pseudorandom_function(&self, chip_nonce: &[u8], terminal_nonce: &[u8], prime_order: &BoxedUint) -> Zeroizing<BoxedUint> {
        const C0_128: [u8; 16] = hex!("a668892a7c41e3ca739f40b057d85904");
        const C1_128: [u8; 16] = hex!("a4e136ac725f738b01c1f60217c188ad");
        const C0_256: [u8; 32] = hex!("d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676");
        const C1_256: [u8; 32] = hex!("54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517");

        // first time around, chip_nonce (s) is used as the data and terminal_nonce (t) as the key
        assert_eq!(terminal_nonce.len(), self.cipher_key_size());
        assert!(chip_nonce.len() % self.cipher_block_size() == 0);

        // pick out what we feed as data to the next rounds
        let (c0, c1) = match self.cipher_key_size() {
            16 => (&C0_128[..], &C1_128[..]), // 128 bits (3DES, AES-128)
            24|32 => (&C0_256[..], &C1_256[..]), // 192 (AES-192) or 256 bits (AES-256)
            _ => panic!("unexpected cipher key size"),
        };

        let zero_iv = vec![0; self.cipher_block_size()];

        // construct initial key by encrypting chip_nonce using terminal_nonce
        let mut key = Zeroizing::new(chip_nonce.to_vec());
        self.encrypt_padded_data(key.as_mut_slice(), terminal_nonce, &zero_iv);

        let mut output_buf = Zeroizing::new(Vec::new());
        let mut n = 0;
        let chip_nonce_bits = 8 * chip_nonce.len();
        while n * chip_nonce_bits < usize::try_from(prime_order.bits()).unwrap() + 64 {
            let round_key = Zeroizing::new(key[0..self.cipher_key_size()].to_vec());

            // top row (key for the next round)
            key.resize(c0.len(), 0);
            key.copy_from_slice(c0);
            self.encrypt_padded_data(&mut key, &round_key, &zero_iv);

            // bottom row (data for the output)
            let mut data = Zeroizing::new(c1.to_vec());
            self.encrypt_padded_data(&mut data, &round_key, &zero_iv);
            output_buf.extend(data.as_slice());

            n += 1;
        }

        let output_width = u32::try_from(output_buf.len() * 8).unwrap();
        let ret_width = output_width.max(prime_order.bits());
        let output_num = BoxedUint::from_be_slice(
            &output_buf,
            ret_width,
        ).expect("failed to assemble result");
        let ret_num = output_num.rem(&NonZero::new(prime_order.widen(ret_width)).unwrap());
        Zeroizing::new(ret_num)
    }
}


/// 3DES-based cipher and MAC.
///
/// 3DES is used in EDE two-key mode:
/// ```plain
/// encrypt((K1, K2), D) = encrypt(K1, decrypt(K2, encrypt(K1, D)))
/// ```
/// The block mode of operation is Cipher Block Chaining (CBC).
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
///
/// The MAC is Retail MAC (ISO/IEC 9797-1 algorithm 3) with DES, zero IV and padding method 2 (bit 1
/// and then as many zero bits as necessary).
pub struct Cam3Des;
impl CipherAndMac for Cam3Des {
    fn cipher_key_size(&self) -> usize { 16 }
    fn cipher_block_size(&self) -> usize { 8 }
    fn mac_block_size(&self) -> usize { 8 }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        let mut hasher = Sha1::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        Zeroizing::new(result[0..self.cipher_key_size()].to_vec())
    }

    fn decrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Decryptor<TdesEde2> = cbc::Decryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Encryptor<TdesEde2> = cbc::Encryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.encrypt_padded::<NoPadding>(data, data.len()).unwrap();
    }

    fn mac_padded_data(&self, data: &[u8], key: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut retail_mac = RetailMac::<Des>::new_from_slice(key).unwrap();
        DynDigest::update(&mut retail_mac, data);
        let mut mac = vec![0u8; 8];
        retail_mac.finalize_into(&mut mac).unwrap();
        Zeroizing::new(mac)
    }

    fn verify_mac_padded_data(&self, data: &[u8], key: &[u8], expected_mac: &[u8]) -> bool {
        let mut retail_mac = RetailMac::<Des>::new_from_slice(key).unwrap();
        DynDigest::update(&mut retail_mac, data);
        retail_mac.verify_slice(expected_mac).is_ok()
    }

    fn create_secure_messaging(
        &self,
        card: Box<dyn SmartCard>,
        k_session_enc: &[u8],
        k_session_mac: &[u8],
        send_sequence_counter: &[u8],
    ) -> Box<dyn SmartCard> {
        Box::new(Sm3Des::new(
            card,
            k_session_enc.try_into().unwrap(),
            k_session_mac.try_into().unwrap(),
            send_sequence_counter.try_into().unwrap(),
        ))
    }
}


/// AES-128-based cipher and MAC.
///
/// The block mode of operation is Cipher Block Chaining (CBC).
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha1(key || counter)[0..16]
/// ```
///
/// The MAC is CMAC with AES-128 truncated to the initial 8 bytes.
pub struct CamAes128;
impl CipherAndMac for CamAes128 {
    fn cipher_key_size(&self) -> usize { 16 }
    fn cipher_block_size(&self) -> usize { 16 }
    fn mac_block_size(&self) -> usize { 1 }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        let mut hasher = Sha1::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        Zeroizing::new(result[0..self.cipher_key_size()].to_vec())
    }

    fn decrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Decryptor<Aes128> = cbc::Decryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Encryptor<Aes128> = cbc::Encryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.encrypt_padded::<NoPadding>(data, data.len()).unwrap();
    }

    fn mac_padded_data(&self, data: &[u8], key: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut mac = Cmac::<Aes128>::new_from_slice(key).unwrap();
        DynDigest::update(&mut mac, data);
        let mut final_mac = vec![0u8; 16];
        mac.finalize_into(final_mac.as_mut_slice()).unwrap();
        final_mac[8..].fill(0);
        final_mac.truncate(8);
        Zeroizing::new(final_mac)
    }

    fn create_secure_messaging(
        &self,
        card: Box<dyn SmartCard>,
        k_session_enc: &[u8],
        k_session_mac: &[u8],
        send_sequence_counter: &[u8],
    ) -> Box<dyn SmartCard> {
        Box::new(SmAes128::new(
            card,
            k_session_enc.try_into().unwrap(),
            k_session_mac.try_into().unwrap(),
            send_sequence_counter.try_into().unwrap(),
        ))
    }
}


/// AES-192-based cipher and MAC.
///
/// The block mode of operation is Cipher Block Chaining (CBC).
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)[0..24]
/// ```
///
/// The MAC is CMAC with AES-192 truncated to the initial 8 bytes.
pub struct CamAes192;
impl CipherAndMac for CamAes192 {
    fn cipher_key_size(&self) -> usize { 24 }
    fn cipher_block_size(&self) -> usize { 16 }
    fn mac_block_size(&self) -> usize { 1 }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        let mut hasher = Sha256::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        Zeroizing::new(result[0..self.cipher_key_size()].to_vec())
    }

    fn decrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Decryptor<Aes192> = cbc::Decryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Encryptor<Aes192> = cbc::Encryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.encrypt_padded::<NoPadding>(data, data.len()).unwrap();
    }

    fn mac_padded_data(&self, data: &[u8], key: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut mac = Cmac::<Aes192>::new_from_slice(key).unwrap();
        DynDigest::update(&mut mac, data);
        let mut final_mac = vec![0u8; 16];
        mac.finalize_into(final_mac.as_mut_slice()).unwrap();
        final_mac[8..].fill(0);
        final_mac.truncate(8);
        Zeroizing::new(final_mac)
    }

    fn create_secure_messaging(
        &self,
        card: Box<dyn SmartCard>,
        k_session_enc: &[u8],
        k_session_mac: &[u8],
        send_sequence_counter: &[u8],
    ) -> Box<dyn SmartCard> {
        Box::new(SmAes192::new(
            card,
            k_session_enc.try_into().unwrap(),
            k_session_mac.try_into().unwrap(),
            send_sequence_counter.try_into().unwrap(),
        ))
    }
}


/// AES-256-based cipher and MAC.
///
/// The block mode of operation is Cipher Block Chaining (CBC).
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)
/// ```
///
/// The MAC is CMAC with AES-256 truncated to the initial 8 bytes.
pub struct CamAes256;
impl CipherAndMac for CamAes256 {
    fn cipher_key_size(&self) -> usize { 32 }
    fn cipher_block_size(&self) -> usize { 8 }
    fn mac_block_size(&self) -> usize { 1 }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        let mut hasher = Sha256::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        Zeroizing::new(result[0..self.cipher_key_size()].to_vec())
    }

    fn decrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Decryptor<Aes256> = cbc::Decryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        let decryptor: cbc::Encryptor<Aes256> = cbc::Encryptor::new(key.try_into().unwrap(), iv.try_into().unwrap());
        decryptor.encrypt_padded::<NoPadding>(data, data.len()).unwrap();
    }

    fn mac_padded_data(&self, data: &[u8], key: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut mac = Cmac::<Aes256>::new_from_slice(key).unwrap();
        DynDigest::update(&mut mac, data);
        let mut final_mac = vec![0u8; 16];
        mac.finalize_into(final_mac.as_mut_slice()).unwrap();
        final_mac[8..].fill(0);
        final_mac.truncate(8);
        Zeroizing::new(final_mac)
    }

    fn create_secure_messaging(
        &self,
        card: Box<dyn SmartCard>,
        k_session_enc: &[u8],
        k_session_mac: &[u8],
        send_sequence_counter: &[u8],
    ) -> Box<dyn SmartCard> {
        Box::new(SmAes256::new(
            card,
            k_session_enc.try_into().unwrap(),
            k_session_mac.try_into().unwrap(),
            send_sequence_counter.try_into().unwrap(),
        ))
    }
}


#[cfg(test)]
mod tests {
    use super::{CipherAndMac, CamAes128};
    use hex_literal::hex;
    use crate::crypt::boxed_uint_from_be_slice;
    use crate::crypt::elliptic::curves::get_brainpool_p256r1;

    #[test]
    fn test_integrated_mapping_pseudorandom_function_p11_apph1() {
        let chip_nonce = hex!("
            2923BE84 E16CD6AE 529049F1 F1BBE9EB
        ");
        let terminal_nonce = hex!("
            5DD4CBFC 96F5453B 130D890A 1CDBAE32
        ");
        let prime_order = get_brainpool_p256r1().prime().clone();

        let result = CamAes128.integrated_mapping_pseudorandom_function(&chip_nonce, &terminal_nonce, &prime_order);
        let expected_result = boxed_uint_from_be_slice(&hex!("
            A2F8FF2D F50E52C6 599F386A DCB595D2
            29F6A167 ADE2BE5F 2C3296AD D5B7430E
        "));
        assert_eq!(&*result, &expected_result);
    }
}
