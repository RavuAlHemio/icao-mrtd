//! Secure Messaging for PACE.


use std::fmt;

use aes::{Aes128, Aes192, Aes256};
use block_padding::NoPadding;
use cipher::{BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use cmac::{Cmac, KeyInit, Mac};
use des::{Des, TdesEde2};
use digest::{Digest, DynDigest};
use retail_mac::RetailMac;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
use zeroize_derive::ZeroizeOnDrop;

use crate::iso7816::apdu::{Apdu, Data, Response, ResponseTrailer};
use crate::iso7816::card::{CommunicationError, SmartCard};


type RetailMacDes = RetailMac<Des>;


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    GetChallenge,
    ExternalAuthenticate,
}
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GetChallenge => write!(f, "GET CHALLENGE"),
            Self::ExternalAuthenticate => write!(f, "EXTERNAL AUTHENTICATE"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MismatchedValue {
    RndIc,
    RndIfd,
}


#[derive(Debug)]
pub enum Error {
    OperationFailed { operation: Operation, response: Response },
    LengthMismatch {
        operation: Operation,
        obtained: Vec<u8>,
        expected_length: usize,
    },
    ResponseMac,
    ValueMismatch { value: MismatchedValue },
    ResponseTlvFormat,
    MissingResponseMac,
    MissingResponseData,
    MissingResponseStatus,
    StatusLength { obtained: Vec<u8> },
    UnknownPadding { padding_mode: u8 },
    InvalidPadding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::OperationFailed { operation, response }
                => write!(f, "{} failed with response code 0x{:04X}", operation, response.trailer.to_word()),
            Self::LengthMismatch { operation, obtained, expected_length }
                => write!(f, "{} response has length {}, expected {}", operation, obtained.len(), expected_length),
            Self::ResponseMac
                => write!(f, "response MAC incorrect"),
            Self::ValueMismatch { value }
                => write!(f, "{:?} mismatched", value),
            Self::ResponseTlvFormat
                => write!(f, "response has an invalid TLV format"),
            Self::MissingResponseMac
                => write!(f, "response does not contain a MAC"),
            Self::MissingResponseData
                => write!(f, "response does not contain data"),
            Self::MissingResponseStatus
                => write!(f, "response does not contain status"),
            Self::StatusLength { obtained }
                => write!(f, "status has unexpected length {}", obtained.len()),
            Self::UnknownPadding { padding_mode }
                => write!(f, "response payload has unknown padding mode {}", padding_mode),
            Self::InvalidPadding
                => write!(f, "response payload has invalid padding"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OperationFailed { .. } => None,
            Self::LengthMismatch { .. } => None,
            Self::ResponseMac => None,
            Self::ValueMismatch { .. } => None,
            Self::ResponseTlvFormat => None,
            Self::MissingResponseMac => None,
            Self::MissingResponseData => None,
            Self::MissingResponseStatus => None,
            Self::StatusLength { .. } => None,
            Self::UnknownPadding { .. } => None,
            Self::InvalidPadding => None,
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BorrowedTlv<'d> {
    pub tag_and_length: &'d [u8],
    pub data: &'d [u8],
}


/// Operations for Secure Messaging cryptography operations.
pub trait SecureMessagingOperations {
    /// Size of the cipher key in bytes.
    fn cipher_key_size(&self) -> usize;

    /// Block size of the cipher in bytes.
    fn cipher_block_size(&self) -> usize;

    /// Block size of the MAC in bytes.
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
}


/// Cryptographic operations for secure messaging using 3DES.
///
/// 3DES is used in EDE two-key mode, i.e. `K3 = K1`. The block mode of operation is Cipher Block
/// Chaining (CBC).
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
pub struct Smo3Des;
impl SecureMessagingOperations for Smo3Des {
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
        let mut retail_mac = RetailMacDes::new_from_slice(key).unwrap();
        DynDigest::update(&mut retail_mac, data);
        let mut mac = vec![0u8; 8];
        retail_mac.finalize_into(&mut mac).unwrap();
        Zeroizing::new(mac)
    }

    fn verify_mac_padded_data(&self, data: &[u8], key: &[u8], expected_mac: &[u8]) -> bool {
        let mut retail_mac = RetailMacDes::new_from_slice(key).unwrap();
        DynDigest::update(&mut retail_mac, data);
        retail_mac.verify_slice(expected_mac).is_ok()
    }
}


/// Cryptographic operations for secure messaging using AES-128.
///
/// The block mode of operation is Cipher Block Chaining (CBC).
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha1(key || counter)[0..16]
/// ```
///
/// The MAC is CMAC with AES-128 truncated to the initial 8 bytes.
pub struct SmoAes128;
impl SecureMessagingOperations for SmoAes128 {
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
}


/// Cryptographic operations for secure messaging using AES-192.
///
/// The block mode of operation is Cipher Block Chaining (CBC).
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)[0..24]
/// ```
///
/// The MAC is CMAC with AES-192 truncated to the initial 8 bytes.
pub struct SmoAes192;
impl SecureMessagingOperations for SmoAes192 {
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
}


/// Cryptographic operations for secure messaging using AES-256.
///
/// The block mode of operation is Cipher Block Chaining (CBC).
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)
/// ```
///
/// The MAC is CMAC with AES-256 truncated to the initial 8 bytes.
pub struct SmoAes256;
impl SecureMessagingOperations for SmoAes256 {
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
}


/// Operations for Secure Messaging.
pub trait SecureMessaging<SC: SmartCard> {
    /// Size of the cipher key in bytes.
    fn cipher_key_size(&self) -> usize;

    /// The block size of the underlying cipher in bytes.
    fn cipher_block_size(&self) -> usize;

    /// The block size of the underlying MAC algorithm in bytes.
    fn mac_block_size(&self) -> usize;

    /// Obtain the underlying smart card for smart-card operations.
    fn get_smart_card_mut(&mut self) -> &mut SC;

    /// Obtain a mutable reference to the send-sequence counter.
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8];

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

    /// Increment the send sequence counter and return the incremented value.
    fn increment_send_sequence_counter(&mut self) -> &[u8] {
        let ssc = self.get_send_sequence_counter_mut();
        for b in ssc.iter_mut().rev() {
            if *b == 0xFF {
                *b = 0x00;
                // carry; keep going
            } else {
                *b += 1;
                // the buck stops here
                break;
            }
        }
        ssc
    }

    /// Decrypt data in-place that has already been pre-padded with the session key.
    ///
    /// Allowed to panic if the data has not, in fact, been pre-padded.
    fn decrypt_padded_data(&self, data: &mut [u8]);

    /// Encrypt data in-place that has already been pre-padded with the session key.
    ///
    /// Allowed to panic if the data has not, in fact, been pre-padded.
    fn encrypt_padded_data(&self, data: &mut [u8]);

    /// Generate a MAC with the MAC key for data that has already been pre-padded.
    ///
    /// Allowed to panic if the data has not, in fact, been pre-padded.
    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>>;

    /// Verify that the MAC calculated for the given pre-padded data matches the given MAC.
    ///
    /// Allowed to panic if the data has not, in fact, been pre-padded.
    fn verify_mac_padded_data<'d>(&self, data: &[u8], expected_mac: &[u8]) -> bool {
        let calculated_mac = self.mac_padded_data(data);
        calculated_mac.ct_eq(expected_mac).into()
    }

    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        let mut my_request = request.clone();
        let mac_block_size = self.mac_block_size();
        let cipher_block_size = self.cipher_block_size();

        // add secure messaging mark to CLA (header is part of MAC)
        my_request.header.cla |= 0b000_0_11_00;

        // collect the padded header
        let mut padded_header = Zeroizing::new(vec![
            my_request.header.cla,
            my_request.header.ins,
            my_request.header.p1,
            my_request.header.p2,
            0x80,
        ]);
        while padded_header.len() % mac_block_size != 0 {
            padded_header.push(0x00);
        }

        // increment the SSC
        let send_sequence_counter = self.increment_send_sequence_counter();

        // to compute the MAC, concatenate SSC, padded new header, and data
        let mut mac_data = Zeroizing::new(Vec::new());
        mac_data.extend(send_sequence_counter);
        mac_data.extend(padded_header.as_slice());

        let mut body_data = Zeroizing::new(Vec::new());

        if let Some(request_data) = request.data.request_data() {
            // collect the padded data
            let mut padded_data = Zeroizing::new(request_data.to_vec());
            // append padding
            padded_data.push(0x80);
            while padded_data.len() % cipher_block_size != 0 {
                padded_data.push(0x00);
            }

            // encrypt data with session key
            self.encrypt_padded_data(&mut padded_data);

            // construct Data Object 87:
            // 0x87 len padtype data...
            // padtype is 0x01 for ISO 7816 padding
            // 0x87 = 0b10_0_00111 (Context-Specific, Primitive, 7)
            let mut data_object_87 = Zeroizing::new(Vec::with_capacity(1 + 1 + 1 + padded_data.len()));
            data_object_87.push(0x87);
            crate::der_util::encode_primitive_length(&mut data_object_87, 1 + padded_data.len());
            data_object_87.push(0x01); // ISO 7816 padding
            data_object_87.extend(padded_data.as_slice());

            body_data.extend(data_object_87.as_slice());
        }

        // are we expecting something in return?
        match &request.data {
            Data::NoData|Data::RequestDataShort { .. }|Data::RequestDataExtended { .. } => {
                // no
            },
            Data::ResponseDataShort { response_data_length }|Data::BothDataShort { response_data_length, .. } => {
                // yes; append single-byte data object 97
                let data_object_97 = Zeroizing::new([0x97, 0x01, *response_data_length]);
                body_data.extend(data_object_97.as_slice());
            },
            Data::ResponseDataExtended { response_data_length }|Data::BothDataExtended { response_data_length, .. } => {
                // yes; append two-byte data object 97
                let mut data_object_97: Zeroizing<[u8; 4]> = Zeroizing::new([0x97, 0x02, 0x00, 0x00]);
                data_object_97[2..4].copy_from_slice(&response_data_length.to_be_bytes());
                body_data.extend(data_object_97.as_slice());
            },
        }

        // compute the MAC
        mac_data.extend(body_data.as_slice());
        // add padding
        mac_data.push(0x80);
        while mac_data.len() % mac_block_size != 0 {
            mac_data.push(0x00);
        }
        // compute MAC
        let mac = self.mac_padded_data(&mac_data);

        // build data object 8E
        let mut data_object_8e = Zeroizing::new(Vec::with_capacity(1 + 1 + 8));
        data_object_8e.push(0x8E);
        crate::der_util::encode_primitive_length(&mut data_object_8e, mac.len());
        data_object_8e.extend(mac.as_slice());

        // append 8E (MAC) to body
        body_data.extend(data_object_8e.as_slice());

        // update data in APDU
        if body_data.len() > 256 {
            my_request.data = Data::BothDataExtended {
                request_data: body_data.to_vec(),
                response_data_length: 0,
            };
        } else {
            my_request.data = Data::BothDataShort {
                request_data: body_data.to_vec(),
                response_data_length: 0,
            };
        }

        // finally talk to the smart card
        let response = {
            let card = self.get_smart_card_mut();
            card.communicate(&my_request)?
        };

        // decode the raw response
        let mut received_fields = Vec::new();
        let mut response_slice = response.data.as_slice();
        while response_slice.len() > 0 {
            if response_slice.len() < 2 {
                return Err(Error::ResponseTlvFormat.into());
            }

            let (data_length, rest_slice) = crate::der_util::try_decode_primitive_length(&response_slice[1..])
                .ok_or(Error::ResponseTlvFormat)?;
            let tag_and_length = &response_slice[0..response_slice.len()-rest_slice.len()];
            response_slice = rest_slice;

            let tlv = BorrowedTlv {
                tag_and_length,
                data: &response_slice[0..data_length],
            };
            response_slice = &response_slice[data_length..];
            received_fields.push(tlv);
        }

        // assemble the fields for the MAC verification
        let mut received_mac_fields = Vec::new();
        let mut received_mac_opt = None;
        for field in received_fields {
            let tag = field.tag_and_length[0];
            if tag == 0x8E {
                // the MAC itself
                received_mac_opt = Some(field.data);
            } else if tag & 0b1 != 0 {
                // part of the MAC
                received_mac_fields.push(field);
            }
        }

        let Some(received_mac) = received_mac_opt else {
            return Err(Error::MissingResponseMac.into());
        };

        // increment the SSC
        let ssc_for_received = self.increment_send_sequence_counter();

        // verify MAC
        let mut data = Zeroizing::new(Vec::new());
        data.extend(ssc_for_received);
        for field in &received_mac_fields {
            data.extend(field.tag_and_length);
            data.extend(field.data);
        }
        data.push(0x80);
        while data.len() & mac_block_size != 0 {
            data.push(0x00);
        }
        if !self.verify_mac_padded_data(&data, received_mac) {
            return Err(Error::ResponseMac.into());
        }

        // extract the actual response data
        let actual_response_data = if request.data.response_data_length().is_none() {
            Vec::with_capacity(0)
        } else {
            let actual_response = received_mac_fields.iter()
                .filter(|tlv| tlv.tag_and_length[0] == 0x87)
                .nth(0).ok_or(Error::MissingResponseData)?;

            if actual_response.data.len() == 0 {
                return Err(Error::MissingResponseData.into());
            }
            if actual_response.data[0] != 0x01 {
                // not ISO 7816 padding
                return Err(Error::UnknownPadding { padding_mode: actual_response.data[0] }.into());
            }
            let mut encrypted_data = Zeroizing::new(actual_response.data[1..].to_vec());

            self.decrypt_padded_data(encrypted_data.as_mut_slice());

            // strip padding
            while encrypted_data.last() == Some(&0x00) {
                encrypted_data.pop();
            }
            if encrypted_data.last() != Some(&0x80) {
                return Err(Error::InvalidPadding.into());
            }
            encrypted_data.pop();

            println!("decrypted data:");
            crate::hexdump(&encrypted_data);
            encrypted_data.to_vec()
        };
        let actual_status = received_mac_fields.iter()
            .filter(|tlv| tlv.tag_and_length[0] == 0x99)
            .nth(0).ok_or(Error::MissingResponseStatus)?;

        let response = Response {
            data: actual_response_data,
            trailer: ResponseTrailer {
                sw1: actual_status.data[0],
                sw2: actual_status.data[1],
            },
        };
        Ok(response)
    }
}

/// Secure messaging using 3DES.
///
/// 3DES is used in EDE two-key mode, i.e. `K3 = K1`. Secure operations are provided by [`Smo3Des`].
#[derive(ZeroizeOnDrop)]
pub struct Sm3Des<'sc, SC: SmartCard> {
    #[zeroize(skip)] card: &'sc mut SC,
    k_session_enc: [u8; 16],
    k_session_mac: [u8; 16],
    send_sequence_counter: [u8; 8],
}
impl<'sc, SC: SmartCard> Sm3Des<'sc, SC> {
    pub fn new(
        card: &'sc mut SC,
        k_session_enc: [u8; 16],
        k_session_mac: [u8; 16],
        send_sequence_counter: [u8; 8],
    ) -> Self {
        Self {
            card,
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }
}
impl<'sc, SC: SmartCard> SecureMessaging<SC> for Sm3Des<'sc, SC> {
    fn cipher_key_size(&self) -> usize { Smo3Des.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { Smo3Des.cipher_block_size() }
    fn mac_block_size(&self) -> usize { Smo3Des.mac_block_size() }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        Smo3Des.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = [0u8; 8];
        Smo3Des.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        // (IV is always zero, see Doc 9303 Part 11 § 9.8.6.1)
        let iv = [0u8; 8];
        Smo3Des.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        Smo3Des.mac_padded_data(data, &self.k_session_mac)
    }

    fn verify_mac_padded_data<'d>(&self, data: &[u8], expected_mac: &[u8]) -> bool {
        Smo3Des.verify_mac_padded_data(data, &self.k_session_mac, expected_mac)
    }
}
impl<'sc, SC: SmartCard> SmartCard for Sm3Des<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}


/// Secure messaging using AES-128.
///
/// Secure operations are provided by [`SmoAes128`].
#[derive(ZeroizeOnDrop)]
pub struct SmAes128<'sc, SC: SmartCard> {
    #[zeroize(skip)] card: &'sc mut SC,
    k_session_enc: [u8; 16],
    k_session_mac: [u8; 16],
    send_sequence_counter: [u8; 16],
}
impl<'sc, SC: SmartCard> SmAes128<'sc, SC> {
    pub fn new(
        card: &'sc mut SC,
        k_session_enc: [u8; 16],
        k_session_mac: [u8; 16],
        send_sequence_counter: [u8; 16],
    ) -> Self {
        Self {
            card,
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }

    fn derive_iv(&self) -> [u8; 16] {
        let derivation_iv = [0u8; 16];
        let mut actual_iv = self.send_sequence_counter.clone();
        SmoAes128.encrypt_padded_data(&mut actual_iv, &self.k_session_enc, &derivation_iv);
        actual_iv
    }
}
impl<'sc, SC: SmartCard> SecureMessaging<SC> for SmAes128<'sc, SC> {
    fn cipher_key_size(&self) -> usize { SmoAes128.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { SmoAes128.cipher_block_size() }
    fn mac_block_size(&self) -> usize { SmoAes128.mac_block_size() }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        SmoAes128.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        SmoAes128.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        SmoAes128.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        SmoAes128.mac_padded_data(data, &self.k_session_mac)
    }
}
impl<'sc, SC: SmartCard> SmartCard for SmAes128<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}


/// Secure messaging using AES-192.
///
/// Secure operations are provided by [`SmoAes192`].
#[derive(ZeroizeOnDrop)]
pub struct SmAes192<'sc, SC: SmartCard> {
    #[zeroize(skip)] card: &'sc mut SC,
    k_session_enc: [u8; 24],
    k_session_mac: [u8; 24],
    send_sequence_counter: [u8; 16],
}
impl<'sc, SC: SmartCard> SmAes192<'sc, SC> {
    pub fn new(
        card: &'sc mut SC,
        k_session_enc: [u8; 24],
        k_session_mac: [u8; 24],
        send_sequence_counter: [u8; 16],
    ) -> Self {
        Self {
            card,
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }

    fn derive_iv(&self) -> [u8; 16] {
        let derivation_iv = [0u8; 16];
        let mut actual_iv = self.send_sequence_counter.clone();
        SmoAes192.encrypt_padded_data(&mut actual_iv, &self.k_session_enc, &derivation_iv);
        actual_iv
    }
}
impl<'sc, SC: SmartCard> SecureMessaging<SC> for SmAes192<'sc, SC> {
    fn cipher_key_size(&self) -> usize { SmoAes192.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { SmoAes192.cipher_block_size() }
    fn mac_block_size(&self) -> usize { SmoAes192.mac_block_size() }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        SmoAes192.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        SmoAes192.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        SmoAes192.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        SmoAes192.mac_padded_data(data, &self.k_session_mac)
    }
}
impl<'sc, SC: SmartCard> SmartCard for SmAes192<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}


/// Key derivation function for AES-256.
///
/// Secure operations are provided by [`SmoAes256`].
#[derive(ZeroizeOnDrop)]
pub struct SmAes256<'sc, SC: SmartCard> {
    #[zeroize(skip)] card: &'sc mut SC,
    k_session_enc: [u8; 32],
    k_session_mac: [u8; 32],
    send_sequence_counter: [u8; 16],
}
impl<'sc, SC: SmartCard> SmAes256<'sc, SC> {
    pub fn new(
        card: &'sc mut SC,
        k_session_enc: [u8; 32],
        k_session_mac: [u8; 32],
        send_sequence_counter: [u8; 16],
    ) -> Self {
        Self {
            card,
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }

    fn derive_iv(&self) -> [u8; 16] {
        let encryptor = Aes256::new_from_slice(&self.k_session_enc).unwrap();
        let mut iv = self.send_sequence_counter.clone();
        let iv_len = iv.len();
        encryptor.encrypt_padded::<NoPadding>(&mut iv, iv_len).unwrap();
        iv
    }
}
impl<'sc, SC: SmartCard> SecureMessaging<SC> for SmAes256<'sc, SC> {
    fn cipher_key_size(&self) -> usize { SmoAes256.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { SmoAes256.cipher_block_size() }
    fn mac_block_size(&self) -> usize { SmoAes256.mac_block_size() }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        SmoAes256.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        SmoAes256.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        SmoAes256.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        SmoAes256.mac_padded_data(data, &self.k_session_mac)
    }
}
impl<'sc, SC: SmartCard> SmartCard for SmAes256<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}
