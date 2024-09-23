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


/// Operations for Secure Messaging.
pub trait SecureMessaging<SC: SmartCard> {
    type Key;

    /// The block size of the underlying cipher in bytes.
    fn cipher_block_size() -> usize;

    /// The block size of the underlying MAC algorithm in bytes.
    fn mac_block_size() -> usize;

    /// Obtain the underlying smart card for smart-card operations.
    fn get_smart_card_mut(&mut self) -> &mut SC;

    /// Obtain a mutable reference to the send-sequence counter.
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8];

    /// The key derivation function.
    fn derive_key(key_seed: &[u8], counter: u32) -> Self::Key;

    /// The key derivation function for encryption purposes.
    fn derive_encryption_key(key_seed: &[u8]) -> Self::Key {
        Self::derive_key(key_seed, 1)
    }

    /// The key derivation function for message authentication purposes.
    fn derive_mac_key(key_seed: &[u8]) -> Self::Key {
        Self::derive_key(key_seed, 2)
    }

    /// The password-to-key derivation function.
    fn derive_key_from_password(password: &[u8]) -> Self::Key {
        Self::derive_key(password, 3)
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
    fn mac_padded_data<'d>(&self, data: &[u8]) -> Vec<u8>;

    /// Verify that the MAC calculated for the given pre-padded data matches the given MAC.
    ///
    /// Allowed to panic if the data has not, in fact, been pre-padded.
    fn verify_mac_padded_data<'d>(&self, data: &[u8], expected_mac: &[u8]) -> bool {
        let calculated_mac = self.mac_padded_data(data);
        calculated_mac.ct_eq(expected_mac).into()
    }

    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        let mut my_request = request.clone();

        // add secure messaging mark to CLA (header is part of MAC)
        my_request.header.cla |= 0b000_0_11_00;

        // collect the padded header
        let mut padded_header = vec![
            my_request.header.cla,
            my_request.header.ins,
            my_request.header.p1,
            my_request.header.p2,
            0x80,
        ];
        while padded_header.len() % Self::mac_block_size() != 0 {
            padded_header.push(0x00);
        }

        // increment the SSC
        let send_sequence_counter = self.increment_send_sequence_counter();

        // to compute the MAC, concatenate SSC, padded new header, and data
        let mut mac_data = Vec::new();
        mac_data.extend(send_sequence_counter);
        mac_data.extend(&padded_header);

        let mut body_data = Vec::new();

        if let Some(request_data) = request.data.request_data() {
            // collect the padded data
            let mut padded_data = request_data.to_vec();
            // append padding
            padded_data.push(0x80);
            while padded_data.len() % Self::cipher_block_size() != 0 {
                padded_data.push(0x00);
            }

            // encrypt data with session key
            self.encrypt_padded_data(&mut padded_data);

            // construct Data Object 87:
            // 0x87 len padtype data...
            // padtype is 0x01 for ISO 7816 padding
            // 0x87 = 0b10_0_00111 (Context-Specific, Primitive, 7)
            let mut data_object_87 = Vec::with_capacity(1 + 1 + 1 + padded_data.len());
            data_object_87.push(0x87);
            der_encode_primitive_length(&mut data_object_87, 1 + padded_data.len());
            data_object_87.push(0x01); // ISO 7816 padding
            data_object_87.extend(padded_data);

            body_data.extend(&data_object_87);
        }

        // are we expecting something in return?
        match &request.data {
            Data::NoData|Data::RequestDataShort { .. }|Data::RequestDataExtended { .. } => {
                // no
            },
            Data::ResponseDataShort { response_data_length }|Data::BothDataShort { response_data_length, .. } => {
                // yes; append single-byte data object 97
                let data_object_97 = [0x97, 0x01, *response_data_length];
                body_data.extend(&data_object_97);
            },
            Data::ResponseDataExtended { response_data_length }|Data::BothDataExtended { response_data_length, .. } => {
                // yes; append two-byte data object 97
                let mut data_object_97: [u8; 4] = [0x97, 0x02, 0x00, 0x00];
                data_object_97[2..4].copy_from_slice(&response_data_length.to_be_bytes());
                body_data.extend(&data_object_97);
            },
        }

        // compute the MAC
        mac_data.extend(&body_data);
        // add padding
        mac_data.push(0x80);
        while mac_data.len() % Self::mac_block_size() != 0 {
            mac_data.push(0x00);
        }
        // compute MAC
        let mac = self.mac_padded_data(&mac_data);

        // build data object 8E
        let mut data_object_8e = Vec::with_capacity(1 + 1 + 8);
        data_object_8e.push(0x8E);
        der_encode_primitive_length(&mut data_object_8e, mac.len());
        data_object_8e.extend(&mac);

        // append 8E (MAC) to body
        body_data.extend(&data_object_8e);

        // update data in APDU
        if body_data.len() > 256 {
            my_request.data = Data::BothDataExtended {
                request_data: body_data,
                response_data_length: 0,
            };
        } else {
            my_request.data = Data::BothDataShort {
                request_data: body_data,
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

            let (data_length, rest_slice) = der_try_decode_primitive_length(&response_slice[1..])
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
        let mut data = Vec::new();
        data.extend(ssc_for_received);
        for field in &received_mac_fields {
            data.extend(field.tag_and_length);
            data.extend(field.data);
        }
        data.push(0x80);
        while data.len() % Self::mac_block_size() != 0 {
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
            let mut encrypted_data = actual_response.data[1..].to_vec();

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
            encrypted_data
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
/// 3DES is used in EDE two-key mode, i.e. `K3 = K1`.
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
pub struct Sm3Des<'sc, SC: SmartCard> {
    card: &'sc mut SC,
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
    type Key = [u8; 16];

    fn derive_key(key_seed: &[u8], counter: u32) -> [u8; 16] {
        let mut hasher = Sha1::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        let mut keydata = [0u8; 16];
        keydata.copy_from_slice(&result[0..16]);
        keydata
    }

    fn cipher_block_size() -> usize { 8 }
    fn mac_block_size() -> usize { 8 }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn increment_send_sequence_counter(&mut self) -> &[u8] {
        todo!();
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = [0u8; 8];
        let decryptor: cbc::Decryptor<TdesEde2> = cbc::Decryptor::new(&self.k_session_enc.into(), &iv.into());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        // (IV is always zero, see Doc 9303 Part 11 § 9.8.6.1)
        let iv = [0u8; 8];
        let encryptor: cbc::Encryptor<TdesEde2> = cbc::Encryptor::new(&self.k_session_enc.into(), &iv.into());
        encryptor.encrypt_padded::<NoPadding>(data, data.len()).unwrap();
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Vec<u8> {
        let mut retail_mac = RetailMacDes::new_from_slice(&self.k_session_mac).unwrap();
        DynDigest::update(&mut retail_mac, data);
        let mut mac = vec![0u8; 8];
        retail_mac.finalize_into(&mut mac).unwrap();
        mac
    }

    fn verify_mac_padded_data<'d>(&self, data: &[u8], expected_mac: &[u8]) -> bool {
        let mut retail_mac = RetailMacDes::new_from_slice(&self.k_session_mac).unwrap();
        DynDigest::update(&mut retail_mac, data);
        retail_mac.verify_slice(expected_mac).is_ok()
    }
}
impl<'sc, SC: SmartCard> SmartCard for Sm3Des<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}


/// Secure messaging using AES-128.
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha1(key || counter)[0..16]
/// ```
pub struct SmAes128<'sc, SC: SmartCard> {
    card: &'sc mut SC,
    k_session_enc: [u8; 16],
    k_session_mac: [u8; 16],
    send_sequence_counter: [u8; 16],
}
impl<'sc, SC: SmartCard> SmAes128<'sc, SC> {
    fn derive_iv(&self) -> [u8; 16] {
        let encryptor = Aes128::new_from_slice(&self.k_session_enc).unwrap();
        let mut iv = self.send_sequence_counter.clone();
        let iv_len = iv.len();
        encryptor.encrypt_padded::<NoPadding>(&mut iv, iv_len).unwrap();
        iv
    }
}
impl<'sc, SC: SmartCard> SecureMessaging<SC> for SmAes128<'sc, SC> {
    type Key = [u8; 16];

    fn cipher_block_size() -> usize { 16 }
    fn mac_block_size() -> usize { 1 }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(key_seed: &[u8], counter: u32) -> [u8; 16] {
        let mut hasher = Sha1::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        let mut keydata = [0u8; 16];
        keydata.copy_from_slice(&result[0..16]);
        keydata
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        let decryptor: cbc::Decryptor<Aes128> = cbc::Decryptor::new(&self.k_session_enc.into(), &iv.into());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        let encryptor: cbc::Encryptor<Aes128> = cbc::Encryptor::new(&self.k_session_enc.into(), &iv.into());
        let data_len = data.len();
        encryptor.encrypt_padded::<NoPadding>(data, data_len).unwrap();
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = Cmac::<Aes128>::new_from_slice(&self.k_session_mac).unwrap();
        DynDigest::update(&mut mac, data);
        let mut final_mac = vec![0u8; 16];
        mac.finalize_into(final_mac.as_mut_slice()).unwrap();
        final_mac.truncate(8);
        final_mac
    }
}
impl<'sc, SC: SmartCard> SmartCard for SmAes128<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}


/// Secure messaging using AES-192.
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)[0..24]
/// ```
pub struct SmAes192<'sc, SC: SmartCard> {
    card: &'sc mut SC,
    k_session_enc: [u8; 24],
    k_session_mac: [u8; 24],
    send_sequence_counter: [u8; 16],
}
impl<'sc, SC: SmartCard> SmAes192<'sc, SC> {
    fn derive_iv(&self) -> [u8; 16] {
        let encryptor = Aes192::new_from_slice(&self.k_session_enc).unwrap();
        let mut iv = self.send_sequence_counter.clone();
        let iv_len = iv.len();
        encryptor.encrypt_padded::<NoPadding>(&mut iv, iv_len).unwrap();
        iv
    }
}
impl<'sc, SC: SmartCard> SecureMessaging<SC> for SmAes192<'sc, SC> {
    type Key = [u8; 24];

    fn cipher_block_size() -> usize { 16 }
    fn mac_block_size() -> usize { 1 }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(key_seed: &[u8], counter: u32) -> Self::Key {
        let mut hasher = Sha256::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        let mut keydata = [0u8; 24];
        keydata.copy_from_slice(&result[0..24]);
        keydata
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        let decryptor: cbc::Decryptor<Aes192> = cbc::Decryptor::new(&self.k_session_enc.into(), &iv.into());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        let encryptor: cbc::Encryptor<Aes192> = cbc::Encryptor::new(&self.k_session_enc.into(), &iv.into());
        let data_len = data.len();
        encryptor.encrypt_padded::<NoPadding>(data, data_len).unwrap();
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = Cmac::<Aes192>::new_from_slice(&self.k_session_mac).unwrap();
        DynDigest::update(&mut mac, data);
        let mut final_mac = vec![0u8; 16];
        mac.finalize_into(final_mac.as_mut_slice()).unwrap();
        final_mac.truncate(8);
        final_mac
    }
}
impl<'sc, SC: SmartCard> SmartCard for SmAes192<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}


/// Key derivation function for AES-256.
///
/// The KDF is equivalent to:
/// ```plain
/// keydata = sha256(key || counter)
/// ```
pub struct SmAes256<'sc, SC: SmartCard> {
    card: &'sc mut SC,
    k_session_enc: [u8; 32],
    k_session_mac: [u8; 32],
    send_sequence_counter: [u8; 16],
}
impl<'sc, SC: SmartCard> SmAes256<'sc, SC> {
    fn derive_iv(&self) -> [u8; 16] {
        let encryptor = Aes256::new_from_slice(&self.k_session_enc).unwrap();
        let mut iv = self.send_sequence_counter.clone();
        let iv_len = iv.len();
        encryptor.encrypt_padded::<NoPadding>(&mut iv, iv_len).unwrap();
        iv
    }
}
impl<'sc, SC: SmartCard> SecureMessaging<SC> for SmAes256<'sc, SC> {
    type Key = [u8; 32];

    fn cipher_block_size() -> usize { 8 }
    fn mac_block_size() -> usize { 1 }

    fn get_smart_card_mut(&mut self) -> &mut SC { &mut self.card }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(key_seed: &[u8], counter: u32) -> Self::Key {
        let mut hasher = Sha256::new();
        DynDigest::update(&mut hasher, key_seed);
        DynDigest::update(&mut hasher, &counter.to_be_bytes());
        let result = hasher.finalize();

        let mut keydata = [0u8; 32];
        keydata.copy_from_slice(&result[0..32]);
        keydata
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        let decryptor: cbc::Decryptor<Aes256> = cbc::Decryptor::new(&self.k_session_enc.into(), &iv.into());
        decryptor.decrypt_padded::<NoPadding>(data).unwrap();
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        let encryptor: cbc::Encryptor<Aes256> = cbc::Encryptor::new(&self.k_session_enc.into(), &iv.into());
        let data_len = data.len();
        encryptor.encrypt_padded::<NoPadding>(data, data_len).unwrap();
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = Cmac::<Aes256>::new_from_slice(&self.k_session_mac).unwrap();
        DynDigest::update(&mut mac, data);
        let mut final_mac = vec![0u8; 16];
        mac.finalize_into(final_mac.as_mut_slice()).unwrap();
        final_mac.truncate(8);
        final_mac
    }
}
impl<'sc, SC: SmartCard> SmartCard for SmAes256<'sc, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}


/// Encode an ASN.1 DER primitive value length.
pub fn der_encode_primitive_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        // single-byte encoding
        output.push(length.try_into().unwrap());
    } else {
        // 0b1nnn_nnnn and then n additional bytes that actually specify the length
        // (big-endian)
        let length_bytes = length.to_be_bytes();
        let mut trimmed_length_slice = &length_bytes[..];
        while trimmed_length_slice[0] == 0x00 {
            trimmed_length_slice = &trimmed_length_slice[1..];
        }
        output.push(0b1000_0000 | u8::try_from(trimmed_length_slice.len()).unwrap());
        output.extend(trimmed_length_slice);
    }
}


/// Decode an ASN.1 DER primitive value length.
///
/// The length must be at the beginning of the input slice.
///
/// Returns a tuple `(length, rest)` where `rest` is the rest of the input slice once the length has
/// been removed.
pub fn der_try_decode_primitive_length(input: &[u8]) -> Option<(usize, &[u8])> {
    if input.len() == 0 {
        return None;
    }
    let start_byte = input[0];
    let start_lower_bits = start_byte & 0b0111_1111;
    if start_byte & 0b1000_0000 != 0 {
        // multiple bytes
        let length_byte_count: usize = start_lower_bits.into();
        if length_byte_count == 0 {
            return None;
        }
        if length_byte_count > input.len() - 1 {
            // that will never fit
            return None;
        }
        let mut length: usize = 0;
        for length_byte in &input[1..1+length_byte_count] {
            let Some(multiplied) = length.checked_mul(256) else { return None };
            length = multiplied;
            let Some(added) = length.checked_add(usize::from(*length_byte)) else { return None };
            length = added;
        }
        Some((length, &input[1+length_byte_count..]))
    } else {
        let length = start_lower_bits.into();
        Some((length, &input[1..]))
    }
}
