//! Secure Messaging for PACE.


use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
use zeroize_derive::ZeroizeOnDrop;

use crate::crypt::cipher_mac::{Cam3Des, CamAes128, CamAes192, CamAes256, CipherAndMac};
use crate::iso7816::apdu::{Apdu, Data, Response, ResponseTrailer};
use crate::iso7816::card::{CommunicationError, SmartCard};


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
pub trait SecureMessaging {
    /// Size of the cipher key in bytes.
    fn cipher_key_size(&self) -> usize;

    /// The block size of the underlying cipher in bytes.
    fn cipher_block_size(&self) -> usize;

    /// The block size of the underlying MAC algorithm in bytes.
    ///
    /// Note that this is only used when establishing Secure Messaging. Once it is established,
    /// decisions about padding are made depending on [`SecureMessaging::cipher_block_size`]
    /// instead.
    fn mac_block_size(&self) -> usize;

    /// Obtain the underlying smart card for smart-card operations.
    fn get_smart_card_mut(&mut self) -> &mut Box<dyn SmartCard>;

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

    /// Drops the secure messaging context and returns the inner smart card.
    fn into_smart_card(self) -> Box<dyn SmartCard>;

    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        let mut my_request = request.clone();
        let cipher_block_size = self.cipher_block_size();

        // add secure messaging mark to CLA (header is part of MAC)
        my_request.header.cla |= 0b000_0_11_00;

        // collect the padded header
        let mut padded_header = Zeroizing::new(vec![
            my_request.header.cla,
            my_request.header.ins,
            my_request.header.p1,
            my_request.header.p2,
        ]);
        if cipher_block_size > 1 {
            padded_header.push(0x80);
            while padded_header.len() % cipher_block_size != 0 {
                padded_header.push(0x00);
            }
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
        if cipher_block_size > 1 {
            // add padding
            mac_data.push(0x80);
            while mac_data.len() % cipher_block_size != 0 {
                mac_data.push(0x00);
            }
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
        if cipher_block_size > 1 {
            data.push(0x80);
            while data.len() % cipher_block_size != 0 {
                data.push(0x00);
            }
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
impl<SM: SecureMessaging> SmartCard for SM {
    fn communicate(&mut self, request: &crate::iso7816::apdu::Apdu) -> Result<crate::iso7816::apdu::Response, CommunicationError> {
        SecureMessaging::communicate(self, request)
    }
}

/// Secure messaging using 3DES.
///
/// 3DES is used in EDE two-key mode, i.e. `K3 = K1`. Secure operations are provided by [`Cam3Des`].
#[derive(ZeroizeOnDrop)]
pub struct Sm3Des {
    #[zeroize(skip)] card: Option<Box<dyn SmartCard>>,
    k_session_enc: [u8; 16],
    k_session_mac: [u8; 16],
    send_sequence_counter: [u8; 8],
}
impl Sm3Des {
    pub fn new(
        card: Box<dyn SmartCard>,
        k_session_enc: [u8; 16],
        k_session_mac: [u8; 16],
        send_sequence_counter: [u8; 8],
    ) -> Self {
        Self {
            card: Some(card),
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }
}
impl SecureMessaging for Sm3Des {
    fn cipher_key_size(&self) -> usize { Cam3Des.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { Cam3Des.cipher_block_size() }
    fn mac_block_size(&self) -> usize { Cam3Des.mac_block_size() }

    fn into_smart_card(mut self) -> Box<dyn SmartCard> {
        let card = std::mem::take(&mut self.card);
        card.unwrap()
    }

    fn get_smart_card_mut(&mut self) -> &mut Box<dyn SmartCard> { self.card.as_mut().unwrap() }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        Cam3Des.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = [0u8; 8];
        Cam3Des.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        // (IV is always zero, see Doc 9303 Part 11 § 9.8.6.1)
        let iv = [0u8; 8];
        Cam3Des.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        Cam3Des.mac_padded_data(data, &self.k_session_mac)
    }

    fn verify_mac_padded_data<'d>(&self, data: &[u8], expected_mac: &[u8]) -> bool {
        Cam3Des.verify_mac_padded_data(data, &self.k_session_mac, expected_mac)
    }
}


/// Secure messaging using AES-128.
///
/// Secure operations are provided by [`CamAes128`].
#[derive(ZeroizeOnDrop)]
pub struct SmAes128 {
    #[zeroize(skip)] card: Option<Box<dyn SmartCard>>,
    k_session_enc: [u8; 16],
    k_session_mac: [u8; 16],
    send_sequence_counter: [u8; 16],
}
impl SmAes128 {
    pub fn new(
        card: Box<dyn SmartCard>,
        k_session_enc: [u8; 16],
        k_session_mac: [u8; 16],
        send_sequence_counter: [u8; 16],
    ) -> Self {
        Self {
            card: Some(card),
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }

    fn derive_iv(&self) -> [u8; 16] {
        let derivation_iv = [0u8; 16];
        let mut actual_iv = self.send_sequence_counter.clone();
        CamAes128.encrypt_padded_data(&mut actual_iv, &self.k_session_enc, &derivation_iv);
        actual_iv
    }
}
impl SecureMessaging for SmAes128 {
    fn cipher_key_size(&self) -> usize { CamAes128.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { CamAes128.cipher_block_size() }
    fn mac_block_size(&self) -> usize { CamAes128.mac_block_size() }

    fn into_smart_card(mut self) -> Box<dyn SmartCard> {
        let card = std::mem::take(&mut self.card);
        card.unwrap()
    }

    fn get_smart_card_mut(&mut self) -> &mut Box<dyn SmartCard> { self.card.as_mut().unwrap() }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        CamAes128.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        CamAes128.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        CamAes128.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        CamAes128.mac_padded_data(data, &self.k_session_mac)
    }
}


/// Secure messaging using AES-192.
///
/// Secure operations are provided by [`CamAes192`].
#[derive(ZeroizeOnDrop)]
pub struct SmAes192 {
    #[zeroize(skip)] card: Option<Box<dyn SmartCard>>,
    k_session_enc: [u8; 24],
    k_session_mac: [u8; 24],
    send_sequence_counter: [u8; 16],
}
impl SmAes192 {
    pub fn new(
        card: Box<dyn SmartCard>,
        k_session_enc: [u8; 24],
        k_session_mac: [u8; 24],
        send_sequence_counter: [u8; 16],
    ) -> Self {
        Self {
            card: Some(card),
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }

    fn derive_iv(&self) -> [u8; 16] {
        let derivation_iv = [0u8; 16];
        let mut actual_iv = self.send_sequence_counter.clone();
        CamAes192.encrypt_padded_data(&mut actual_iv, &self.k_session_enc, &derivation_iv);
        actual_iv
    }
}
impl SecureMessaging for SmAes192 {
    fn cipher_key_size(&self) -> usize { CamAes192.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { CamAes192.cipher_block_size() }
    fn mac_block_size(&self) -> usize { CamAes192.mac_block_size() }

    fn into_smart_card(mut self) -> Box<dyn SmartCard> {
        let card = std::mem::take(&mut self.card);
        card.unwrap()
    }

    fn get_smart_card_mut(&mut self) -> &mut Box<dyn SmartCard> { self.card.as_mut().unwrap() }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        CamAes192.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        CamAes192.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        CamAes192.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        CamAes192.mac_padded_data(data, &self.k_session_mac)
    }
}


/// Key derivation function for AES-256.
///
/// Secure operations are provided by [`CamAes256`].
#[derive(ZeroizeOnDrop)]
pub struct SmAes256 {
    #[zeroize(skip)] card: Option<Box<dyn SmartCard>>,
    k_session_enc: [u8; 32],
    k_session_mac: [u8; 32],
    send_sequence_counter: [u8; 16],
}
impl SmAes256 {
    pub fn new(
        card: Box<dyn SmartCard>,
        k_session_enc: [u8; 32],
        k_session_mac: [u8; 32],
        send_sequence_counter: [u8; 16],
    ) -> Self {
        Self {
            card: Some(card),
            k_session_enc,
            k_session_mac,
            send_sequence_counter,
        }
    }

    fn derive_iv(&self) -> [u8; 16] {
        let derivation_iv = [0u8; 16];
        let mut actual_iv = self.send_sequence_counter.clone();
        CamAes256.encrypt_padded_data(&mut actual_iv, &self.k_session_enc, &derivation_iv);
        actual_iv
    }
}
impl SecureMessaging for SmAes256 {
    fn cipher_key_size(&self) -> usize { CamAes256.cipher_key_size() }
    fn cipher_block_size(&self) -> usize { CamAes256.cipher_block_size() }
    fn mac_block_size(&self) -> usize { CamAes256.mac_block_size() }

    fn into_smart_card(mut self) -> Box<dyn SmartCard> {
        let card = std::mem::take(&mut self.card);
        card.unwrap()
    }

    fn get_smart_card_mut(&mut self) -> &mut Box<dyn SmartCard> { self.card.as_mut().unwrap() }
    fn get_send_sequence_counter_mut(&mut self) -> &mut [u8] { &mut self.send_sequence_counter }

    fn derive_key(&self, key_seed: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
        CamAes256.derive_key(key_seed, counter)
    }

    fn decrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        CamAes256.decrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn encrypt_padded_data(&self, data: &mut [u8]) {
        let iv = self.derive_iv();
        CamAes256.encrypt_padded_data(data, &self.k_session_enc, &iv)
    }

    fn mac_padded_data<'d>(&self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        CamAes256.mac_padded_data(data, &self.k_session_mac)
    }
}
