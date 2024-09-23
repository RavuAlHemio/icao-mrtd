//! Basic Access Control.


use std::fmt;

use block_padding::{Iso7816, NoPadding, RawPadding};
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use des::{Des, TdesEde2};
use digest::{Digest, DynDigest, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use retail_mac::RetailMac;
use sha1::Sha1;

use crate::iso7816::card::{CommunicationError, SmartCard};
use crate::iso7816::apdu::{Apdu, CommandHeader, Data, Response, ResponseTrailer};
use crate::pace::asn1::{der_encode_primitive_length, der_try_decode_primitive_length};
use crate::pace::kdf::{Kdf, Kdf3Des};


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
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BorrowedTlv<'d> {
    pub tag_and_length: &'d [u8],
    pub data: &'d [u8],
}


pub struct BacCard<'c, SC: SmartCard> {
    card: &'c mut SC,
    k_session_enc: [u8; 16],
    k_session_mac: [u8; 16],
    send_sequence_counter: [u8; 8],
}
impl<'c, SC: SmartCard> BacCard<'c, SC> {
    pub fn new(
        card: &'c mut SC,
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
impl<'c, SC: SmartCard> BacCard<'c, SC> {
    fn increment_send_sequence_counter(&mut self) {
        for b in self.send_sequence_counter.iter_mut().rev() {
            if *b == 0xFF {
                *b = 0x00;
                // carry; keep going
            } else {
                *b += 1;
                // the buck stops here
                break;
            }
        }
    }
}
impl<'c, SC: SmartCard> SmartCard for BacCard<'c, SC> {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, CommunicationError> {
        let mut my_request = request.clone();

        // add secure messaging mark to CLA
        my_request.header.cla |= 0b000_0_11_00;

        // collect the padded header
        let padded_header = [
            my_request.header.cla,
            my_request.header.ins,
            my_request.header.p1,
            my_request.header.p2,
            0x80, 0x00, 0x00, 0x00,
        ];

        // increment the SSC
        self.increment_send_sequence_counter();

        // to compute the MAC, concatenate SSC, padded new header, and data
        let mut mac_data = Vec::new();
        mac_data.extend(&self.send_sequence_counter);
        mac_data.extend(&padded_header);

        let mut body_data = Vec::new();

        if let Some(request_data) = request.data.request_data() {
            // collect the padded data
            let mut padded_data = request_data.to_vec();
            // append padding
            padded_data.push(0x80);
            while padded_data.len() % 8 != 0 {
                padded_data.push(0x00);
            }
            let padded_data_len = padded_data.len();

            // encrypt data with session key
            // (IV is always zero, see Doc 9303 Part 11 § 9.8.6.1)
            let iv = [0u8; 8];
            let encryptor: cbc::Encryptor<TdesEde2> = cbc::Encryptor::new(&self.k_session_enc.into(), &iv.into());
            let encrypted_slice = encryptor.encrypt_padded::<NoPadding>(&mut padded_data, padded_data_len).unwrap();

            // construct Data Object 87:
            // 0x87 len padtype data...
            // padtype is 0x01 for ISO 7816 padding
            // 0x87 = 0b10_0_00111 (Context-Specific, Primitive, 7)
            let mut data_object_87 = Vec::with_capacity(1 + 1 + 1 + encrypted_slice.len());
            data_object_87.push(0x87);
            der_encode_primitive_length(&mut data_object_87, 1 + encrypted_slice.len());
            data_object_87.push(0x01); // ISO 7816 padding
            data_object_87.extend(encrypted_slice);

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
        while mac_data.len() % 8 != 0 {
            mac_data.push(0x00);
        }
        // compute MAC
        let mut retail_mac = RetailMacDes::new_from_slice(&self.k_session_mac).unwrap();
        DynDigest::update(&mut retail_mac, &mac_data);
        let mut mac = [0u8; 8];
        retail_mac.finalize_into(&mut mac).unwrap();

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
        println!("sending to card: {:#?}", my_request);
        let response = self.card.communicate(&my_request)?;
        println!("obtained from card: {:#?}", response);

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

        // verify MAC
        let mut received_retail_mac = RetailMacDes::new_from_slice(&self.k_session_mac).unwrap();
        let mut written_count = 0;
        for field in &received_mac_fields {
            DynDigest::update(&mut received_retail_mac, field.tag_and_length);
            DynDigest::update(&mut received_retail_mac, field.data);
            written_count += field.tag_and_length.len() + field.data.len();
        }
        DynDigest::update(&mut received_retail_mac, &[0x80]);
        written_count += 1;
        while written_count % 8 != 0 {
            DynDigest::update(&mut received_retail_mac, &[0x00]);
            written_count += 1;
        }
        received_retail_mac.verify_slice(received_mac)
            .map_err(|_| Error::ResponseMac)?;

        // extract the actual response data
        let actual_response = received_mac_fields.iter()
            .filter(|tlv| tlv.tag_and_length[0] == 0x87)
            .nth(0).ok_or(Error::MissingResponseData)?;
        let actual_status = received_mac_fields.iter()
            .filter(|tlv| tlv.tag_and_length[0] == 0x99)
            .nth(0).ok_or(Error::MissingResponseStatus)?;

        let response = Response {
            data: actual_response.data.to_vec(),
            trailer: ResponseTrailer {
                sw1: actual_status.data[0],
                sw2: actual_status.data[1],
            },
        };
        Ok(response)
    }
}


fn get_challenge<SC: SmartCard>(card: &mut SC) -> Result<[u8; 8], CommunicationError> {
    let get_challenge_apdu = Apdu {
        header: CommandHeader {
            cla: 0x00,
            ins: 0x84, // GET CHALLENGE
            p1: 0x00,
            p2: 0x00,
        },
        data: Data::ResponseDataShort {
            response_data_length: 8,
        },
    };
    let response = card.communicate(&get_challenge_apdu)?;
    if response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed { operation: Operation::GetChallenge, response }.into());
    }
    if response.data.len() != 8 {
        return Err(Error::LengthMismatch {
            operation: Operation::GetChallenge,
            obtained: response.data,
            expected_length: 8,
        }.into());
    }
    let mut ret = [0u8; 8];
    ret.copy_from_slice(response.data.as_slice());
    Ok(ret)
}

pub fn establish<'c, SC: SmartCard>(card: &'c mut SC, mrz_data: &[u8]) -> Result<BacCard<'c, SC>, CommunicationError> {
    // calculate SHA-1 hash of MRZ data
    let mut sha1 = Sha1::new();
    Digest::update(&mut sha1, mrz_data);
    let sha1_hash = sha1.finalize();
    let k_seed = &sha1_hash[0..16];

    // derive the keys
    // (the key derivation functions have remained the same with PACE)
    let k_enc = Kdf3Des::derive_encryption_key(k_seed);
    let k_mac = Kdf3Des::derive_mac_key(k_seed);

    // obtain the challenge
    let rnd_ic = get_challenge(card)?;

    // generate some random bytes
    let mut rnd_ifd = [0u8; 8];
    let mut k_ifd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd_ifd);
    OsRng.fill_bytes(&mut k_ifd);

    // concatenate the three values
    let mut ext_auth_data = [0u8; 32+8];
    ext_auth_data[0..8].copy_from_slice(&rnd_ifd);
    ext_auth_data[8..16].copy_from_slice(&rnd_ic);
    ext_auth_data[16..32].copy_from_slice(&k_ifd);

    // encrypt using 3DES (EDE 2-key) in CBC mode with an all-zeroes IV and no padding
    let iv = [0u8; 8];
    let encryptor: cbc::Encryptor<TdesEde2> = cbc::Encryptor::new(&k_enc.into(), &iv.into());
    encryptor.encrypt_padded::<NoPadding>(&mut ext_auth_data[0..32], 32).unwrap();
    // ext_auth_data[0..32] is now encrypted

    // pad according to ISO 7816, then generate Retail MAC
    Iso7816::raw_pad(&mut ext_auth_data, 32);
    let mut retail_mac = RetailMacDes::new_from_slice(&k_mac).unwrap();
    DynDigest::update(&mut retail_mac, &ext_auth_data);
    // MAC fits right where the padding was
    retail_mac.finalize_into(&mut ext_auth_data[32..32+8]).unwrap();

    // send EXTERNAL AUTHENTICATE
    let ext_auth_request = Apdu {
        header: CommandHeader {
            cla: 0x00,
            ins: 0x82, // EXTERNAL AUTHENTICATE
            p1: 0x00,
            p2: 0x00,
        },
        data: Data::BothDataShort {
            request_data: ext_auth_data.to_vec(),
            response_data_length: 40,
        },
    };
    let mut ext_auth_response = card.communicate(&ext_auth_request)?;
    if ext_auth_response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed {
            operation: Operation::ExternalAuthenticate,
            response: ext_auth_response,
        }.into());
    }
    if ext_auth_response.data.len() != 40 {
        return Err(Error::LengthMismatch {
            operation: Operation::ExternalAuthenticate,
            obtained: ext_auth_response.data,
            expected_length: 40,
        }.into());
    }

    // verify MAC of what we obtained
    let mut response_data_to_verify = [0u8; 32+8];
    response_data_to_verify[0..32].copy_from_slice(&ext_auth_response.data[0..32]);
    Iso7816::raw_pad(&mut response_data_to_verify, 32);
    let mut response_mac = RetailMacDes::new_from_slice(&k_mac).unwrap();
    DynDigest::update(&mut response_mac, &response_data_to_verify);
    if let Err(_) = response_mac.verify_slice(&ext_auth_response.data[32..32+8]) {
        return Err(Error::ResponseMac.into());
    }

    // decrypt
    let iv = [0u8; 8];
    let decryptor: cbc::Decryptor<TdesEde2> = cbc::Decryptor::new(&k_enc.into(), &iv.into());
    let decrypted_slice = decryptor.decrypt_padded::<NoPadding>(&mut ext_auth_response.data[0..32]).unwrap();

    let mut rnd_ic_second = [0u8; 8];
    let mut rnd_ifd_second = [0u8; 8];
    let mut k_ic = [0u8; 16];
    rnd_ic_second.copy_from_slice(&decrypted_slice[0..8]);
    rnd_ifd_second.copy_from_slice(&decrypted_slice[8..16]);
    k_ic.copy_from_slice(&decrypted_slice[16..32]);

    if rnd_ic != rnd_ic_second {
        return Err(Error::ValueMismatch { value: MismatchedValue::RndIc }.into());
    }
    if rnd_ifd != rnd_ifd_second {
        return Err(Error::ValueMismatch { value: MismatchedValue::RndIfd }.into());
    }

    let mut k_session_seed = [0u8; 16];
    for ((kss, kifd), kic) in k_session_seed.iter_mut().zip(rnd_ifd.iter()).zip(rnd_ic.iter()) {
        *kss = *kifd ^ *kic;
    }

    let k_session_enc = Kdf3Des::derive_encryption_key(&k_session_seed);
    let k_session_mac = Kdf3Des::derive_mac_key(&k_session_seed);

    let mut send_sequence_counter = [0u8; 8];
    send_sequence_counter[0..4].copy_from_slice(&rnd_ic[4..8]);
    send_sequence_counter[4..8].copy_from_slice(&rnd_ifd[4..8]);

    Ok(BacCard {
        card,
        k_session_enc,
        k_session_mac,
        send_sequence_counter,
    })
}
