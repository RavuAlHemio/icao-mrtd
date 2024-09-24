//! Implementation of Password Authenticated Connection Establishment.


pub mod asn1;


use std::fmt;

use rasn::types::{Any, ObjectIdentifier, Oid, SetOf};

use crate::der_util;
use crate::iso7816::apdu::{Apdu, CommandHeader, Data, Response};
use crate::iso7816::card::{CommunicationError, SmartCard};
use crate::pace::asn1::PaceInfo;


macro_rules! pace_oids {
    ($($name:ident => $($num:literal),+ $(,)?);+ $(;)?) => {
        $(
            pub const $name: &'static Oid = Oid::const_new(&[0, 4, 0, 127, 0, 7, 2, 2, 4, $($num),+]);
        )+
    };
}

pace_oids! {
    PACE_DH_GM_3DES_CBC_CBC => 1, 1;
    PACE_DH_GM_AES_CBC_CMAC_128 => 1, 2;
    PACE_DH_GM_AES_CBC_CMAC_192 => 1, 3;
    PACE_DH_GM_AES_CBC_CMAC_256 => 1, 4;

    PACE_ECDH_GM_3DES_CBC_CBC => 2, 1;
    PACE_ECDH_GM_AES_CBC_CMAC_128 => 2, 2;
    PACE_ECDH_GM_AES_CBC_CMAC_192 => 2, 3;
    PACE_ECDH_GM_AES_CBC_CMAC_256 => 2, 4;

    PACE_DH_IM_3DES_CBC_CBC => 3, 1;
    PACE_DH_IM_AES_CBC_CMAC_128 => 3, 2;
    PACE_DH_IM_AES_CBC_CMAC_192 => 3, 3;
    PACE_DH_IM_AES_CBC_CMAC_256 => 3, 4;

    PACE_ECDH_IM_3DES_CBC_CBC => 4, 1;
    PACE_ECDH_IM_AES_CBC_CMAC_128 => 4, 2;
    PACE_ECDH_IM_AES_CBC_CMAC_192 => 4, 3;
    PACE_ECDH_IM_AES_CBC_CMAC_256 => 4, 4;

    PACE_ECDH_CAM_AES_CBC_CMAC_128 => 6, 2;
    PACE_ECDH_CAM_AES_CBC_CMAC_192 => 6, 3;
    PACE_ECDH_CAM_AES_CBC_CMAC_256 => 6, 4;
}

pub const PACE_PROTOCOL_OIDS: [&'static Oid; 19] = [
    PACE_DH_GM_3DES_CBC_CBC, PACE_DH_GM_AES_CBC_CMAC_128,
    PACE_DH_GM_AES_CBC_CMAC_192, PACE_DH_GM_AES_CBC_CMAC_256,
    PACE_ECDH_GM_3DES_CBC_CBC, PACE_ECDH_GM_AES_CBC_CMAC_128,
    PACE_ECDH_GM_AES_CBC_CMAC_192, PACE_ECDH_GM_AES_CBC_CMAC_256,
    PACE_DH_IM_3DES_CBC_CBC, PACE_DH_IM_AES_CBC_CMAC_128,
    PACE_DH_IM_AES_CBC_CMAC_192, PACE_DH_IM_AES_CBC_CMAC_256,
    PACE_ECDH_IM_3DES_CBC_CBC, PACE_ECDH_IM_AES_CBC_CMAC_128,
    PACE_ECDH_IM_AES_CBC_CMAC_192, PACE_ECDH_IM_AES_CBC_CMAC_256,
    PACE_ECDH_CAM_AES_CBC_CMAC_128, PACE_ECDH_CAM_AES_CBC_CMAC_192,
    PACE_ECDH_CAM_AES_CBC_CMAC_256,
];


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    SetAuthenticationTemplate,
    ObtainNonce,
}


#[derive(Debug)]
pub enum Error {
    CardAccessDecoding(rasn::error::DecodeError),
    CardAccessEntryDecoding {
        entry_index: usize,
        error: rasn::error::DecodeError,
    },
    CardAccessEntryDecodingPace {
        entry_index: usize,
        error: rasn::error::DecodeError,
    },
    OperationFailed {
        operation: Operation,
        response: Response,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::CardAccessDecoding(e)
                => write!(f, "failed to decode EF.CardAccess: {}", e),
            Self::CardAccessEntryDecoding { entry_index, error }
                => write!(f, "failed to decode EF.CardAccess entry {}: {}", entry_index, error),
            Self::CardAccessEntryDecodingPace { entry_index, error }
                => write!(f, "failed to decode EF.CardAccess entry {} as PaceInfo: {}", entry_index, error),
            Self::OperationFailed { operation, response }
                => write!(f, "operation {:?} failed with response code 0x{:04X}", operation, response.trailer.to_word()),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CardAccessDecoding(_) => None,
            Self::CardAccessEntryDecoding { .. } => None,
            Self::CardAccessEntryDecodingPace { .. } => None,
            Self::OperationFailed { .. } => None,
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PasswordSource {
    Mrz,
    Can,
}


pub fn set_authentication_template<SC: SmartCard>(card: &mut SC, mechanism: &Oid, password_source: PasswordSource) -> Result<(), CommunicationError> {
    let mut request_data = Vec::new();

    // encode mechanism (0x80)
    let mechanism_bytes = der_util::oid_to_der_bytes(mechanism);
    request_data.push(0x80);
    der_util::encode_primitive_length(&mut request_data, mechanism_bytes.len());
    request_data.extend(&mechanism_bytes);

    // encode password source (0x83)
    request_data.push(0x83);
    request_data.push(0x01);
    match password_source {
        PasswordSource::Mrz => request_data.push(0x01),
        PasswordSource::Can => request_data.push(0x02),
    }

    // do it
    let request = Apdu {
        header: CommandHeader {
            cla: 0x00,
            ins: 0x22, // MANAGE SECURITY ENVIRONMENT
            p1: 0b1100_0001, // verify/encrypt/extauth, compute/decrypt/intauth, set
            p2: 0xA4, // control reference template for authentication
        },
        data: Data::RequestDataShort { request_data },
    };
    let response = card.communicate(&request)?;
    if response.trailer.to_word() == 0x9000 {
        Ok(())
    } else {
        Err(Error::OperationFailed {
            operation: Operation::SetAuthenticationTemplate,
            response,
        }.into())
    }
}


pub fn obtain_nonce<SC: SmartCard>(card: &mut SC) -> Result<Vec<u8>, CommunicationError> {
    let request_data = vec![
        0x7C, // dynamic authentication data
        0x00, // no data
    ];

    // do it
    let request = Apdu {
        header: CommandHeader {
            cla: 0b000_1_00_00, // not the last in a chain, no secure messaging, logical channel 0
            ins: 0x86, // GENERAL AUTHENTICATE
            p1: 0x00, // algorithm is known (from "set authentication template")
            p2: 0x00, // key index is known (from "set authentication template")
        },
        data: Data::BothDataShort {
            request_data,
            response_data_length: 0,
        },
    };
    let response = card.communicate(&request)?;
    if response.trailer.to_word() == 0x9000 {
        Ok(response.data)
    } else {
        Err(Error::OperationFailed {
            operation: Operation::ObtainNonce,
            response,
        }.into())
    }
}


/// Authenticates with the card using PACE.
pub fn establish(card: &pcsc::Card, card_access: &[u8]) -> Result<(), Error> {
    // card_access is the data in EF.CardAccess, which is DER-encoded

    // try to decode its base structure as a SET OF Any (SetOf<Any>)
    let security_infos: SetOf<Any> = rasn::der::decode(card_access)
        .map_err(|e| Error::CardAccessDecoding(e))?;

    // now try to decode each of its entries as a SEQUENCE OF Any (Vec<Any>)
    for (entry_index, security_info) in security_infos.to_vec().into_iter().enumerate() {
        let security_info_seq: Vec<Any> = rasn::der::decode(security_info.as_bytes())
            .map_err(|error| Error::CardAccessEntryDecoding { entry_index, error })?;
        if security_info_seq.len() < 1 {
            // assume invalid structure and skip
            // FIXME: return an error instead?
            continue;
        }
        let Ok(security_info_oid): Result<ObjectIdentifier, _> = rasn::der::decode(security_info_seq[0].as_bytes()) else {
            // assume invalid structure and skip
            // FIXME: return an error instead?
            continue;
        };
        if !PACE_PROTOCOL_OIDS.contains(&&*security_info_oid) {
            // not relevant
            continue;
        }

        // try to decode the whole thing as a PaceInfo now
        let pace_info: PaceInfo = rasn::der::decode(security_info.as_bytes())
            .map_err(|error| Error::CardAccessEntryDecodingPace { entry_index, error })?;
        println!("{:#?}", pace_info);
    }
    todo!();
}
