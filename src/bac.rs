//! Basic Access Control.


use std::fmt;

use crate::iso7816::card::{CommunicationError, SmartCard};
use crate::iso7816::apdu::{Apdu, CommandHeader, Data, Response};


#[derive(Debug)]
pub enum Error {
    GetChallengeCommunication(CommunicationError),
    GetChallengeFailed(Response),
    GetChallengeLengthMismatch {
        obtained: Vec<u8>,
        expected_length: usize,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::GetChallengeCommunication(e)
                => write!(f, "error communicating with card when performing GET CHALLENGE: {}", e),
            Self::GetChallengeFailed(r)
                => write!(f, "GET CHALLENGE failed with response code 0x{:04X}", r.trailer.to_word()),
            Self::GetChallengeLengthMismatch { obtained, expected_length }
                => write!(f, "GET CHALLENGE response has length {}, expected {}", obtained.len(), expected_length),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::GetChallengeCommunication(e) => Some(e),
            Self::GetChallengeFailed(_) => None,
            Self::GetChallengeLengthMismatch { .. } => None,
        }
    }
}


fn get_challenge<SC: SmartCard>(card: &SC) -> Result<[u8; 8], Error> {
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
    let response = card.communicate(&get_challenge_apdu)
        .map_err(|e| Error::GetChallengeCommunication(e))?;
    if response.trailer.to_word() != 0x9000 {
        return Err(Error::GetChallengeFailed(response));
    }
    if response.data.len() != 8 {
        return Err(Error::GetChallengeLengthMismatch {
            obtained: response.data,
            expected_length: 8,
        });
    }
    let mut ret = [0u8; 8];
    ret.copy_from_slice(response.data.as_slice());
    Ok(ret)
}
