use std::fmt;

use crate::iso7816::apdu;


#[derive(Debug)]
pub enum CommunicationError {
    Write(apdu::WriteError),
    Pcsc(pcsc::Error),
    ShortResponse,
}
impl fmt::Display for CommunicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(e) => write!(f, "APDU write error: {}", e),
            Self::Pcsc(e) => write!(f, "PCSC error: {}", e),
            Self::ShortResponse => write!(f, "response too short"),
        }
    }
}
impl std::error::Error for CommunicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Write(e) => Some(e),
            Self::Pcsc(e) => Some(e),
            Self::ShortResponse => None,
        }
    }
}
impl From<apdu::WriteError> for CommunicationError {
    fn from(value: apdu::WriteError) -> Self { Self::Write(value) }
}
impl From<pcsc::Error> for CommunicationError {
    fn from(value: pcsc::Error) -> Self { Self::Pcsc(value) }
}


/// A smart card compatible with ISO/IEC 7816.
pub trait SmartCard {
    /// Send a request APDU to the smart card and receive a response APDU.
    fn communicate(&self, request: &apdu::Apdu) -> Result<apdu::Response, CommunicationError>;
}
impl SmartCard for pcsc::Card {
    fn communicate(&self, request: &apdu::Apdu) -> Result<apdu::Response, CommunicationError> {
        let mut out_buf = Vec::new();
        request.write_bytes(&mut out_buf)?;
        let mut in_buf = vec![0u8; request.data.response_data_length() + 2];
        let in_slice = self.transmit(&out_buf, &mut in_buf)?;
        apdu::Response::from_slice(in_slice)
            .ok_or(CommunicationError::ShortResponse)
    }
}
