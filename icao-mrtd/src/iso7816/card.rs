use std::fmt;

use crate::iso7816::apdu;
use crate::pace;
use crate::secure_messaging;


#[derive(Debug)]
pub enum CommunicationError {
    Write(apdu::WriteError),
    Pcsc(pcsc::Error),
    ShortResponse,
    SecureMessaging(secure_messaging::Error),
    Pace(pace::Error),
}
impl fmt::Display for CommunicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(e) => write!(f, "APDU write error: {}", e),
            Self::Pcsc(e) => write!(f, "PCSC error: {}", e),
            Self::ShortResponse => write!(f, "response too short"),
            Self::SecureMessaging(e) => write!(f, "Secure Messaging error: {}", e),
            Self::Pace(e) => write!(f, "PACE error: {}", e),
        }
    }
}
impl std::error::Error for CommunicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Write(e) => Some(e),
            Self::Pcsc(e) => Some(e),
            Self::ShortResponse => None,
            Self::SecureMessaging(e) => Some(e),
            Self::Pace(e) => Some(e),
        }
    }
}
impl From<apdu::WriteError> for CommunicationError {
    fn from(value: apdu::WriteError) -> Self { Self::Write(value) }
}
impl From<pcsc::Error> for CommunicationError {
    fn from(value: pcsc::Error) -> Self { Self::Pcsc(value) }
}
impl From<secure_messaging::Error> for CommunicationError {
    fn from(value: secure_messaging::Error) -> Self { Self::SecureMessaging(value) }
}
impl From<pace::Error> for CommunicationError {
    fn from(value: pace::Error) -> Self { Self::Pace(value) }
}


/// A smart card compatible with ISO/IEC 7816.
pub trait SmartCard {
    /// Send a request APDU to the smart card and receive a response APDU.
    fn communicate(&mut self, request: &apdu::Apdu) -> Result<apdu::Response, CommunicationError>;
}
impl SmartCard for pcsc::Card {
    fn communicate(&mut self, request: &apdu::Apdu) -> Result<apdu::Response, CommunicationError> {
        let mut out_buf = Vec::new();
        request.write_bytes(&mut out_buf)?;
        println!("sending to card:");
        crate::hexdump(&out_buf);
        let mut in_buf = vec![0u8; request.data.response_data_length().unwrap_or(0) + 2];
        let in_slice = self.transmit(&out_buf, &mut in_buf)?;
        println!("received from card:");
        crate::hexdump(&in_slice);
        apdu::Response::from_slice(in_slice)
            .ok_or(CommunicationError::ShortResponse)
    }
}
