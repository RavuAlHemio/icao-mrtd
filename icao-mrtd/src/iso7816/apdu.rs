//! Structures related to application protocol data units (APDUs).


use std::fmt;
use std::io::{self, Write};


#[derive(Debug)]
pub enum WriteError {
    Io(io::Error),
    EmptyData,
    DataTooLong { maximum: usize, obtained: usize },
}
impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::EmptyData => write!(f, "data is, but must not be, empty"),
            Self::DataTooLong { maximum, obtained } => write!(f, "too much data: obtained {} bytes, expected maximum {} bytes", obtained, maximum),
        }
    }
}
impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::EmptyData => None,
            Self::DataTooLong { .. } => None,
        }
    }
}
impl From<io::Error> for WriteError {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}


#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommandHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
}
impl CommandHeader {
    pub const fn to_bytes(&self) -> [u8; 4] {
        [self.cla, self.ins, self.p1, self.p2]
    }

    pub const fn to_be_u32(&self) -> u32 {
        ((self.cla as u32) << 24)
        | ((self.ins as u32) << 16)
        | ((self.p1 as u32) <<  8)
        | ((self.p2 as u32) <<  0)
    }

    pub fn write_bytes<W: Write>(&self, writer: &mut W) -> Result<(), WriteError> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        Ok(())
    }
}
impl fmt::Debug for CommandHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommandHeader {} cla: 0x{:02X}, ins: 0x{:02X}, p1: 0x{:02X}, p2: 0x{:02X} {}",
            '{', self.cla, self.ins, self.p1, self.p2, '}',
        )
    }
}

#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResponseTrailer {
    pub sw1: u8,
    pub sw2: u8,
}
impl ResponseTrailer {
    pub const fn new(sw1: u8, sw2: u8) -> Self {
        Self {
            sw1,
            sw2,
        }
    }

    pub const fn to_bytes(&self) -> [u8; 2] {
        [self.sw1, self.sw2]
    }

    pub const fn to_word(&self) -> u16 {
        u16::from_be_bytes([self.sw1, self.sw2])
    }

    pub fn write_bytes<W: Write>(&self, writer: &mut W) -> Result<(), WriteError> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        Ok(())
    }
}
impl fmt::Debug for ResponseTrailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResponseTrailer {} sw1: 0x{:02X}, sw2: 0x{:02X} {}", '{', self.sw1, self.sw2, '}')
    }
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Data {
    NoData,
    RequestDataShort {
        request_data: Vec<u8>,
    },
    RequestDataExtended {
        request_data: Vec<u8>,
    },
    ResponseDataShort {
        response_data_length: u8,
    },
    ResponseDataExtended {
        response_data_length: u16,
    },
    BothDataShort {
        request_data: Vec<u8>,
        response_data_length: u8,
    },
    BothDataExtended {
        request_data: Vec<u8>,
        response_data_length: u16,
    },
}
impl Data {
    pub fn response_data_length(&self) -> Option<usize> {
        match self {
            Self::NoData => None,
            Self::RequestDataShort { .. } => None,
            Self::RequestDataExtended { .. } => None,
            Self::ResponseDataShort { response_data_length } => Some((*response_data_length).try_into().unwrap()),
            Self::ResponseDataExtended { response_data_length } => Some((*response_data_length).try_into().unwrap()),
            Self::BothDataShort { response_data_length, .. } => Some((*response_data_length).try_into().unwrap()),
            Self::BothDataExtended { response_data_length, .. } => Some((*response_data_length).try_into().unwrap()),
        }
    }

    pub fn request_data(&self) -> Option<&[u8]> {
        match self {
            Self::NoData => None,
            Self::RequestDataShort { request_data } => Some(request_data.as_slice()),
            Self::RequestDataExtended { request_data } => Some(request_data.as_slice()),
            Self::ResponseDataShort { .. } => None,
            Self::ResponseDataExtended { .. } => None,
            Self::BothDataShort { request_data, .. } => Some(request_data.as_slice()),
            Self::BothDataExtended { request_data, .. } => Some(request_data.as_slice()),
        }
    }

    pub fn write_bytes<W: Write>(&self, writer: &mut W) -> Result<(), WriteError> {
        fn ensure_not_empty(request_data: &Vec<u8>) -> Result<(), WriteError> {
            if request_data.len() == 0 {
                Err(WriteError::EmptyData)
            } else {
                Ok(())
            }
        }
        fn ensure_max_length(request_data: &Vec<u8>, max_length: usize) -> Result<(), WriteError> {
            if request_data.len() > max_length {
                Err(WriteError::DataTooLong { maximum: max_length, obtained: request_data.len() })
            } else {
                Ok(())
            }
        }

        match self {
            // "case" refers to the cases in ISO/IEC 7816-3:2006 § 12.1.3
            Data::NoData => {
                // case 1
                Ok(())
            },
            Data::RequestDataShort { request_data } => {
                // case 3S
                ensure_not_empty(request_data)?;
                ensure_max_length(request_data, 256)?;

                let length_byte = if request_data.len() == 256 {
                    0x00
                } else {
                    request_data.len().try_into().unwrap()
                };

                // [Lc] [Data]
                writer.write_all(&[length_byte])?;
                writer.write_all(request_data)?;
                Ok(())
            },
            Data::RequestDataExtended { request_data } => {
                // case 3E
                ensure_not_empty(request_data)?;
                ensure_max_length(request_data, 65536)?;

                let length_word: u16 = if request_data.len() == 65536 {
                    0x0000
                } else {
                    request_data.len().try_into().unwrap()
                };
                let length_bytes = length_word.to_be_bytes();

                // [0x00] [LcMSB] [LcLSB] [Data]
                writer.write_all(&[0x00, length_bytes[0], length_bytes[1]])?;
                writer.write_all(request_data)?;
                Ok(())
            },
            Data::ResponseDataShort { response_data_length } => {
                // case 2S
                // [Le]
                writer.write_all(&[*response_data_length])?;
                Ok(())
            },
            Data::ResponseDataExtended { response_data_length } => {
                // case 2E
                // [0x00] [LeMSB] [LeLSB]
                let length_bytes = response_data_length.to_be_bytes();
                writer.write_all(&[0x00, length_bytes[0], length_bytes[1]])?;
                Ok(())
            },
            Data::BothDataShort { request_data, response_data_length } => {
                // case 4S
                ensure_not_empty(request_data)?;
                ensure_max_length(request_data, 256)?;

                let length_byte = if request_data.len() == 256 {
                    0x00
                } else {
                    request_data.len().try_into().unwrap()
                };

                // [Lc] [Data] [Le]
                writer.write_all(&[length_byte])?;
                writer.write_all(request_data)?;
                writer.write_all(&[*response_data_length])?;
                Ok(())
            },
            Data::BothDataExtended { request_data, response_data_length } => {
                // case 4E
                ensure_not_empty(request_data)?;
                ensure_max_length(request_data, 65536)?;

                let request_length_word: u16 = if request_data.len() == 65536 {
                    0x0000
                } else {
                    request_data.len().try_into().unwrap()
                };
                let request_length_bytes = request_length_word.to_be_bytes();
                let response_length_bytes = response_data_length.to_be_bytes();

                // [0x00] [LcMSB] [LcLSB] [Data] [LeMSB] [LeLSB]
                writer.write_all(&[0x00, request_length_bytes[0], request_length_bytes[1]])?;
                writer.write_all(request_data)?;
                writer.write_all(&response_length_bytes)?;
                Ok(())
            },
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Apdu {
    pub header: CommandHeader,
    pub data: Data,
}
impl Apdu {
    pub fn write_bytes<W: Write>(&self, writer: &mut W) -> Result<(), WriteError> {
        self.header.write_bytes(writer)?;
        self.data.write_bytes(writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Response {
    pub data: Vec<u8>,
    pub trailer: ResponseTrailer,
}
impl Response {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }

        let data = bytes[..bytes.len() - 2].to_vec();
        let trailer = ResponseTrailer {
            sw1: bytes[bytes.len() - 2],
            sw2: bytes[bytes.len() - 1],
        };
        Some(Self {
            data,
            trailer,
        })
    }
}
