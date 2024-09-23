use std::fmt;

use pcsc::Card;

use crate::iso7816::apdu;
use crate::iso7816::card::{CommunicationError, SmartCard};


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetadataEntry {
    FileLengthWithoutStructural { length_bytes: Vec<u8> },
    FileLengthWithStructural { length_bytes: Vec<u8> },
    Descriptor {
        descriptor: FileDescriptor,
        coding: Option<DataCoding>,
        max_record_size: Option<u16>,
        record_count: Option<u16>,
    },
    FileIdentifier { identifier: u16 },
    DfName { name: Vec<u8> },
    ShortEfIdentifier { identifier: Option<u8> },
    LifecycleStatus { status: LifecycleStatus },
    DfList { dfs: Vec<u16> },
    EfList { efs: Vec<(u16, u8)> },
    Other { tag: u8, data: Vec<u8> },
}

macro_rules! fd_ensure_not_rfu {
    ($byte:expr) => {
        if $byte & 0b10_000_000 == 0b10_000_000 {
            return None;
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum FileType {
    /// Dedicated File (directory file)
    Df,

    /// Elementary File whose data is not interpreted by the card
    EfWorking,

    /// Elementary File whose data is interpreted by the card
    EfInternal,

    /// A proprietary kind of Elementary File.
    OtherEf(u8),
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum FileStructure {
    NoInformation,
    Transparent,
    LinearFixedSize,
    LinearFixedSizeTlv,
    LinearVariableSize,
    LinearVariableSizeTlv,
    CyclicFixedSize,
    CyclicFixedSizeTlv,
    BerTlv,
    SimpleTlv,
}

#[derive(Clone, Copy, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileDescriptor(pub u8);
impl FileDescriptor {
    pub const fn is_shareable(&self) -> Option<bool> {
        fd_ensure_not_rfu!(self.0);
        Some(self.0 & 0b01_000_000 != 0)
    }

    pub const fn file_type(&self) -> Option<FileType> {
        fd_ensure_not_rfu!(self.0);
        match self.0 & 0b00_111_000 {
            0b00_111_000 => {
                // DF?
                if self.0 & 0b00_111_111 == 0b00_111_000 {
                    Some(FileType::Df)
                } else {
                    // not actually
                    None
                }
            },
            0b00_000_000 => Some(FileType::EfWorking),
            0b00_001_000 => Some(FileType::EfInternal),
            other => Some(FileType::OtherEf((other >> 3) & 0b111))
        }
    }

    pub const fn file_structure(&self) -> Option<FileStructure> {
        fd_ensure_not_rfu!(self.0);
        if self.0 & 0b00_111_000 == 0b00_111_000 {
            // DF
            match self.0 & 0b00_000_111 {
                0b00_000_001 => Some(FileStructure::BerTlv),
                0b00_000_010 => Some(FileStructure::SimpleTlv),
                _ => None,
            }
        } else {
            match self.0 & 0b00_000_111 {
                0b00_000_000 => Some(FileStructure::NoInformation),
                0b00_000_001 => Some(FileStructure::Transparent),
                0b00_000_010 => Some(FileStructure::LinearFixedSize),
                0b00_000_011 => Some(FileStructure::LinearFixedSizeTlv),
                0b00_000_100 => Some(FileStructure::LinearVariableSize),
                0b00_000_101 => Some(FileStructure::LinearVariableSizeTlv),
                0b00_000_110 => Some(FileStructure::CyclicFixedSize),
                0b00_000_111 => Some(FileStructure::CyclicFixedSizeTlv),
                _ => unreachable!(),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum WriteBehavior {
    OneTime,
    Proprietary,
    WriteOr,
    WriteAnd,
}

#[derive(Clone, Copy, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct DataCoding(u8);
impl DataCoding {
    pub const fn supports_ber_tlv_efs(&self) -> bool {
        self.0 & 0b1_00_0_0000 != 0
    }

    pub const fn write_behavior(&self) -> WriteBehavior {
        match self.0 & 0b0_11_0_0000 {
            0b0_00_0_0000 => WriteBehavior::OneTime,
            0b0_01_0_0000 => WriteBehavior::Proprietary,
            0b0_10_0_0000 => WriteBehavior::WriteOr,
            0b0_11_0_0000 => WriteBehavior::WriteAnd,
            _ => unreachable!(),
        }
    }

    pub const fn is_ber_tlv_tag_0xff_valid(&self) -> bool {
        self.0 & 0b0_00_1_0000 != 0
    }

    /// Size of one data unit, expressed in the power-of-two of quartets
    /// (four-bit units, nybbles).
    ///
    /// Examples:
    /// * value 1 = 2**1 quartets = 2 quartets = 1 byte (octet)
    /// * value 4 = 2**4 quartets = 16 quartets = 8 bytes (octets)
    pub const fn data_unit_size_2pow_quartets(&self) -> u8 {
        self.0 & 0b0_00_0_1111
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecycleStatus {
    NoInformation,
    Created,
    Initialized,
    OperationalActivated(u8),
    OperationalDeactivated(u8),
    Terminated(u8),
    Proprietary(u8),
    Rfu(u8),
}
impl From<u8> for LifecycleStatus {
    fn from(value: u8) -> Self {
        if value == 0b0000_0000 {
            Self::NoInformation
        } else if value == 0b0000_0001 {
            Self::Created
        } else if value == 0b0000_0011 {
            Self::Initialized
        } else if value & 0b1111_1101 == 0b0000_0101 {
            Self::OperationalActivated(value)
        } else if value & 0b1111_1101 == 0b0000_0100 {
            Self::OperationalDeactivated(value)
        } else if value & 0b1111_1100 == 0b0000_1100 {
            Self::Terminated(value)
        } else if value & 0b1111_0000 != 0b0000_0000 {
            Self::Proprietary(value)
        } else {
            Self::Rfu(value)
        }
    }
}

#[derive(Debug)]
pub enum ReadError {
    SelectCommunication(CommunicationError),
    FileNotFound,
    SelectFailed(apdu::Response),
    MetadataDecoding,
    UnknownLength,
    ReadCommunication(CommunicationError),
    ReadFailed(apdu::Response),
}
impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::SelectCommunication(e)
                => write!(f, "SELECT communication failed: {}", e),
            Self::FileNotFound
                => write!(f, "file not found"),
            Self::SelectFailed(response)
                => write!(f, "SELECT operation failed with status code 0x{:04X}", response.trailer.to_word()),
            Self::MetadataDecoding
                => write!(f, "metadata decoding failed"),
            Self::UnknownLength
                => write!(f, "file has unknown length"),
            Self::ReadCommunication(e)
                => write!(f, "READ BINARY communication failed: {}", e),
            Self::ReadFailed(response)
                => write!(f, "READ BINARY operation failed with status code 0x{:04X}", response.trailer.to_word()),
        }
    }
}
impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SelectCommunication(e) => Some(e),
            Self::FileNotFound => None,
            Self::SelectFailed(_response) => None,
            Self::MetadataDecoding => None,
            Self::UnknownLength => None,
            Self::ReadCommunication(e) => Some(e),
            Self::ReadFailed(_response) => None,
        }
    }
}

pub fn decode_metadata_entries(buf: &[u8]) -> Option<Vec<MetadataEntry>> {
    let mut remaining_slice = buf;

    // metadata has to start with 0x62, 0x64 or 0x6F
    if remaining_slice.len() < 2 {
        return None;
    }
    if remaining_slice[0] != 0x62 && remaining_slice[0] != 0x64 && remaining_slice[0] != 0x6F {
        return None;
    }

    // get length of metadata
    let metadata_length: usize = remaining_slice[1].try_into().unwrap();
    remaining_slice = &remaining_slice[2..];
    if metadata_length > remaining_slice.len() {
        // not enough data
        return None;
    }

    let mut entries = Vec::new();
    while remaining_slice.len() >= 2 {
        let tag = remaining_slice[0];
        let length: usize = remaining_slice[1].try_into().unwrap();
        remaining_slice = &remaining_slice[2..];
        if length > remaining_slice.len() {
            // not enough data
            return None;
        }
        let data_slice = &remaining_slice[0..length];
        remaining_slice = &remaining_slice[length..];

        let entry = match tag {
            0x80 => MetadataEntry::FileLengthWithoutStructural { length_bytes: data_slice.to_vec() },
            0x81 => MetadataEntry::FileLengthWithStructural { length_bytes: data_slice.to_vec() },
            0x82 => {
                if data_slice.len() < 1 || data_slice.len() > 6 {
                    continue;
                }

                MetadataEntry::Descriptor {
                    descriptor: FileDescriptor(data_slice[0]),
                    coding: if data_slice.len() > 1 { Some(DataCoding(data_slice[1])) } else { None },
                    max_record_size: if data_slice.len() == 3 {
                        Some(data_slice[2].into())
                    } else if data_slice.len() > 3 {
                        Some(u16::from_be_bytes([data_slice[2], data_slice[3]]))
                    } else {
                        None
                    },
                    record_count: if data_slice.len() == 5 {
                        Some(data_slice[4].into())
                    } else if data_slice.len() > 5 {
                        Some(u16::from_be_bytes([data_slice[4], data_slice[5]]))
                    } else {
                        None
                    },
                }
            },
            0x83 => {
                if data_slice.len() != 2 {
                    continue;
                }
                MetadataEntry::FileIdentifier {
                    identifier: u16::from_be_bytes([data_slice[0], data_slice[1]]),
                }
            },
            0x84 => {
                if data_slice.len() > 16 {
                    continue;
                }
                MetadataEntry::DfName { name: data_slice.to_vec() }
            },
            0x88 => {
                if data_slice.len() > 1 {
                    continue;
                }
                MetadataEntry::ShortEfIdentifier { identifier: data_slice.get(0).copied() }
            },
            0x8A => {
                if data_slice.len() != 1 {
                    continue;
                }
                MetadataEntry::LifecycleStatus { status: LifecycleStatus::from(data_slice[0]) }
            },
            0x97 => {
                if data_slice.len() % 2 != 0 {
                    continue;
                }
                let mut dfs = Vec::with_capacity(data_slice.len() / 2);
                for df in data_slice.chunks(2) {
                    dfs.push(u16::from_be_bytes([df[0], df[1]]));
                }
                MetadataEntry::DfList { dfs }
            },
            0x9B => {
                if data_slice.len() % 3 != 0 {
                    continue;
                }
                let mut efs = Vec::with_capacity(data_slice.len() / 3);
                for ef in data_slice.chunks(3) {
                    efs.push((u16::from_be_bytes([ef[0], ef[1]]), ef[2]));
                }
                MetadataEntry::EfList { efs }
            },
            other => MetadataEntry::Other { tag: other, data: data_slice.to_vec() },
        };
        entries.push(entry);
    }

    Some(entries)
}

pub fn read_file<SC: SmartCard>(card: &mut SC, select_apdu: &apdu::Apdu) -> Result<Vec<u8>, ReadError> {
    use crate::iso7816::file::MetadataEntry;

    // select the file
    let select_response = card.communicate(select_apdu)
        .map_err(|e| ReadError::SelectCommunication(e))?;
    if select_response.trailer.to_word() == 0x6A82 {
        return Err(ReadError::FileNotFound);
    }
    if select_response.trailer.to_word() != 0x9000 && select_response.trailer.to_word() != 0x6282 {
        return Err(ReadError::SelectFailed(select_response));
    }
    let file_metadata = crate::iso7816::file::decode_metadata_entries(&select_response.data)
        .ok_or(ReadError::MetadataDecoding)?;

    // try to fish out the length
    let length_bytes = file_metadata
        .iter()
        .filter_map(|me| if let MetadataEntry::FileLengthWithoutStructural { length_bytes } = me { Some(length_bytes) } else { None })
        .nth(0).ok_or(ReadError::UnknownLength)?;
    let mut response_data_length: u16 = 0;
    for &b in length_bytes {
        response_data_length = response_data_length.checked_mul(0x100).expect("length too great");
        response_data_length += u16::from(b);
    }
    let read_response = card.communicate(
        &apdu::Apdu {
            header: apdu::CommandHeader {
                cla: 0x00,
                ins: 0xB0, // READ BINARY, offset or short EF identifier
                p1: 0x00, // offset in curEF, offset 0
                p2: 0x00, // continued: offset 0
            },
            data: apdu::Data::ResponseDataExtended {
                response_data_length,
            },
        }
    )
        .map_err(|e| ReadError::ReadCommunication(e))?;
    if read_response.trailer.to_word() != 0x9000 {
        return Err(ReadError::ReadFailed(read_response));
    }
    Ok(read_response.data)
}
