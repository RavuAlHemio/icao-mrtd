mod iso7816;


use std::fmt;

use clap::Parser;
use pcsc;


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
enum Mode {
    ListReaders,
    Read(ReadOpts),
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
struct ReadOpts {
    #[arg(short, long = "reader", default_value = "0")]
    pub reader_index: usize,
}


fn hexdump(buf: &[u8]) {
    let mut offset = 0;
    while offset < buf.len() {
        print!("{:08X}  ", offset);

        for i in 0..16 {
            if offset + i < buf.len() {
                print!(" {:02X}", buf[offset + i]);
            } else {
                print!("   ");
            }
        }

        print!(" |");
        for i in 0..16 {
            if offset + i >= buf.len() {
                break;
            }

            let b = buf[offset + i];
            if b >= b' ' && b <= b'~' {
                print!("{}", char::from_u32(b.into()).unwrap());
            } else {
                print!(".");
            }
        }
        println!("|");

        offset += 16;
    }
}

#[derive(Debug)]
enum CommunicationError {
    Write(iso7816::apdu::WriteError),
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
impl From<iso7816::apdu::WriteError> for CommunicationError {
    fn from(value: iso7816::apdu::WriteError) -> Self { Self::Write(value) }
}
impl From<pcsc::Error> for CommunicationError {
    fn from(value: pcsc::Error) -> Self { Self::Pcsc(value) }
}

fn communicate(card: &pcsc::Card, request: &iso7816::apdu::Apdu) -> Result<iso7816::apdu::Response, CommunicationError> {
    let mut out_buf = Vec::new();
    request.write_bytes(&mut out_buf)?;
    let mut in_buf = vec![0u8; request.data.response_data_length() + 2];
    let in_slice = card.transmit(&out_buf, &mut in_buf)?;
    iso7816::apdu::Response::from_slice(in_slice)
        .ok_or(CommunicationError::ShortResponse)
}


fn main() {
    let mode = Mode::parse();

    let ctx = pcsc::Context::establish(pcsc::Scope::User)
        .expect("failed to establish PC/SC user context");

    let readers_buf_len = ctx.list_readers_len()
        .expect("failed to obtain length of buffer for PC/SC reader list");
    let mut readers_buf = vec![0u8; readers_buf_len];
    let mut readers = ctx.list_readers(&mut readers_buf)
        .expect("failed to list PC/SC readers");

    let card = match mode {
        Mode::ListReaders => {
            for (i, reader) in readers.enumerate() {
                println!("{}: {:?}", i, reader);
            }
            return;
        },
        Mode::Read(opts) => {
            let Some(reader) = readers.nth(opts.reader_index) else {
                panic!("no reader at index {}", opts.reader_index)
            };

            match ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
                Ok(c) => c,
                Err(e) => panic!("failed to connect to card: {}", e),
            }
        },
    };

    // try reading EF.CardAccess
    let card_access = communicate(
        &card,
        &iso7816::apdu::Apdu {
            header: iso7816::apdu::CommandHeader {
                cla: 0x00,
                ins: 0xA4, // SELECT
                p1: 0b000_010_00, // select from MF
                p2: 0b0000_00_00, // return basic metadata, return first or only occurrence
            },
            data: iso7816::apdu::Data::BothDataShort {
                request_data: vec![0x01, 0x1C],
                response_data_length: 255,
            },
        }
    )
        .expect("failed to select EF.CardAccess");
    let card_access_metadata = iso7816::file::decode_metadata_entries(&card_access.data)
        .expect("failed to decode EF.CardAccess metadata");
    println!("trailer: 0x{:04X}", card_access.trailer.to_word());
    if card_access.trailer.to_word() == 0x9000 || card_access.trailer.to_word() == 0x6282 {
        // try to fish out the length
        let length_bytes = card_access_metadata
            .iter()
            .filter_map(|me| if let iso7816::file::MetadataEntry::FileLengthWithoutStructural { length_bytes } = me { Some(length_bytes) } else { None })
            .nth(0).expect("EF.CardAccess does not have a length");
        let mut response_data_length: u16 = 0;
        for &b in length_bytes {
            response_data_length = response_data_length.checked_mul(0x100).expect("length too great");
            response_data_length += u16::from(b);
        }
        println!("EF.CardAccess length: {}", response_data_length);
        let card_access_content = communicate(
            &card,
            &iso7816::apdu::Apdu {
                header: iso7816::apdu::CommandHeader {
                    cla: 0x00,
                    ins: 0xB0, // READ BINARY, offset or short EF identifier
                    p1: 0x00, // offset in curEF, offset 0
                    p2: 0x00, // continued: offset 0
                },
                data: iso7816::apdu::Data::ResponseDataExtended {
                    response_data_length,
                },
            }
        )
            .expect("failed to read EF.CardAccess");
        println!("read EF.CardAccess response: {:?}", card_access_content);
    }

    // select application LDS1 eMRTD (A0 00 00 02 47 10 01)
    let select_mf = iso7816::apdu::Apdu {
        header: iso7816::apdu::CommandHeader {
            cla: 0x00,
            ins: 0xA4, // SELECT
            p1: 0b000_001_00, // select by DF name
            p2: 0b0000_00_00, // return FCI template, return first or only occurrence
        },
        data: iso7816::apdu::Data::BothDataShort {
            request_data: vec![0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01],
            response_data_length: 0,
        },
    };
    let mut out_buf = Vec::new();
    select_mf.write_bytes(&mut out_buf)
        .expect("failed to prepare SELECT LDS1 eMRTD buffer");
    let mut in_buf = [0u8; 256 + 2];

    let in_slice = card.transmit(&out_buf, &mut in_buf)
        .expect("failed to transmit SELECT LDS1 eMRTD");
    println!("SELECT LDS1 eMRTD response:");
    hexdump(&in_slice);

    // select EF.COM file
    let select_mf = iso7816::apdu::Apdu {
        header: iso7816::apdu::CommandHeader {
            cla: 0x00,
            ins: 0xA4, // SELECT
            p1: 0b000_000_10, // select EF under current DF
            p2: 0b0000_11_00, // return no metadata, return first or only occurrence
        },
        data: iso7816::apdu::Data::RequestDataShort {
            request_data: vec![0x01, 0x1E], // EF.COM
        },
    };
    let mut out_buf = Vec::new();
    select_mf.write_bytes(&mut out_buf)
        .expect("failed to prepare SELECT EF.COM buffer");
    let mut in_buf = [0u8; 2];

    let in_slice = card.transmit(&out_buf, &mut in_buf)
        .expect("failed to transmit SELECT EF.COM");
    println!("SELECT EF.COM response:");
    hexdump(&in_slice);
}
