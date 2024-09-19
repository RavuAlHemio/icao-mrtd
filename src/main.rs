mod iso7816;
mod pace;


use std::convert::Infallible;

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
    let select_card_access = iso7816::apdu::Apdu {
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
    };

    let mut authenticated = false;
    match crate::iso7816::file::read_file(&card, &select_card_access) {
        Ok(card_access) => {
            crate::pace::establish(&card, &card_access)
                .expect("failed to establish PACE");
            authenticated = true;
        },
        Err(crate::iso7816::file::ReadError::FileNotFound) => {
            // fall through to Basic Access Control
        },
        Err(e) => {
            panic!("failed to read EF.CardAccess: {}", e);
        },
    };

    if !authenticated {
        authenticated = establish_bac(&card)
            .expect("failed to establish BAC");
    }
}

/// Authenticates with the card using BAC. Returns whether authentication succeded.
fn establish_bac(card: &pcsc::Card) -> Result<bool, Infallible> {
    // TODO
    Ok(false)
}
