use std::path::PathBuf;

use clap::Parser;
use icao_mrtd::iso7816::card::SmartCard;
use pcsc;


#[derive(Clone, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
enum Mode {
    ListReaders,
    Read(ReadOpts),
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
struct ReadOpts {
    #[arg(short, long = "reader", default_value = "0")]
    pub reader_index: usize,

    #[arg(short, long = "mrz")]
    pub mrz_path: PathBuf,

    #[arg(short, long)]
    pub bac: bool,
}


/// Selects the eMRTD application.
///
/// If BAC is to be used, this must happen before BAC is established. If PACE is to be used, this
/// can only be used after PACE is established.
fn select_emrtd(card: &mut Box<dyn SmartCard>) {
    let select_emrtd_app = icao_mrtd::iso7816::apdu::Apdu {
        header: icao_mrtd::iso7816::apdu::CommandHeader {
            cla: 0x00,
            ins: 0xA4, // SELECT
            p1: 0b000_001_00, // select by DF name (application identifier)
            p2: 0b0000_11_00, // return no metadata, return first or only occurrence
        },
        data: icao_mrtd::iso7816::apdu::Data::RequestDataShort {
            request_data: vec![0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01],
        },
    };
    let response = card.communicate(&select_emrtd_app)
        .expect("failed to SELECT eMRTD Application");
    if response.trailer.to_word() != 0x9000 {
        panic!("obtained response 0x{:04X} when SELECTing eMRTD Application", response.trailer.to_word());
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

    let (mrz_string, card_inner, use_bac) = match mode {
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

            let mrz_string = std::fs::read_to_string(&opts.mrz_path)
                .expect("failed to read MRZ")
                .trim()
                .to_owned();

            match ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
                Ok(c) => (mrz_string, c, opts.bac),
                Err(e) => panic!("failed to connect to card: {}", e),
            }
        },
    };
    let mut card: Box<dyn SmartCard> = Box::new(card_inner);

    // parse the MRZ
    let mrz: icao_mrtd::mrz::Data = mrz_string.parse()
        .expect("failed to parse MRZ");
    println!("MRZ validity check:");
    println!("  document no.: {}", mrz.is_document_number_valid());
    println!("  birth date:   {}", mrz.is_birth_date_valid());
    println!("  expiry date:  {}", mrz.is_expiry_date_valid());
    println!("  optional 1:   {:?}", mrz.is_optional_data_1_valid());
    println!("  composite:    {}", mrz.is_composite_valid());

    // try reading EF.CardAccess
    let select_card_access = icao_mrtd::iso7816::apdu::Apdu {
        header: icao_mrtd::iso7816::apdu::CommandHeader {
            cla: 0x00,
            ins: 0xA4, // SELECT
            p1: 0b000_010_00, // select from MF
            p2: 0b0000_00_00, // return basic metadata, return first or only occurrence
        },
        data: icao_mrtd::iso7816::apdu::Data::BothDataShort {
            request_data: vec![0x01, 0x1C],
            response_data_length: 255,
        },
    };

    let card_access = match icao_mrtd::iso7816::file::read_file(&mut card, &select_card_access) {
        Ok(card_access) => {
            println!("EF.CardAccess:");
            icao_mrtd::hexdump(&card_access);
            card_access
        },
        Err(e) => panic!("failed to read EF.CardAccess: {}", e),
    };

    let mut secure_card: Box<dyn SmartCard> = if use_bac {
        // select eMRTD Application (prerequisite for BAC)
        select_emrtd(&mut card);

        icao_mrtd::bac::establish(card, mrz.mrz_key().as_bytes())
            .expect("failed to establish BAC")
    } else {
        let mut pace: Box<dyn SmartCard> = icao_mrtd::pace::establish(card, &card_access, mrz.mrz_key().as_bytes())
            .expect("failed to establish PACE");

        // select eMRTD Application (may only happen after establishing PACE)
        select_emrtd(&mut pace);

        pace
    };

    /*
    // try reading EF.CardAccess through the encrypted channel
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
    match crate::iso7816::file::read_file(&mut bac, &select_card_access) {
        Ok(card_access) => {
            println!("EF.CardAccess:");
            hexdump(&card_access);
        },
        Err(e) => {
            panic!("failed to read EF.CardAccess: {}", e);
        },
    };
    */

    for file_index in 1..=16 {
        let select_file = icao_mrtd::iso7816::apdu::Apdu {
            header: icao_mrtd::iso7816::apdu::CommandHeader {
                cla: 0x00,
                ins: 0xA4, // SELECT
                p1: 0b000_000_10, // select EF under current DF
                p2: 0b0000_00_00, // return basic metadata, return first or only occurrence
            },
            data: icao_mrtd::iso7816::apdu::Data::BothDataExtended {
                request_data: vec![0x01, file_index],
                response_data_length: 0,
            },
        };
        match icao_mrtd::iso7816::file::read_file(&mut secure_card, &select_file) {
            Ok(bs) => {
                println!("EF.DG{}:", file_index);
                icao_mrtd::hexdump(&bs);
            },
            Err(e) => {
                eprintln!("failed to read EF.DG{}: {}", file_index, e);
            },
        };
    }
}
