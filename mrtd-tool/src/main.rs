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

    let (mrz_string, mut card) = match mode {
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
                Ok(c) => (mrz_string, c),
                Err(e) => panic!("failed to connect to card: {}", e),
            }
        },
    };

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

    /*
    // select eMRTD Application (prerequisite for BAC)
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

    let mut bac = icao_mrtd::bac::establish(&mut card, mrz.mrz_key().as_bytes())
        .expect("failed to establish BAC");
    */

    let mut pace = icao_mrtd::pace::establish(&mut card, &card_access, mrz.mrz_key().as_bytes())
        .expect("failed to establish PACE");

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

    // try reading EF.COM through the encrypted channel
    let select_com = icao_mrtd::iso7816::apdu::Apdu {
        header: icao_mrtd::iso7816::apdu::CommandHeader {
            cla: 0x00,
            ins: 0xA4, // SELECT
            p1: 0b000_000_10, // select EF under current DF
            p2: 0b0000_00_00, // return basic metadata, return first or only occurrence
        },
        data: icao_mrtd::iso7816::apdu::Data::BothDataShort {
            request_data: vec![0x01, 0x1E],
            response_data_length: 0,
        },
    };
    //match icao_mrtd::iso7816::file::read_file(&mut bac, &select_com) {
    match icao_mrtd::iso7816::file::read_file(&mut pace, &select_com) {
        Ok(com) => {
            println!("EF.COM:");
            icao_mrtd::hexdump(&com);
        },
        Err(e) => {
            panic!("failed to read EF.COM: {}", e);
        },
    };
}
