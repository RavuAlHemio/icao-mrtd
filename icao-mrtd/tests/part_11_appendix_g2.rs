use hex_literal::hex;
use icao_mrtd::iso7816::apdu::{Apdu, Response, ResponseTrailer};
use icao_mrtd::iso7816::card::SmartCard;
use icao_mrtd::pace::crypt::{boxed_uint_from_be_slice, KeyExchange};
use icao_mrtd::pace::PasswordSource;
use rasn::types::Oid;


/// A fake smart card that acts exactly like the card in ICAO Doc 9303 Part 11 Appendix G.2.
///
/// If any of its expectations are not met, it responds with 0x69 0x88.
struct AppendixG2Card {
    state: u8,
}
impl AppendixG2Card {
    const EXPECTED_MSE_SET_AT_PAYLOAD: [u8; 15] = hex!("80 0A 04 00 7F 00 07 02 02 04 01 02 83 01 01");
    const EXPECTED_GA_INITIAL_PAYLOAD: [u8; 2] = hex!("7C 00");
    const GA_INITIAL_RESPONSE: [u8; 20] = hex!("7C 12 80 10 85 4D 8D F5 82 7F A6 85 2D 1A 4F A7 01 CD DD CA");
    const EXPECTED_GA_MAPPING_PAYLOAD: [u8; 134] = hex!("
        7C 81 83 81 81 80 23 FB 37 49 EA 03 0D 2A 25 B2 78 D2 A5
        62 04 7A DE 3F 01 B7 4F 17 A1 54 02 CB 73 52 CA 7D 2B 3E B7 1C 34 3D B1
        3D 1D EB CE 9A 36 66 DB CF C9 20 B4 91 74 A6 02 CB 47 96 5C AA 73 DC 70
        24 89 A4 4D 41 DB 91 4D E9 61 3D C5 E9 8C 94 16 05 51 C0 DF 86 27 4B 93
        59 BC 04 90 D0 1B 03 AD 54 02 2D CB 4F 57 FA D6 32 24 97 D7 A1 E2 8D 46
        71 0F 46 1A FE 71 0F BB BC 5F 8B A1 66 F4 31 19 75 EC 6C
    ");
    const GA_MAPPING_RESPONSE: [u8; 134] = hex!("
        7C 81 83 82 81 80 78 87 9F 57 22 5A A8 08 0D 52 ED 0F C8 90 A4 B2 53 36
        F6 99 AA 89 A2 D3 A1 89 65 4A F7 07 29 E6 23 EA 57 38 B2 63 81 E4 DA 19
        E0 04 70 6F AC E7 B2 35 C2 DB F2 F3 87 48 31 2F 3C 98 C2 DD 48 82 A4 19
        47 B3 24 AA 12 59 AC 22 57 9D B9 3F 70 85 65 5A F3 08 89 DB B8 45 D9 E6
        78 3F E4 2C 9F 24 49 40 03 06 25 4C 8A E8 EE 9D D8 12 A8 04 C0 B6 6E 8C
        AF C1 4F 84 D8 25 89 50 A9 1B 44 12 6E E6
    ");
    const EXPECTED_GA_AGREEMENT_PAYLOAD: [u8; 134] = hex!("
        7C 81 83 83 81 80 90 7D 89 E2 D4 25 A1 78 AA 81 AF 4A 77
        74 EC 8E 38 8C 11 5C AE 67 03 1E 85 EE CE 52 0B D9 11 55 1B 9A E4 D0 43
        69 F2 9A 02 62 6C 86 FB C6 74 7C C7 BC 35 26 45 B6 16 1A 2A 42 D4 4E DA
        80 A0 8F A8 D6 1B 76 D3 A1 54 AD 8A 5A 51 78 6B 0B C0 71 47 05 78 71 A9
        22 21 2C 5F 67 F4 31 73 17 22 36 B7 74 7D 16 71 E6 D6 92 A3 C7 D4 0A 0C
        3C 5C E3 97 54 5D 01 5C 17 5E B5 13 05 51 ED BC 2E E5 D4
    ");
    const GA_AGREEMENT_RESPONSE: [u8; 134] = hex!("
        7C 81 83 84 81 80 07 56 93 D9 AE 94 18 77 57 3E 63 4B 6E 64 4F 8E 60 AF
        17 A0 07 6B 8B 12 3D 92 01 07 4D 36 15 2B D8 B3 A2 13 F5 38 20 C4 2A DC
        79 AB 5D 0A EE C3 AE FB 91 39 4D A4 76 BD 97 B9 B1 4D 0A 65 C1 FC 71 A0
        E0 19 CB 08 AF 55 E1 F7 29 00 5F BA 7E 3F A5 DC 41 89 92 38 A2 50 76 7A
        6D 46 DB 97 40 64 38 6C D4 56 74 35 85 F8 E5 D9 0C C8 B4 00 4B 1F 6D 86
        6C 79 CE 05 84 E4 96 87 FF 61 BC 29 AE A1
    ");
    const EXPECTED_GA_MUTUAL_PAYLOAD: [u8; 12] = hex!("7C 0A 85 08 B4 6D D9 BD 4D 98 38 1F");
    const GA_MUTUAL_RESPONSE: [u8; 12] = hex!("7C 0A 86 08 91 7F 37 B5 C0 E6 D8 D1");

    pub const fn new() -> Self {
        Self {
            state: 0,
        }
    }
}
impl SmartCard for AppendixG2Card {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, icao_mrtd::iso7816::card::CommunicationError> {
        println!("AppendixG2Card received: {:#?}", request);
        if request.header.to_be_u32() == 0x00_22_C1_A4
                && request.data.request_data() == Some(&Self::EXPECTED_MSE_SET_AT_PAYLOAD)
                && request.data.response_data_length().is_none() {
            self.state = 1;
            Ok(Response { data: Vec::with_capacity(0), trailer: ResponseTrailer::new(0x90, 0x00) })
        } else if self.state == 1
                && request.header.to_be_u32() == 0x10_86_00_00
                && request.data.request_data() == Some(&Self::EXPECTED_GA_INITIAL_PAYLOAD)
                && request.data.response_data_length() == Some(0x100) {
            self.state = 2;
            // send response
            Ok(Response {
                data: Self::GA_INITIAL_RESPONSE.to_vec(),
                trailer: ResponseTrailer::new(0x90, 0x00),
            })
        } else if self.state == 2
                && request.header.to_be_u32() == 0x10_86_00_00
                && request.data.request_data() == Some(&Self::EXPECTED_GA_MAPPING_PAYLOAD)
                && request.data.response_data_length() == Some(0x100) {
            self.state = 3;
            Ok(Response {
                data: Self::GA_MAPPING_RESPONSE.to_vec(),
                trailer: ResponseTrailer::new(0x90, 0x00),
            })
        } else if self.state == 3
                && request.header.to_be_u32() == 0x10_86_00_00
                && request.data.request_data() == Some(&Self::EXPECTED_GA_AGREEMENT_PAYLOAD)
                && request.data.response_data_length() == Some(0x100) {
            self.state = 4;
            Ok(Response {
                data: Self::GA_AGREEMENT_RESPONSE.to_vec(),
                trailer: ResponseTrailer::new(0x90, 0x00),
            })
        } else if self.state == 4
                && request.header.to_be_u32() == 0x00_86_00_00 // no more chaining
                && request.data.request_data() == Some(&Self::EXPECTED_GA_MUTUAL_PAYLOAD)
                && request.data.response_data_length() == Some(0x100) {
            self.state = 5;
            Ok(Response {
                data: Self::GA_MUTUAL_RESPONSE.to_vec(),
                trailer: ResponseTrailer::new(0x90, 0x00),
            })
        } else {
            // IDFK
            Ok(Response {
                data: Vec::with_capacity(0),
                trailer: ResponseTrailer::new(0x69, 0x88),
            })
        }
    }
}

#[test]
fn test_pace_setup_appg2() {
    const MRZ_DATA: [u8; 24] = *b"T22000129364081251010318";
    const DERIVATION_PRIVATE_KEY: [u8; 20] = hex!("
        5265030F 751F4AD1 8B08AC56 5FC7AC95 2E41618D
    ");
    const AGREEMENT_PRIVATE_KEY: [u8; 20] = hex!("
        89CCD99B 0E8D3B1F 11E1296D CA68EC53 411CF2CA
    ");
    const PROTOCOL: &Oid = icao_mrtd::pace::PACE_DH_GM_AES_CBC_CMAC_128;

    let mut card = AppendixG2Card::new();

    let derivation_private_key = boxed_uint_from_be_slice(&DERIVATION_PRIVATE_KEY);
    let agreement_private_key = boxed_uint_from_be_slice(&AGREEMENT_PRIVATE_KEY);

    // set mechanism
    icao_mrtd::pace::set_authentication_template(&mut card, PROTOCOL, PasswordSource::Mrz)
        .expect("failed to set authentication template");

    // request nonce
    let encrypted_nonce = icao_mrtd::pace::obtain_encrypted_nonce(&mut card)
        .expect("failed to obtain encrypted nonce");

    // make it happen
    let key_exchange = KeyExchange::DiffieHellman(
        icao_mrtd::pace::crypt::dh::params::get_1024_modp_160_po(),
    );
    icao_mrtd::pace::perform_gm_kex_with_values(
        &mut card,
        PROTOCOL,
        key_exchange,
        icao_mrtd::pace::CipherAndMac::Aes128CipherCmacMac,
        &MRZ_DATA,
        encrypted_nonce.as_slice(),
        &derivation_private_key,
        &agreement_private_key,
    ).expect("failed to establish PACE");
}
