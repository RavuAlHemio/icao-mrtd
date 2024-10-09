use hex_literal::hex;
use icao_mrtd::crypt::{boxed_uint_from_be_slice, KeyExchange};
use icao_mrtd::iso7816::apdu::{Apdu, Response, ResponseTrailer};
use icao_mrtd::iso7816::card::SmartCard;
use icao_mrtd::pace::PasswordSource;
use rasn::types::Oid;


/// A fake smart card that acts exactly like the card in ICAO Doc 9303 Part 11 Appendix G.1.
///
/// If any of its expectations are not met, it responds with 0x69 0x88.
struct AppendixG1Card {
    state: u8,
}
impl AppendixG1Card {
    const EXPECTED_MSE_SET_AT_PAYLOAD: [u8; 15] = hex!("80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 01");
    const EXPECTED_GA_INITIAL_PAYLOAD: [u8; 2] = hex!("7C 00");
    const GA_INITIAL_RESPONSE: [u8; 20] = hex!("7C 12 80 10 95 A3 A0 16 52 2E E9 8D 01 E7 6C B6 B9 8B 42 C3");
    const EXPECTED_GA_MAPPING_PAYLOAD: [u8; 69] = hex!("
        7C 43 81 41 04 7A CF 3E FC 98 2E C4 55 65 A4 B1 55
        12 9E FB C7 46 50 DC BF A6 36 2D 89 6F C7 02 62 E0 C2 CC 5E 54 45
        52 DC B6 72 52 18 79 91 15 B5 5C 9B AA 6D 9F 6B C3 A9 61 8E 70 C2
        5A F7 17 77 A9 C4 92 2D
    ");
    const GA_MAPPING_RESPONSE: [u8; 69] = hex!("
        7C 43 82 41 04 82 4F BA 91 C9 CB E2 6B EF 53 A0 EB E7 34 2A 3B F1
        78 CE A9 F4 5D E0 B7 0A A6 01 65 1F BA 3F 57 30 D8 C8 79 AA A9 C9
        F7 39 91 E6 1B 58 F4 D5 2E B8 7A 0A 0C 70 9A 49 DC 63 71 93 63 CC
        D1 3C 54
    ");
    const EXPECTED_GA_AGREEMENT_PAYLOAD: [u8; 69] = hex!("
        7C 43 83 41 04 2D B7 A6 4C 03 55 04 4E C9 DF 19
        05 14 C6 25 CB A2 CE A4 87 54 88 71 22 F3 A5 EF 0D 5E DD 30 1C
        35 56 F3 B3 B1 86 DF 10 B8 57 B5 8F 6A 7E B8 0F 20 BA 5D C7 BE
        1D 43 D9 BF 85 01 49 FB B3 64 62
    ");
    const GA_AGREEMENT_RESPONSE: [u8; 69] = hex!("
        7C 43 84 41 04 9E 88 0F 84 29 05 B8 B3 18 1F 7A F7 CA A9 F0 EF
        B7 43 84 7F 44 A3 06 D2 D2 8C 1D 9E C6 5D F6 DB 77 64 B2 22 77
        A2 ED DC 3C 26 5A 9F 01 8F 9C B8 52 E1 11 B7 68 B3 26 90 4B 59
        A0 19 37 76 F0 94
    ");
    const EXPECTED_GA_MUTUAL_PAYLOAD: [u8; 12] = hex!("7C 0A 85 08 C2 B0 BD 78 D9 4B A8 66");
    const GA_MUTUAL_RESPONSE: [u8; 12] = hex!("7C 0A 86 08 3A BB 96 74 BC E9 3C 08");

    pub const fn new() -> Self {
        Self {
            state: 0,
        }
    }
}
impl SmartCard for AppendixG1Card {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, icao_mrtd::iso7816::card::CommunicationError> {
        println!("AppendixG1Card received: {:#?}", request);
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
fn test_pace_setup_appg1() {
    const MRZ_DATA: [u8; 24] = *b"T22000129364081251010318";
    const DERIVATION_PRIVATE_KEY: [u8; 32] = hex!("
        7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C
        F21F249D 953BC46F 4C6E1925 9C010F99
    ");
    const AGREEMENT_PRIVATE_KEY: [u8; 32] = hex!("
        A73FB703 AC1436A1 8E0CFA5A BB3F7BEC
        7A070E7A 6788486B EE230C4A 22762595
    ");
    const PROTOCOL: &Oid = icao_mrtd::pace::PACE_ECDH_GM_AES_CBC_CMAC_128;

    let mut card = AppendixG1Card::new();

    let derivation_private_key = boxed_uint_from_be_slice(&DERIVATION_PRIVATE_KEY);
    let agreement_private_key = boxed_uint_from_be_slice(&AGREEMENT_PRIVATE_KEY);

    // set mechanism
    icao_mrtd::pace::set_authentication_template(&mut card, PROTOCOL, PasswordSource::Mrz)
        .expect("failed to set authentication template");

    // request nonce
    let encrypted_nonce = icao_mrtd::pace::obtain_encrypted_nonce(&mut card)
        .expect("failed to obtain encrypted nonce");

    // make it happen
    let key_exchange = KeyExchange::PrimeWeierstrassEllipticDiffieHellman(
        icao_mrtd::crypt::elliptic::curves::get_brainpool_p256r1(),
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
