use hex_literal::hex;
use icao_mrtd::iso7816::apdu::{Apdu, CommandHeader, Data, Response, ResponseTrailer};
use icao_mrtd::iso7816::card::SmartCard;


/// A fake smart card that acts exactly like the card in ICAO Doc 9303 Part 11 Appendix D.
///
/// If any of its expectations are not met, it responds with 0x69 0x88.
struct AppendixDCard {
    state: u8,
}
impl AppendixDCard {
    const RND_IC: [u8; 8] = hex!("4608F91988702212");
    const EXPECTED_EXTERNAL_AUTHENTICATE_PAYLOAD: [u8; 40] = hex!("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7");
    const EXTERNAL_AUTHENTICATE_RESPONSE: [u8; 40] = hex!("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449");
    const EXPECTED_SELECT_PAYLOAD: [u8; 21] = hex!("8709016375432908C044F68E08BF8B92D635FF24F8");
    const SELECT_RESPONSE: [u8; 14] = hex!("990290008E08FA855A5D4C50A8ED");
    const EXPECTED_READ_4_PAYLOAD: [u8; 13] = hex!("9701048E08ED6705417E96BA55");
    const READ_4_RESPONSE: [u8; 25] = hex!("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED");
    const EXPECTED_READ_REST_PAYLOAD: [u8; 13] = hex!("9701128E082EA28A70F3C7B535");
    const READ_REST_RESPONSE: [u8; 41] = hex!("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74");

    pub const fn new() -> Self {
        Self {
            state: 0,
        }
    }
}
impl SmartCard for AppendixDCard {
    fn communicate(&mut self, request: &Apdu) -> Result<Response, icao_mrtd::iso7816::card::CommunicationError> {
        println!("AppendixDCard received: {:#?}", request);
        if request.header.to_be_u32() == 0x00_84_00_00
                && request.data.request_data().is_none()
                && request.data.response_data_length() == Some(8) {
            self.state = 1;
            Ok(Response { data: Self::RND_IC.to_vec(), trailer: ResponseTrailer::new(0x90, 0x00) })
        } else if request.header.to_be_u32() == 0x00_82_00_00
                && request.data.request_data() == Some(&Self::EXPECTED_EXTERNAL_AUTHENTICATE_PAYLOAD)
                && request.data.response_data_length() == Some(0x28) {
            self.state = 2;
            // send response
            Ok(Response {
                data: Self::EXTERNAL_AUTHENTICATE_RESPONSE.to_vec(),
                trailer: ResponseTrailer::new(0x90, 0x00),
            })
        } else if self.state >= 2
                && request.header.to_be_u32() == 0x0C_A4_02_0C
                && request.data.request_data() == Some(&Self::EXPECTED_SELECT_PAYLOAD)
                && request.data.response_data_length() == Some(0x100) {
            self.state = 3;
            Ok(Response {
                data: Self::SELECT_RESPONSE.to_vec(),
                trailer: ResponseTrailer::new(0x90, 0x00),
            })
        } else if self.state >= 3
                && request.header.to_be_u32() == 0x0C_B0_00_00
                && request.data.request_data() == Some(&Self::EXPECTED_READ_4_PAYLOAD)
                && request.data.response_data_length() == Some(0x100) {
            Ok(Response {
                data: Self::READ_4_RESPONSE.to_vec(),
                trailer: ResponseTrailer::new(0x90, 0x00),
            })
        } else if self.state >= 3
                && request.header.to_be_u32() == 0x0C_B0_00_04
                && request.data.request_data() == Some(&Self::EXPECTED_READ_REST_PAYLOAD)
                && request.data.response_data_length() == Some(0x100) {
            Ok(Response {
                data: Self::READ_REST_RESPONSE.to_vec(),
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
fn test_bac_setup_appd() {
    const K_SEED: [u8; 16] = hex!("239AB9CB282DAF66231DC5A4DF6BFBAE");
    const RND_IFD: [u8; 8] = hex!("781723860C06C226");
    const K_IFD: [u8; 16] = hex!("0B795240CB7049B01C19B33E32804F0B");
    const DECRYPTED_READ_4: [u8; 4] = hex!("60145F01");
    const DECRYPTED_READ_REST: [u8; 18] = hex!("04303130365F36063034303030305C026175");

    let card: Box<dyn SmartCard> = Box::new(AppendixDCard::new());
    let mut bac_card = icao_mrtd::bac::establish_from_values(
        card,
        &K_SEED,
        &AppendixDCard::RND_IC,
        &RND_IFD,
        &K_IFD,
    ).expect("failed to establish BAC");

    {
        // select EF.COM
        let select_result = bac_card.communicate(&Apdu {
            header: CommandHeader {
                cla: 0x00,
                ins: 0xA4,
                p1: 0x02,
                p2: 0x0C,
            },
            data: Data::RequestDataShort {
                request_data: vec![0x01, 0x1E],
            }
        }).expect("failed to select EF.COM");
        assert_eq!(select_result.trailer.to_word(), 0x9000);
    }

    {
        // read initial 4 bytes of EF.COM
        let read_four = bac_card.communicate(&Apdu {
            header: CommandHeader {
                cla: 0x00,
                ins: 0xB0,
                p1: 0x00,
                p2: 0x00,
            },
            data: Data::ResponseDataShort { response_data_length: 4 },
        }).expect("failed to read 4 bytes of EF.COM");
        assert_eq!(read_four.trailer.to_word(), 0x9000);
        assert_eq!(read_four.data.as_slice(), &DECRYPTED_READ_4);
    }

    {
        // read rest of EF.COM
        let read_rest = bac_card.communicate(&Apdu {
            header: CommandHeader {
                cla: 0x00,
                ins: 0xB0,
                p1: 0x00,
                p2: 0x04,
            },
            data: Data::ResponseDataShort { response_data_length: 0x12 },
        }).expect("failed to read rest of EF.COM");
        assert_eq!(read_rest.trailer.to_word(), 0x9000);
        assert_eq!(read_rest.data.as_slice(), &DECRYPTED_READ_REST);
    }
}
