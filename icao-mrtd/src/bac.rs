//! Basic Access Control.


use block_padding::{Iso7816, NoPadding, RawPadding};
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use des::{Des, TdesEde2};
use digest::{Digest, DynDigest, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use retail_mac::RetailMac;
use sha1::Sha1;

use crate::iso7816::card::{CommunicationError, SmartCard};
use crate::iso7816::apdu::{Apdu, CommandHeader, Data};
use crate::secure_messaging::{Error, Kdf3Des, KeyDerivation, MismatchedValue, Operation, Sm3Des};


type RetailMacDes = RetailMac<Des>;


fn get_challenge<SC: SmartCard>(card: &mut SC) -> Result<[u8; 8], CommunicationError> {
    let get_challenge_apdu = Apdu {
        header: CommandHeader {
            cla: 0x00,
            ins: 0x84, // GET CHALLENGE
            p1: 0x00,
            p2: 0x00,
        },
        data: Data::ResponseDataShort {
            response_data_length: 8,
        },
    };
    let response = card.communicate(&get_challenge_apdu)?;
    if response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed { operation: Operation::GetChallenge, response }.into());
    }
    if response.data.len() != 8 {
        return Err(Error::LengthMismatch {
            operation: Operation::GetChallenge,
            obtained: response.data,
            expected_length: 8,
        }.into());
    }
    let mut ret = [0u8; 8];
    ret.copy_from_slice(response.data.as_slice());
    Ok(ret)
}

pub fn establish_from_values<'c, SC: SmartCard>(
    card: &'c mut SC,
    k_seed: &[u8],
    rnd_ic: &[u8],
    rnd_ifd: &[u8],
    k_ifd: &[u8],
) -> Result<Sm3Des<'c, SC>, CommunicationError> {
    // derive the keys
    // (the key derivation functions have remained the same with PACE)
    let k_enc = Kdf3Des::derive_encryption_key(k_seed);
    let k_mac = Kdf3Des::derive_mac_key(k_seed);

    // concatenate the three values
    let mut ext_auth_data = [0u8; 32+8];
    ext_auth_data[0..8].copy_from_slice(&rnd_ifd);
    ext_auth_data[8..16].copy_from_slice(&rnd_ic);
    ext_auth_data[16..32].copy_from_slice(&k_ifd);

    // encrypt using 3DES (EDE 2-key) in CBC mode with an all-zeroes IV and no padding
    let iv = [0u8; 8];
    let encryptor: cbc::Encryptor<TdesEde2> = cbc::Encryptor::new(k_enc.as_slice().try_into().unwrap(), &iv.into());
    encryptor.encrypt_padded::<NoPadding>(&mut ext_auth_data[0..32], 32).unwrap();
    // ext_auth_data[0..32] is now encrypted

    // pad according to ISO 7816, then generate Retail MAC
    Iso7816::raw_pad(&mut ext_auth_data, 32);
    let mut retail_mac = RetailMacDes::new_from_slice(&k_mac).unwrap();
    DynDigest::update(&mut retail_mac, &ext_auth_data);
    // MAC fits right where the padding was
    retail_mac.finalize_into(&mut ext_auth_data[32..32+8]).unwrap();

    // send EXTERNAL AUTHENTICATE
    let ext_auth_request = Apdu {
        header: CommandHeader {
            cla: 0x00,
            ins: 0x82, // EXTERNAL AUTHENTICATE
            p1: 0x00,
            p2: 0x00,
        },
        data: Data::BothDataShort {
            request_data: ext_auth_data.to_vec(),
            response_data_length: 40,
        },
    };
    let mut ext_auth_response = card.communicate(&ext_auth_request)?;
    if ext_auth_response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed {
            operation: Operation::ExternalAuthenticate,
            response: ext_auth_response,
        }.into());
    }
    if ext_auth_response.data.len() != 40 {
        return Err(Error::LengthMismatch {
            operation: Operation::ExternalAuthenticate,
            obtained: ext_auth_response.data,
            expected_length: 40,
        }.into());
    }

    // verify MAC of what we obtained
    let mut response_data_to_verify = [0u8; 32+8];
    response_data_to_verify[0..32].copy_from_slice(&ext_auth_response.data[0..32]);
    Iso7816::raw_pad(&mut response_data_to_verify, 32);
    let mut response_mac = RetailMacDes::new_from_slice(&k_mac).unwrap();
    DynDigest::update(&mut response_mac, &response_data_to_verify);
    if let Err(_) = response_mac.verify_slice(&ext_auth_response.data[32..32+8]) {
        return Err(Error::ResponseMac.into());
    }

    // decrypt
    let iv = [0u8; 8];
    let decryptor: cbc::Decryptor<TdesEde2> = cbc::Decryptor::new(&k_enc.as_slice().try_into().unwrap(), &iv.into());
    let decrypted_slice = decryptor.decrypt_padded::<NoPadding>(&mut ext_auth_response.data[0..32]).unwrap();

    let mut rnd_ic_second = [0u8; 8];
    let mut rnd_ifd_second = [0u8; 8];
    let mut k_ic = [0u8; 16];
    rnd_ic_second.copy_from_slice(&decrypted_slice[0..8]);
    rnd_ifd_second.copy_from_slice(&decrypted_slice[8..16]);
    k_ic.copy_from_slice(&decrypted_slice[16..32]);

    if rnd_ic != rnd_ic_second {
        return Err(Error::ValueMismatch { value: MismatchedValue::RndIc }.into());
    }
    if rnd_ifd != rnd_ifd_second {
        return Err(Error::ValueMismatch { value: MismatchedValue::RndIfd }.into());
    }

    let mut k_session_seed = [0u8; 16];
    for ((kss, kifd), kic) in k_session_seed.iter_mut().zip(k_ifd.iter()).zip(k_ic.iter()) {
        *kss = *kifd ^ *kic;
    }

    let k_session_enc = Kdf3Des::derive_encryption_key(&k_session_seed);
    let k_session_mac = Kdf3Des::derive_mac_key(&k_session_seed);

    let mut send_sequence_counter = [0u8; 8];
    send_sequence_counter[0..4].copy_from_slice(&rnd_ic[4..8]);
    send_sequence_counter[4..8].copy_from_slice(&rnd_ifd[4..8]);

    Ok(Sm3Des::new(
        card,
        k_session_enc.as_slice().try_into().unwrap(),
        k_session_mac.as_slice().try_into().unwrap(),
        send_sequence_counter,
    ))
}

pub fn establish<'c, SC: SmartCard>(card: &'c mut SC, mrz_data: &[u8]) -> Result<Sm3Des<'c, SC>, CommunicationError> {
    // calculate SHA-1 hash of MRZ data
    let mut sha1 = Sha1::new();
    Digest::update(&mut sha1, mrz_data);
    let sha1_hash = sha1.finalize();
    let k_seed = &sha1_hash[0..16];

    // obtain the challenge
    let rnd_ic = get_challenge(card)?;

    // generate some random bytes
    let mut rnd_ifd = [0u8; 8];
    let mut k_ifd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd_ifd);
    OsRng.fill_bytes(&mut k_ifd);

    establish_from_values(card, k_seed, &rnd_ic, &rnd_ifd, &k_ifd)
}
