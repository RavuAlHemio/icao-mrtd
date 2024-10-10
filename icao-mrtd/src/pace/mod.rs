//! Implementation of Password Authenticated Connection Establishment.


pub mod asn1;


use std::fmt;

use crypto_bigint::BoxedUint;
use digest::Digest;
use rand::RngCore;
use rand::rngs::OsRng;
use rasn::types::{Any, ObjectIdentifier, Oid, SetOf};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypt::{boxed_uint_from_be_slice, KeyExchange};
use crate::crypt::cipher_mac::{CipherAndMac, Cam3Des, CamAes128, CamAes192, CamAes256};
use crate::der_util::{self, encode_primitive_length, oid_to_der_bytes, try_decode_primitive_length};
use crate::iso7816::apdu::{Apdu, CommandHeader, Data, Response};
use crate::iso7816::card::{CommunicationError, SmartCard};
use crate::pace::asn1::PaceInfo;


macro_rules! pace_oids {
    ($($name:ident => $($num:literal),+ $(,)?);+ $(;)?) => {
        $(
            pub const $name: &'static Oid = Oid::const_new(&[0, 4, 0, 127, 0, 7, 2, 2, 4, $($num),+]);
        )+
    };
}

pace_oids! {
    PACE_DH_GM_3DES_CBC_CBC => 1, 1;
    PACE_DH_GM_AES_CBC_CMAC_128 => 1, 2;
    PACE_DH_GM_AES_CBC_CMAC_192 => 1, 3;
    PACE_DH_GM_AES_CBC_CMAC_256 => 1, 4;

    PACE_ECDH_GM_3DES_CBC_CBC => 2, 1;
    PACE_ECDH_GM_AES_CBC_CMAC_128 => 2, 2;
    PACE_ECDH_GM_AES_CBC_CMAC_192 => 2, 3;
    PACE_ECDH_GM_AES_CBC_CMAC_256 => 2, 4;

    PACE_DH_IM_3DES_CBC_CBC => 3, 1;
    PACE_DH_IM_AES_CBC_CMAC_128 => 3, 2;
    PACE_DH_IM_AES_CBC_CMAC_192 => 3, 3;
    PACE_DH_IM_AES_CBC_CMAC_256 => 3, 4;

    PACE_ECDH_IM_3DES_CBC_CBC => 4, 1;
    PACE_ECDH_IM_AES_CBC_CMAC_128 => 4, 2;
    PACE_ECDH_IM_AES_CBC_CMAC_192 => 4, 3;
    PACE_ECDH_IM_AES_CBC_CMAC_256 => 4, 4;

    PACE_ECDH_CAM_AES_CBC_CMAC_128 => 6, 2;
    PACE_ECDH_CAM_AES_CBC_CMAC_192 => 6, 3;
    PACE_ECDH_CAM_AES_CBC_CMAC_256 => 6, 4;
}

pub const PACE_PROTOCOL_OIDS: [&'static Oid; 19] = [
    PACE_DH_GM_3DES_CBC_CBC, PACE_DH_GM_AES_CBC_CMAC_128,
    PACE_DH_GM_AES_CBC_CMAC_192, PACE_DH_GM_AES_CBC_CMAC_256,
    PACE_ECDH_GM_3DES_CBC_CBC, PACE_ECDH_GM_AES_CBC_CMAC_128,
    PACE_ECDH_GM_AES_CBC_CMAC_192, PACE_ECDH_GM_AES_CBC_CMAC_256,
    PACE_DH_IM_3DES_CBC_CBC, PACE_DH_IM_AES_CBC_CMAC_128,
    PACE_DH_IM_AES_CBC_CMAC_192, PACE_DH_IM_AES_CBC_CMAC_256,
    PACE_ECDH_IM_3DES_CBC_CBC, PACE_ECDH_IM_AES_CBC_CMAC_128,
    PACE_ECDH_IM_AES_CBC_CMAC_192, PACE_ECDH_IM_AES_CBC_CMAC_256,
    PACE_ECDH_CAM_AES_CBC_CMAC_128, PACE_ECDH_CAM_AES_CBC_CMAC_192,
    PACE_ECDH_CAM_AES_CBC_CMAC_256,
];


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    SetAuthenticationTemplate,
    ObtainNonce,
    ExchangeMappingPublicKeys,
    ExchangeEphemeralPublicKeys,
    MutualAuthentication,
}


#[derive(Debug)]
pub enum Error {
    NotSupported,
    MappingNotSupported { protocol: ObjectIdentifier },
    CardAccessDecoding(rasn::error::DecodeError),
    CardAccessEntryDecoding {
        entry_index: usize,
        error: rasn::error::DecodeError,
    },
    CardAccessEntryDecodingPace {
        entry_index: usize,
        error: rasn::error::DecodeError,
    },
    OperationFailed {
        operation: Operation,
        response: Response,
    },
    CustomParameters,
    IncompatibleProtocolParameter {
        protocol: ObjectIdentifier,
        parameter: i32,
    },
    ShortResponse {
        operation: Operation,
        response: Response,
        min_data_len: usize,
    },
    UnexpectedType {
        operation: Operation,
        type_tag: u8,
    },
    TlvEncoding {
        operation: Operation,
        data: Zeroizing<Vec<u8>>,
    },
    DiffieHellmanKeysEqual,
    MutualAuthentication,
    PublicKey { bytes: Zeroizing<Vec<u8>> },
    DiffieHellmanResult,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::NotSupported
                => write!(f, "PACE is not supported"),
            Self::MappingNotSupported { protocol }
                => write!(f, "the mapping of protocol {} is currently not supported", protocol),
            Self::CardAccessDecoding(e)
                => write!(f, "failed to decode EF.CardAccess: {}", e),
            Self::CardAccessEntryDecoding { entry_index, error }
                => write!(f, "failed to decode EF.CardAccess entry {}: {}", entry_index, error),
            Self::CardAccessEntryDecodingPace { entry_index, error }
                => write!(f, "failed to decode EF.CardAccess entry {} as PaceInfo: {}", entry_index, error),
            Self::OperationFailed { operation, response }
                => write!(f, "operation {:?} failed with response code 0x{:04X}", operation, response.trailer.to_word()),
            Self::CustomParameters
                => write!(f, "custom parameters are not currently supported"),
            Self::IncompatibleProtocolParameter { protocol, parameter }
                => write!(f, "protocol {} is incompatible with parameter {}", protocol, parameter),
            Self::ShortResponse { operation, response, min_data_len }
                => write!(f, "operation {:?} received short response {:?} (expected at least {} bytes)", operation, response, min_data_len),
            Self::UnexpectedType { operation, type_tag }
                => write!(f, "operation {:?} received response of unexpected type 0x{:02X}", operation, type_tag),
            Self::TlvEncoding { operation, .. }
                => write!(f, "invalid TLV encoding for operation {:?}", operation),
            Self::DiffieHellmanKeysEqual
                => write!(f, "terminal and chip Diffie-Hellman keys are equal"),
            Self::MutualAuthentication
                => write!(f, "mutual authentication failed"),
            Self::PublicKey { .. }
                => write!(f, "invalid public key"),
            Self::DiffieHellmanResult
                => write!(f, "invalid Diffie-Hellman result"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotSupported => None,
            Self::MappingNotSupported { .. } => None,
            Self::CardAccessDecoding(_) => None,
            Self::CardAccessEntryDecoding { .. } => None,
            Self::CardAccessEntryDecodingPace { .. } => None,
            Self::OperationFailed { .. } => None,
            Self::CustomParameters => None,
            Self::IncompatibleProtocolParameter { .. } => None,
            Self::ShortResponse { .. } => None,
            Self::UnexpectedType { .. } => None,
            Self::TlvEncoding { .. } => None,
            Self::DiffieHellmanKeysEqual => None,
            Self::MutualAuthentication => None,
            Self::PublicKey { .. } => None,
            Self::DiffieHellmanResult => None,
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PasswordSource {
    Mrz,
    Can,
}


fn extract_double_wrapped(operation: Operation, response: Response, outer_tag: u8, inner_tag: u8) -> Result<Zeroizing<Vec<u8>>, CommunicationError> {
    if response.data.len() < 4 {
        return Err(Error::ShortResponse {
            operation,
            response,
            min_data_len: 4,
        }.into());
    }
    if response.data[0] != outer_tag {
        return Err(Error::UnexpectedType { operation, type_tag: response.data[0] }.into());
    }
    let (tlv_length, tlv_rest) = try_decode_primitive_length(&response.data[1..])
        .ok_or_else(|| Error::TlvEncoding { operation, data: Zeroizing::new(response.data.clone()) })?;
    if tlv_length != tlv_rest.len() {
        // consider this an error too
        return Err(Error::TlvEncoding { operation, data: Zeroizing::new(response.data.clone()) }.into());
    }

    if tlv_rest.len() < 2 {
        return Err(Error::ShortResponse {
            operation,
            response,
            min_data_len: 2,
        }.into());
    }
    if tlv_rest[0] != inner_tag {
        return Err(Error::UnexpectedType { operation, type_tag: tlv_rest[0] }.into());
    }
    let (data_length, data_rest) = try_decode_primitive_length(&tlv_rest[1..])
        .ok_or_else(|| Error::TlvEncoding { operation, data: Zeroizing::new(tlv_rest.to_vec()) })?;
    Ok(Zeroizing::new(data_rest[0..data_length].to_vec()))
}


pub fn set_authentication_template(card: &mut Box<dyn SmartCard>, mechanism: &Oid, password_source: PasswordSource) -> Result<(), CommunicationError> {
    let mut request_data = Vec::new();

    // encode mechanism (0x80)
    let mechanism_bytes = der_util::oid_to_der_bytes(mechanism);
    request_data.push(0x80);
    der_util::encode_primitive_length(&mut request_data, mechanism_bytes.len());
    request_data.extend(&mechanism_bytes);

    // encode password source (0x83)
    request_data.push(0x83);
    request_data.push(0x01);
    match password_source {
        PasswordSource::Mrz => request_data.push(0x01),
        PasswordSource::Can => request_data.push(0x02),
    }

    // do it
    let request = Apdu {
        header: CommandHeader {
            cla: 0x00,
            ins: 0x22, // MANAGE SECURITY ENVIRONMENT
            p1: 0b1100_0001, // verify/encrypt/extauth, compute/decrypt/intauth, set
            p2: 0xA4, // control reference template for authentication
        },
        data: Data::RequestDataShort { request_data },
    };
    let response = card.communicate(&request)?;
    if response.trailer.to_word() == 0x9000 {
        Ok(())
    } else {
        Err(Error::OperationFailed {
            operation: Operation::SetAuthenticationTemplate,
            response,
        }.into())
    }
}


pub fn obtain_encrypted_nonce(card: &mut Box<dyn SmartCard>) -> Result<Zeroizing<Vec<u8>>, CommunicationError> {
    let request_data = vec![
        0x7C, // dynamic authentication data
        0x00, // no data
    ];

    // do it
    let request = Apdu {
        header: CommandHeader {
            cla: 0b000_1_00_00, // not the last in a chain, no secure messaging, logical channel 0
            ins: 0x86, // GENERAL AUTHENTICATE
            p1: 0x00, // algorithm is known (from "set authentication template")
            p2: 0x00, // key index is known (from "set authentication template")
        },
        data: Data::BothDataShort {
            request_data,
            response_data_length: 0,
        },
    };
    let response = card.communicate(&request)?;
    if response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed {
            operation: Operation::ObtainNonce,
            response,
        }.into());
    }
    extract_double_wrapped(Operation::ObtainNonce, response, 0x7C, 0x80)
}


/// Exchanges mapping values with the chip.
///
/// For generic mapping, these are the derivation public keys. For integrated mapping, this is the
/// terminal nonce sent from the terminal to the chip and the chip answering with empty information.
fn exchange_mapping_values(card: &mut Box<dyn SmartCard>, mapping_values: &[u8]) -> Result<Zeroizing<Vec<u8>>, CommunicationError> {
    let mut mapping_data_tlv = Zeroizing::new(vec![0x81]); // mapping data
    encode_primitive_length(&mut mapping_data_tlv, mapping_values.len());
    mapping_data_tlv.extend(mapping_values);

    let mut request_data = vec![0x7C]; // dynamic authentication data
    encode_primitive_length(&mut request_data, mapping_data_tlv.len());
    request_data.extend(&*mapping_data_tlv);
    // (Apdu will zeroize us on drop)

    // do it
    let request = Apdu {
        header: CommandHeader {
            cla: 0b000_1_00_00, // not the last in a chain, no secure messaging, logical channel 0
            ins: 0x86, // GENERAL AUTHENTICATE
            p1: 0x00, // algorithm is known (from "set authentication template")
            p2: 0x00, // key index is known (from "set authentication template")
        },
        data: Data::BothDataShort {
            request_data,
            response_data_length: 0,
        },
    };
    let response = card.communicate(&request)?;
    if response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed {
            operation: Operation::ExchangeMappingPublicKeys,
            response,
        }.into());
    }
    extract_double_wrapped(Operation::ExchangeMappingPublicKeys, response, 0x7C, 0x82)
}


fn exchange_ephemeral_public_keys(card: &mut Box<dyn SmartCard>, public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, CommunicationError> {
    let mut mapping_data_tlv = Zeroizing::new(vec![0x83]); // ephemeral pubkey
    encode_primitive_length(&mut mapping_data_tlv, public_key.len());
    mapping_data_tlv.extend(public_key);

    let mut request_data = vec![0x7C]; // dynamic authentication data
    encode_primitive_length(&mut request_data, mapping_data_tlv.len());
    request_data.extend(&*mapping_data_tlv);
    // (Apdu will zeroize us on drop)

    // do it
    let request = Apdu {
        header: CommandHeader {
            cla: 0b000_1_00_00, // not the last in a chain, no secure messaging, logical channel 0
            ins: 0x86, // GENERAL AUTHENTICATE
            p1: 0x00, // algorithm is known (from "set authentication template")
            p2: 0x00, // key index is known (from "set authentication template")
        },
        data: Data::BothDataShort {
            request_data,
            response_data_length: 0,
        },
    };
    let response = card.communicate(&request)?;
    if response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed {
            operation: Operation::ExchangeEphemeralPublicKeys,
            response,
        }.into());
    }
    extract_double_wrapped(Operation::ExchangeEphemeralPublicKeys, response, 0x7C, 0x84)
}


fn mutual_authentication(card: &mut Box<dyn SmartCard>, outgoing_token: &[u8]) -> Result<Zeroizing<Vec<u8>>, CommunicationError> {
    let mut mapping_data_tlv = Zeroizing::new(vec![0x85]); // terminal's token
    encode_primitive_length(&mut mapping_data_tlv, outgoing_token.len());
    mapping_data_tlv.extend(outgoing_token);

    let mut request_data = vec![0x7C]; // dynamic authentication data
    encode_primitive_length(&mut request_data, mapping_data_tlv.len());
    request_data.extend(&*mapping_data_tlv);
    // (Apdu will zeroize us on drop)

    // do it
    let request = Apdu {
        header: CommandHeader {
            cla: 0b000_0_00_00, // last in a chain, no secure messaging, logical channel 0
            ins: 0x86, // GENERAL AUTHENTICATE
            p1: 0x00, // algorithm is known (from "set authentication template")
            p2: 0x00, // key index is known (from "set authentication template")
        },
        data: Data::BothDataShort {
            request_data,
            response_data_length: 0,
        },
    };
    let response = card.communicate(&request)?;
    if response.trailer.to_word() != 0x9000 {
        return Err(Error::OperationFailed {
            operation: Operation::MutualAuthentication,
            response,
        }.into());
    }
    extract_double_wrapped(Operation::MutualAuthentication, response, 0x7C, 0x86)
}


/// Calculates the token used for mutual authentication.
fn calculate_mutual_token(
    cipher_and_mac: &Box<dyn CipherAndMac>,
    protocol: &Oid,
    public_key_tag: u8,
    public_key: &[u8],
    k_session_mac: &[u8],
) -> Zeroizing<Vec<u8>> {
    let protocol_bytes = oid_to_der_bytes(protocol);

    // inner structure:
    // 0x06 LL protocol_oid
    // keytag LL card_pubkey
    let mut inner_data = Zeroizing::new(Vec::new());
    inner_data.push(0x06); // OID (of public key type)
    encode_primitive_length(&mut inner_data, protocol_bytes.len());
    inner_data.extend(&protocol_bytes);
    inner_data.push(public_key_tag);
    encode_primitive_length(&mut inner_data, public_key.len());
    inner_data.extend(public_key);

    // outer structure:
    // 0x7F_0x49 LL inner_data
    let mut outer_data = Zeroizing::new(Vec::new());
    outer_data.extend(&[0x7F, 0x49]); // ASN.1 public key
    encode_primitive_length(&mut outer_data, inner_data.len());
    outer_data.extend(inner_data.as_slice());

    if cipher_and_mac.mac_block_size() > 1 {
        // padding
        outer_data.push(0x80);
        while outer_data.len() & cipher_and_mac.mac_block_size() != 0 {
            outer_data.push(0x00);
        }
    }

    cipher_and_mac.mac_padded_data(&outer_data, &k_session_mac)
}


/// Performs a generic mapping key exchange using specific values.
pub fn perform_gm_kex_with_values(
    mut card: Box<dyn SmartCard>,
    protocol: &Oid,
    key_exchange: KeyExchange,
    cipher_and_mac: &Box<dyn CipherAndMac>,
    mrz_data: &[u8],
    encrypted_nonce: &[u8],
    derivation_private_key: &BoxedUint,
    session_private_key: &BoxedUint,
) -> Result<Box<dyn SmartCard>, CommunicationError> {
    // derive key from MRZ data
    let mut mrz_hasher = Sha1::new();
    mrz_hasher.update(mrz_data);
    let mrz_hash = mrz_hasher.finalize();
    let nonce_key = cipher_and_mac.derive_key_from_password(&mrz_hash);

    // decrypt the nonce
    let nonce_iv = vec![0u8; cipher_and_mac.cipher_block_size()];
    let mut nonce_bytes = Zeroizing::new(encrypted_nonce.to_vec());
    cipher_and_mac.decrypt_padded_data(&mut nonce_bytes, &nonce_key, &nonce_iv);
    let nonce = Zeroizing::new(boxed_uint_from_be_slice(&nonce_bytes));

    // derive the shared secret for generic mapping using Diffie-Hellman
    let session_key_exchange = {
        let public_key_bytes = key_exchange.calculate_public_key(&derivation_private_key);
        let card_public_key_bytes = exchange_mapping_values(&mut card, &public_key_bytes)?;
        key_exchange.derive_generic_mapping(&nonce, &derivation_private_key, &card_public_key_bytes)
    };

    // second round of key agreement with the new parameters
    let (shared_secret_bytes, public_key_bytes, card_public_key_bytes) = {
        let public_key_bytes = session_key_exchange.calculate_public_key(&session_private_key);
        let card_public_key_bytes = exchange_ephemeral_public_keys(&mut card, &public_key_bytes)?;
        if public_key_bytes.ct_eq(card_public_key_bytes.as_slice()).into() {
            return Err(Error::DiffieHellmanKeysEqual.into());
        }
        let shared_secret = session_key_exchange.exchange_keys(&session_private_key, &card_public_key_bytes);
        (shared_secret, public_key_bytes, card_public_key_bytes)
    };

    // derive keys
    let k_session_enc = cipher_and_mac.derive_encryption_key(&shared_secret_bytes);
    let k_session_mac = cipher_and_mac.derive_mac_key(&shared_secret_bytes);

    // mutual authentication
    let outgoing_token = calculate_mutual_token(
        cipher_and_mac,
        protocol,
        key_exchange.public_key_tag(),
        &card_public_key_bytes,
        &k_session_mac,
    );
    let expected_token = calculate_mutual_token(
        cipher_and_mac,
        protocol,
        key_exchange.public_key_tag(),
        &public_key_bytes,
        &k_session_mac,
    );
    let incoming_token = mutual_authentication(&mut card, &outgoing_token)?;
    if !bool::from(incoming_token.ct_eq(&expected_token)) {
        return Err(Error::MutualAuthentication.into());
    }

    // set up secure messaging
    // the initial send sequence counter is all-zeroes for PACE
    let send_sequence_counter = vec![0u8; cipher_and_mac.cipher_block_size()];
    Ok(cipher_and_mac.create_secure_messaging(
        card,
        &k_session_enc,
        &k_session_mac,
        &send_sequence_counter,
    ))
}


/// Performs a generic mapping key exchange.
fn perform_gm_kex(
    card: Box<dyn SmartCard>,
    protocol: &Oid,
    key_exchange: KeyExchange,
    cipher_and_mac: &Box<dyn CipherAndMac>,
    mrz_data: &[u8],
    encrypted_nonce: &[u8],
) -> Result<Box<dyn SmartCard>, CommunicationError> {
    let mut derivation_private_key_bytes = Zeroizing::new(vec![0u8; key_exchange.private_key_len_bytes()]);
    OsRng.fill_bytes(derivation_private_key_bytes.as_mut_slice());
    let derivation_private_key = Zeroizing::new(boxed_uint_from_be_slice(&derivation_private_key_bytes));

    let mut session_private_key_bytes = Zeroizing::new(vec![0u8; key_exchange.private_key_len_bytes()]);
    OsRng.fill_bytes(session_private_key_bytes.as_mut_slice());
    let session_private_key = Zeroizing::new(boxed_uint_from_be_slice(&session_private_key_bytes));

    perform_gm_kex_with_values(
        card,
        protocol,
        key_exchange,
        cipher_and_mac,
        mrz_data,
        encrypted_nonce,
        &*derivation_private_key,
        &*session_private_key,
    )
}


/// Performs an integrated mapping key exchange using specific values.
pub fn perform_im_kex_with_values(
    mut card: Box<dyn SmartCard>,
    protocol: &Oid,
    key_exchange: KeyExchange,
    cipher_and_mac: &Box<dyn CipherAndMac>,
    mrz_data: &[u8],
    encrypted_nonce: &[u8],
    terminal_nonce: &[u8],
    session_private_key: &BoxedUint,
) -> Result<Box<dyn SmartCard>, CommunicationError> {
    // derive key from MRZ data
    let mut mrz_hasher = Sha1::new();
    mrz_hasher.update(mrz_data);
    let mrz_hash = mrz_hasher.finalize();
    let nonce_key = cipher_and_mac.derive_key_from_password(&mrz_hash);

    // decrypt the (chip's) nonce
    let nonce_iv = vec![0u8; cipher_and_mac.cipher_block_size()];
    let mut nonce_bytes = Zeroizing::new(encrypted_nonce.to_vec());
    cipher_and_mac.decrypt_padded_data(&mut nonce_bytes, &nonce_key, &nonce_iv);

    // send our nonce to the chip, expecting nothing in return
    exchange_mapping_values(&mut card, terminal_nonce)?;

    // run the pseudorandom function
    let pseudorandom_result = cipher_and_mac.integrated_mapping_pseudorandom_function(
        &nonce_bytes,
        terminal_nonce,
        key_exchange.prime_order(),
    );

    // derive the session key exchange from that
    let session_key_exchange = key_exchange.derive_integrated_mapping(&pseudorandom_result);

    // key agreement with the new parameters
    let (shared_secret_bytes, public_key_bytes, card_public_key_bytes) = {
        let public_key_bytes = session_key_exchange.calculate_public_key(&session_private_key);
        let card_public_key_bytes = exchange_ephemeral_public_keys(&mut card, &public_key_bytes)?;
        if public_key_bytes.ct_eq(card_public_key_bytes.as_slice()).into() {
            return Err(Error::DiffieHellmanKeysEqual.into());
        }
        let shared_secret = session_key_exchange.exchange_keys(&session_private_key, &card_public_key_bytes);
        (shared_secret, public_key_bytes, card_public_key_bytes)
    };

    // derive keys
    let k_session_enc = cipher_and_mac.derive_encryption_key(&shared_secret_bytes);
    let k_session_mac = cipher_and_mac.derive_mac_key(&shared_secret_bytes);

    // mutual authentication
    let outgoing_token = calculate_mutual_token(
        cipher_and_mac,
        protocol,
        key_exchange.public_key_tag(),
        &card_public_key_bytes,
        &k_session_mac,
    );
    let expected_token = calculate_mutual_token(
        cipher_and_mac,
        protocol,
        key_exchange.public_key_tag(),
        &public_key_bytes,
        &k_session_mac,
    );
    let incoming_token = mutual_authentication(&mut card, &outgoing_token)?;
    if !bool::from(incoming_token.ct_eq(&expected_token)) {
        return Err(Error::MutualAuthentication.into());
    }

    // set up secure messaging
    // the initial send sequence counter is all-zeroes for PACE
    let send_sequence_counter = vec![0u8; cipher_and_mac.cipher_block_size()];
    Ok(cipher_and_mac.create_secure_messaging(
        card,
        &k_session_enc,
        &k_session_mac,
        &send_sequence_counter,
    ))
}


/// Performs an integrated mapping key exchange.
fn perform_im_kex(
    card: Box<dyn SmartCard>,
    protocol: &Oid,
    key_exchange: KeyExchange,
    cipher_and_mac: &Box<dyn CipherAndMac>,
    mrz_data: &[u8],
    encrypted_nonce: &[u8],
) -> Result<Box<dyn SmartCard>, CommunicationError> {
    let mut terminal_nonce = Zeroizing::new(vec![0u8; cipher_and_mac.cipher_block_size()]);
    OsRng.fill_bytes(terminal_nonce.as_mut_slice());

    let mut session_private_key_bytes = Zeroizing::new(vec![0u8; key_exchange.private_key_len_bytes()]);
    OsRng.fill_bytes(session_private_key_bytes.as_mut_slice());
    let session_private_key = Zeroizing::new(boxed_uint_from_be_slice(&session_private_key_bytes));

    perform_im_kex_with_values(
        card,
        protocol,
        key_exchange,
        cipher_and_mac,
        mrz_data,
        encrypted_nonce,
        &terminal_nonce,
        &session_private_key,
    )
}


macro_rules! equals_any {
    ($template:expr, $option1:expr $(, $options:expr)* $(,)?) => {
        ($template == $option1 $(|| $template == $options)*)
    };
}


/// Authenticates with the card using PACE.
///
/// `card_access` is the data read from the file `EF.CardAccess`; `mrz_data` corresponds to the concatenation of
/// document number (including check digit), date of birth (including check digit) and date of expiry (including check
/// digit).
pub fn establish(
    mut card: Box<dyn SmartCard>,
    card_access: &[u8],
    mrz_data: &[u8],
) -> Result<Box<dyn SmartCard>, CommunicationError> {
    // card_access is the data in EF.CardAccess, which is DER-encoded

    // try to decode its base structure as a SET OF Any (SetOf<Any>)
    let security_infos: SetOf<Any> = rasn::der::decode(card_access)
        .map_err(|e| Error::CardAccessDecoding(e))?;

    // now try to decode each of its entries as a SEQUENCE OF Any (Vec<Any>)
    let mut pace_info_opt = None;
    let mut unsupported_mapping = None;
    for (entry_index, security_info) in security_infos.to_vec().into_iter().enumerate() {
        let security_info_seq: Vec<Any> = rasn::der::decode(security_info.as_bytes())
            .map_err(|error| Error::CardAccessEntryDecoding { entry_index, error })?;
        if security_info_seq.len() < 1 {
            // assume invalid structure and skip
            // FIXME: return an error instead?
            continue;
        }
        let Ok(security_info_oid): Result<ObjectIdentifier, _> = rasn::der::decode(security_info_seq[0].as_bytes()) else {
            // assume invalid structure and skip
            // FIXME: return an error instead?
            continue;
        };
        if !PACE_PROTOCOL_OIDS.contains(&&*security_info_oid) {
            // not relevant
            continue;
        }
        if equals_any!(
            security_info_oid,
            PACE_DH_IM_3DES_CBC_CBC, PACE_DH_IM_AES_CBC_CMAC_128,
            PACE_DH_IM_AES_CBC_CMAC_192, PACE_DH_IM_AES_CBC_CMAC_256,
            PACE_ECDH_IM_3DES_CBC_CBC, PACE_ECDH_IM_AES_CBC_CMAC_128,
            PACE_ECDH_IM_AES_CBC_CMAC_192, PACE_ECDH_IM_AES_CBC_CMAC_256,
            PACE_ECDH_CAM_AES_CBC_CMAC_128, PACE_ECDH_CAM_AES_CBC_CMAC_192,
            PACE_ECDH_CAM_AES_CBC_CMAC_256,
        ) {
            unsupported_mapping = Some(security_info_oid.clone());
            continue;
        }

        // try to decode the whole thing as a PaceInfo now
        let pace_info: PaceInfo = rasn::der::decode(security_info.as_bytes())
            .map_err(|error| Error::CardAccessEntryDecodingPace { entry_index, error })?;
        pace_info_opt = Some(pace_info);
        break;
    }

    let pace_info = match pace_info_opt {
        Some(pi) => pi,
        None => {
            return Err(
                match unsupported_mapping {
                    Some(protocol) => Error::MappingNotSupported { protocol },
                    None => Error::NotSupported,
                }.into()
            );
        },
    };

    // we currently only support standard parameters (Doc 9303 Part 11 § 9.5.1)
    let pace_parameter_id_integer = pace_info.parameter_id
        .ok_or(Error::CustomParameters)?;
    let pace_parameter_id = pace_parameter_id_integer.try_into()
        .map_err(|_| Error::CustomParameters)?;

    let key_exchange = if equals_any!(
        pace_info.protocol,
        PACE_DH_GM_3DES_CBC_CBC, PACE_DH_GM_AES_CBC_CMAC_128,
        PACE_DH_GM_AES_CBC_CMAC_192, PACE_DH_GM_AES_CBC_CMAC_256,
    ) {
        match pace_parameter_id {
            0 => KeyExchange::DiffieHellman(crate::crypt::dh::params::get_1024_modp_160_po()),
            1 => KeyExchange::DiffieHellman(crate::crypt::dh::params::get_2048_modp_224_po()),
            2 => KeyExchange::DiffieHellman(crate::crypt::dh::params::get_2048_modp_256_po()),
            other => return Err(Error::IncompatibleProtocolParameter { protocol: pace_info.protocol, parameter: other }.into()),
        }
    } else if equals_any!(
        pace_info.protocol,
        PACE_ECDH_GM_3DES_CBC_CBC, PACE_ECDH_GM_AES_CBC_CMAC_128,
        PACE_ECDH_GM_AES_CBC_CMAC_192, PACE_ECDH_GM_AES_CBC_CMAC_256,
    ) {
        // elliptic-curve Diffie-Hellman
        match pace_parameter_id {
            8 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_nist_p192()),
            9 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_brainpool_p192r1()),
            10 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_nist_p224()),
            11 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_brainpool_p224r1()),
            12 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_nist_p256()),
            13 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_brainpool_p256r1()),
            14 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_brainpool_p320r1()),
            15 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_nist_p384()),
            16 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_brainpool_p384r1()),
            17 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_brainpool_p512r1()),
            18 => KeyExchange::PrimeWeierstrassEllipticDiffieHellman(crate::crypt::elliptic::curves::get_nist_p521()),
            other => return Err(Error::IncompatibleProtocolParameter { protocol: pace_info.protocol, parameter: other }.into()),
        }
    } else {
        unreachable!()
    };
    let cipher_and_mac: Box<dyn CipherAndMac> = if equals_any!(pace_info.protocol, PACE_DH_GM_3DES_CBC_CBC, PACE_ECDH_GM_3DES_CBC_CBC) {
        Box::new(Cam3Des)
    } else if equals_any!(pace_info.protocol, PACE_DH_GM_AES_CBC_CMAC_128, PACE_ECDH_GM_AES_CBC_CMAC_128) {
        Box::new(CamAes128)
    } else if equals_any!(pace_info.protocol, PACE_DH_GM_AES_CBC_CMAC_192, PACE_ECDH_GM_AES_CBC_CMAC_192) {
        Box::new(CamAes192)
    } else if equals_any!(pace_info.protocol, PACE_DH_GM_AES_CBC_CMAC_256, PACE_ECDH_GM_AES_CBC_CMAC_256) {
        Box::new(CamAes256)
    } else {
        unreachable!()
    };

    // choose the encryption method
    set_authentication_template(&mut card, &pace_info.protocol, PasswordSource::Mrz)?;

    // obtain the encrypted nonce from the chip
    let nonce_data = obtain_encrypted_nonce(&mut card)?;

    perform_gm_kex(
        card, &pace_info.protocol, key_exchange, &cipher_and_mac, mrz_data, &nonce_data,
    )
}
