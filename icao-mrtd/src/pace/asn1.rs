//! ASN.1 structures relevant to PACE.


use rasn::{AsnType, Decode, Encode};
use rasn::types::{Any, Integer, ObjectIdentifier};


/// An item of PACE-related security information in the `EF.CardAccess` file on the travel document
/// chip.
///
/// The content of `EF.CardAccess` is a SET OF such structures; the first item is always an OID
/// specifying the protocol, but non-`PaceInfo` items need not adhere to this structure, so it is
/// necessary to ensure that a `PaceInfo` structure is being decoded. It is therefore recommended
/// to first decode `EF.CardAccess` as a `SetOf<Any>`, then each entry as a `Vec<Any>`, then each
/// entry's first member as an `ObjectIdentifier`.
///
/// Specified in ICAO Doc 9303 Part 11 § 9.2.1.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PaceInfo {
    pub protocol: ObjectIdentifier,
    pub version: Integer,
    pub parameter_id: Option<Integer>,
}
impl PaceInfo {
    pub fn new(
        protocol: ObjectIdentifier,
        version: Integer,
        parameter_id: Option<Integer>,
    ) -> Self {
        Self {
            protocol,
            version,
            parameter_id,
        }
    }
}


/// An item of PACE domain parameter security information in the `EF.CardAccess` file on the travel
/// document chip.
///
/// `domain_parameter` can be decoded as [`AlgorithmIdentifier`] to identify the underlying
/// algorithm. Concrete implementations are currently not provided.
///
/// Specified in ICAO Doc 9303 Part 11 § 9.2.2.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[rasn(automatic_tags)]
pub struct PaceDomainParameterInfo {
    pub protocol: ObjectIdentifier,
    pub domain_parameter: Any,
    pub parameter_id: Option<Integer>,
}
impl PaceDomainParameterInfo {
    pub fn new(
        protocol: ObjectIdentifier,
        domain_parameter: Any,
        parameter_id: Option<Integer>,
    ) -> Self {
        Self {
            protocol,
            domain_parameter,
            parameter_id,
        }
    }
}


/// An identifier identifying a specific cryptographic algorithm and, optionally, parameters for it.
///
/// Algorithms may provide additional information following `algorithm` which is specific to that
/// `algorithm`. This type is kept deliberately generic to allow algorithm detection.
///
/// Specified in ICAO Doc 9303 Part 11 § 9.2. The definition of `parameters` is delegated to ANSI
/// X9.42 (Diffie-Hellman) and BSI TR-03111 (Elliptic-Curve Diffie-Hellman).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[rasn(automatic_tags)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    // parameters ANY DEFINED BY algorithm OPTIONAL,
}
impl AlgorithmIdentifier {
    pub fn new(
        algorithm: ObjectIdentifier,
    ) -> Self {
        Self {
            algorithm,
        }
    }
}


/// Encode an ASN.1 DER primitive value length.
pub fn der_encode_primitive_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        // single-byte encoding
        output.push(length.try_into().unwrap());
    } else {
        // 0b1nnn_nnnn and then n additional bytes that actually specify the length
        // (big-endian)
        let length_bytes = length.to_be_bytes();
        let mut trimmed_length_slice = &length_bytes[..];
        while trimmed_length_slice[0] == 0x00 {
            trimmed_length_slice = &trimmed_length_slice[1..];
        }
        output.push(0b1000_0000 | u8::try_from(trimmed_length_slice.len()).unwrap());
        output.extend(trimmed_length_slice);
    }
}


/// Decode an ASN.1 DER primitive value length.
///
/// The length must be at the beginning of the input slice.
///
/// Returns a tuple `(length, rest)` where `rest` is the rest of the input slice once the length has
/// been removed.
pub fn der_try_decode_primitive_length(input: &[u8]) -> Option<(usize, &[u8])> {
    if input.len() == 0 {
        return None;
    }
    let start_byte = input[0];
    let start_lower_bits = start_byte & 0b0111_1111;
    if start_byte & 0b1000_0000 != 0 {
        // multiple bytes
        let length_byte_count: usize = start_lower_bits.into();
        if length_byte_count == 0 {
            return None;
        }
        if length_byte_count > input.len() - 1 {
            // that will never fit
            return None;
        }
        let mut length: usize = 0;
        for length_byte in &input[1..1+length_byte_count] {
            let Some(multiplied) = length.checked_mul(256) else { return None };
            length = multiplied;
            let Some(added) = length.checked_add(usize::from(*length_byte)) else { return None };
            length = added;
        }
        Some((length, &input[1+length_byte_count..]))
    } else {
        let length = start_lower_bits.into();
        Some((length, &input[1..]))
    }
}
