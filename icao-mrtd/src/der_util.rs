//! Utility functions for Distinguished Encoding Rules.


use rasn::types::Oid;


/// Encode an ASN.1 DER primitive value length.
pub fn encode_primitive_length(output: &mut Vec<u8>, length: usize) {
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
pub fn try_decode_primitive_length(input: &[u8]) -> Option<(usize, &[u8])> {
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


/// Encode an object identifier value into bytes using DER encoding rules.
///
/// No tag or length is encoded, only the actual value.
pub fn oid_to_der_bytes(oid: &Oid) -> Vec<u8> {
    const SEVEN_BIT_MASK: u32 = 0b0111_1111;
    const TOP_BIT: u8 = 0b1000_0000;

    assert!(oid.len() >= 2);
    assert!(oid[0] <= 2);
    if oid[0] < 2 {
        assert!(oid[1] <= 39);
    }

    fn encode_arc(ret: &mut Vec<u8>, arc: u32) {
        if arc <= 0b111_1111 {
            // 0b0nnn_nnnn
            ret.push(u8::try_from((arc >>  0) & SEVEN_BIT_MASK).unwrap());
        } else if arc <= 0b111_1111_111_1111 {
            // 0b1nnn_nnnn 0b0nnn_nnnn
            ret.push(u8::try_from((arc >>  7) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >>  0) & SEVEN_BIT_MASK).unwrap());
        } else if arc <= 0b111_1111_111_1111_111_1111 {
            // 0b1nnn_nnnn 0b1nnn_nnnn 0b0nnn_nnnn
            ret.push(u8::try_from((arc >> 14) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >>  7) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >>  0) & SEVEN_BIT_MASK).unwrap());
        } else if arc <= 0b111_1111_111_1111_111_1111_111_1111 {
            // 0b1nnn_nnnn 0b1nnn_nnnn 0b1nnn_nnnn 0b0nnn_nnnn
            ret.push(u8::try_from((arc >> 21) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >> 14) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >>  7) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >>  0) & SEVEN_BIT_MASK).unwrap());
        } else {
            // 0b1nnn_nnnn 0b1nnn_nnnn 0b1nnn_nnnn 0b1nnn_nnnn 0b0nnn_nnnn
            ret.push(u8::try_from((arc >> 28) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >> 21) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >> 14) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >>  7) & SEVEN_BIT_MASK).unwrap() | TOP_BIT);
            ret.push(u8::try_from((arc >>  0) & SEVEN_BIT_MASK).unwrap());
        }
    }

    let mut ret = Vec::new();
    let first_arc_pair = 40*oid[0] + oid[1];
    encode_arc(&mut ret, first_arc_pair);

    for arc in oid.iter().skip(2) {
        encode_arc(&mut ret, *arc);
    }

    ret
}
