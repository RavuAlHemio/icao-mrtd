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
#[rasn(automatic_tags)]
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
