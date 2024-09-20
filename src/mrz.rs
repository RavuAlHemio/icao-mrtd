//! Decoding of machine-readable zones.
//!
//! Three form factors are defined: TD1 (credit-card size), TD2 (old German ID card size, ISO 216
//! size A7) and TD3 (passport, ISO 216 size B7).
//!
//! The TD1 encoding is:
//! ```plain
//! TTSSSNNNNNNNNNCOOOOOOOOOOOOOOO
//! BBBBBBDXEEEEEEFAAAPPPPPPPPPPPG
//! IIIIIIIIIIIIIIIIIIIIIIIIIIIIII
//! ```
//! with
//! * `TT`: type of document (right-padded with `<`)
//! * `SSS`: issuing state or organization (right-padded with `<`)
//! * `NNNNNNNNN`: first 9 characters of document number (spaces replaced by `<`, right-padded with
//!   `<`)
//! * `C`: check digit of document number, or `<` if document number is longer than 9 digits
//! * `OOOOOOOOOOOOOOO`: optional data (right-padded with `<`); if document number is longer than 9
//!   digits, beings with remaining digits of document number followed by check digit followed by
//!   `<`
//! * `BBBBBB`: date of birth as YYMMDD
//! * `D`: check digit of date of birth
//! * `X`: sex (`F`, `M`, or `<` for unspecified)
//! * `EEEEEE`: date of expiry as YYMMDD
//! * `F`: check digit of date of expiry
//! * `AAA`: nationality
//! * `PPPPPPPPPPP`: optional data (right-padded with `<`)
//! * `G`: composite check digit of `NNNNNNNNNCOOOOOOOOOOOOOOOBBBBBBDEEEEEEFPPPPPPPPPPP`
//! * `IIIIIIIIIIIIIIIIIIIIIIIIIIIIII`: name (possibly truncated):
//!   1. primary identifier (components separated by `<`)
//!   2. if there is a secondary identifier: `<<`
//!   3. secondary identifier (components separated by `<`)
//!   4. padding with `<`
//!
//! The TD2 encoding is:
//! ```plain
//! TTSSSIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
//! NNNNNNNNNCAAABBBBBBDXEEEEEEFOOOOOOOG
//! ```
//! The fields are as with TD1, except the composite check digit `G` is calculated from
//! `NNNNNNNNNCBBBBBBDEEEEEEFOOOOOOO`.
//!
//! The TD3 encoding is:
//! ```plain
//! TTSSSIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
//! NNNNNNNNNCAAABBBBBBDXEEEEEEFOOOOOOOOOOOOOOQG
//! ```
//! The fields are as with TD1, except:
//! * `NNNNNNNNN` (passport number) cannot be longer than 9 characters
//! * `Q` is a check digit of `OOOOOOOOOOOOOO`
//! * `G` (composite check digit) is calculated from
//!   `NNNNNNNNNCBBBBBBDEEEEEEFOOOOOOOOOOOOOOQ`


use std::fmt::Write;

use smallstr::SmallString;


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Variant {
    Td1,
    Td2,
    Td3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Sex {
    Female,
    Male,
    Unspecified,
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Td1Data {
    /// Document type.
    pub document_type: SmallString<[u8; 2]>,

    /// Issuer state or organization of the document.
    pub issuer: SmallString<[u8; 3]>,

    /// Number of the document.
    ///
    /// Can be alphanumeric.
    pub document_number: SmallString<[u8; 22]>,

    /// Check digit of the document number.
    pub document_number_check: u8,

    /// Optional data 1.
    pub optional_data_1: SmallString<[u8; 15]>,

    /// Date of birth.
    pub date_of_birth: SmallString<[u8; 6]>,

    /// Check digit for date of birth.
    pub date_of_birth_check: u8,

    /// Sex.
    pub sex: Sex,

    /// Date of expiry.
    pub date_of_expiry: SmallString<[u8; 6]>,

    /// Check digit for date of expiry.
    pub date_of_expiry_check: u8,

    /// Nationality of holder.
    pub nationality: SmallString<[u8; 3]>,

    /// Optional data 2.
    pub optional_data_2: SmallString<[u8; 11]>,

    /// Composite check digit.
    pub composite_check: u8,

    /// Name of holder.
    pub name: SmallString<[u8; 39]>,
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Td2Data {
    /// Document type.
    pub document_type: SmallString<[u8; 2]>,

    /// Issuer state or organization of the document.
    pub issuer: SmallString<[u8; 3]>,

    /// Name of holder.
    pub name: SmallString<[u8; 39]>,

    /// Number of the document.
    ///
    /// Can be alphanumeric.
    pub document_number: SmallString<[u8; 22]>,

    /// Check digit of the document number.
    pub document_number_check: u8,

    /// Nationality of holder.
    pub nationality: SmallString<[u8; 3]>,

    /// Date of birth.
    pub date_of_birth: SmallString<[u8; 6]>,

    /// Check digit for date of birth.
    pub date_of_birth_check: u8,

    /// Sex.
    pub sex: Sex,

    /// Date of expiry.
    pub date_of_expiry: SmallString<[u8; 6]>,

    /// Check digit for date of expiry.
    pub date_of_expiry_check: u8,

    /// Optional data 1.
    pub optional_data_1: SmallString<[u8; 15]>,

    /// Composite check digit.
    pub composite_check: u8,
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Td3Data {
    /// Document type.
    pub document_type: SmallString<[u8; 2]>,

    /// Issuer state or organization of the document.
    pub issuer: SmallString<[u8; 3]>,

    /// Name of holder.
    pub name: SmallString<[u8; 39]>,

    /// Number of the document.
    ///
    /// Can be alphanumeric.
    pub document_number: SmallString<[u8; 22]>,

    /// Check digit of the document number.
    pub document_number_check: u8,

    /// Nationality of holder.
    pub nationality: SmallString<[u8; 3]>,

    /// Date of birth.
    pub date_of_birth: SmallString<[u8; 6]>,

    /// Check digit for date of birth.
    pub date_of_birth_check: u8,

    /// Sex.
    pub sex: Sex,

    /// Date of expiry.
    pub date_of_expiry: SmallString<[u8; 6]>,

    /// Check digit for date of expiry.
    pub date_of_expiry_check: u8,

    /// Optional data 1.
    pub optional_data_1: SmallString<[u8; 15]>,

    /// Check digit for optional data 1.
    pub optional_data_1_check: u8,

    /// Composite check digit.
    pub composite_check: u8,
}


macro_rules! mrz_field {
    ($name:ident, $type:ty) => {
        pub fn $name(&self) -> $type {
            match self {
                Self::Td1(d) => &d.$name,
                Self::Td2(d) => &d.$name,
                Self::Td3(d) => &d.$name,
            }
        }
    };
    ($name:ident, $type:ty, copy) => {
        pub fn $name(&self) -> $type {
            match self {
                Self::Td1(d) => d.$name,
                Self::Td2(d) => d.$name,
                Self::Td3(d) => d.$name,
            }
        }
    };
    ($name:ident, $type:ty, 1) => {
        pub fn $name(&self) -> Option<$type> {
            match self {
                Self::Td1(d) => Some(&d.$name),
                Self::Td2(_) => None,
                Self::Td3(_) => None,
            }
        }
    };
    ($name:ident, $type:ty, 13) => {
        pub fn $name(&self) -> Option<$type> {
            match self {
                Self::Td1(d) => Some(&d.$name),
                Self::Td2(_) => None,
                Self::Td3(d) => Some(&d.$name),
            }
        }
    };
    ($name:ident, $type:ty, copy3) => {
        pub fn $name(&self) -> Option<$type> {
            match self {
                Self::Td1(_) => None,
                Self::Td2(_) => None,
                Self::Td3(d) => Some(d.$name),
            }
        }
    };
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MrzData {
    Td1(Td1Data),
    Td2(Td2Data),
    Td3(Td3Data),
}
impl MrzData {
    mrz_field!(document_type, &str);
    mrz_field!(issuer, &str);
    mrz_field!(document_number, &str);
    mrz_field!(document_number_check, u8, copy);
    mrz_field!(optional_data_1, &str);
    mrz_field!(date_of_birth, &str);
    mrz_field!(date_of_birth_check, u8, copy);
    mrz_field!(sex, Sex, copy);
    mrz_field!(date_of_expiry, &str);
    mrz_field!(date_of_expiry_check, u8, copy);
    mrz_field!(nationality, &str);
    mrz_field!(optional_data_2, &str, 1);
    mrz_field!(composite_check, u8, copy);
    mrz_field!(name, &str);

    mrz_field!(optional_data_1_check, u8, copy3);

    pub fn variant(&self) -> Variant {
        match self {
            Self::Td1(_) => Variant::Td1,
            Self::Td2(_) => Variant::Td2,
            Self::Td3(_) => Variant::Td3,
        }
    }

    pub fn mrz_key(&self) -> String {
        let mut ret = String::with_capacity(22 + 1 + 6 + 1 + 6 + 1);
        ret.push_str(&self.document_number());
        write!(ret, "{}", self.document_number_check()).unwrap();
        ret.push_str(&self.date_of_birth());
        write!(ret, "{}", self.date_of_birth_check()).unwrap();
        ret.push_str(&self.date_of_expiry());
        write!(ret, "{}", self.date_of_expiry_check()).unwrap();
        ret
    }

    pub fn is_document_number_valid(&self) -> bool {
        check_digit(&self.document_number()) == self.document_number_check()
    }

    pub fn is_date_of_birth_valid(&self) -> bool {
        check_digit(&self.date_of_birth()) == self.date_of_birth_check()
    }

    pub fn is_date_of_expiry_valid(&self) -> bool {
        check_digit(&self.date_of_expiry()) == self.date_of_expiry_check()
    }
}

fn check_digit(data: &[u8]) -> u8 {
    const WEIGHTS: [u8; 3] = [7, 3, 1];

    let mut weight_index = 0;
    let mut check_digit: u8 = 0;
    for (b, weight) in data.iter().map(|b| *b).zip(WEIGHTS.iter().map(|w| *w).cycle()) {
        let value = if b >= b'0' && b <= b'9' {
            b - b'0'
        } else if b >= b'A' && b <= b'Z' {
            b + 10 - b'A'
        } else {
            // skip '<' as well as invalid characters
            // (they have value 0, but we keep cycling the weight)
            continue;
        };

        // worst-case scenario: 'Z' at weight 7 (7 * 35 = 245) plus current check digit 9 = 254
        // that always fits into u8
        let weighted = value * weight;
        weight_index = (weight_index + 1) % WEIGHTS.len();
        check_digit = (check_digit + weighted) % 10;
    }

    check_digit
}
