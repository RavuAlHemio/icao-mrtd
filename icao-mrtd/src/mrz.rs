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


use std::fmt::{self, Write};
use std::str::FromStr;

use smallstr::SmallString;
use smallvec::SmallVec;


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
impl From<Sex> for char {
    fn from(value: Sex) -> Self {
        match value {
            Sex::Female => 'F',
            Sex::Male => 'M',
            Sex::Unspecified => '<',
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CheckDigitKind {
    DocumentNumber,
    BirthDate,
    ExpiryDate,
    OptionalData1,
    Composite,
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ParseError {
    InvalidCharacter { byte_position: usize, character: char },
    LineCount { expected: usize, obtained: usize },
    CharsPerLine { line_index: usize, expected: usize, obtained: usize },
    InvalidCheckDigit { kind: CheckDigitKind, byte_value: u8 },
    InvalidSex { byte_value: u8 },
    InvalidFormat,
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InvalidCharacter { byte_position, character }
                => write!(f, "invalid character U+{:04X} at position {}", u32::from(*character), byte_position),
            Self::LineCount { expected, obtained }
                => write!(f, "expected {} lines, obtained {}", expected, obtained),
            Self::CharsPerLine { line_index, expected, obtained }
                => write!(f, "expected {} characters on line with index {}, obtained {}", expected, line_index, obtained),
            Self::InvalidCheckDigit { kind, byte_value }
                => write!(f, "invalid {:?} check digit U+{:04X}", kind, byte_value),
            Self::InvalidSex { byte_value }
                => write!(f, "invalid sex U+{:04X}", byte_value),
            Self::InvalidFormat
                => write!(f, "the MRZ data has an invalid format"),
        }
    }
}
impl std::error::Error for ParseError {
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
    pub birth_date: SmallString<[u8; 6]>,

    /// Check digit for date of birth.
    pub birth_date_check: u8,

    /// Sex.
    pub sex: Sex,

    /// Date of expiry.
    pub expiry_date: SmallString<[u8; 6]>,

    /// Check digit for date of expiry.
    pub expiry_date_check: u8,

    /// Nationality of holder.
    pub nationality: SmallString<[u8; 3]>,

    /// Optional data 2.
    pub optional_data_2: SmallString<[u8; 11]>,

    /// Composite check digit.
    pub composite_check: u8,

    /// Name of holder.
    pub name: SmallString<[u8; 39]>,
}
impl Td1Data {
    pub fn is_composite_valid(&self) -> bool {
        // collect top (except type and issuer) and middle line (except sex and nationality)
        let mut all_bytes = String::new();
        if self.document_number.len() > 9 {
            // split
            all_bytes.push_str(&self.document_number[0..9]);
            all_bytes.push('<');
            all_bytes.push_str(&self.document_number[9..]);
            write!(all_bytes, "{}", self.document_number_check).unwrap();
            if self.optional_data_1.len() > 0 {
                all_bytes.push('<');
                all_bytes.push_str(&self.optional_data_1);
            }
        } else {
            append_right_padded(&mut all_bytes, &self.document_number, 9);
            write!(all_bytes, "{}", self.document_number_check).unwrap();
            all_bytes.push_str(&self.optional_data_1);
        }
        while all_bytes.len() < 25 {
            all_bytes.push('<');
        }

        append_right_padded(&mut all_bytes, &self.birth_date, 6);
        write!(all_bytes, "{}", self.birth_date_check).unwrap();
        append_right_padded(&mut all_bytes, &self.expiry_date, 6);
        write!(all_bytes, "{}", self.expiry_date_check).unwrap();
        all_bytes.push_str(&self.optional_data_2);
        while all_bytes.len() < 54 {
            all_bytes.push('<');
        }

        check_digit(all_bytes.as_bytes()) == self.composite_check
    }
}
impl FromStr for Td1Data {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure_charset(s)?;
        ensure_line_count(s, 3)?;
        ensure_line_lengths(s, 30)?;

        let lines: SmallVec<[&str; 3]> = s.split('\n').collect();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| l.len() == 30));

        let document_type: SmallString<_> = lines[0][0..2]
            .trim_end_matches('<')
            .into();
        let issuer: SmallString<_> = lines[0][2..5]
            .trim_end_matches('<')
            .into();
        let mut document_number: SmallString<_> = lines[0][5..14]
            .trim_end_matches('<')
            .into();
        let mut document_number_check_str: SmallString<[u8; 1]> = lines[0][14..15]
            .trim_end_matches('<')
            .into();
        let mut optional_data_1: SmallString<_> = lines[0][15..30]
            .trim_end_matches('<')
            .into();

        // does the document number extend beyond the regular field?
        if document_number_check_str.len() == 0 {
            // yes; split at first fill character
            let document_number_rest = if let Some((document_number_rest, optional_data_1_rest)) = optional_data_1.split_once('<') {
                let dnr = document_number_rest.into();
                optional_data_1 = optional_data_1_rest
                    .into();
                dnr
            } else {
                // no fill character; take the whole thing
                optional_data_1.clone()
            };

            let actual_document_number_rest = &document_number_rest[0..document_number_rest.len() - 1];
            document_number.push_str(actual_document_number_rest);
            document_number_check_str = document_number_rest[document_number_rest.len()-1..]
                .into();
        }

        let document_number_check = decode_check_digit(&document_number_check_str, CheckDigitKind::DocumentNumber)?;

        let birth_date: SmallString<_> = lines[1][0..6]
            .trim_end_matches('<')
            .into();
        let birth_date_check = decode_check_digit(&lines[1][6..7], CheckDigitKind::BirthDate)?;

        let sex = decode_sex(lines[1].as_bytes()[7])?;

        let expiry_date: SmallString<_> = lines[1][8..14]
            .trim_end_matches('<')
            .into();
        let expiry_date_check = decode_check_digit(&lines[1][14..15], CheckDigitKind::BirthDate)?;

        let nationality = lines[1][15..18]
            .trim_end_matches('<')
            .into();
        let optional_data_2 = lines[1][18..29]
            .trim_end_matches('<')
            .into();

        let composite_check = decode_check_digit(&lines[1][29..30], CheckDigitKind::Composite)?;

        let name = lines[2]
            .trim_end_matches('<')
            .replace('<', " ")
            .into();

        Ok(Self {
            document_type,
            issuer,
            document_number,
            document_number_check,
            optional_data_1,
            birth_date,
            birth_date_check,
            sex,
            expiry_date,
            expiry_date_check,
            nationality,
            optional_data_2,
            composite_check,
            name,
        })
    }
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
    pub birth_date: SmallString<[u8; 6]>,

    /// Check digit for date of birth.
    pub birth_date_check: u8,

    /// Sex.
    pub sex: Sex,

    /// Date of expiry.
    pub expiry_date: SmallString<[u8; 6]>,

    /// Check digit for date of expiry.
    pub expiry_date_check: u8,

    /// Optional data 1.
    pub optional_data_1: SmallString<[u8; 15]>,

    /// Composite check digit.
    pub composite_check: u8,
}
impl Td2Data {
    pub fn is_composite_valid(&self) -> bool {
        // collect bottom line (except sex and issuer)
        let mut all_bytes = String::new();
        let document_number_rest = if self.document_number.len() > 9 {
            // split
            all_bytes.push_str(&self.document_number[0..9]);
            all_bytes.push('<');
            format!("{}{}", &self.document_number[9..], self.document_number_check)
        } else {
            append_right_padded(&mut all_bytes, &self.document_number, 9);
            write!(all_bytes, "{}", self.document_number_check).unwrap();
            String::with_capacity(0)
        };

        append_right_padded(&mut all_bytes, &self.birth_date, 6);
        write!(all_bytes, "{}", self.birth_date_check).unwrap();
        append_right_padded(&mut all_bytes, &self.expiry_date, 6);
        write!(all_bytes, "{}", self.expiry_date_check).unwrap();

        if document_number_rest.len() > 0 {
            // in this case, optional data 1 is actually:
            // 1. rest of document number
            // 2. full document number check digit
            // 3. '<'
            // 4. actual optional data
            all_bytes.push_str(&document_number_rest);
            if self.optional_data_1.len() > 0 {
                all_bytes.push('<');
                all_bytes.push_str(&self.optional_data_1);
            }
        }

        while all_bytes.len() < 35 {
            all_bytes.push('<');
        }

        check_digit(all_bytes.as_bytes()) == self.composite_check
    }
}
impl FromStr for Td2Data {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure_charset(s)?;
        ensure_line_count(s, 2)?;
        ensure_line_lengths(s, 36)?;

        let lines: SmallVec<[&str; 2]> = s.split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| l.len() == 36));

        let document_type: SmallString<_> = lines[0][0..2]
            .trim_end_matches('<')
            .into();
        let issuer: SmallString<_> = lines[0][2..5]
            .trim_end_matches('<')
            .into();

        let name = lines[0][5..36]
            .trim_end_matches('<')
            .replace('<', " ")
            .into();

        let mut document_number: SmallString<_> = lines[1][0..9]
            .trim_end_matches('<')
            .into();
        let mut document_number_check_str: SmallString<[u8; 1]> = lines[1][9..10]
            .trim_end_matches('<')
            .into();
        let nationality = lines[1][10..13]
            .trim_end_matches('<')
            .into();

        let birth_date: SmallString<_> = lines[1][13..19]
            .trim_end_matches('<')
            .into();
        let birth_date_check = decode_check_digit(&lines[1][19..20], CheckDigitKind::BirthDate)?;

        let sex = decode_sex(lines[1].as_bytes()[20])?;

        let expiry_date: SmallString<_> = lines[1][21..27]
            .trim_end_matches('<')
            .into();
        let expiry_date_check = decode_check_digit(&lines[1][27..28], CheckDigitKind::ExpiryDate)?;

        let mut optional_data_1: SmallString<_> = lines[1][28..35]
            .trim_end_matches('<')
            .into();

        // does the document number extend beyond the regular field?
        if document_number_check_str.len() == 0 {
            // yes; split at first fill character
            let document_number_rest = if let Some((document_number_rest, optional_data_1_rest)) = optional_data_1.split_once('<') {
                let dnr = document_number_rest.into();
                optional_data_1 = optional_data_1_rest
                    .into();
                dnr
            } else {
                // no fill character; take the whole thing
                optional_data_1.clone()
            };

            let actual_document_number_rest = &document_number_rest[0..document_number_rest.len() - 1];
            document_number.push_str(actual_document_number_rest);
            document_number_check_str = document_number_rest[document_number_rest.len()-1..]
                .into();
        }

        let document_number_check = decode_check_digit(&document_number_check_str, CheckDigitKind::DocumentNumber)?;

        let composite_check = decode_check_digit(&lines[1][35..36], CheckDigitKind::Composite)?;

        Ok(Self {
            document_type,
            issuer,
            document_number,
            document_number_check,
            optional_data_1,
            birth_date,
            birth_date_check,
            sex,
            expiry_date,
            expiry_date_check,
            nationality,
            composite_check,
            name,
        })
    }
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
    pub birth_date: SmallString<[u8; 6]>,

    /// Check digit for date of birth.
    pub birth_date_check: u8,

    /// Sex.
    pub sex: Sex,

    /// Date of expiry.
    pub expiry_date: SmallString<[u8; 6]>,

    /// Check digit for date of expiry.
    pub expiry_date_check: u8,

    /// Optional data 1.
    pub optional_data_1: SmallString<[u8; 15]>,

    /// Check digit for optional data 1.
    pub optional_data_1_check: u8,

    /// Composite check digit.
    pub composite_check: u8,
}
impl Td3Data {
    pub fn is_composite_valid(&self) -> bool {
        // collect bottom line (except sex and issuer)
        let mut all_bytes = String::new();

        // with TD3, document number is guaranteed to be 9 characters max
        append_right_padded(&mut all_bytes, &self.document_number, 9);
        write!(all_bytes, "{}", self.document_number_check).unwrap();
        append_right_padded(&mut all_bytes, &self.birth_date, 6);
        write!(all_bytes, "{}", self.birth_date_check).unwrap();
        append_right_padded(&mut all_bytes, &self.expiry_date, 6);
        write!(all_bytes, "{}", self.expiry_date_check).unwrap();
        append_right_padded(&mut all_bytes, &self.optional_data_1, 14);
        write!(all_bytes, "{}", self.optional_data_1_check).unwrap();

        check_digit(all_bytes.as_bytes()) == self.composite_check
    }
}
impl FromStr for Td3Data {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure_charset(s)?;
        ensure_line_count(s, 2)?;
        ensure_line_lengths(s, 44)?;

        let lines: SmallVec<[&str; 2]> = s.split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| l.len() == 44));

        let document_type: SmallString<_> = lines[0][0..2]
            .trim_end_matches('<')
            .into();
        let issuer: SmallString<_> = lines[0][2..5]
            .trim_end_matches('<')
            .into();

        let name = lines[0][5..44]
            .trim_end_matches('<')
            .replace('<', " ")
            .into();

        // a passport's document number can be up to 9 characters
        let document_number: SmallString<_> = lines[1][0..9]
            .trim_end_matches('<')
            .into();
        let document_number_check = decode_check_digit(&lines[1][9..10], CheckDigitKind::DocumentNumber)?;

        let nationality = lines[1][10..13]
            .trim_end_matches('<')
            .into();

        let birth_date: SmallString<_> = lines[1][13..19]
            .trim_end_matches('<')
            .into();
        let birth_date_check = decode_check_digit(&lines[1][19..20], CheckDigitKind::BirthDate)?;

        let sex = decode_sex(lines[1].as_bytes()[20])?;

        let expiry_date: SmallString<_> = lines[1][21..27]
            .trim_end_matches('<')
            .into();
        let expiry_date_check = decode_check_digit(&lines[1][27..28], CheckDigitKind::ExpiryDate)?;

        let optional_data_1: SmallString<_> = lines[1][28..42]
            .trim_end_matches('<')
            .into();
        let optional_data_1_check = decode_check_digit(&lines[1][42..43], CheckDigitKind::OptionalData1)?;

        let composite_check = decode_check_digit(&lines[1][43..44], CheckDigitKind::Composite)?;

        Ok(Self {
            document_type,
            issuer,
            document_number,
            document_number_check,
            optional_data_1,
            optional_data_1_check,
            birth_date,
            birth_date_check,
            sex,
            expiry_date,
            expiry_date_check,
            nationality,
            composite_check,
            name,
        })
    }
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
pub enum Data {
    Td1(Td1Data),
    Td2(Td2Data),
    Td3(Td3Data),
}
impl Data {
    mrz_field!(document_type, &str);
    mrz_field!(issuer, &str);
    mrz_field!(document_number, &str);
    mrz_field!(document_number_check, u8, copy);
    mrz_field!(optional_data_1, &str);
    mrz_field!(birth_date, &str);
    mrz_field!(birth_date_check, u8, copy);
    mrz_field!(sex, Sex, copy);
    mrz_field!(expiry_date, &str);
    mrz_field!(expiry_date_check, u8, copy);
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
        append_right_padded(&mut ret, self.document_number(), 9);
        write!(ret, "{}", self.document_number_check()).unwrap();
        ret.push_str(&self.birth_date());
        write!(ret, "{}", self.birth_date_check()).unwrap();
        ret.push_str(&self.expiry_date());
        write!(ret, "{}", self.expiry_date_check()).unwrap();
        ret
    }

    pub fn is_document_number_valid(&self) -> bool {
        check_digit(self.document_number().as_bytes()) == self.document_number_check()
    }

    pub fn is_birth_date_valid(&self) -> bool {
        check_digit(&self.birth_date().as_bytes()) == self.birth_date_check()
    }

    pub fn is_expiry_date_valid(&self) -> bool {
        check_digit(&self.expiry_date().as_bytes()) == self.expiry_date_check()
    }

    pub fn is_optional_data_1_valid(&self) -> Option<bool> {
        match self {
            Self::Td1(_) => None,
            Self::Td2(_) => None,
            Self::Td3(td3) => Some(check_digit(td3.optional_data_1.as_bytes()) == td3.optional_data_1_check),
        }
    }

    pub fn is_composite_valid(&self) -> bool {
        match self {
            Self::Td1(td1) => td1.is_composite_valid(),
            Self::Td2(td2) => td2.is_composite_valid(),
            Self::Td3(td3) => td3.is_composite_valid(),
        }
    }
}
impl FromStr for Data {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure_charset(s)?;

        let line_count = s.split('\n').count();
        if line_count < 2 || line_count > 3 {
            return Err(ParseError::InvalidFormat);
        }
        let lines: SmallVec<[&str; 3]> = s.split('\n').collect();
        let line_length = lines[0].len();
        for other_line in lines.iter().skip(1) {
            if other_line.len() != line_length {
                return Err(ParseError::InvalidFormat);
            }
        }

        if line_count == 2 && line_length == 44 {
            Td3Data::from_str(s)
                .map(Self::Td3)
        } else if line_count == 2 && line_length == 36 {
            Td2Data::from_str(s)
                .map(Self::Td2)
        } else if line_count == 3 && line_length == 30 {
            Td1Data::from_str(s)
                .map(Self::Td1)
        } else {
            Err(ParseError::InvalidFormat)
        }
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

const fn ascii_digit_to_value(digit: u8) -> Option<u8> {
    if digit >= b'0' && digit <= b'9' {
        Some(digit - b'0')
    } else {
        None
    }
}

fn decode_check_digit(check_digit_str: &str, kind: CheckDigitKind) -> Result<u8, ParseError> {
    assert_eq!(check_digit_str.len(), 1);
    let byte_value = check_digit_str.as_bytes()[0];
    ascii_digit_to_value(byte_value)
        .ok_or(ParseError::InvalidCheckDigit { kind, byte_value })
}

fn decode_sex(sex_byte: u8) -> Result<Sex, ParseError> {
    match sex_byte {
        b'F' => Ok(Sex::Female),
        b'M' => Ok(Sex::Male),
        b'<' => Ok(Sex::Unspecified),
        other => Err(ParseError::InvalidSex { byte_value: other }),
    }
}

fn append_right_padded(ret: &mut String, value: &str, pad_to_len: usize) {
    ret.push_str(value);
    for _ in 0..(pad_to_len-value.len()) {
        ret.push('<');
    }
}

#[must_use]
fn ensure_charset(mrz_string: &str) -> Result<(), ParseError> {
    let first_bad_char_opt = mrz_string.char_indices()
        .filter(|(_byte_pos, c)|
            !(
                *c == '\n'
                || (*c >= '0' && *c <= '9')
                || *c == '<'
                || (*c >= 'A' && *c <= 'Z')
            )
        )
        .nth(0);
    match first_bad_char_opt {
        Some((byte_position, character)) => Err(ParseError::InvalidCharacter { byte_position, character }),
        None => Ok(()),
    }
}

#[must_use]
fn ensure_line_count(mrz_string: &str, expected_count: usize) -> Result<(), ParseError> {
    let newline_count = mrz_string.chars()
        .filter(|c| *c == '\n')
        .count();
    let line_count = newline_count + 1;

    if line_count == expected_count {
        Ok(())
    } else {
        Err(ParseError::LineCount { expected: expected_count, obtained: line_count })
    }
}

#[must_use]
fn ensure_line_lengths(mrz_string: &str, expected_line_length: usize) -> Result<(), ParseError> {
    for (line_index, line) in mrz_string.split('\n').enumerate() {
        // thanks to our limited charset, character and UTF-8 byte lengths of the line are the same
        if line.len() != expected_line_length {
            return Err(ParseError::CharsPerLine {
                line_index,
                expected: expected_line_length,
                obtained: line.len(),
            });
        }
    }
    Ok(())
}
