//! Cryptographic functionality for PACE.


mod dh;
mod elliptic;


use crate::pace::crypt::dh::DiffieHellman;
use crate::pace::crypt::elliptic::PrimeWeierstrassCurve;


pub enum AnyDiffieHellman {
    Classic(DiffieHellman),
    EllipticCurve(PrimeWeierstrassCurve),
}


pub struct ProtocolSet {
}
