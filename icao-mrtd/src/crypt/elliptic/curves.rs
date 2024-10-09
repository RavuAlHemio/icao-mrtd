//! Specific elliptic curves that can be used with PACE.
//!
//! Most parameters were taken from the [Standard Curve Database](https://neuromancer.sk/std/). The
//! standardized curves are listed in ICAO Document 9303 Part 11 Section 9.5.1.


use hex_literal::hex;

use crate::crypt::boxed_uint_from_be_slice;
use crate::crypt::elliptic::{AffinePoint, PrimeWeierstrassCurve};


pub fn get_nist_p192() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("fffffffffffffffffffffffffffffffeffffffffffffffff")),
        boxed_uint_from_be_slice(&hex!("fffffffffffffffffffffffffffffffefffffffffffffffc")),
        boxed_uint_from_be_slice(&hex!("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")),
            boxed_uint_from_be_slice(&hex!("07192b95ffc8da78631011ed6b24cdd573f977a11e794811")),
        ),
    )
}

pub fn get_nist_p224() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("ffffffffffffffffffffffffffffffff000000000000000000000001")),
        boxed_uint_from_be_slice(&hex!("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe")),
        boxed_uint_from_be_slice(&hex!("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21")),
            boxed_uint_from_be_slice(&hex!("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34")),
        ),
    )
}

pub fn get_nist_p256() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")),
        boxed_uint_from_be_slice(&hex!("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc")),
        boxed_uint_from_be_slice(&hex!("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")),
            boxed_uint_from_be_slice(&hex!("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")),
        ),
    )
}

pub fn get_nist_p384() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")),
        boxed_uint_from_be_slice(&hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc")),
        boxed_uint_from_be_slice(&hex!("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")),
            boxed_uint_from_be_slice(&hex!("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")),
        ),
    )
}

pub fn get_nist_p521() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
        boxed_uint_from_be_slice(&hex!("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc")),
        boxed_uint_from_be_slice(&hex!("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66")),
            boxed_uint_from_be_slice(&hex!("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")),
        ),
    )
}

pub fn get_brainpool_p192r1() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("c302f41d932a36cda7a3463093d18db78fce476de1a86297")),
        boxed_uint_from_be_slice(&hex!("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef")),
        boxed_uint_from_be_slice(&hex!("469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6")),
            boxed_uint_from_be_slice(&hex!("14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f")),
        ),
    )
}

pub fn get_brainpool_p224r1() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff")),
        boxed_uint_from_be_slice(&hex!("68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43")),
        boxed_uint_from_be_slice(&hex!("2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d")),
            boxed_uint_from_be_slice(&hex!("58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd")),
        ),
    )
}

pub fn get_brainpool_p256r1() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377")),
        boxed_uint_from_be_slice(&hex!("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9")),
        boxed_uint_from_be_slice(&hex!("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262")),
            boxed_uint_from_be_slice(&hex!("547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997")),
        ),
    )
}

pub fn get_brainpool_p320r1() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27")),
        boxed_uint_from_be_slice(&hex!("3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4")),
        boxed_uint_from_be_slice(&hex!("520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611")),
            boxed_uint_from_be_slice(&hex!("14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1")),
        ),
    )
}

pub fn get_brainpool_p384r1() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53")),
        boxed_uint_from_be_slice(&hex!("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826")),
        boxed_uint_from_be_slice(&hex!("04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e")),
            boxed_uint_from_be_slice(&hex!("8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315")),
        ),
    )
}

pub fn get_brainpool_p512r1() -> PrimeWeierstrassCurve {
    PrimeWeierstrassCurve::new(
        boxed_uint_from_be_slice(&hex!("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3")),
        boxed_uint_from_be_slice(&hex!("7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca")),
        boxed_uint_from_be_slice(&hex!("3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723")),
        AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822")),
            boxed_uint_from_be_slice(&hex!("7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892")),
        ),
    )
}
