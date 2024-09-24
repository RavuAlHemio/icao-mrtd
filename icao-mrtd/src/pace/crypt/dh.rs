//! The Diffie-Hellman secret exchange process.


use num_bigint::BigUint;
use rand::RngCore;
use rand::rngs::OsRng;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DiffieHellman {
    /// The prime or modulus.
    prime: BigUint,

    /// The generator or base.
    generator: BigUint,

    /// The private key.
    private_key: BigUint,
}
impl DiffieHellman {
    /// Returns a reference to the prime or modulus.
    pub fn prime(&self) -> &BigUint { &self.prime }

    /// Returns a reference to the generator or base.
    pub fn generator(&self) -> &BigUint { &self.prime }

    /// Creates a new Diffie-Hellman structure with the given prime and generator as well as a
    /// randomly generated private key that has the length matching the given subgroup size.
    pub fn new(prime: BigUint, generator: BigUint, subgroup_size_bytes: usize) -> Self {
        // generate a private key
        let mut private_key_bytes = vec![0u8; subgroup_size_bytes];
        OsRng.fill_bytes(private_key_bytes.as_mut_slice());
        let private_key = BigUint::from_bytes_be(private_key_bytes.as_slice());

        Self::new_with_private_key(prime, generator, private_key)
    }

    /// Creates a new Diffie-Hellman structure with the given prime, generator and private key.
    pub fn new_with_private_key(prime: BigUint, generator: BigUint, private_key: BigUint) -> Self {
        Self {
            prime,
            generator,
            private_key,
        }
    }

    /// Generates the public key for this Diffie-Hellman structure.
    pub fn public_key(&self) -> BigUint {
        // pubkey = generator ** private_key mod prime
        self.generator.modpow(&self.private_key, &self.prime)
    }

    /// Derives the secret for this Diffie-Hellman structure given the public key of the other
    /// party.
    pub fn finalize(&self, other_public_key: &BigUint) -> BigUint {
        // secret = other_public_key ** secret_key mod prime
        other_public_key.modpow(&self.private_key, &self.prime)
    }
}


#[cfg(test)]
mod tests {
    use super::DiffieHellman;
    use hex_literal::hex;
    use num_bigint::BigUint;

    #[test]
    fn wikipedia_example() {
        let prime = BigUint::from(23u8);
        let generator = BigUint::from(5u8);

        let alice_private = BigUint::from(4u8);
        let bob_private = BigUint::from(3u8);

        let alice_dh = DiffieHellman::new_with_private_key(prime.clone(), generator.clone(), alice_private);
        let bob_dh = DiffieHellman::new_with_private_key(prime.clone(), generator.clone(), bob_private);

        let alice_public = alice_dh.public_key();
        assert_eq!(alice_public, BigUint::from(4u8));
        let bob_public = bob_dh.public_key();
        assert_eq!(bob_public, BigUint::from(10u8));

        let alice_secret = alice_dh.finalize(&bob_public);
        let bob_secret = bob_dh.finalize(&alice_public);
        assert_eq!(alice_secret, bob_secret);
        assert_eq!(alice_secret, BigUint::from(18u8));
        assert_eq!(bob_secret, BigUint::from(18u8));
    }

    #[test]
    fn icao_doc9303_part11_secg2_example() {
        let prime = BigUint::from_bytes_be(&hex!("
            B10B8F96 A080E01D DE92DE5E AE5D54EC
            52C99FBC FB06A3C6 9A6A9DCA 52D23B61
            6073E286 75A23D18 9838EF1E 2EE652C0
            13ECB4AE A9061123 24975C3C D49B83BF
            ACCBDD7D 90C4BD70 98488E9C 219A7372
            4EFFD6FA E5644738 FAA31A4F F55BCCC0
            A151AF5F 0DC8B4BD 45BF37DF 365C1A65
            E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371
        "));
        let generator = BigUint::from_bytes_be(&hex!("
            A4D1CBD5 C3FD3412 6765A442 EFB99905
            F8104DD2 58AC507F D6406CFF 14266D31
            266FEA1E 5C41564B 777E690F 5504F213
            160217B4 B01B886A 5E91547F 9E2749F4
            D7FBD7D3 B9A92EE1 909D0D22 63F80A76
            A6A24C08 7A091F53 1DBF0A01 69B6A28A
            D662A4D1 8E73AFA3 2D779D59 18D08BC8
            858F4DCE F97C2A24 855E6EEB 22B3B2E5
        "));

        let terminal_private = BigUint::from_bytes_be(&hex!("
            5265030F 751F4AD1 8B08AC56 5FC7AC95 2E41618D
        "));
        let chip_private = BigUint::from_bytes_be(&hex!("
            66DDAFEA C1609CB5 B963BB0C B3FF8B3E 047F336C
        "));

        let terminal_dh = DiffieHellman::new_with_private_key(prime.clone(), generator.clone(), terminal_private);
        let chip_dh = DiffieHellman::new_with_private_key(prime.clone(), generator.clone(), chip_private);

        let terminal_public = terminal_dh.public_key();
        assert_eq!(
            terminal_public,
            BigUint::from_bytes_be(&hex!("
                23FB3749 EA030D2A 25B278D2 A562047A
                DE3F01B7 4F17A154 02CB7352 CA7D2B3E
                B71C343D B13D1DEB CE9A3666 DBCFC920
                B49174A6 02CB4796 5CAA73DC 702489A4
                4D41DB91 4DE9613D C5E98C94 160551C0
                DF86274B 9359BC04 90D01B03 AD54022D
                CB4F57FA D6322497 D7A1E28D 46710F46
                1AFE710F BBBC5F8B A166F431 1975EC6C
            ")),
        );
        let chip_public = chip_dh.public_key();
        assert_eq!(
            chip_public,
            BigUint::from_bytes_be(&hex!("
                78879F57 225AA808 0D52ED0F C890A4B2
                5336F699 AA89A2D3 A189654A F70729E6
                23EA5738 B26381E4 DA19E004 706FACE7
                B235C2DB F2F38748 312F3C98 C2DD4882
                A41947B3 24AA1259 AC22579D B93F7085
                655AF308 89DBB845 D9E6783F E42C9F24
                49400306 254C8AE8 EE9DD812 A804C0B6
                6E8CAFC1 4F84D825 8950A91B 44126EE6
            ")),
        );

        let terminal_secret = terminal_dh.finalize(&chip_public);
        let chip_secret = chip_dh.finalize(&terminal_public);
        let shared_secret = BigUint::from_bytes_be(&hex!("
            5BABEBEF 5B74E5BA 94B5C063 FDA15F1F
            1CDE9487 3EE0A5D3 A2FCAB49 F258D07F
            544F13CB 66658C3A FEE9E727 389BE3F6
            CBBBD321 28A8C21D D6EEA3CF 7091CDDF
            B08B8D00 7D40318D CCA4FFBF 51208790
            FB4BD111 E5A968ED 6B6F08B2 6CA87C41
            0B3CE0C3 10CE104E ABD16629 AA48620C
            1279270C B0750C0D 37C57FFF E302AE7F
        "));
        assert_eq!(terminal_secret, chip_secret);
        assert_eq!(terminal_secret, shared_secret);
        assert_eq!(chip_secret, shared_secret);
    }
}
