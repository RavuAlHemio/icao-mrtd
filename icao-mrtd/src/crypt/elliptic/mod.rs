//! Elliptic-curve cryptography.


pub mod curves;


use std::ops::{Add, Mul};

use crypto_bigint::{BoxedUint, Integer, NonZero};
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroizing;
use zeroize_derive::ZeroizeOnDrop;

use crate::crypt::boxed_uint_from_be_slice;


/// A point in affine coordinates.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct AffinePoint {
    x: BoxedUint,
    y: BoxedUint,
}
impl AffinePoint {
    pub const fn new(x: BoxedUint, y: BoxedUint) -> Self {
        Self { x, y }
    }

    pub fn x(&self) -> &BoxedUint { &self.x }
    pub fn y(&self) -> &BoxedUint { &self.y }

    pub fn to_be_bytes(&self, bytes_per_component: usize) -> Zeroizing<Vec<u8>> {
        let mut ret = Zeroizing::new(Vec::with_capacity(1 + 2*bytes_per_component));
        ret.push(0x04); // uncompressed coordinates

        let x_bytes = Zeroizing::new(self.x.to_be_bytes());
        assert!(x_bytes.len() <= bytes_per_component);
        for _ in 0..(bytes_per_component - x_bytes.len()) {
            ret.push(0x00);
        }
        ret.extend(&*x_bytes);

        let y_bytes = Zeroizing::new(self.y.to_be_bytes());
        assert!(y_bytes.len() <= bytes_per_component);
        for _ in 0..(bytes_per_component - y_bytes.len()) {
            ret.push(0x00);
        }
        ret.extend(&*y_bytes);

        ret
    }

    pub fn try_from_be_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            // mode x y
            return None;
        }
        if bytes[0] != 0x04 {
            // we only support the uncompressed representation
            return None;
        }
        if (bytes.len() - 1) % 2 != 0 {
            // it must be possible to split the value in the middle
            return None;
        }
        let coordinate_length = (bytes.len() - 1) / 2;

        let x_bytes = &bytes[1..1+coordinate_length];
        let y_bytes = &bytes[1+coordinate_length..];
        assert_eq!(x_bytes.len(), y_bytes.len());

        let x = boxed_uint_from_be_slice(x_bytes);
        let y = boxed_uint_from_be_slice(y_bytes);
        Some(Self { x, y })
    }
}


/// A point in projective coordinates in Montgomery form.
#[derive(Clone, Debug, Eq, PartialEq)]
struct MontyProjectivePoint {
    x: BoxedMontyForm,
    y: BoxedMontyForm,
    z: BoxedMontyForm,
}
impl MontyProjectivePoint {
    pub fn new(x: BoxedMontyForm, y: BoxedMontyForm, z: BoxedMontyForm) -> Self {
        assert_eq!(x.params(), y.params());
        assert_eq!(x.params(), z.params());
        Self { x, y, z }
    }
}

#[derive(Clone, Debug)]
struct MontyKnowledge {
    params: BoxedMontyParams,
    a: BoxedMontyForm,
    b: BoxedMontyForm,
}

/// An elliptic curve of the form `y**2 ≡ x**3 + ax + b` modulo a prime number.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct PrimeWeierstrassCurve {
    /// The prime (modulus) of the curve.
    prime: BoxedUint,

    /// Coefficient `a` in the curve's formula.
    coefficient_a: BoxedUint,

    /// Coefficient `b` in the curve's formula.
    coefficient_b: BoxedUint,

    /// The coordinates of the generator point of the curve.
    generator: AffinePoint,

    /// The cofactor of the curve.
    ///
    /// A cofactor n means that only each nth point on the curve is part of the group. In practice,
    /// this means that values like secret keys must be divisible by the cofactor.
    cofactor: u8,

    // we don't store q
}
impl PrimeWeierstrassCurve {
    pub fn new(
        prime: BoxedUint,
        coefficient_a: BoxedUint,
        coefficient_b: BoxedUint,
        generator: AffinePoint,
        cofactor: u8,
    ) -> Self {
        if !bool::from(prime.is_odd()) {
            panic!("prime is not odd");
        }

        let curve = Self {
            prime,
            coefficient_a,
            coefficient_b,
            generator,
            cofactor,
        };
        if !bool::from(curve.is_on_curve_affine(&curve.generator)) {
            panic!("generator is not on curve");
        }
        curve
    }

    pub fn prime(&self) -> &BoxedUint { &self.prime }
    pub fn coefficient_a(&self) -> &BoxedUint { &self.coefficient_a }
    pub fn coefficient_b(&self) -> &BoxedUint { &self.coefficient_b }
    pub fn generator(&self) -> &AffinePoint { &self.generator }
    pub fn cofactor(&self) -> u8 { self.cofactor }

    /// Calculates the number of bytes a private key used with this curve should have.
    pub fn private_key_len_bytes(&self) -> usize {
        let mut bits = self.prime().bits();
        let mut bytes = 0;
        while bits >= 8 {
            bits -= 8;
            bytes += 1;
        }
        if bits > 0 {
            bytes += 1;
        }
        bytes
    }

    /// Returns important curve parameters for operations in Montgomery form.
    fn monty_knowledge(&self) -> MontyKnowledge {
        let monty_params = BoxedMontyParams::new(self.prime.to_odd().unwrap());
        MontyKnowledge {
            params: monty_params.clone(),
            a: BoxedMontyForm::new(self.coefficient_a.clone(), monty_params.clone()),
            b: BoxedMontyForm::new(self.coefficient_b.clone(), monty_params.clone()),
        }
    }

    fn internal_is_on_curve(monty: &MontyKnowledge, point: &MontyProjectivePoint) -> Choice {
        let inverse_option = point.z.invert();
        let inverse_alternative = point.z.clone();
        let inverse = inverse_option.clone().into_option().unwrap_or(inverse_alternative);

        let x = (&point.x).mul(&inverse);
        let y = (&point.y).mul(&inverse);

        let y_squared = (&y).mul(&y);
        let x_cubed = (&x).mul(&x).mul(&x);
        let ax = (&x).mul(&monty.a);
        let rhs = (&x_cubed).add(&ax).add(&monty.b);
        let are_equal = y_squared.retrieve().ct_eq(&rhs.retrieve());
        Choice::conditional_select(&Choice::from(0), &are_equal, inverse_option.is_some())
    }

    fn internal_affine_to_monty_projective(monty: &MontyKnowledge, point: &AffinePoint) -> MontyProjectivePoint {
        let x = BoxedMontyForm::new(point.x.clone(), monty.params.clone());
        let y = BoxedMontyForm::new(point.y.clone(), monty.params.clone());
        let z = BoxedMontyForm::one(monty.params.clone());
        MontyProjectivePoint::new(x, y, z)
    }

    fn internal_monty_projective_to_affine(point: &MontyProjectivePoint) -> CtOption<(BoxedMontyForm, BoxedMontyForm)> {
        let inverse_option = point.z.invert();
        let inverse_alternative = point.z.clone();
        let inverse = inverse_option.clone().into_option().unwrap_or(inverse_alternative);

        let x = (&point.x).mul(&inverse);
        let y = (&point.y).mul(&inverse);

        CtOption::new((x, y), inverse_option.is_some())
    }

    fn internal_double_point(monty: &MontyKnowledge, point: &MontyProjectivePoint) -> MontyProjectivePoint {
        // Renes/Costello/Batina 2015 (https://eprint.iacr.org/2015/1060), Algorithm 3
        let b3 = (&monty.b).add(&monty.b).add(&monty.b);

        // 1. t0 ← X · X
        let mut t0 = (&point.x).mul(&point.x);
        // 2. t1 ← Y · Y
        let t1 = (&point.y).mul(&point.y);
        // 3. t2 ← Z · Z
        let mut t2 = (&point.z).mul(&point.z);
        // 4. t3 ← X · Y
        let mut t3 = (&point.x).mul(&point.y);
        // 5. t3 ← t3 + t3
        t3 = (&t3).add(&t3);
        // 6. Z3 ← X · Z
        let mut z3 = (&point.x).mul(&point.z);
        // 7. Z3 ← Z3 + Z3
        z3 = (&z3).add(&z3);
        // 8. X3 ← a · Z3
        let mut x3 = (&monty.a).mul(&z3);
        // 9. Y3 ← b3 · t2
        let mut y3 = (&b3).mul(&t2);
        // 10. Y3 ← X3 + Y3
        y3 = (&x3).add(&y3);
        // 11. X3 ← t1 − Y3
        x3 = (&t1).sub(&y3);
        // 12. Y3 ← t1 + Y3
        y3 = (&t1).add(&y3);
        // 13. Y3 ← X3 · Y3
        y3 = (&x3).mul(&y3);
        // 14. X3 ← t3 · X3
        x3 = (&t3).mul(&x3);
        // 15. Z3 ← b3 · Z3
        z3 = (&b3).mul(&z3);
        // 16. t2 ← a · t2
        t2 = (&monty.a).mul(&t2);
        // 17. t3 ← t0 − t2
        t3 = (&t0).sub(&t2);
        // 18. t3 ← a · t3
        t3 = (&monty.a).mul(&t3);
        // 19. t3 ← t3 + Z3
        t3 = (&t3).add(&z3);
        // 20. Z3 ← t0 + t0
        z3 = (&t0).add(&t0);
        // 21. t0 ← Z3 + t0
        t0 = (&z3).add(&t0);
        // 22. t0 ← t0 + t2
        t0 = (&t0).add(&t2);
        // 23. t0 ← t0 · t3
        t0 = (&t0).mul(&t3);
        // 24. Y3 ← Y3 + t0
        y3 = (&y3).add(&t0);
        // 25. t2 ← Y · Z
        t2 = (&point.y).mul(&point.z);
        // 26. t2 ← t2 + t2
        t2 = (&t2).add(&t2);
        // 27. t0 ← t2 · t3
        t0 = (&t2).mul(&t3);
        // 28. X3 ← X3 − t0
        x3 = (&x3).sub(&t0);
        // 29. Z3 ← t2 · t1
        z3 = (&t2).mul(&t1);
        // 30. Z3 ← Z3 + Z3
        z3 = (&z3).add(&z3);
        // 31. Z3 ← Z3 + Z3
        z3 = (&z3).add(&z3);
        MontyProjectivePoint { x: x3, y: y3, z: z3 }
    }

    fn internal_add_points(monty: &MontyKnowledge, lhs: &MontyProjectivePoint, rhs: &MontyProjectivePoint) -> MontyProjectivePoint {
        // Renes/Costello/Batina 2015 (https://eprint.iacr.org/2015/1060), Algorithm 1
        let b3 = (&monty.b).add(&monty.b).add(&monty.b);

        // 1. t0 ← X1 · X2
        let mut t0 = (&lhs.x).mul(&rhs.x);
        // 2. t1 ← Y1 · Y2
        let mut t1 = (&lhs.y).mul(&rhs.y);
        // 3. t2 ← Z1 · Z2
        let mut t2 = (&lhs.z).mul(&rhs.z);
        // 4. t3 ← X1 + Y1
        let mut t3 = (&lhs.x).add(&lhs.y);
        // 5. t4 ← X2 + Y2
        let mut t4 = (&rhs.x).add(&rhs.y);
        // 6. t3 ← t3 · t4
        t3 = (&t3).mul(&t4);
        // 7. t4 ← t0 + t1
        t4 = (&t0).add(&t1);
        // 8. t3 ← t3 − t4
        t3 = (&t3).sub(&t4);
        // 9. t4 ← X1 + Z1
        t4 = (&lhs.x).add(&lhs.z);
        // 10. t5 ← X2 + Z2
        let mut t5 = (&rhs.x).add(&rhs.z);
        // 11. t4 ← t4 · t5
        t4 = (&t4).mul(&t5);
        // 12. t5 ← t0 + t2
        t5 = (&t0).add(&t2);
        // 13. t4 ← t4 − t5
        t4 = (&t4).sub(&t5);
        // 14. t5 ← Y1 + Z1
        t5 = (&lhs.y).add(&lhs.z);
        // 15. X3 ← Y2 + Z2
        let mut x3 = (&rhs.y).add(&rhs.z);
        // 16. t5 ← t5 · X3
        t5 = (&t5).mul(&x3);
        // 17. X3 ← t1 + t2
        x3 = (&t1).add(&t2);
        // 18. t5 ← t5 − X3
        t5 = (&t5).sub(&x3);
        // 19. Z3 ← a · t4
        let mut z3 = (&monty.a).mul(&t4);
        // 20. X3 ← b3 · t2
        x3 = (&b3).mul(&t2);
        // 21. Z3 ← X3 + Z3
        z3 = (&x3).add(&z3);
        // 22. X3 ← t1 − Z3
        x3 = (&t1).sub(&z3);
        // 23. Z3 ← t1 + Z3
        z3 = (&t1).add(&z3);
        // 24. Y3 ← X3 · Z3
        let mut y3 = (&x3).mul(&z3);
        // 25. t1 ← t0 + t0
        t1 = (&t0).add(&t0);
        // 26. t1 ← t1 + t0
        t1 = (&t1).add(&t0);
        // 27. t2 ← a · t2
        t2 = (&monty.a).mul(&t2);
        // 28. t4 ← b3 · t4
        t4 = (&b3).mul(&t4);
        // 29. t1 ← t1 + t2
        t1 = (&t1).add(&t2);
        // 30. t2 ← t0 − t2
        t2 = (&t0).sub(&t2);
        // 31. t2 ← a · t2
        t2 = (&monty.a).mul(&t2);
        // 32. t4 ← t4 + t2
        t4 = (&t4).add(&t2);
        // 33. t0 ← t1 · t4
        t0 = (&t1).mul(&t4);
        // 34. Y3 ← Y3 + t0
        y3 = (&y3).add(&t0);
        // 35. t0 ← t5 · t4
        t0 = (&t5).mul(&t4);
        // 36. X3 ← t3 · X3
        x3 = (&t3).mul(&x3);
        // 37. X3 ← X3 − t0
        x3 = (&x3).sub(&t0);
        // 38. t0 ← t3 · t1
        t0 = (&t3).mul(&t1);
        // 39. Z3 ← t5 · Z3
        z3 = (&t5).mul(&z3);
        // 40. Z3 ← Z3 + t0
        z3 = (&z3).add(&t0);
        MontyProjectivePoint { x: x3, y: y3, z: z3 }
    }

    fn internal_point_at_infinity(monty: &MontyKnowledge) -> MontyProjectivePoint {
        let x = BoxedMontyForm::zero(monty.params.clone());
        let y = BoxedMontyForm::one(monty.params.clone());
        let z = BoxedMontyForm::zero(monty.params.clone());
        MontyProjectivePoint { x, y, z }
    }

    fn internal_multiply_scalar_with_point(&self, monty: &MontyKnowledge, scalar: &BoxedUint, point: &MontyProjectivePoint) -> MontyProjectivePoint {
        debug_assert!(bool::from(Self::internal_is_on_curve(monty, point)));

        let mut result = Self::internal_point_at_infinity(monty);

        if bool::from(scalar.is_zero()) {
            return result;
        }

        let mut double_me = point.clone();
        for i in 0..scalar.bits() {
            let sum = Self::internal_add_points(monty, &result, &double_me);
            debug_assert!(bool::from(Self::internal_is_on_curve(monty, &sum)));
            result = if bool::from(scalar.bit(i)) { sum } else { result };
            double_me = Self::internal_double_point(monty, &double_me);
            debug_assert!(bool::from(Self::internal_is_on_curve(monty, &double_me)));
        }

        debug_assert!(bool::from(Self::internal_is_on_curve(monty, &result)));

        result
    }

    pub fn is_on_curve_affine(&self, point: &AffinePoint) -> Choice {
        let monty = self.monty_knowledge();
        let projective = Self::internal_affine_to_monty_projective(&monty, &point);
        Self::internal_is_on_curve(&monty, &projective)
    }

    /// Calculates a public key from a private key.
    pub fn calculate_public_key(&self, private_key: &BoxedUint) -> AffinePoint {
        // public_key = private_key * generator
        let monty = self.monty_knowledge();
        let generator = Self::internal_affine_to_monty_projective(&monty, &self.generator);
        let product = self.internal_multiply_scalar_with_point(&monty, private_key, &generator);

        let (x, y) = Self::internal_monty_projective_to_affine(&product)
            .unwrap();
        AffinePoint {
            x: x.retrieve(),
            y: y.retrieve(),
        }
    }

    pub fn diffie_hellman(&self, private_key: &BoxedUint, other_public_key: &AffinePoint) -> CtOption<AffinePoint> {
        // secret_key = private_key * other_public_key
        let monty = self.monty_knowledge();
        let other_pub = Self::internal_affine_to_monty_projective(&monty, other_public_key);

        // defend against skullduggery: check if other public key is on the curve
        let is_other_pub_on_curve = Self::internal_is_on_curve(&monty, &other_pub);

        let product = self.internal_multiply_scalar_with_point(&monty, private_key, &other_pub);

        let (x, y) = Self::internal_monty_projective_to_affine(&product)
            .unwrap();
        let result = AffinePoint {
            x: x.retrieve(),
            y: y.retrieve(),
        };

        CtOption::new(result, is_other_pub_on_curve)
    }

    pub fn derive_generic_mapping_session_curve(&self, nonce: &BoxedUint, shared_secret: &AffinePoint) -> Self {
        // new_generator = (nonce * original_generator) + shared_secret
        let monty = self.monty_knowledge();
        let generator_proj = Self::internal_affine_to_monty_projective(&monty, &self.generator);
        let shared_secret_proj = Self::internal_affine_to_monty_projective(&monty, shared_secret);

        let product = self.internal_multiply_scalar_with_point(&monty, nonce, &generator_proj);
        debug_assert!(bool::from(Self::internal_is_on_curve(&monty, &product)));
        let sum = Self::internal_add_points(&monty, &product, &shared_secret_proj);
        debug_assert!(bool::from(Self::internal_is_on_curve(&monty, &sum)));

        let (x, y) = Self::internal_monty_projective_to_affine(&sum)
            .unwrap();
        let new_generator = AffinePoint {
            x: x.retrieve(),
            y: y.retrieve()
        };

        Self {
            prime: self.prime.clone(),
            coefficient_a: self.coefficient_a.clone(),
            coefficient_b: self.coefficient_b.clone(),
            generator: new_generator,
            cofactor: self.cofactor,
        }
    }

    /// Derives a new generator using integrated mapping from the given pseudorandom function result.
    pub fn derive_integrated_mapping_generator(&self, pseudorandom_result: &BoxedUint) -> AffinePoint {
        let two = BoxedUint::from_be_slice(&[0x02], self.prime.bits_precision()).unwrap();
        let three = BoxedUint::from_be_slice(&[0x03], self.prime.bits_precision()).unwrap();
        let four_non_zero = NonZero::new(BoxedUint::from_be_slice(&[0x04], self.prime.bits_precision()).unwrap()).unwrap();
        if !bool::from(self.prime.rem(&four_non_zero).ct_eq(&three)) {
            panic!("can only derive point if p == 3 (mod 4)");
        }

        let monty = self.monty_knowledge();
        let pseudorandom_monty = BoxedMontyForm::new(pseudorandom_result.clone(), monty.params.clone());
        let one_monty = BoxedMontyForm::one(monty.params.clone());
        let prime_minus_two = self.prime() - &two;

        // step 1
        let alpha = pseudorandom_monty.square().neg();

        // step 2 (see implementation note)
        let minus_b = (&monty.b).neg();
        let alpha_plus_alpha_squared = (&alpha).add(&alpha.square());
        let one_plus_alpha_plus_alpha_squared = (&one_monty).add(&alpha_plus_alpha_squared);
        let a_times_alpha_plus_alpha_squared = (&monty.a).mul(&alpha_plus_alpha_squared);
        let powered = a_times_alpha_plus_alpha_squared.pow(&prime_minus_two);
        let x2 = (&minus_b).mul(&one_plus_alpha_plus_alpha_squared).mul(&powered);

        // step 3
        let x3 = (&alpha).mul(&x2);

        // step 4
        let a_mul_x2 = (&monty.a).mul(&x2);
        let h2 = (&x2).pow(&three).add(&a_mul_x2).add(&monty.b);

        // step 5
        //let a_mul_x3 = (&monty.a).mul(&x3);
        //let h3 = (&x3).pow(&three).add(a_mul_x3).add(&monty.b);

        // step 6
        let u = (&pseudorandom_monty).pow(&three).mul(&h2);

        // step 7
        let prime_plus_one_by_four = (self.prime() + &BoxedUint::one()) / (&four_non_zero);
        let prime_minus_one_minus_ppobf = self.prime() - &BoxedUint::one() - &prime_plus_one_by_four;
        let a = h2.pow(&prime_minus_one_minus_ppobf);

        // step 8
        let aah2 = (&a).square().mul(&h2);
        let mut point = if aah2 == one_monty {
            MontyProjectivePoint::new(
                x2,
                &a * &h2,
                one_monty.clone(),
            )
        } else {
            MontyProjectivePoint::new(
                x3,
                &a * &u,
                one_monty.clone(),
            )
        };

        if self.cofactor != 1 {
            let cofactor_big = BoxedUint::from_be_slice(&[self.cofactor], self.prime.bits_precision()).unwrap();
            point = self.internal_multiply_scalar_with_point(&monty, &cofactor_big, &point);
        }
        let (x, y) = Self::internal_monty_projective_to_affine(&point).unwrap();
        AffinePoint::new(
            x.retrieve(),
            y.retrieve(),
        )
    }
}


#[cfg(test)]
mod tests {
    use super::{AffinePoint, PrimeWeierstrassCurve};
    use crypto_bigint::BoxedUint;
    use hex_literal::hex;

    fn boxed_uint_from_be_slice(slice: &[u8]) -> BoxedUint {
        let bits: u32 = (8 * slice.len()).try_into().unwrap();
        BoxedUint::from_be_slice(slice, bits).unwrap()
    }

    #[test]
    fn icao_doc9303_part11_secg1_example() {
        // elliptic-curve Diffie-Hellman
        // the curve is Brainpool p256r1
        let prime = boxed_uint_from_be_slice(&hex!("
            A9FB57DB A1EEA9BC 3E660A90 9D838D72
            6E3BF623 D5262028 2013481D 1F6E5377
        "));
        let coefficient_a = boxed_uint_from_be_slice(&hex!("
            7D5A0975 FC2C3057 EEF67530 417AFFE7
            FB8055C1 26DC5C6C E94A4B44 F330B5D9
        "));
        let coefficient_b = boxed_uint_from_be_slice(&hex!("
            26DC5C6C E94A4B44 F330B5D9 BBD77CBF
            95841629 5CF7E1CE 6BCCDC18 FF8C07B6
        "));
        let generator_x = boxed_uint_from_be_slice(&hex!("
            8BD2AEB9 CB7E57CB 2C4B482F FC81B7AF
            B9DE27E1 E3BD23C2 3A4453BD 9ACE3262
        "));
        let generator_y = boxed_uint_from_be_slice(&hex!("
            547EF835 C3DAC4FD 97F8461A 14611DC9
            C2774513 2DED8E54 5C1D54C7 2F046997
        "));
        let generator = AffinePoint::new(generator_x, generator_y);
        let curve = PrimeWeierstrassCurve::new(
            prime.clone(),
            coefficient_a.clone(),
            coefficient_b.clone(),
            generator.clone(),
            1,
        );

        // obtain nonce
        let nonce = boxed_uint_from_be_slice(&hex!("
            3F00C4D3 9D153F2B 2A214A07 8D899B22
        "));

        // perform key agreement for session secret
        let terminal_private = boxed_uint_from_be_slice(&hex!("
            7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C
            F21F249D 953BC46F 4C6E1925 9C010F99
        "));
        let chip_private = boxed_uint_from_be_slice(&hex!("
            498FF497 56F2DC15 87840041 839A8598
            2BE7761D 14715FB0 91EFA7BC E9058560
        "));

        let terminal_public = curve.calculate_public_key(&terminal_private);
        let chip_public = curve.calculate_public_key(&chip_private);

        assert_eq!(
            terminal_public.x,
            boxed_uint_from_be_slice(&hex!("
                7ACF3EFC 982EC455 65A4B155 129EFBC7
                4650DCBF A6362D89 6FC70262 E0C2CC5E
            ")),
        );
        assert_eq!(
            terminal_public.y,
            boxed_uint_from_be_slice(&hex!("
                544552DC B6725218 799115B5 5C9BAA6D
                9F6BC3A9 618E70C2 5AF71777 A9C4922D
            ")),
        );
        assert_eq!(
            chip_public.x,
            boxed_uint_from_be_slice(&hex!("
                824FBA91 C9CBE26B EF53A0EB E7342A3B
                F178CEA9 F45DE0B7 0AA60165 1FBA3F57
            ")),
        );
        assert_eq!(
            chip_public.y,
            boxed_uint_from_be_slice(&hex!("
                30D8C879 AAA9C9F7 3991E61B 58F4D52E
                B87A0A0C 709A49DC 63719363 CCD13C54
            ")),
        );

        let terminal_secret = curve.diffie_hellman(&terminal_private, &chip_public).unwrap();
        let chip_secret = curve.diffie_hellman(&chip_private, &terminal_public).unwrap();
        let shared_secret = AffinePoint::new(
            boxed_uint_from_be_slice(&hex!("
                60332EF2 450B5D24 7EF6D386 8397D398
                852ED6E8 CAF6FFEE F6BF85CA 57057FD5
            ")),
            boxed_uint_from_be_slice(&hex!("
                0840CA74 15BAF3E4 3BD414D3 5AA4608B
                93A2CAF3 A4E3EA4E 82C9C13D 03EB7181
            ")),
        );
        assert_eq!(terminal_secret, chip_secret);
        assert_eq!(terminal_secret, shared_secret);
        assert_eq!(chip_secret, shared_secret);

        // map a new generator:
        // (nonce * original_generator) + shared_secret
        let session_curve = curve.derive_generic_mapping_session_curve(&nonce, &shared_secret);
        assert_eq!(
            session_curve.generator.x,
            boxed_uint_from_be_slice(&hex!("
                8CED63C9 1426D4F0 EB1435E7 CB1D74A4
                6723A0AF 21C89634 F65A9AE8 7A9265E2
            ")),
        );
        assert_eq!(
            session_curve.generator.y,
            boxed_uint_from_be_slice(&hex!("
                8C879506 743F8611 AC33645C 5B985C80
                B5F09A0B 83407C1B 6A4D857A E76FE522
            ")),
        );

        let session_terminal_private = boxed_uint_from_be_slice(&hex!("
            A73FB703 AC1436A1 8E0CFA5A BB3F7BEC
            7A070E7A 6788486B EE230C4A 22762595
        "));
        let session_chip_private = boxed_uint_from_be_slice(&hex!("
            107CF586 96EF6155 053340FD 633392BA
            81909DF7 B9706F22 6F32086C 7AFF974A
        "));

        let session_terminal_public = session_curve.calculate_public_key(&session_terminal_private);
        let session_chip_public = session_curve.calculate_public_key(&session_chip_private);

        assert_eq!(
            session_terminal_public.x,
            boxed_uint_from_be_slice(&hex!("
                2DB7A64C 0355044E C9DF1905 14C625CB
                A2CEA487 54887122 F3A5EF0D 5EDD301C
            ")),
        );
        assert_eq!(
            session_terminal_public.y,
            boxed_uint_from_be_slice(&hex!("
                3556F3B3 B186DF10 B857B58F 6A7EB80F
                20BA5DC7 BE1D43D9 BF850149 FBB36462
            ")),
        );
        assert_eq!(
            session_chip_public.x,
            boxed_uint_from_be_slice(&hex!("
                9E880F84 2905B8B3 181F7AF7 CAA9F0EF
                B743847F 44A306D2 D28C1D9E C65DF6DB
            ")),
        );
        assert_eq!(
            session_chip_public.y,
            boxed_uint_from_be_slice(&hex!("
                7764B222 77A2EDDC 3C265A9F 018F9CB8
                52E111B7 68B32690 4B59A019 3776F094
            ")),
        );

        let session_terminal_secret = session_curve.diffie_hellman(&session_terminal_private, &session_chip_public).unwrap();
        let session_chip_secret = session_curve.diffie_hellman(&session_chip_private, &session_terminal_public).unwrap();
        let session_shared_secret = boxed_uint_from_be_slice(&hex!("
            28768D20 701247DA E81804C9 E780EDE5
            82A9996D B4A31502 0B273319 7DB84925
        "));
        assert_eq!(session_terminal_secret.x, session_shared_secret);
        assert_eq!(session_chip_secret.x, session_shared_secret);
    }

    #[test]
    fn icao_doc9303_part11_sech1_example() {
        // elliptic-curve Diffie-Hellman
        // the curve is Brainpool p256r1
        let prime = boxed_uint_from_be_slice(&hex!("
            A9FB57DB A1EEA9BC 3E660A90 9D838D72
            6E3BF623 D5262028 2013481D 1F6E5377
        "));
        let coefficient_a = boxed_uint_from_be_slice(&hex!("
            7D5A0975 FC2C3057 EEF67530 417AFFE7
            FB8055C1 26DC5C6C E94A4B44 F330B5D9
        "));
        let coefficient_b = boxed_uint_from_be_slice(&hex!("
            26DC5C6C E94A4B44 F330B5D9 BBD77CBF
            95841629 5CF7E1CE 6BCCDC18 FF8C07B6
        "));
        let generator_x = boxed_uint_from_be_slice(&hex!("
            8BD2AEB9 CB7E57CB 2C4B482F FC81B7AF
            B9DE27E1 E3BD23C2 3A4453BD 9ACE3262
        "));
        let generator_y = boxed_uint_from_be_slice(&hex!("
            547EF835 C3DAC4FD 97F8461A 14611DC9
            C2774513 2DED8E54 5C1D54C7 2F046997
        "));
        let generator = AffinePoint::new(generator_x, generator_y);
        let curve = PrimeWeierstrassCurve::new(
            prime.clone(),
            coefficient_a.clone(),
            coefficient_b.clone(),
            generator.clone(),
            1,
        );

        let pseudorandom_result = boxed_uint_from_be_slice(&hex!("
            A2F8FF2D F50E52C6 599F386A DCB595D2
            29F6A167 ADE2BE5F 2C3296AD D5B7430E
        "));
        let new_generator = curve.derive_integrated_mapping_generator(&pseudorandom_result);
        let new_generator_x = boxed_uint_from_be_slice(&hex!("
            8E82D315 59ED0FDE 92A4D049 8ADD3C23
            BABA94FB 77691E31 E90AEA77 FB17D427
        "));
        let new_generator_y = boxed_uint_from_be_slice(&hex!("
            4C1AE14B D0C3DBAC 0C871B7F 36081693
            64437CA3 0AC243A0 89D3F266 C1E60FAD
        "));
        assert_eq!(new_generator.x(), &new_generator_x);
        assert_eq!(new_generator.y(), &new_generator_y);
    }
}
