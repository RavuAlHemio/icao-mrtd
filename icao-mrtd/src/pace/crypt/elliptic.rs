use std::{ops::{Add, Div, Mul, Sub}, sync::LazyLock};

use crypto_bigint::{modular::{BoxedMontyForm, BoxedMontyParams}, BitOps, BoxedUint, Integer, NonZero};
use zeroize_derive::ZeroizeOnDrop;


static ONE: LazyLock<BoxedUint> = LazyLock::new(|| BoxedUint::one());
static TWO: LazyLock<BoxedUint> = LazyLock::new(|| &*ONE + &*ONE);
static THREE: LazyLock<BoxedUint> = LazyLock::new(|| &*TWO + &BoxedUint::one());
static FOUR: LazyLock<BoxedUint> = LazyLock::new(|| &*TWO + &*TWO);
static EIGHT: LazyLock<BoxedUint> = LazyLock::new(|| &*FOUR + &*FOUR);


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BoxedInt {
    pub negative: bool,
    pub magnitude: BoxedUint,
}
impl BoxedInt {
    pub fn add(&self, rhs: &Self) -> Self {
        match (self.negative, rhs.negative) {
            (false, false)|(true, true) => {
                // just add them up, taking the common sign
                // for the negative case, (-a) + (-b) == -(a + b)
                Self {
                    negative: self.negative,
                    magnitude: (&self.magnitude) + (&rhs.magnitude),
                }
            },
            (false, true) => {
                // self >= 0, rhs < 0
                if self.magnitude >= rhs.magnitude {
                    // positive result or zero
                    Self {
                        negative: false,
                        magnitude: (&self.magnitude) - (&rhs.magnitude),
                    }
                } else {
                    // negative result; swap operands in subtraction
                    Self {
                        negative: true,
                        magnitude: (&rhs.magnitude) - (&self.magnitude),
                    }
                }
            },
            (true, false) => {
                // run the gauntlet with swapped operands
                rhs.add(self)
            },
        }
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        // a - b == a + (-b)
        self.add(&Self {
            negative: !rhs.negative,
            magnitude: rhs.magnitude.clone(),
        })
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        Self {
            negative: self.negative ^ rhs.negative,
            magnitude: (&self.magnitude) * (&rhs.magnitude),
        }
    }

    pub fn div(&self, rhs: &Self) -> Self {
        Self {
            negative: self.negative ^ rhs.negative,
            magnitude: (&self.magnitude) / NonZero::new(rhs.magnitude.clone()).unwrap(),
        }
    }

    pub fn is_greater_than(&self, rhs: &Self) -> bool {
        match (self.negative, rhs.negative) {
            (false, false) => self.magnitude > rhs.magnitude,
            (true, false) => false,
            (false, true) => true,
            (true, true) => self.magnitude < rhs.magnitude,
        }
    }

    pub fn zero() -> Self {
        Self {
            negative: false,
            magnitude: BoxedUint::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            negative: false,
            magnitude: BoxedUint::one(),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.magnitude.is_zero().into()
    }
}
impl From<&BoxedUint> for BoxedInt {
    fn from(value: &BoxedUint) -> Self {
        Self {
            negative: false,
            magnitude: value.clone(),
        }
    }
}


fn modulo_inverse(number: &BoxedUint, modulus: &BoxedUint) -> Option<BoxedUint> {
    // extended Euclidean algorithm
    let mut t = BoxedInt::zero();
    let mut newt = BoxedInt::one();
    let mut r: BoxedInt = modulus.into();
    let mut newr: BoxedInt = number.into();

    while !newr.is_zero() {
        let quotient = r.div(&newr);

        let newert = t.sub(&quotient.mul(&newt));
        (t, newt) = (newt, newert);

        let newerr = r.sub(&quotient.mul(&newr));
        (r, newr) = (newr, newerr);
    }

    if r.is_greater_than(&BoxedInt::one()) {
        // not invertible
        None
    } else {
        if BoxedInt::zero().is_greater_than(&t) {
            t = t.add(&modulus.into());
        }
        Some(t.magnitude)
    }
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct AffinePoint {
    pub x: BoxedUint,
    pub y: BoxedUint,
}
impl AffinePoint {
    pub const fn new(x: BoxedUint, y: BoxedUint) -> Self {
        Self {
            x,
            y,
        }
    }

    pub fn into_projective(self) -> ConcreteProjectivePoint {
        ConcreteProjectivePoint::new(
            self.x.clone(),
            self.y.clone(),
            BoxedUint::one(),
        )
    }
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub enum ProjectivePoint {
    Concrete(ConcreteProjectivePoint),
    AtInfinity,
}
impl ProjectivePoint {
    pub fn as_concrete(&self) -> Option<&ConcreteProjectivePoint> {
        match self {
            Self::Concrete(c) => Some(c),
            _ => None,
        }
    }
}
impl From<ConcreteProjectivePoint> for ProjectivePoint {
    fn from(value: ConcreteProjectivePoint) -> Self { Self::Concrete(value) }
}


#[derive(Clone, Debug, Eq, PartialEq)]
enum MontyProjectivePoint {
    Concrete { x: BoxedMontyForm, y: BoxedMontyForm, z: BoxedMontyForm },
    AtInfinity,
}
impl MontyProjectivePoint {
    pub fn take(point: &ProjectivePoint, params: BoxedMontyParams) -> Self {
        match point {
            ProjectivePoint::AtInfinity => Self::AtInfinity,
            ProjectivePoint::Concrete(cpp) => Self::take_concrete(cpp, params),
        }
    }

    pub fn take_concrete(point: &ConcreteProjectivePoint, params: BoxedMontyParams) -> Self {
        Self::Concrete {
            x: BoxedMontyForm::new(point.x.widen(params.bits_precision()), params.clone()),
            y: BoxedMontyForm::new(point.y.widen(params.bits_precision()), params.clone()),
            z: BoxedMontyForm::new(point.z.widen(params.bits_precision()), params.clone()),
        }
    }

    pub fn retrieve(&self) -> ProjectivePoint {
        match self {
            Self::Concrete { x, y, z } => ProjectivePoint::Concrete(ConcreteProjectivePoint::new(
                x.retrieve(), y.retrieve(), z.retrieve(),
            )),
            Self::AtInfinity => ProjectivePoint::AtInfinity,
        }
    }

    pub fn as_concrete(&self) -> Option<(&BoxedMontyForm, &BoxedMontyForm, &BoxedMontyForm)> {
        match self {
            Self::Concrete { x, y, z } => Some((x, y, z)),
            Self::AtInfinity => None,
        }
    }
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct ConcreteProjectivePoint {
    pub x: BoxedUint,
    pub y: BoxedUint,
    pub z: BoxedUint,
}
impl ConcreteProjectivePoint {
    pub const fn new(x: BoxedUint, y: BoxedUint, z: BoxedUint) -> Self {
        Self {
            x,
            y,
            z,
        }
    }

    pub fn into_affine(self, modulus: &BoxedUint) -> Option<AffinePoint> {
        // invert Z
        let z_inverted = modulo_inverse(&self.z, modulus)?;
        let x = self.x.mul_mod(&z_inverted, modulus);
        let y = self.y.mul_mod(&z_inverted, modulus);
        Some(AffinePoint::new(x, y))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MontyKnowledge {
    params: BoxedMontyParams,
    a: BoxedMontyForm,
    b: BoxedMontyForm,
    two: BoxedMontyForm,
    three: BoxedMontyForm,
    four: BoxedMontyForm,
    eight: BoxedMontyForm,
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

    // we don't store q or h
}
impl PrimeWeierstrassCurve {
    pub fn new(
        prime: BoxedUint,
        coefficient_a: BoxedUint,
        coefficient_b: BoxedUint,
        generator: AffinePoint,
    ) -> Self {
        if !bool::from(prime.is_odd()) {
            panic!("prime is not odd");
        }

        let curve = Self {
            prime,
            coefficient_a,
            coefficient_b,
            generator,
        };
        if !curve.is_on_curve(&curve.generator) {
            panic!("generator is not on curve");
        }
        curve
    }

    pub fn prime(&self) -> &BoxedUint { &self.prime }
    pub fn coefficient_a(&self) -> &BoxedUint { &self.coefficient_a }
    pub fn coefficient_b(&self) -> &BoxedUint { &self.coefficient_b }
    pub fn generator(&self) -> &AffinePoint { &self.generator }

    fn monty_knowledge(&self) -> MontyKnowledge {
        let monty_params = BoxedMontyParams::new(self.prime.to_odd().unwrap());
        MontyKnowledge {
            params: monty_params.clone(),
            a: BoxedMontyForm::new(self.coefficient_a.clone(), monty_params.clone()),
            b: BoxedMontyForm::new(self.coefficient_b.clone(), monty_params.clone()),
            two: BoxedMontyForm::new(TWO.widen(monty_params.bits_precision()), monty_params.clone()),
            three: BoxedMontyForm::new(THREE.widen(monty_params.bits_precision()), monty_params.clone()),
            four: BoxedMontyForm::new(FOUR.widen(monty_params.bits_precision()), monty_params.clone()),
            eight: BoxedMontyForm::new(EIGHT.widen(monty_params.bits_precision()), monty_params.clone()),
        }
    }

    fn is_on_curve_internal(&self, monty: &MontyKnowledge, x_monty: &BoxedMontyForm, y_monty: &BoxedMontyForm) -> bool {
        let y_squared = y_monty.mul(y_monty);
        let x_cubed = x_monty.mul(x_monty).mul(x_monty);
        let ax = (&x_monty).mul(&monty.a);
        let rhs = (&x_cubed).add(&ax).add(&monty.b);
        y_squared == rhs
    }

    pub fn is_on_curve(&self, point: &AffinePoint) -> bool {
        let monty = self.monty_knowledge();

        let x_monty = BoxedMontyForm::new(point.x.clone(), monty.params.clone());
        let y_monty = BoxedMontyForm::new(point.y.clone(), monty.params.clone());

        self.is_on_curve_internal(&monty, &x_monty, &y_monty)
    }

    fn double_point_internal(&self, monty: &MontyKnowledge, x: &BoxedMontyForm, y: &BoxedMontyForm, z: &BoxedMontyForm) -> MontyProjectivePoint {
        // Renes/Costello/Batina 2015 (https://eprint.iacr.org/2015/1060), Algorithm 3
        let b3 = (&monty.b).add(&monty.b).add(&monty.b);

        // 1. t0 ← X · X
        let mut t0 = x.mul(x);
        // 2. t1 ← Y · Y
        let mut t1 = y.mul(y);
        // 3. t2 ← Z · Z
        let mut t2 = z.mul(z);
        // 4. t3 ← X · Y
        let mut t3 = x.mul(&y);
        // 5. t3 ← t3 + t3
        t3 = (&t3).add(&t3);
        // 6. Z3 ← X · Z
        let mut z3 = x.mul(z);
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
        t2 = y.mul(z);
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
        MontyProjectivePoint::Concrete { x: x3, y: y3, z: z3 }
    }

    pub fn double_point(&self, point: &ConcreteProjectivePoint) -> ProjectivePoint {
        if bool::from(point.y.is_zero()) {
            return ProjectivePoint::AtInfinity;
        }

        let monty = self.monty_knowledge();
        let x_monty = BoxedMontyForm::new(point.x.clone(), monty.params.clone());
        let y_monty = BoxedMontyForm::new(point.y.clone(), monty.params.clone());
        let z_monty = BoxedMontyForm::new(point.z.clone(), monty.params.clone());

        self.double_point_internal(&monty, &x_monty, &y_monty, &z_monty).retrieve()
    }

    fn add_points_internal(&self, monty: &MontyKnowledge, x1: &BoxedMontyForm, y1: &BoxedMontyForm, z1: &BoxedMontyForm, x2: &BoxedMontyForm, y2: &BoxedMontyForm, z2: &BoxedMontyForm) -> MontyProjectivePoint {
        // Renes/Costello/Batina 2015 (https://eprint.iacr.org/2015/1060), Algorithm 1
        let b3 = (&monty.b).add(&monty.b).add(&monty.b);

        // 1. t0 ← X1 · X2
        let mut t0 = x1.mul(x2);
        // 2. t1 ← Y1 · Y2
        let mut t1 = y1.mul(y2);
        // 3. t2 ← Z1 · Z2
        let mut t2 = z1.mul(z2);
        // 4. t3 ← X1 + Y1
        let mut t3 = x1.add(y1);
        // 5. t4 ← X2 + Y2
        let mut t4 = x2.add(y2);
        // 6. t3 ← t3 · t4
        t3 = (&t3).mul(&t4);
        // 7. t4 ← t0 + t1
        t4 = (&t0).add(&t1);
        // 8. t3 ← t3 − t4
        t3 = (&t3).sub(&t4);
        // 9. t4 ← X1 + Z1
        t4 = (&x1).add(&z1);
        // 10. t5 ← X2 + Z2
        let mut t5 = (&x2).add(&z2);
        // 11. t4 ← t4 · t5
        t4 = (&t4).mul(&t5);
        // 12. t5 ← t0 + t2
        t5 = (&t0).add(&t2);
        // 13. t4 ← t4 − t5
        t4 = (&t4).sub(&t5);
        // 14. t5 ← Y1 + Z1
        t5 = (&y1).add(&z1);
        // 15. X3 ← Y2 + Z2
        let mut x3 = (&y2).add(&z2);
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
        MontyProjectivePoint::Concrete { x: x3, y: y3, z: z3 }
    }

    pub fn add_points(&self, lhs: &ConcreteProjectivePoint, rhs: &ConcreteProjectivePoint) -> ProjectivePoint {
        let monty = self.monty_knowledge();
        let (x1, y1, z1) = (
            BoxedMontyForm::new(lhs.x.widen(monty.params.bits_precision()), monty.params.clone()),
            BoxedMontyForm::new(lhs.y.widen(monty.params.bits_precision()), monty.params.clone()),
            BoxedMontyForm::new(lhs.z.widen(monty.params.bits_precision()), monty.params.clone()),
        );
        let (x2, y2, z2) = (
            BoxedMontyForm::new(rhs.x.widen(monty.params.bits_precision()), monty.params.clone()),
            BoxedMontyForm::new(rhs.y.widen(monty.params.bits_precision()), monty.params.clone()),
            BoxedMontyForm::new(rhs.z.widen(monty.params.bits_precision()), monty.params.clone()),
        );
        self.add_points_internal(&monty, &x1, &y1, &z1, &x2, &y2, &z2).retrieve()
    }

    pub fn multiply_scalar_with_point(&self, scalar: &BoxedUint, point: &ConcreteProjectivePoint) -> ProjectivePoint {
        if bool::from(scalar.is_zero()) {
            return ProjectivePoint::AtInfinity;
        }

        let monty = self.monty_knowledge();
        let mut result = MontyProjectivePoint::AtInfinity;
        let mut double_me = MontyProjectivePoint::take_concrete(&point, monty.params.clone());
        for i in 0..scalar.bits() {
            if bool::from(scalar.bit(i)) {
                result = match &result {
                    MontyProjectivePoint::AtInfinity => double_me.clone(),
                    MontyProjectivePoint::Concrete { x: x1, y: y1, z: z1 } => {
                        let (x2, y2, z2) = double_me.as_concrete().unwrap();
                        self.add_points_internal(&monty, x1, y1, z1, x2, y2, z2)
                    },
                };
            }
            let (x, y, z) = double_me.as_concrete().unwrap();
            double_me = self.double_point_internal(&monty, x, y, z);
        }
        result.retrieve()
    }

    pub fn add_affine(&self, left: &AffinePoint, right: &AffinePoint) -> AffinePoint {
        let left_projective = left.clone().into_projective();
        let right_projective = right.clone().into_projective();
        self.add_points(&left_projective, &right_projective)
            .as_concrete().unwrap()
            .clone()
            .into_affine(&self.prime).unwrap()
    }

    pub fn multiply_scalar_with_affine(&self, scalar: &BoxedUint, point: &AffinePoint) -> AffinePoint {
        let point_projective = point.clone().into_projective();
        let multiplied_projective = self.multiply_scalar_with_point(scalar, &point_projective);
        multiplied_projective
            .as_concrete().unwrap()
            .clone()
            .into_affine(&self.prime).unwrap()
    }

    pub fn calculate_public_key(&self, private_key: &BoxedUint) -> AffinePoint {
        // public_key = private_key * generator
        self.multiply_scalar_with_affine(private_key, &self.generator)
    }

    pub fn diffie_hellman(&self, private_key: &BoxedUint, other_public_key: &AffinePoint) -> AffinePoint {
        // secret_key = private_key * other_public_key
        self.multiply_scalar_with_affine(private_key, other_public_key)
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

        let terminal_secret = curve.diffie_hellman(&terminal_private, &chip_public);
        let chip_secret = curve.diffie_hellman(&chip_private, &terminal_public);
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
        let nonced_generator = curve.multiply_scalar_with_affine(&nonce, &generator);
        let session_generator = curve.add_affine(&nonced_generator, &shared_secret);
        assert_eq!(
            session_generator.x,
            boxed_uint_from_be_slice(&hex!("
                8CED63C9 1426D4F0 EB1435E7 CB1D74A4
                6723A0AF 21C89634 F65A9AE8 7A9265E2
            ")),
        );
        assert_eq!(
            session_generator.y,
            boxed_uint_from_be_slice(&hex!("
                8C879506 743F8611 AC33645C 5B985C80
                B5F09A0B 83407C1B 6A4D857A E76FE522
            ")),
        );

        // set up a curve with the same coefficients but this new generator
        let session_curve = PrimeWeierstrassCurve::new(
            prime,
            coefficient_a,
            coefficient_b,
            session_generator,
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

        let session_terminal_secret = session_curve.diffie_hellman(&session_terminal_private, &session_chip_public);
        let session_chip_secret = session_curve.diffie_hellman(&session_chip_private, &session_terminal_public);
        let session_shared_secret = boxed_uint_from_be_slice(&hex!("
            28768D20 701247DA E81804C9 E780EDE5 
            82A9996D B4A31502 0B273319 7DB84925
        "));
        assert_eq!(session_terminal_secret.x, session_shared_secret);
        assert_eq!(session_chip_secret.x, session_shared_secret);
    }
}
