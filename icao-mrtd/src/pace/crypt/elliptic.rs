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

    fn double_point_internal(&self, monty: &MontyKnowledge, x_monty: &BoxedMontyForm, y_monty: &BoxedMontyForm, z_monty: &BoxedMontyForm) -> MontyProjectivePoint {
        if bool::from(y_monty.is_zero()) {
            return MontyProjectivePoint::AtInfinity;
        }

        // w = a*z*z + 3*x*x
        let w = (&monty.a).mul(z_monty).mul(z_monty).add(x_monty.mul(x_monty).mul(&monty.three));
        // s = y*z
        let s = y_monty.mul(z_monty);
        // b = x*y*s
        let b = x_monty.mul(y_monty).mul(&s);
        // h = w*w - 8*b
        let h = (&w).mul(&w).sub((&monty.eight).mul(&b));
        // x1 = 2*h*s
        let x1 = (&monty.two).mul(&h).mul(&s);
        let s_squared = (&s).mul(&s);
        // y1 = w*(4*b - h) - 8*y*y*s*s
        let y1 = (&w).mul(&(&monty.four).mul(&b).sub(&h)).sub((&monty.eight).mul(y_monty).mul(y_monty).mul(&s_squared));
        // z1 = 8*s*s*s
        let z1 = (&monty.eight).mul(&s_squared).mul(&s);
        MontyProjectivePoint::Concrete { x: x1, y: y1, z: z1 }
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
        // u1 = y2*z1
        let u1 = y2.mul(z1);
        // u2 = y1*z2
        let u2= y1.mul(z2);
        // v1 = x2*z1
        let v1 = x2.mul(z1);
        // v2 = x1*z2
        let v2 = x1.mul(z2);
        if v1 == v2 {
            return if u1 != u2 {
                MontyProjectivePoint::AtInfinity
            } else {
                self.double_point_internal(monty, x1, y1, z1)
            };
        }
        // u = u1 - u2
        let u = (&u1).sub(&u2);
        // v = v1 - v2
        let v = (&v1).sub(&v2);
        // w = z1*z2
        let w = z1.mul(z2);
        // a = u*u*w - v*v*v - 2*v*v*v2
        let v_squared = (&v).mul(&v);
        let v_cubed = (&v_squared).mul(&v);
        let v_v_v2 = (&v_squared).mul(&v2);
        let a = (&u).mul(&u).mul(&v).sub((&v_squared).mul(&v)).sub((&monty.two).mul(&v_v_v2));
        // x3 = v*a
        let x3 = (&v).mul(&a);
        // y3 = u*(v*v*v2 - a) - v*v*v*u2
        let y3 = (&u).mul(&(&v_v_v2).sub(&a)).sub((&v_cubed).mul(&u2));
        // z3 = v^3*w
        let z3 = (&v_cubed).mul(&w);
        MontyProjectivePoint::Concrete { x: x3, y: y3, z: z3 }
    }

    pub fn add_points(&self, lhs: &ConcreteProjectivePoint, rhs: &ConcreteProjectivePoint) -> ProjectivePoint {
        let monty = self.monty_knowledge();
        let (x1, y1, z1) = (
            BoxedMontyForm::new(lhs.x.clone(), monty.params.clone()),
            BoxedMontyForm::new(lhs.y.clone(), monty.params.clone()),
            BoxedMontyForm::new(lhs.z.clone(), monty.params.clone()),
        );
        let (x2, y2, z2) = (
            BoxedMontyForm::new(rhs.x.clone(), monty.params.clone()),
            BoxedMontyForm::new(rhs.y.clone(), monty.params.clone()),
            BoxedMontyForm::new(rhs.z.clone(), monty.params.clone()),
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

    fn multiply_scalar_with_affine(&self, scalar: &BoxedUint, point: &AffinePoint) -> AffinePoint {
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

        let curve = PrimeWeierstrassCurve::new(
            prime,
            coefficient_a,
            coefficient_b,
            AffinePoint::new(generator_x, generator_y),
        );

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

        // TODO: mapping
    }
}
