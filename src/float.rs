use crate::debug::ToPlaintext;
use crate::encoding::Encoding;
use crate::integer::{IntCiphertext, IntPlaintext};
use crate::paillier_crypto::{Cryptosystem, MODULUS};
use crate::traits::{CryptoAdd, CryptoDecrypt, CryptoEncrypt, CryptoMul, ProtocolAdd, ProtocolMul, ProtocolSub, RerandomizeCiphertext};
use crate::traits::{GeneralError, Result};
use dashu::float::FBig;
use dashu::integer::IBig;
use paillier_common::{DecryptionKey, EncryptionKey, PrecomputedRandomness};
use rust_bigint::BigInt;
use std::marker::PhantomData;
use std::ops::{Add, Mul};
use serde::{Deserialize, Serialize};
use tracing::instrument;

impl Encoding<FBig, FloatPlaintext> {
    pub fn new() -> Self {
        let modulus = &MODULUS.clone();
        let max_int = modulus / 2;
        Self {
            modulus: modulus.clone(),
            max_int,
            _marker: PhantomData,
            _marker2: PhantomData,
        }
    }
    pub fn encode(&self, value: FBig) -> Result<FloatPlaintext> {
        let (significand, exponent) = value.into_repr().into_parts();

        let plaintext = IntPlaintext::from_plaintext(significand)?;
        let res = FloatPlaintext {
            exponent,
            mantissa: plaintext,
        };
        Ok(res)
    }

    pub fn decode(&self, float_plaintext: &FloatPlaintext) -> FBig {
        let significand = float_plaintext.mantissa.plaintext.clone();
        let exponent = float_plaintext.exponent;
        FBig::from_parts(significand, exponent)
    }
}

impl FloatPlaintext {
    pub fn decrease_exponent_to(&self, exponent: isize) -> Result<FloatPlaintext> {
        assert!(self.exponent >= exponent);
        let diff = self.exponent.abs_diff(exponent);
        let e = exponent;
        let m = self.mantissa.clone() * (BigInt::one() << diff);
        let res = FloatPlaintext {
            exponent: e,
            mantissa: m?,
        };
        Ok(res)
    }

    pub fn increase_exponent_to(&self, exponent: isize) -> Result<FloatPlaintext> {
        if self.exponent > exponent {
            return Err(GeneralError::new(format!(
                "trying to increase exponent from {} to {} ",
                self.exponent, exponent
            ))
            .into());
        }
        let diff = self.exponent.abs_diff(exponent);
        let e = exponent;
        let m = (self.mantissa.clone() >> diff)?;
        let res = FloatPlaintext {
            exponent: e,
            mantissa: m,
        };
        Ok(res)
    }

    pub fn change_exponent_to(&self, exponent: isize) -> Result<FloatPlaintext> {
        if exponent == self.exponent {
            Ok(self.clone())
        } else if self.exponent > exponent {
            self.decrease_exponent_to(exponent)
        } else {
            self.increase_exponent_to(exponent)
        }
    }
    pub fn from_plaintext(plaintext: f64) -> Result<Self> {
        let encoding = Encoding::<FBig, FloatPlaintext>::new();
        encoding.encode(FBig::try_from(plaintext).map_err(|e| GeneralError::from(e.to_string()))?)
    }
    pub fn to_fbig(&self) -> FBig {
        let encoding = Encoding::<FBig, FloatPlaintext>::new();
        encoding.decode(self)
    }
    pub fn to_plaintext(&self) -> f64 {
        self.to_fbig().to_f64().value()
    }
}
impl ToPlaintext<f64> for FloatPlaintext {
    fn to_plaintext(&self) -> f64 {
        self.to_plaintext()
    }
}


impl<'a, 'b: 'a> RerandomizeCiphertext<&EncryptionKey, PrecomputedRandomness, FloatCiphertext<'a>> for FloatCiphertext<'b> {
    fn rerandomize(&self, key: &EncryptionKey, randomness: PrecomputedRandomness) -> FloatCiphertext<'a> {
        FloatCiphertext {
            exponent: self.exponent,
            mantissa_ciphertext: self.mantissa_ciphertext.rerandomize(key, randomness),
        }
    }
}

impl Add<FloatPlaintext> for FloatPlaintext {
    type Output = Result<Self>;
    #[instrument(name = "float P+P")]
    fn add(self, rhs: FloatPlaintext) -> Self::Output {
        if self.exponent == rhs.exponent {
            let res = FloatPlaintext {
                exponent: self.exponent,
                mantissa: (self.mantissa + rhs.mantissa)?,
            };
            Ok(res)
        } else if self.exponent > rhs.exponent {
            let adapted_self = self.decrease_exponent_to(rhs.exponent)?;
            adapted_self + rhs
        } else {
            let adapted_rhs = rhs.decrease_exponent_to(self.exponent)?;
            self + adapted_rhs
        }
    }
}

impl Mul<FloatPlaintext> for FloatPlaintext {
    type Output = Result<Self>;
    #[instrument(name = "float P*P")]
    fn mul(self, rhs: FloatPlaintext) -> Self::Output {
        let new_exponent = (self.exponent.clone() + rhs.exponent.clone()) / 2;
        let result = FloatPlaintext {
            exponent: self.exponent + rhs.exponent,
            mantissa: (self.mantissa * rhs.mantissa)?,
        };
        if new_exponent <= result.exponent {
            result.decrease_exponent_to(new_exponent)
        } else {
            result.increase_exponent_to(new_exponent)
        }
    }
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct FloatPlaintext {
    pub exponent: isize,
    pub mantissa: IntPlaintext,
}

impl<'a> CryptoEncrypt<&EncryptionKey, FloatPlaintext, FloatCiphertext<'a>> for Cryptosystem {
    #[instrument(name = "encrypt float")]
    fn encrypt(key: &EncryptionKey, plaintext: FloatPlaintext) -> FloatCiphertext<'a> {
        let ciphertext = Cryptosystem::encrypt(key, plaintext.mantissa);
        FloatCiphertext {
            exponent: plaintext.exponent,
            mantissa_ciphertext: ciphertext,
        }
    }
}

impl<'a> CryptoDecrypt<DecryptionKey, FloatCiphertext<'a>, Result<FloatPlaintext>>
    for Cryptosystem
{
    #[instrument(name = "decrypt float")]
    fn decrypt(key: &DecryptionKey, ciphertext: FloatCiphertext<'a>) -> Result<FloatPlaintext> {
        let plaintext = Cryptosystem::decrypt(key, ciphertext.mantissa_ciphertext)?;
        let res = FloatPlaintext {
            exponent: ciphertext.exponent,
            mantissa: plaintext,
        };
        Ok(res)
    }
}

impl<'a>
    ProtocolAdd<
        &EncryptionKey,
        FloatCiphertext<'a>,
        FloatCiphertext<'a>,
        Result<FloatCiphertext<'a>>,
    > for Cryptosystem
{
    #[instrument(name = "float C+C")]
    async fn add_protocol(
        &self,
        key: &EncryptionKey,
        ct1: FloatCiphertext<'a>,
        ct2: FloatCiphertext<'a>,
    ) -> Result<FloatCiphertext<'a>> {

        let mut adapted_ct1 = ct1.clone();
        let mut adapted_ct2 = ct2.clone();

        if ct1.exponent > ct2.exponent {
            adapted_ct1 = self.decrease_exponent_to(key, ct1, ct2.exponent)?;
        } else {
            adapted_ct2 = self.decrease_exponent_to(key, ct2, ct1.exponent)?;
        }

        let res = FloatCiphertext {
            exponent: adapted_ct1.exponent,
            mantissa_ciphertext: self.add(
                key,
                adapted_ct1.mantissa_ciphertext,
                adapted_ct2.mantissa_ciphertext,
            ),
        };
        self.scale_ciphertext_to_range(key, res).await
    }
}

impl<'a>
    ProtocolAdd<&EncryptionKey, FloatCiphertext<'a>, FloatPlaintext, Result<FloatCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument(name = "float C+P")]
    async fn add_protocol(
        &self,
        key: &EncryptionKey,
        ct: FloatCiphertext<'a>,
        pt: FloatPlaintext,
    ) -> Result<FloatCiphertext<'a>> {
        let res = self
            .add_protocol(key, ct, Cryptosystem::encrypt(key, pt))
            .await?;

        self.scale_ciphertext_to_range(key, res).await
    }
}

impl<'a>
    ProtocolMul<
        &EncryptionKey,
        FloatCiphertext<'a>,
        FloatCiphertext<'a>,
        Result<FloatCiphertext<'a>>,
    > for Cryptosystem
{
    #[instrument(name = "float C*C")]
    async fn mul_protocol(
        &self,
        key: &EncryptionKey,
        ct1: FloatCiphertext<'a>,
        ct2: FloatCiphertext<'a>,
    ) -> Result<FloatCiphertext<'a>> {
        let new_exponent = ct1.exponent + ct2.exponent;

        let new_mantissa = self
            .mul_protocol(key, ct1.mantissa_ciphertext, ct2.mantissa_ciphertext)
            .await?;

        let res = FloatCiphertext {
            exponent: new_exponent,
            mantissa_ciphertext: new_mantissa,
        };
        self.scale_ciphertext_to_range(key, res).await
    }
}

impl<'a>
    ProtocolMul<&EncryptionKey, FloatCiphertext<'a>, FloatPlaintext, Result<FloatCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument(name = "float C*P")]
    async fn mul_protocol(
        &self,
        key: &EncryptionKey,
        ct1: FloatCiphertext<'a>,
        ct2: FloatPlaintext,
    ) -> Result<FloatCiphertext<'a>> {

        let mul = self.mul(key, ct1.mantissa_ciphertext, ct2.mantissa);
        let res = FloatCiphertext {
            exponent: ct1.exponent + ct2.exponent,
            mantissa_ciphertext: mul,
        };

        self.scale_ciphertext_to_range(key, res).await
    }
}

impl<'a>
    ProtocolSub<
        &EncryptionKey,
        FloatCiphertext<'a>,
        FloatCiphertext<'a>,
        Result<FloatCiphertext<'a>>,
    > for Cryptosystem
{
    #[instrument(name = "float C-C")]
    async fn sub_protocol(
        &self,
        key: &EncryptionKey,
        val1: FloatCiphertext<'a>,
        val2: FloatCiphertext<'a>,
    ) -> Result<FloatCiphertext<'a>> {
        let inverse = FloatPlaintext {
            exponent: 0,
            mantissa: IntPlaintext::from_plaintext(IBig::NEG_ONE)?,
        };

        let val2 = self.mul_protocol(key, val2, inverse).await?;
        self.add_protocol(key, val1, val2).await
    }
}
impl<'a>
    ProtocolSub<&EncryptionKey, FloatCiphertext<'a>, FloatPlaintext, Result<FloatCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument(name = "float C-P")]
    async fn sub_protocol(
        &self,
        key: &EncryptionKey,
        val1: FloatCiphertext<'a>,
        val2: FloatPlaintext,
    ) -> Result<FloatCiphertext<'a>> {
        let inverse = FloatPlaintext {
            exponent: 0,
            mantissa: IntPlaintext::from_plaintext(IBig::NEG_ONE)?,
        };

        let val2 = self
            .mul_protocol(key, Cryptosystem::encrypt(key, val2), inverse)
            .await?;
        self.add_protocol(key, val1, val2).await
    }
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct FloatCiphertext<'a> {
    pub exponent: isize,
    pub mantissa_ciphertext: IntCiphertext<'a>,
}

impl<'a> From<IntCiphertext<'a>> for FloatCiphertext<'a> {
    fn from(value: IntCiphertext<'a>) -> Self {
        Self {
            exponent: 0,
            mantissa_ciphertext: value,
        }
    }
}
