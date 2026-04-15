use crate::big_int_extension::{ToBigInt, ToIBig};
use crate::debug::ToPlaintext;
use crate::encoding::Encoding;
use crate::paillier_crypto::{Cryptosystem, MODULUS};
use crate::traits::{
    CombineCiphertexts, CryptoAND, CryptoAdd, CryptoDecrypt, CryptoEncrypt, CryptoMul, CryptoSub,
    CryptoXOR, GeneralError, ProtocolAND, ProtocolMul, RerandomizeCiphertext,
};
use crate::traits::{ProtocolOR, Result};
use dashu::base::BitTest;
use dashu::integer::IBig;
use paillier_common::{
    Add, Decrypt, DecryptionKey, Encrypt, EncryptionKey, Mul, Paillier, PrecomputedRandomness,
    RawCiphertext, RawPlaintext,
};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use rust_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::borrow::Cow;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::ops::{Add as StdAdd, Mul as StdMul, Shl, Shr, Sub as StdSub};
use std::sync::Arc;
use tracing::{instrument, Instrument};

impl Encoding<IBig, BigInt> {
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
    pub fn encode_bigint(&self, plaintext: &IBig) -> Result<BigInt> {
        let res = (plaintext.to_bigint()? + &self.modulus) % &self.modulus; // mod on negative stays negative
        Ok(res)
    }
    pub fn decode(&self, encoded_plaintext: &BigInt) -> Result<IBig> {
        let big_int_decoded = if encoded_plaintext <= &self.max_int {
            encoded_plaintext.clone()
        } else {
            encoded_plaintext - &self.modulus
        };

        big_int_decoded.to_ibig()
    }
}

#[derive(Clone, PartialEq,Serialize,Deserialize)]
pub struct IntPlaintext {
    pub encoded_plaintext: BigInt,
    pub plaintext: IBig,
}
impl Display for IntPlaintext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.plaintext.to_string())
    }
}
impl Debug for IntPlaintext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl IntPlaintext {
    pub fn one() -> Result<Self> {
        let one = IBig::ONE;
        Self::from_plaintext(one)
    }
    pub fn zero() -> Result<Self> {
        let zero = IBig::ZERO;
        Self::from_plaintext(zero)
    }

    pub fn from_plaintext(plaintext: IBig) -> Result<Self> {
        let encoding = Encoding::<IBig, BigInt>::new();
        let encoded_plaintext = encoding.encode_bigint(&plaintext)?;
        let res = IntPlaintext {
            encoded_plaintext,
            plaintext,
        };
        Ok(res)
    }
    pub fn from_encoded_plaintext(encoded_plaintext: BigInt) -> Result<Self> {
        let encoding = Encoding::<IBig, BigInt>::new();
        let plaintext = encoding.decode(&encoded_plaintext)?;

        let res = IntPlaintext {
            encoded_plaintext,
            plaintext,
        };

        Ok(res)
    }
    pub fn get_bit(&self, bit_number: usize) -> Result<IntPlaintext> {
        let bit = self.plaintext.bit(bit_number);
        IntPlaintext::from_plaintext(IBig::from(bit))
    }
}

impl PartialEq<usize> for IntPlaintext {
    fn eq(&self, other: &usize) -> bool {
        self.plaintext == IBig::from(*other)
    }
}
impl PartialEq<usize> for &IntPlaintext {
    fn eq(&self, other: &usize) -> bool {
        self.plaintext == IBig::from(*other)
    }
}

impl ToPlaintext<IBig> for IntPlaintext {
    fn to_plaintext(&self) -> IBig {
        self.plaintext.clone()
    }
}

impl Shr<usize> for IntPlaintext {
    type Output = Result<Self>;
    #[instrument(name = "shr P")]
    fn shr(self, rhs: usize) -> Self::Output {
        let res = self.plaintext >> rhs;
        Self::from_plaintext(res)
    }
}

impl Shl<usize> for IntPlaintext {
    type Output = Result<Self>;
    #[instrument(name = "shl P")]
    fn shl(self, rhs: usize) -> Self::Output {
        let res = self.plaintext << rhs;
        Self::from_plaintext(res)
    }
}
//
// impl Div<IBig> for IntPlaintext {
//     type Output = Result<Self>;
//
//     fn div(self, d: IBig) -> Self::Output {
//         let res = self.plaintext / d;
//         Self::from_plaintext(res, &self.modulus)
//     }
// }

impl StdAdd for IntPlaintext {
    type Output = Result<IntPlaintext>;
    #[instrument(name = "int P+P")]
    fn add(self, other: Self) -> Self::Output {
        self.apply_modular_arithmetic(other.encoded_plaintext, |a, b| a + b)
    }
}

impl<T> StdAdd<T> for IntPlaintext
where
    T: Into<BigInt> + Debug,
{
    type Output = Result<IntPlaintext>;
    #[instrument(name = "int P+P")]
    fn add(self, rhs: T) -> Self::Output {
        self.apply_modular_arithmetic(rhs.into(), |a, b| a + b)
    }
}

impl StdSub for IntPlaintext {
    type Output = Result<IntPlaintext>;
    #[instrument(name = "int P-P")]
    fn sub(self, other: Self) -> Self::Output {
        self.apply_modular_arithmetic(other.encoded_plaintext, |a, b| a - b)
    }
}

impl<T> StdSub<T> for IntPlaintext
where
    T: Into<BigInt> + Debug,
{
    type Output = Result<IntPlaintext>;
    #[instrument(name = "int P-P")]
    fn sub(self, rhs: T) -> Self::Output {
        self.apply_modular_arithmetic(rhs.into(), |a, b| a - b)
    }
}

impl StdMul for IntPlaintext {
    type Output = Result<IntPlaintext>;

    #[instrument(name = "int P*P")]
    fn mul(self, other: Self) -> Self::Output {
        self.apply_modular_arithmetic(other.encoded_plaintext, |a, b| a * b)
    }
}

impl<T> StdMul<T> for IntPlaintext
where
    T: Into<BigInt> + Debug,
{
    type Output = Result<IntPlaintext>;

    #[instrument(name = "int P*P")]
    fn mul(self, rhs: T) -> Self::Output {
        self.apply_modular_arithmetic(rhs.into(), |a, b| a * b)
    }
}

impl IntPlaintext {
    fn apply_modular_arithmetic<F>(self, other: BigInt, op: F) -> Result<Self>
    where
        F: FnOnce(BigInt, BigInt) -> BigInt,
    {
        let result = op(self.encoded_plaintext, other) % &MODULUS.clone();
        Self::from_encoded_plaintext(result)
    }
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct IntCiphertext<'a> {
    pub encoded_ciphertext: RawCiphertext<'a>,
}

impl<'a, 'b: 'a> RerandomizeCiphertext<&EncryptionKey, PrecomputedRandomness, IntCiphertext<'a>>
for IntCiphertext<'b>
{
    #[instrument]
    fn rerandomize(
        &self,
        key: &EncryptionKey,
        randomness: PrecomputedRandomness,
    ) -> IntCiphertext<'a> {
        let d = (self.encoded_ciphertext.0.borrow() as &BigInt * randomness.0) % &key.nn;
        let rerandomized = RawCiphertext(Cow::Owned(d));
        IntCiphertext {
            encoded_ciphertext: rerandomized,
        }
    }
}

impl<'a> IntCiphertext<'a> {
    pub fn to_static(&self) -> IntCiphertext<'static> {
        IntCiphertext {
            encoded_ciphertext: RawCiphertext(Cow::Owned(
                self.encoded_ciphertext.0.clone().into_owned(),
            )),
        }
    }
}

impl<'a> CryptoEncrypt<&EncryptionKey, IntPlaintext, IntCiphertext<'a>> for Cryptosystem {
    #[instrument(name = "encrypt int")]
    fn encrypt(key: &EncryptionKey, plaintext: IntPlaintext) -> IntCiphertext<'a> {
        let raw_plaintext = RawPlaintext::from(&plaintext.encoded_plaintext);

        let encrypted = Paillier::encrypt(key, raw_plaintext);

        IntCiphertext {
            encoded_ciphertext: encrypted,
        }
    }
}

impl<'a> CryptoDecrypt<DecryptionKey, IntCiphertext<'a>, Result<IntPlaintext>> for Cryptosystem {
    #[instrument(name = "decrypt int")]
    fn decrypt(key: &DecryptionKey, ciphertext: IntCiphertext<'a>) -> Result<IntPlaintext> {
        let raw_plaintext = Paillier::decrypt(key, &ciphertext.encoded_ciphertext);

        IntPlaintext::from_encoded_plaintext(BigInt::from(raw_plaintext))
    }
}

impl<'a> CryptoDecrypt<DecryptionKey, Vec<IntCiphertext<'a>>, Result<Vec<IntPlaintext>>>
    for Cryptosystem
{
    #[instrument]

    fn decrypt(key: &DecryptionKey, cts: Vec<IntCiphertext<'a>>) -> Result<Vec<IntPlaintext>> {
        cts.clone()
            .into_iter()
            .map(|ct| Cryptosystem::decrypt(key, ct))
            .collect()
    }
}

impl<'a, 'b> CryptoMul<&EncryptionKey, IntCiphertext<'a>, IntPlaintext, IntCiphertext<'b>>
    for Cryptosystem
{
    #[instrument(name = "int C*P")]
    fn mul(
        &self,
        key: &EncryptionKey,
        ct1: IntCiphertext<'a>,
        val2: IntPlaintext,
    ) -> IntCiphertext<'b> {
        let multiplied = Paillier::mul(
            key,
            ct1.encoded_ciphertext.clone(),
            RawPlaintext::from(&val2.encoded_plaintext),
        );

        let res = IntCiphertext {
            encoded_ciphertext: multiplied,
        };
        res
    }
}

impl<'a, 'b, 'c>
ProtocolMul<&EncryptionKey, IntCiphertext<'a>, IntCiphertext<'b>, Result<IntCiphertext<'c>>>
    for Cryptosystem
{
    #[instrument(name = "int C*C")]
    async fn mul_protocol(
        &self,
        key: &EncryptionKey,
        val1: IntCiphertext<'a>,
        val2: IntCiphertext<'b>,
    ) -> Result<IntCiphertext<'c>> {
        self.disguised_multiplication(key, val1, val2).await
    }
}

impl<'a, 'b, 'c>
ProtocolAND<
    &EncryptionKey,
    IntCiphertext<'a>,
    IntCiphertext<'b>,
    Result<IntCiphertext<'c>>,
> for Cryptosystem
{
    async fn and_protocol(
        &self,
        key: &EncryptionKey,
        val1: IntCiphertext<'a>,
        val2: IntCiphertext<'b>,
    ) -> Result<IntCiphertext<'c>> {
        self.mul_protocol(key, val1, val2).await
    }
}

impl<'a> ProtocolOR<&EncryptionKey, IntCiphertext<'a>, IntCiphertext<'a>, Result<IntCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument]
    async fn or_protocol(
        &self,
        key: &EncryptionKey,
        ct1: IntCiphertext<'a>,
        ct2: IntCiphertext<'a>,
    ) -> Result<IntCiphertext<'a>> {
        let arc_self = Arc::new(self.clone());

        // a + b - a*b

        let key2 = key.clone();

        let addition = tokio::spawn({
            let arc_self = arc_self.clone();
            let key = key.clone();
            let ct1 = ct1.to_static();
            let ct2 = ct2.to_static();
            async move { arc_self.add(&key, ct1, ct2) }.in_current_span()
        });

        let multiplication = arc_self.mul_protocol(key, ct1, ct2);

        self.sub(&key2, addition.await?, multiplication.await?)
    }
}

impl<'a> CryptoAND<&EncryptionKey, IntCiphertext<'a>, IntPlaintext, IntCiphertext<'a>>
    for Cryptosystem
{
}

impl<'a> CryptoAdd<&EncryptionKey, IntCiphertext<'a>, IntCiphertext<'a>, IntCiphertext<'a>>
    for Cryptosystem
{
    #[instrument(name = "int C+C")]
    fn add(
        &self,
        key: &EncryptionKey,
        val1: IntCiphertext<'a>,
        val2: IntCiphertext<'a>,
    ) -> IntCiphertext<'a> {
        let added = Paillier::add(
            key,
            val1.encoded_ciphertext.clone(),
            val2.encoded_ciphertext.clone(),
        );
        IntCiphertext {
            encoded_ciphertext: added,
        }
    }
}

impl<'a> CryptoAdd<&EncryptionKey, IntCiphertext<'a>, IntPlaintext, IntCiphertext<'a>>
    for Cryptosystem
{
    #[instrument(name = "int C+P")]
    fn add(
        &self,
        key: &EncryptionKey,
        val1: IntCiphertext<'a>,
        val2: IntPlaintext,
    ) -> IntCiphertext<'a> {
        let added = Paillier::add(
            key,
            val1.encoded_ciphertext.clone(),
            RawPlaintext::from(&val2.encoded_plaintext),
        );
        IntCiphertext {
            encoded_ciphertext: added,
        }
    }
}

impl<'a> CryptoSub<&EncryptionKey, IntCiphertext<'a>, IntCiphertext<'a>, Result<IntCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument(name = "int C-C")]
    fn sub(
        &self,
        e_key: &EncryptionKey,
        ct1: IntCiphertext<'a>,
        ct2: IntCiphertext<'a>,
    ) -> Result<IntCiphertext<'a>> {
        let inverse = IntPlaintext::from_plaintext(IBig::NEG_ONE)?;
        let val2 = self.mul(e_key, ct2, inverse);
        Ok(self.add(e_key, ct1, val2))
    }
}

impl<'a> CryptoSub<&EncryptionKey, IntPlaintext, IntCiphertext<'a>, Result<IntCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument(name = "int P-C")]
    fn sub(
        &self,
        e_key: &EncryptionKey,
        pt: IntPlaintext,
        ct: IntCiphertext<'a>,
    ) -> Result<IntCiphertext<'a>> {
        let inverse = IntPlaintext::from_plaintext(IBig::NEG_ONE)?;
        let inv_ct = self.mul(e_key, ct, inverse);

        Ok(self.add(e_key, inv_ct, pt))
    }
}

impl<'a> CryptoSub<&EncryptionKey, IntCiphertext<'a>, IntPlaintext, Result<IntCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument(name = "int C-P")]
    fn sub(
        &self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        pt: IntPlaintext,
    ) -> Result<IntCiphertext<'a>> {
        let inv_pt = (pt * -1)?;

        Ok(self.add(e_key, ct, inv_pt))
    }
}

impl<'a> CryptoXOR<&EncryptionKey, IntCiphertext<'a>, IntPlaintext, Result<IntCiphertext<'a>>>
    for Cryptosystem
{
    #[instrument]
    fn xor(
        &self,
        key: &EncryptionKey,
        val1: IntCiphertext<'a>,
        val2: IntPlaintext,
    ) -> Result<IntCiphertext<'a>> {
        if val2.plaintext == IBig::ZERO {
            Ok(val1.clone())
        } else {
            self.sub(key, val2, val1) // 1-ciphertext
        }
    }
}
#[derive(Debug)]
pub enum CombineDirection {
    SmallIndexIsSmallValue,
    SmallIndexIsBigValue,
}
impl<'a>
CombineCiphertexts<
    IntCiphertext<'a>,
    &EncryptionKey,
    CombineDirection,
    Result<IntCiphertext<'a>>,
> for Cryptosystem
{
    #[instrument]
    fn combine_ciphertexts(
        &self,
        e_key: &EncryptionKey,
        cts: Vec<IntCiphertext<'a>>,
        ct_length: usize,
        direction: CombineDirection,
    ) -> Result<IntCiphertext<'a>> {
        assert!(!cts.is_empty());

        let cts = match direction {
            CombineDirection::SmallIndexIsBigValue => cts.iter().rev().cloned().collect(),
            CombineDirection::SmallIndexIsSmallValue => cts,
        };
        let res: Result<_> = cts
            .into_par_iter()
            .enumerate()
            .map(|(index, ct)| {
                let curr_mul = IBig::ONE << (index * ct_length);
                let pt = IntPlaintext::from_plaintext(curr_mul)?;
                Ok(self.mul(e_key, ct, pt))
            })
            .reduce_with(|ct1, ct2| Ok(self.add(e_key, ct1?, ct2?)))
            .ok_or(GeneralError::new("There were no ciphertexts to combine").into());

        res?
    }
}
