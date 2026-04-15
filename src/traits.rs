use std::error::Error;
use std::fmt::{Display, Formatter};

pub trait CryptoEncrypt<EncryptionKey, Plaintext, Ciphertext> {
    fn encrypt(key: EncryptionKey, plaintext: Plaintext) -> Ciphertext;
}

pub trait CryptoDecrypt<DecryptionKey, Ciphertext, Plaintext> {
    fn decrypt(key: &DecryptionKey, ciphertext: Ciphertext) -> Plaintext;
}

pub trait CryptoSub<EncryptionKey, Val1, Val2, Result> {
    fn sub(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}
pub trait ProtocolSub<EncryptionKey, Val1, Val2, Result> {
    async fn sub_protocol(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}
pub trait CryptoAdd<EncryptionKey, Val1, Val2, Result> {
    fn add(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}
pub trait ProtocolAdd<EncryptionKey, Val1, Val2, Result> {
    async fn add_protocol(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}
pub trait CryptoMul<EncryptionKey, Val1, Val2, Result> {
    fn mul(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}
pub trait ProtocolMul<EncryptionKey, Val1, Val2, Result> {
    async fn mul_protocol(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}
pub trait CryptoXOR<EncryptionKey, Val1, Val2, Result> {
    fn xor(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}

pub trait ProtocolAND<EncryptionKey, Val1, Val2, Result>:
    ProtocolMul<EncryptionKey, Val1, Val2, Result>
{
    async fn and_protocol(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}

pub trait CryptoAND<EncryptionKey, Val1, Val2, Result>:
    CryptoMul<EncryptionKey, Val1, Val2, Result>
{
    fn and(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result {
        self.mul(key, val1, val2)
    }
}

pub trait ProtocolOR<EncryptionKey, Val1, Val2, Result> {
    async fn or_protocol(&self, key: EncryptionKey, val1: Val1, val2: Val2) -> Result;
}

pub trait CombineCiphertexts<Ciphertext, EncryptionKey, Direction, Result> {
    fn combine_ciphertexts(
        &self,
        key: EncryptionKey,
        ciphertexts: Vec<Ciphertext>,
        ct_length: usize,
        direction: Direction,
    ) -> Result;
}

pub trait RerandomizeCiphertext<EncryptionKey, PrecomputedRandomness, Result> {
    fn rerandomize(&self, key: EncryptionKey, randomness: PrecomputedRandomness) -> Result;
}

pub(crate) type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
pub struct GeneralError {
    message: String,
}
impl GeneralError {
    pub(crate) fn new(message: impl Into<String>) -> GeneralError {
        GeneralError {
            message: message.into(),
        }
    }
}
impl Error for GeneralError {}
impl Display for GeneralError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

unsafe impl Send for GeneralError {}

impl From<GeneralError> for Box<dyn Error + Send> {
    fn from(value: GeneralError) -> Self {
        Box::new(value)
    }
}

impl From<String> for GeneralError {
    fn from(value: String) -> Self {
        GeneralError::new(value)
    }
}
