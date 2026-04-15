use crate::traits::{GeneralError, Result};
use dashu::integer::IBig;
use paillier_common::BigInt;

pub trait ToBigInt {
    fn to_bigint(&self) -> Result<BigInt>;
}
pub trait ToIBig {
    fn to_ibig(&self) -> Result<IBig>;
}
impl ToBigInt for IBig {
    fn to_bigint(&self) -> Result<BigInt> {
        let serialized = self.in_radix(36);
        BigInt::from_str_radix(format!("{}", serialized).as_str(), 36).map_err(|e| GeneralError::from(e.to_string()).into())
    }
}
impl ToIBig for BigInt {
    fn to_ibig(&self) -> Result<IBig> {
        let serialized = self.to_str_radix(36);
        let res = IBig::from_str_radix(serialized.as_str(),36).map_err(|e| GeneralError::from(e.to_string()).into());
        res
    }
}

