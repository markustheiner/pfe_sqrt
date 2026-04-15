use paillier_common::BigInt;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct Encoding<From, To> {
    pub modulus: BigInt,
    pub max_int: BigInt,
    pub _marker: PhantomData<From>,
    pub _marker2: PhantomData<To>,
}


