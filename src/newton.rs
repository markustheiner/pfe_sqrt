
use crate::float::{FloatCiphertext, FloatPlaintext};
use crate::integer::{CombineDirection,  IntPlaintext};
use crate::newton::Operations::{AddCC, AddCP, InvC, MulCC, MulCP, SubCC, SubCP};
use crate::paillier_crypto::{Cryptosystem, GetBitsSettings, TestSetup};
use crate::traits::{
    CombineCiphertexts, CryptoAdd, CryptoDecrypt, CryptoEncrypt, CryptoMul, GeneralError,
    ProtocolAdd, ProtocolMul, ProtocolOR, ProtocolSub, Result,
};
use dashu::float::FBig;
use dashu::integer::IBig;
use itertools::Either;
use itertools::Either::Left;
use paillier_common::EncryptionKey;
use std::sync::Arc;
use dashu::base::SquareRoot;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{instrument, Instrument};
use Either::Right;
use serde::{Deserialize, Serialize};
use crate::debug::{ DebugSender};

#[derive(Clone, Debug, Eq, PartialEq,Serialize,Deserialize)]
pub enum SqrtApproximationSettings {
    Bits { get_bits: GetBitsSettings },
    Rough { modify_randomness: Option<usize> },
    Optimized {},
}
#[instrument]
pub async fn newton_sqrt<'a: 'static>(
    iterations: usize,
    num_enc: FloatCiphertext<'a>,
    starting_value: Either<SqrtApproximationSettings, f64>,
    t: TestSetup,
) -> Result<FBig> {
    let e_key = &t.e_key;
    let d_key = &t.d_key;

    let s_value = match starting_value {
        Left(approx) => approx_sqrt(&num_enc, &t, e_key, approx).await?,
        Right(f) => Cryptosystem::encrypt(e_key, FloatPlaintext::from_plaintext(f)?),
    };
    let half = FloatPlaintext::from_plaintext(0.5)?;
    let mut xn = s_value.clone();

    for _ in 0..iterations {
        // 0.5 * (xn + (a/xn))

        let xn_inv = ct_op(&t, InvC(xn.clone()));

        let a_xn = ct_op(&t, MulCC(num_enc.clone(), xn_inv.await??));

        let brackets = ct_op(&t, AddCC(xn.clone(), a_xn.await??));

        xn = ct_op(&t, MulCP(brackets.await??, half.clone())).await??;
    }

    let res = Cryptosystem::decrypt(d_key, xn)?;

    Ok(res.to_fbig())
}
#[instrument]
async fn approx_sqrt<'a: 'static>(
    num_enc: &FloatCiphertext<'a>,
    t: &TestSetup,
    e_key: &EncryptionKey,
    approx: SqrtApproximationSettings,
) -> Result<FloatCiphertext<'a>> {
    let approx_mantissa = match approx {
        SqrtApproximationSettings::Bits { get_bits } => {
            let bits = t
                .cryptosystem
                .get_bits_protocol(e_key, num_enc.mantissa_ciphertext.clone(), 64, get_bits)
                .await?;

            let approx_bits = t.cryptosystem.approx_sqrt_from_bits(e_key, bits).await?;

            t.cryptosystem.combine_ciphertexts(
                e_key,
                approx_bits,
                1,
                CombineDirection::SmallIndexIsSmallValue,
            )
        }
        SqrtApproximationSettings::Rough { modify_randomness } => {
            t.cryptosystem
                .approx_sqrt_rough(
                    e_key,
                    num_enc.mantissa_ciphertext.clone(),
                    modify_randomness,
                )
                .await
        }
        SqrtApproximationSettings::Optimized {} => {
            let bit_number = t.cryptosystem.max_bit_accuracy as usize;
            let (bit_sender, mut bit_receiver) = mpsc::channel(bit_number);

            let debug_sender = DebugSender{
                id: "get bits".to_string(),
                sender: bit_sender,
            };

            let _async_bits_handle = t.cryptosystem
                .approximate_get_bits_parallel_channeled(
                    e_key,
                    num_enc.mantissa_ciphertext.clone(),
                    debug_sender,
                )
                .await?;

            let mut combined_bits : JoinSet<Result<_>> = JoinSet::new();

            let mut bit_storage = Vec::with_capacity(bit_number);
            bit_storage.resize(bit_number, None);
            let key_arc = Arc::new(e_key.clone());

            while let Some((index, bit)) = bit_receiver.recv().await {
                bit_storage[index]= Some(bit.clone());

                let corresponding_index = if index % 2 == 0 { index + 1 } else { index - 1 };
                if bit_storage[corresponding_index].is_none() {
                    continue;
                }
                let key_arc = key_arc.clone();
                let corresponding_bit = bit_storage[corresponding_index].clone().unwrap();
                let t = t.clone();
                combined_bits.spawn(async move {
                    let res = t
                        .cryptosystem
                        .or_protocol(
                            key_arc.as_ref(),
                            bit,
                            corresponding_bit,
                        )
                        .await?;
                    let res = t.cryptosystem.mul(
                        key_arc.as_ref(),
                        res,
                        IntPlaintext::from_plaintext(IBig::ONE << (index / 2))?,
                    );
                    Ok(res)
                });
            }


            let result = combined_bits
                .join_all()
                .await
                .into_iter()
                .flatten()
                .reduce(|acc, x| {
                    t.cryptosystem.add(e_key, acc, x)
                }
                );


            result.ok_or(GeneralError::new("could not combine bits").into())
        }
    }?;

    let new_exponent = num_enc.exponent / 2;
    let res = FloatCiphertext {
        exponent: new_exponent,
        mantissa_ciphertext: approx_mantissa,
    };
    Ok(res)
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub enum InvSqrtApproximationSettings {
    ApproxSqrtAndInv {
        get_bits: GetBitsSettings,
        advanced_inverse_approximation: Option<bool>, // None => division, Some => simple or advanced bitwise inverse
    },
    LinearApprox {
        slope: f64,
        offset: f64,
    },
}
#[instrument]
pub async fn newton_inv_sqrt<'a: 'static>(
    iterations: usize,
    num_enc: FloatCiphertext<'a>,
    starting_value_logic: Either<InvSqrtApproximationSettings, f64>,
    t: TestSetup,
) -> Result<FBig> {
    let e_key = &t.e_key;
    let d_key = &t.d_key;

    let mut res_enc = match starting_value_logic {
        Left(settings) => approx_inv_sqrt(&num_enc, &t, e_key, settings).await?,
        Right(f) => Cryptosystem::encrypt(e_key, FloatPlaintext::from_plaintext(f)?),
    };

    let num_half_enc = ct_op(
        &t,
        MulCP(num_enc.clone(), FloatPlaintext::from_plaintext(0.5)?),
    )
    .await??;

    for _ in 0..iterations {
        let num_half_enc = num_half_enc.clone();

        let x0_a_enc = ct_op(
            &t,
            MulCP(res_enc.clone(), FloatPlaintext::from_plaintext(1.5)?),
        );
        let x0_b1_enc = ct_op(&t, MulCC(num_half_enc, res_enc.clone()));
        let x0_b2_enc = ct_op(&t, MulCC(res_enc.clone(), res_enc));
        let x0_b_enc = ct_op(&t, MulCC(x0_b1_enc.await??, x0_b2_enc.await??));

        res_enc = ct_op(&t, SubCC(x0_a_enc.await??, x0_b_enc.await??)).await??;
    }

    let res_final_enc = ct_op(&t, MulCC(res_enc, num_enc));
    let res_final_dec = Cryptosystem::decrypt(d_key, res_final_enc.await??)?;
    Ok(res_final_dec.to_fbig())
}
#[instrument]
async fn approx_inv_sqrt<'a: 'static>(
    num_enc: &FloatCiphertext<'a>,
    t: &TestSetup,
    e_key: &EncryptionKey,
    settings: InvSqrtApproximationSettings,
) -> Result<FloatCiphertext<'a>> {
    Ok(match settings {
        InvSqrtApproximationSettings::ApproxSqrtAndInv {
            get_bits,
            advanced_inverse_approximation,
        } => {
            let bits = t
                .cryptosystem
                .get_bits_protocol(e_key, num_enc.mantissa_ciphertext.clone(), 64, get_bits)
                .await?;

            let approx_bits = t.cryptosystem.approx_sqrt_from_bits(e_key, bits).await?;

            if let Some(advanced_inverse_approximation) = advanced_inverse_approximation {
                let inverse_bits = if advanced_inverse_approximation {
                    t.cryptosystem
                        .clone()
                        .approximate_inverse(
                            &t.e_key,
                            approx_bits.iter().map(|x| x.to_static()).collect(),
                            64 - 1,
                            1,
                        )
                        .await?
                        .1
                } else {
                    let isolated_bit = t
                        .cryptosystem
                        .isolate_highest_bit(&t.e_key, approx_bits)
                        .await?;

                    let mut res = isolated_bit[0].clone();
                    let two_pow_64 = IntPlaintext::from_plaintext(IBig::ONE << 64 - 1)?;
                    res = t.cryptosystem.mul(&t.e_key, res, two_pow_64);

                    for i in 1..isolated_bit.len() {
                        let curr = isolated_bit[i].clone();
                        let two_pow_64_minus_i =
                            IntPlaintext::from_plaintext(IBig::ONE << (64 - i - 1))?;
                        let mul_result = t.cryptosystem.mul(&t.e_key, curr, two_pow_64_minus_i);
                        res = t.cryptosystem.add(&t.e_key, res, mul_result);
                    }

                    res
                };

                let res_float = FloatCiphertext {
                    exponent: -(num_enc.exponent / 2) - 64,
                    mantissa_ciphertext: inverse_bits,
                };

                res_float
            } else {
                let combined_bits = t.cryptosystem.combine_ciphertexts(
                    e_key,
                    approx_bits,
                    1,
                    CombineDirection::SmallIndexIsSmallValue,
                )?;

                let convergence_correction : FBig = FBig::from(3).sqrt() / FBig::from(2);

                let sqrt_float = FloatCiphertext {
                    exponent: 0,
                    mantissa_ciphertext: combined_bits,
                };

                let mut res = t
                    .cryptosystem
                    .disguised_inverse(&t.e_key, sqrt_float)
                    .await?;
                res.exponent = res.exponent - (num_enc.exponent / 2);

                res = t.cryptosystem.mul_protocol(&t.e_key, res, FloatPlaintext::from_plaintext(convergence_correction.to_f64().value())?).await?;

                res
            }
        }
        InvSqrtApproximationSettings::LinearApprox { slope, offset } => {
            let slope = FloatPlaintext::from_plaintext(slope)?;
            let offset = FloatPlaintext::from_plaintext(offset)?;
            let res = ct_op(&t, MulCP(num_enc.clone(), slope));
            ct_op(&t, AddCP(res.await??, offset)).await??
        }
    })
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Operations<'a> {
    AddCC(FloatCiphertext<'a>, FloatCiphertext<'a>),
    AddCP(FloatCiphertext<'a>, FloatPlaintext),
    MulCC(FloatCiphertext<'a>, FloatCiphertext<'a>),
    MulCP(FloatCiphertext<'a>, FloatPlaintext),
    SubCC(FloatCiphertext<'a>, FloatCiphertext<'a>),
    SubCP(FloatCiphertext<'a>, FloatPlaintext),
    InvC(FloatCiphertext<'a>),
}

pub fn ct_op<'a: 'static>(
    t: &TestSetup,
    op: Operations<'a>,
) -> JoinHandle<Result<FloatCiphertext<'a>>> {
    let t = t.clone();

    tokio::spawn(
        async move {
            let res = match op {
                AddCC(ct1, ct2) => {
                    let res = t
                        .cryptosystem
                        .add_protocol(&t.e_key, ct1.clone(), ct2.clone())
                        .in_current_span()
                        .await?;
                    res
                }
                AddCP(ct, pt) => {
                    let res = t
                        .cryptosystem
                        .add_protocol(&t.e_key, ct.clone(), pt.clone())
                        .in_current_span()
                        .await?;
                    res
                }
                MulCC(ct1, ct2) => {
                    let res = t
                        .cryptosystem
                        .mul_protocol(&t.e_key, ct1.clone(), ct2.clone())
                        .in_current_span()
                        .await?;
                    res
                }
                MulCP(ct, pt) => {
                    let res = t
                        .cryptosystem
                        .mul_protocol(&t.e_key, ct.clone(), pt.clone())
                        .in_current_span()
                        .await?;
                    res
                }
                SubCC(ct1, ct2) => {
                    let res = t
                        .cryptosystem
                        .sub_protocol(&t.e_key, ct1.clone(), ct2.clone())
                        .in_current_span()
                        .await?;
                    res
                }
                SubCP(ct, pt) => {
                    let res = t
                        .cryptosystem
                        .sub_protocol(&t.e_key, ct.clone(), pt.clone())
                        .in_current_span()
                        .await?;
                    res
                }
                InvC(ct) => {
                    let res = t
                        .cryptosystem
                        .disguised_inverse(&t.e_key, ct.clone())
                        .in_current_span()
                        .await?;
                    res
                }
            };

            Ok(res)
        }
        .in_current_span(),
    )
}
