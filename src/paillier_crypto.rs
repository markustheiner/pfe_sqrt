use crate::debug::DebugSender;
use crate::big_int_extension::ToIBig;
use crate::debug::{debug_decrypt};
use crate::float::{FloatCiphertext, FloatPlaintext};
use crate::integer::CombineDirection::SmallIndexIsSmallValue;
use crate::integer::{IntCiphertext, IntPlaintext};
use crate::randomness_provider::RandomnessProvider;
use crate::traits::{CombineCiphertexts, RerandomizeCiphertext, Result};
use crate::traits::{
    CryptoAND, CryptoAdd, CryptoDecrypt, CryptoEncrypt, CryptoMul, CryptoSub, CryptoXOR,
    GeneralError, ProtocolAND, ProtocolMul, ProtocolOR,
};
use dashu::base::BitTest;
use dashu::float::FBig;
use dashu::integer::{IBig, UBig};
use itertools::Itertools;
use once_cell::sync::Lazy;
use paillier_common::{BigInt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier};
use rand::{thread_rng, Rng};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::join;
use serde::{Deserialize, Serialize};
use std::iter::zip;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tokio::try_join;
use tracing::{info, info_span, instrument, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

//mock struct representing the communication with the data owner
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct MockCommunication {
    pub(crate) delay: Duration,
}

impl MockCommunication {
    //multiplying 2 values by decrypting

    #[instrument]
    pub async fn mult_inverse<'a>(&self, ct: IntCiphertext<'a>) -> Result<FloatCiphertext<'a>> {
        self.communication_delay().await;
        // needed to keep accuracy, as inverse is calculated of very big number (disguised)
        let min_exponent = -512;
        let pt = Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)?;

        let pt_decoded = pt.plaintext;

        let inv: FBig = FBig::ONE / FBig::from(pt_decoded);

        let repr = inv.repr();
        let exponent = repr.exponent();
        let significand = repr.significand().clone();

        let new_significand = if exponent < min_exponent {
            significand >> (min_exponent.abs_diff(exponent))
        } else {
            significand
        };

        let new_exponent = if exponent < min_exponent {
            min_exponent
        } else {
            exponent
        };

        let int_pt = IntPlaintext::from_plaintext(new_significand)?;

        let float_pt = FloatPlaintext {
            exponent: new_exponent,
            mantissa: int_pt,
        };

        let res = Cryptosystem::encrypt(&DEBUG_KEYS.0, float_pt);
        Ok(res)
    }

    #[instrument]
    pub async fn mult<'a>(
        &self,
        ct1: IntCiphertext<'a>,
        ct2: IntCiphertext<'a>,
    ) -> Result<IntCiphertext<'a>> {
        self.communication_delay().await;

        let (pt1, pt2) = join(
            || Cryptosystem::decrypt(&DEBUG_KEYS.1, ct1),
            || Cryptosystem::decrypt(&DEBUG_KEYS.1, ct2),
        );

        let mult = (pt1? * pt2?)?;

        let result = Cryptosystem::encrypt(&DEBUG_KEYS.0, mult);

        Ok(result)
    }

    #[instrument]
    pub async fn get_all_bits<'a>(
        &self,
        ct: IntCiphertext<'a>,
        bit_number: usize,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        self.communication_delay().await;

        let pt = Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)?;

        let plaintext = pt.encoded_plaintext.to_ibig()?;

        let current_span = tracing::Span::current();
        let encrypted_bits = (0..bit_number)
            .into_par_iter()
            .map(|i| {
                let iteration_span = info_span!("get bits and encrypt");
                iteration_span.set_parent(current_span.context());
                let _enter = iteration_span.enter();

                let bit = plaintext.bit(i);

                let pt_bit = if bit {
                    IntPlaintext::one()?
                } else {
                    IntPlaintext::zero()?
                };

                let res = Cryptosystem::encrypt(&DEBUG_KEYS.0, pt_bit);

                Ok(res)
            })
            .collect();

        encrypted_bits
    }
    #[instrument]
    pub async fn get_all_bits_channeled<'a>(
        &self,
        ct: IntCiphertext<'a>,
        bit_number: usize,
        channel: DebugSender<(usize, IntCiphertext<'static>)>,
    ) -> Result<JoinSet<Result<()>>> {
        self.communication_delay().await;

        let pt = Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)?;

        let plaintext = pt.encoded_plaintext.to_ibig()?;

        let mut set: JoinSet<Result<()>> = JoinSet::new();

        (0..bit_number).into_iter().for_each(|i| {
            let channel = channel.clone();
            let plaintext = plaintext.clone();

            set.spawn(
                async move {
                    let bit = plaintext.bit(i);

                    let pt_bit = if bit {
                        IntPlaintext::one()?
                    } else {
                        IntPlaintext::zero()?
                    };

                    let res = Cryptosystem::encrypt(&DEBUG_KEYS.0, pt_bit);
                    channel.send((i, res)).await?;

                    Ok(())
                }
                .in_current_span(),
            );
        });

        Ok(set)
    }

    #[instrument]
    pub async fn get_x_bits<'a>(
        &self,
        ct: IntCiphertext<'a>,
        bit_number: usize,
    ) -> Result<(Vec<IntCiphertext<'a>>, IntCiphertext<'a>)> {
        self.communication_delay().await;

        let pt = Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)?;

        let plaintext = pt.encoded_plaintext.to_ibig()?;

        let mut bits: Vec<IBig> = vec![];
        for i in 0..bit_number {
            bits.push(plaintext.bit(i).into());
        }

        let rest = plaintext >> bit_number;

        bits.push(rest);

        // parallel encryption
        let mut results: Vec<_> = bits
            .into_par_iter()
            .map(|value| {
                IntPlaintext::from_plaintext(value)
                    .map(move |result| Cryptosystem::encrypt(&DEBUG_KEYS.0, result))
            })
            .flatten()
            .collect();

        let rest_encrypted = results.pop().ok_or(GeneralError::new(
            "Results was empty for some unknown reason.",
        ))?;

        Ok((results, rest_encrypted))
    }

    #[instrument]
    pub async fn shift_right<'a>(
        &self,
        ct: IntCiphertext<'a>,
        shift_amount: usize,
    ) -> Result<IntCiphertext<'a>> {
        self.communication_delay().await;

        let pt = Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)?;
        let shifted = pt >> shift_amount;
        Ok(Cryptosystem::encrypt(&DEBUG_KEYS.0, shifted?))
    }

    #[instrument]
    pub async fn split_ciphertext<'a>(
        &self,
        ct: IntCiphertext<'a>,
        block_size: usize,
        block_num: usize,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        self.communication_delay().await;
        let pt = Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)?;
        let plaintext: IBig = pt.encoded_plaintext.to_ibig()?;

        let mask = IBig::from((1u64 << block_size) - 1);

        let encryptions: Vec<_> = (0..block_num)
            .into_par_iter()
            .map(|i| {
                let shift_amount = i * block_size;
                let chunk_value = (&plaintext >> shift_amount) & &mask;
                IntPlaintext::from_plaintext(chunk_value)
                    .map(move |result| Cryptosystem::encrypt(&DEBUG_KEYS.0, result))
            })
            .flatten()
            .collect();

        debug_decrypt("blocks", encryptions.clone());

        Ok(encryptions)
    }

    #[instrument(name = "DELAY")]
    async fn communication_delay(&self) {
        sleep(self.delay).await
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Cryptosystem {
    pub mock_communication: MockCommunication,
    pub disguise_length: usize,
    pub max_bit_accuracy: isize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GetBitsSettings {
    Simple {
        bits_per_communication: usize,
    },
    Advanced {
        block_size: usize,
        bits_per_communication: usize,
    },
    Approximation {},
}

impl Cryptosystem {
    #[instrument]
    pub async fn disguised_inverse<'a>(
        &self,
        e_key: &EncryptionKey,
        ct: FloatCiphertext<'a>,
    ) -> Result<FloatCiphertext<'a>> {
        let randomness = RANDOMNESS_PROVIDER.get_randomness();

        let exponent_ct = ct.exponent;
        let mantissa_ct = ct.mantissa_ciphertext;

        let encoded_disguise_mul = self.generate_encoded_disguise(None)?;

        let disguised = self.mul(e_key, mantissa_ct, encoded_disguise_mul.clone());

        let encoded_disguise_add = self.generate_encoded_disguise(None)?;

        let disguised = self.add(e_key, disguised, encoded_disguise_add.clone());

        let disguised_inverse = self
            .mock_communication
            .mult_inverse(disguised.rerandomize(e_key, randomness.await?));

        let disguise_as_float = FloatPlaintext {
            exponent: -exponent_ct,
            mantissa: encoded_disguise_mul,
        };

        let inverse = self.mul_protocol(e_key, disguised_inverse.await?, disguise_as_float);

        Ok(inverse.await?)
    }

    // protocol for multiplying 2 Ciphertexts
    #[instrument]

    pub async fn disguised_multiplication<'a, 'b, 'c>(
        &self,
        e_key: &EncryptionKey,
        ct1: IntCiphertext<'a>,
        ct2: IntCiphertext<'b>,
    ) -> Result<IntCiphertext<'c>> {
        let randomness1 = RANDOMNESS_PROVIDER.get_randomness();
        let randomness2 = RANDOMNESS_PROVIDER.get_randomness();

        let encoded_disguise1 = self.generate_encoded_disguise(None)?;
        let encoded_disguise2 = self.generate_encoded_disguise(None)?;

        // calculate disguised values
        let disguised_val1 = self
            .add(e_key, ct1.clone(), encoded_disguise1.clone())
            .to_static();
        let disguised_val2 = self
            .add(e_key, ct2.clone(), encoded_disguise2.clone())
            .to_static();

        // disguised multiplication
        let disguised_mult = self.mock_communication.mult(
            disguised_val1.rerandomize(e_key, randomness1.await?),
            disguised_val2.rerandomize(e_key, randomness2.await?),
        );
        // recover original multiplication
        let unmask1 = self.mul(e_key, ct1.clone(), encoded_disguise2.clone());
        let unmask2 = self.mul(e_key, ct2.clone(), encoded_disguise1.clone());
        let unmask3 = (encoded_disguise1 * encoded_disguise2)?;

        let result = self.sub(e_key, disguised_mult.await?, unmask1)?;
        let result = self.sub(e_key, result, unmask2)?;
        let res = self.sub(e_key, result, unmask3)?;

        Ok(res)
    }

    #[instrument]
    pub async fn disguised_shift_right<'a>(
        self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        bit_number: usize,
    ) -> Result<IntCiphertext<'a>> {
        if bit_number == 0 {
            return Ok(ct);
        }

        let randomness = RANDOMNESS_PROVIDER.get_randomness();

        let encoded_disguise = self.generate_encoded_disguise(None)?;
        let disguised_val = self
            .add(e_key, ct.clone(), encoded_disguise.clone())
            .to_static();

        let mock_comm = Arc::new(self.mock_communication.clone());
        let e_key_arc = Arc::new(e_key.clone());

        let disguised_shift = tokio::spawn(
            async move {
                mock_comm
                    .clone()
                    .shift_right(
                        disguised_val.rerandomize(&e_key_arc.clone(), randomness.await?),
                        bit_number,
                    )
                    .in_current_span()
                    .await
            }
            .in_current_span(),
        );

        let shifted_disguise = (encoded_disguise >> bit_number)?;
        let res = self.sub(e_key, disguised_shift.await??, shifted_disguise)?;

        Ok(res)
    }

    #[instrument]
    fn generate_encoded_disguise(&self, disguise_length: Option<usize>) -> Result<IntPlaintext> {
        let disguise_number = match disguise_length {
            None => Self::generate_disguise_number(self.disguise_length),
            Some(d) => Self::generate_disguise_number(d),
        };

        IntPlaintext::from_plaintext(disguise_number.into())
    }

    fn generate_disguise_number(bit_length: usize) -> UBig {
        thread_rng().gen_range(UBig::ZERO..UBig::ONE << bit_length)
    }

    #[instrument]
    pub async fn get_bits_protocol<'a: 'static>(
        &self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        bit_number: usize,
        settings: GetBitsSettings,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        match settings {
            GetBitsSettings::Simple {
                bits_per_communication,
            } => self
                .clone()
                .disguised_get_bits(e_key, ct, bit_number, bits_per_communication)
                .await
                .map(|(bits, _)| bits),
            GetBitsSettings::Advanced {
                block_size,
                bits_per_communication,
            } => {
                self.advanced_get_bits(e_key, ct, bit_number, block_size, bits_per_communication)
                    .await
            }
            GetBitsSettings::Approximation {} => {
                self.approximate_get_bits_parallel(e_key, ct).await
            }
        }
    }

    #[instrument]
    async fn approximate_get_bits<'a>(
        self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        let randomness = RANDOMNESS_PROVIDER.get_randomness();

        let bit_number = self.max_bit_accuracy as usize;
        let mut result_bits: Vec<IntCiphertext> = vec![];

        let disguise = self.generate_encoded_disguise(None)?;
        let mut disguise_bits = vec![];
        for i in 0..bit_number {
            disguise_bits.push(disguise.get_bit(i)?)
        }

        let disguised_bits = self.add(e_key, ct.clone(), disguise.clone());

        let bits = self
            .mock_communication
            .get_all_bits(
                disguised_bits.rerandomize(e_key, randomness.await?),
                bit_number,
            )
            .await?;

        if disguise == IntPlaintext::zero()? {
            return Ok(bits);
        }

        let mut carry_flag = Cryptosystem::encrypt(e_key, IntPlaintext::zero()?);
        let mut carry_calculation = false;
        for i in (1..bit_number).rev() {
            let curr_disguise_bit = &disguise_bits[i];
            let next_disguise_bit = &disguise_bits[i - 1];
            let curr_bit = &bits[i];
            let next_bit = &bits[i - 1];

            if curr_disguise_bit == 0 && next_disguise_bit == 1 {
                result_bits.push(
                    self.and_protocol(e_key, curr_bit.clone(), next_bit.clone())
                        .await?,
                );
                let xored = self.xor(e_key, next_bit.clone(), IntPlaintext::one()?);
                carry_flag = self.and_protocol(e_key, curr_bit.clone(), xored?).await?;
                carry_calculation = true
            } else if carry_calculation {
                if curr_disguise_bit == 1 && next_disguise_bit == 1 {
                    let xored = self.xor(e_key, next_bit.clone(), IntPlaintext::one()?);
                    carry_flag = self.and_protocol(e_key, carry_flag, xored?).await?;
                    let xored_flag = self.xor(e_key, carry_flag.clone(), IntPlaintext::one()?);
                    result_bits.push(
                        self.xor_protocol(e_key, xored_flag?, curr_bit.clone())
                            .await?,
                    )
                }
                if curr_disguise_bit == 1 && next_disguise_bit == 0 {
                    result_bits.push(carry_flag.clone());
                    carry_calculation = false
                }
            } else {
                result_bits.push(self.xor(e_key, curr_bit.clone(), curr_disguise_bit.clone())?);
            }
        }
        result_bits.push(self.xor(e_key, bits[0].clone(), disguise_bits[0].clone())?);
        let result_bits: Vec<_> = result_bits.into_iter().rev().collect();

        Ok(result_bits)
    }
    async fn approximate_get_bits_parallel<'a: 'static>(
        self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        let randomness = RANDOMNESS_PROVIDER.get_randomness();
        let bit_number = self.max_bit_accuracy as usize;

        let disguise = self.generate_encoded_disguise(None)?;

        let mut disguise_bits = vec![];
        for i in 0..bit_number {
            disguise_bits.push(disguise.get_bit(i)?)
        }

        let disguised_bits = self.add(e_key, ct.clone(), disguise.clone());

        let bits = self
            .mock_communication
            .get_all_bits(
                disguised_bits.rerandomize(e_key, randomness.await?),
                bit_number,
            )
            .await?;

        if disguise == IntPlaintext::zero()? {
            return Ok(bits);
        }

        let mut disconnected_parts = vec![];

        let mut start = 0;
        // split into parts where new row of 1 s starts
        for i in 0..bit_number - 1 {
            if disguise_bits[i] == 1 && disguise_bits[i + 1] == 0 {
                let disguise_bits_part = disguise_bits[start..=i + 1].to_vec();
                let bits_part = bits[start..=i + 1].to_vec();
                disconnected_parts.push((disguise_bits_part, bits_part));
                start = i + 2;
            }
        }
        if start < bit_number {
            let disguise_bits_part = disguise_bits[start..].to_vec();
            let bits_part = bits[start..].to_vec();
            disconnected_parts.push((disguise_bits_part, bits_part));
        }

        let mut set: JoinSet<Result<(usize, Vec<_>)>> = JoinSet::new();

        let self_arc = Arc::new(self.clone());
        let key_arc = Arc::new(e_key.clone());

        let current_span = tracing::Span::current();
        disconnected_parts
            .into_iter()
            .enumerate()
            .for_each(|(index, (disguise_bits, bits))| {
                let index = index;
                let key_arc = key_arc.clone();
                let self_arc = self_arc.clone();

                let disguise_bits = disguise_bits.clone();
                let bits = bits.clone();

                set.spawn(
                    async move {
                        let mut result_bits: Vec<_> = vec![];
                        let mut carry_flag =
                            Cryptosystem::encrypt(key_arc.as_ref(), IntPlaintext::zero()?);

                        let mut carry_calculation = false;

                        for i in (1..disguise_bits.len()).rev() {
                            let curr_disguise_bit = &disguise_bits[i];
                            let next_disguise_bit = &disguise_bits[i - 1];
                            let curr_bit = &bits[i];
                            let next_bit = &bits[i - 1];

                            if curr_disguise_bit == 0 && next_disguise_bit == 1 {
                                {
                                    let self_arc = self_arc.clone();
                                    let curr_bit = curr_bit.clone();
                                    let next_bit = next_bit.clone();
                                    let key_arc = key_arc.clone();
                                    result_bits.push(tokio::spawn(
                                        async move {
                                            self_arc
                                                .and_protocol(key_arc.as_ref(), curr_bit, next_bit)
                                                .await
                                        }
                                        .in_current_span(),
                                    ));
                                }
                                let xored = self_arc.xor(
                                    key_arc.as_ref(),
                                    next_bit.clone(),
                                    IntPlaintext::one()?,
                                );
                                carry_flag = self_arc
                                    .and_protocol(key_arc.as_ref(), curr_bit.clone(), xored?)
                                    .await?;
                                carry_calculation = true
                            } else if carry_calculation {
                                if curr_disguise_bit == 1 && next_disguise_bit == 1 {
                                    let old_carry = carry_flag.clone();
                                    let xored = self_arc.xor(
                                        key_arc.as_ref(),
                                        next_bit.clone(),
                                        IntPlaintext::one()?,
                                    )?;

                                    carry_flag = self_arc
                                        .and_protocol(key_arc.as_ref(), carry_flag, xored)
                                        .await?;

                                    {
                                        let self_arc = self_arc.clone();
                                        let key_arc = key_arc.clone();
                                        let next_bit = next_bit.clone();
                                        result_bits.push(tokio::spawn(
                                            async move {
                                                self_arc
                                                    .and_protocol(
                                                        key_arc.as_ref(),
                                                        old_carry,
                                                        next_bit,
                                                    )
                                                    .await
                                            }
                                            .in_current_span(),
                                        ))
                                    }
                                }
                                if curr_disguise_bit == 1 && next_disguise_bit == 0 {
                                    {
                                        let carry_flag = carry_flag.clone();
                                        result_bits.push(tokio::spawn(
                                            async { Ok(carry_flag) }.in_current_span(),
                                        ));
                                    }

                                    carry_calculation = false
                                }
                            } else {
                                let key_arc = key_arc.clone();
                                let curr_bit = curr_bit.clone();
                                let curr_disguise_bit = curr_disguise_bit.clone();
                                result_bits.push(tokio::spawn(
                                    async move {
                                        self.xor(key_arc.as_ref(), curr_bit, curr_disguise_bit)
                                    }
                                    .in_current_span(),
                                ));
                            }
                        }
                        let key_arc = key_arc.clone();
                        let bit_0 = bits[0].clone();
                        let disguise_bit_0 = disguise_bits[0].clone();
                        result_bits.push(tokio::spawn(
                            async move { self.xor(key_arc.as_ref(), bit_0, disguise_bit_0) }
                                .in_current_span(),
                        ));

                        Ok((index, result_bits.into_iter().rev().collect()))
                    }
                    .instrument({
                        let span = info_span!("parallel part");
                        span.set_parent(current_span.context());
                        span
                    }),
                );
            });

        let async_bits: Vec<_> = set
            .join_all()
            .await
            .into_iter()
            .flatten()
            .sorted_by_key(|(index, _value)| *index)
            .map(|(_index, value)| value)
            .flatten()
            .collect();
        let mut result: Vec<_> = vec![];
        for async_bit in async_bits {
            result.push(async_bit.await??)
        }

        Ok(result)
    }
    #[instrument]
    pub(crate) async fn approximate_get_bits_parallel_channeled<'a: 'static>(
        self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        channel: DebugSender<(usize, IntCiphertext<'static>)>,
    ) -> Result<JoinSet<Result<JoinSet<Result<()>>>>> {
        //generate randomness at start for parallelism
        let randomness = RANDOMNESS_PROVIDER.get_randomness();

        let bit_number = self.max_bit_accuracy as usize;

        //gen disguise + get bits
        let disguise = self.generate_encoded_disguise(None)?;
        let mut disguise_bits = vec![];
        for i in 0..bit_number {
            disguise_bits.push(disguise.get_bit(i)?)
        }

        //disguise ct
        let disguised_ct = self.add(e_key, ct.clone(), disguise.clone());

        //get bits of disguised ct via channel
        let (bits_sender, mut bits_receiver) = mpsc::channel(bit_number);
        let debug_sender = DebugSender {
            id: "get_bits_comm".to_string(),
            sender: bits_sender,
        };
        let _async_bits_handle = self
            .mock_communication
            .get_all_bits_channeled(
                disguised_ct.rerandomize(e_key, randomness.await?),
                bit_number,
                debug_sender,
            )
            .await?;

        let mut disconnected_parts = vec![];

        //split into parts where new row of 1 s starts
        let mut start = 0;
        for i in 0..bit_number - 1 {
            if disguise_bits[i] == 1 && disguise_bits[i + 1] == 0 {
                let disguise_bits_part = disguise_bits[start..=i + 1].to_vec();
                disconnected_parts.push((disguise_bits_part, (start, i + 1)));
                start = i + 2;
            }
        }
        //get rest
        if start < bit_number {
            let disguise_bits_part = disguise_bits[start..].to_vec();
            disconnected_parts.push((disguise_bits_part, (start, disguise_bits.len() - 1)));
        }

        let mut set: JoinSet<Result<JoinSet<Result<()>>>> = JoinSet::new();

        let mut bit_storage = Vec::with_capacity(bit_number);
        bit_storage.resize(bit_number, None);

        let self_arc = Arc::new(self.clone());
        let key_arc = Arc::new(e_key.clone());

        //wait for bits from channel
        while let Some((index, bit)) = bits_receiver.recv().await {
            bit_storage[index] = Some(bit);
            //for which part (based on the disguise), a new bit was received
            for (disguise_bits, (start, end)) in &disconnected_parts {
                //check if correct part
                let start = *start;
                let end = *end;
                if !(start..=end).contains(&index) {
                    continue;
                }

                // check if all bits for part are initialized
                let bits = bit_storage[start..=end].iter().cloned().collect::<Vec<_>>();

                let all_initialized = bits.iter().all(|bit| bit.is_some());
                if !all_initialized {
                    continue;
                }
                let bits = bits.into_iter().flatten().collect::<Vec<_>>();

                //init stuff for async
                let key_arc = key_arc.clone();
                let self_arc = self_arc.clone();
                let output_channel = channel.clone();

                let disguise_bits = disguise_bits.clone();
                let bits = bits.clone();

                let current_span = tracing::Span::current();
                set.spawn(
                    async move {
                        let mut result_bits: JoinSet<Result<()>> = JoinSet::new();
                        let mut carry_flag =
                            Cryptosystem::encrypt(key_arc.as_ref(), IntPlaintext::zero()?);

                        let mut carry_calculation = false;

                        // go through disguise part and calc bits
                        for i in (1..disguise_bits.len()).rev() {
                            let curr_disguise_bit = &disguise_bits[i];
                            let next_disguise_bit = &disguise_bits[i - 1];
                            let curr_bit = &bits[i];
                            let next_bit = &bits[i - 1];
                            let output_index = i + start;
                            let output_channel = output_channel.clone();

                            if curr_disguise_bit == 0 && next_disguise_bit == 1 {
                                {
                                    let self_arc = self_arc.clone();
                                    let curr_bit = curr_bit.clone();
                                    let next_bit = next_bit.clone();
                                    let key_arc = key_arc.clone();
                                    result_bits.spawn(
                                        async move {
                                            let bit_result = self_arc
                                                .and_protocol(key_arc.as_ref(), curr_bit, next_bit)
                                                .await?;
                                            output_channel.send((output_index, bit_result)).await?;
                                            Ok(())
                                        }
                                        .in_current_span(),
                                    );
                                }
                                let xored = self_arc.xor(
                                    key_arc.as_ref(),
                                    next_bit.clone(),
                                    IntPlaintext::one()?,
                                );
                                carry_flag = self_arc
                                    .and_protocol(key_arc.as_ref(), curr_bit.clone(), xored?)
                                    .await?;
                                carry_calculation = true
                            } else if carry_calculation {
                                if curr_disguise_bit == 1 && next_disguise_bit == 1 {
                                    let old_carry = carry_flag.clone();
                                    let xored = self_arc.xor(
                                        key_arc.as_ref(),
                                        next_bit.clone(),
                                        IntPlaintext::one()?,
                                    )?;

                                    carry_flag = self_arc
                                        .and_protocol(key_arc.as_ref(), carry_flag, xored)
                                        .await?;

                                    {
                                        let self_arc = self_arc.clone();
                                        let key_arc = key_arc.clone();
                                        let next_bit = next_bit.clone();
                                        result_bits.spawn(
                                            async move {
                                                let bit_result = self_arc
                                                    .and_protocol(
                                                        key_arc.as_ref(),
                                                        old_carry,
                                                        next_bit,
                                                    )
                                                    .await?;
                                                output_channel
                                                    .send((output_index, bit_result))
                                                    .await?;
                                                Ok(())
                                            }
                                            .in_current_span(),
                                        );
                                    }
                                } else if curr_disguise_bit == 1 && next_disguise_bit == 0 {
                                    {
                                        let carry_flag = carry_flag.clone();
                                        result_bits.spawn(
                                            async move {
                                                output_channel
                                                    .send((output_index, carry_flag))
                                                    .await?;
                                                Ok(())
                                            }
                                            .in_current_span(),
                                        );
                                    }

                                    carry_calculation = false
                                }
                            } else {
                                let key_arc = key_arc.clone();
                                let curr_bit = curr_bit.clone();
                                let curr_disguise_bit = curr_disguise_bit.clone();
                                result_bits.spawn(
                                    async move {
                                        let bit_result = self.xor(
                                            key_arc.as_ref(),
                                            curr_bit,
                                            curr_disguise_bit,
                                        )?;
                                        output_channel.send((output_index, bit_result)).await?;
                                        Ok(())
                                    }
                                    .in_current_span(),
                                );
                            }
                        }
                        let key_arc = key_arc.clone();
                        let bit_0 = bits[0].clone();
                        let disguise_bit_0 = disguise_bits[0].clone();
                        result_bits.spawn(
                            async move {
                                let bit_result =
                                    self.xor(key_arc.as_ref(), bit_0, disguise_bit_0)?;
                                output_channel.send((start, bit_result)).await?;
                                Ok(())
                            }
                            .in_current_span(),
                        );

                        Ok(result_bits)
                    }
                    .instrument({
                        let span = info_span!("parallel part");
                        span.set_parent(current_span.context());
                        span
                    }),
                );
            }
        }

        Ok(set)
    }

    async fn xor_protocol<'a>(
        &self,
        e_key: &EncryptionKey,
        ct1: IntCiphertext<'a>,
        ct2: IntCiphertext<'a>,
    ) -> Result<IntCiphertext<'a>> {
        let e_key_arc = Arc::new(e_key.clone());
        let self_arc = Arc::new(self.clone());
        let ct1_static = ct1.to_static();
        let ct2_static = ct2.to_static();
        let multiplied = tokio::spawn(async move {
            self_arc
                .mul_protocol(e_key_arc.as_ref(), ct1_static, ct2_static)
                .in_current_span()
                .await
        });
        let added = self.add(e_key, ct1, ct2);
        let multiplied_await = multiplied.await??;
        let doubled = self.add(e_key, multiplied_await.clone(), multiplied_await);
        let subtracted = self.sub(e_key, added, doubled)?;
        Ok(subtracted)
    }

    #[instrument]
    async fn disguised_get_bits<'a>(
        self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        bit_number: usize,
        bits_per_communication: usize,
    ) -> Result<(Vec<IntCiphertext<'a>>, IntCiphertext<'a>)> {
        assert!(bits_per_communication > 0);
        if bit_number == 0 {
            return Ok((vec![], ct));
        }

        let mut bits: Vec<IntCiphertext> = Vec::with_capacity(bit_number);

        let mut curr = ct.clone();
        while bits.len() < bit_number {
            info!("iteration");

            let iteration_span = info_span!("iteration");
            let _guard = iteration_span.enter();

            let randomness = RANDOMNESS_PROVIDER.get_randomness();
            let disguise = self.generate_encoded_disguise(None)?;

            let mut disguise_bits = vec![];
            for i in 0..bits_per_communication {
                disguise_bits.push(disguise.get_bit(i)?)
            }

            let disguise_curr = self.add(e_key, curr.clone(), disguise.clone()).to_static();

            let e_key_arc = Arc::new(e_key.clone());
            let (disguised_bits, disguised_rest) = tokio::spawn(async move {
                self.mock_communication
                    .get_x_bits(
                        disguise_curr.rerandomize(&e_key_arc.clone(), randomness.await?),
                        bits_per_communication,
                    )
                    .in_current_span()
                    .await
            })
            .await??;

            let mut get_bit = true;
            let mut rest = Cryptosystem::encrypt(e_key, IntPlaintext::zero()?);
            let mut mult = IntPlaintext::one()?;
            let mut shift_disguise = 0;
            let mut carry: IntCiphertext = rest.clone();

            for (disguised_bit, disguise_bit) in zip(disguised_bits, disguise_bits) {
                if bits.len() >= bit_number {
                    break;
                }
                if get_bit {
                    let bit = self.xor(e_key, disguised_bit, disguise_bit.clone())?;

                    bits.push(bit.clone());
                    shift_disguise += 1;

                    if disguise_bit.plaintext != IBig::ZERO || bits.len() >= bit_number {
                        get_bit = false;

                        carry = self.and(e_key, bit, disguise_bit);
                    }
                } else {
                    let shifted = self.mul(e_key, disguised_bit, mult.clone());
                    mult = (mult * 2)?;
                    rest = self.add(e_key, rest, shifted);
                }
            }

            let shifted_disguise = (disguise >> shift_disguise)?;
            let shifted_disguise = self.add(e_key, carry, shifted_disguise);

            let shifted_rest = self.mul(e_key, disguised_rest, mult);
            rest = self.add(e_key, rest, shifted_rest.clone());

            curr = self.sub(e_key, rest, shifted_disguise)?;
        }

        Ok((bits, curr))
    }

    #[instrument]
    async fn advanced_get_bits<'a: 'static>(
        &self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        bit_number: usize,
        block_length: usize,
        bits_per_communication: usize,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        if bit_number == 0 {
            return Ok(vec![]);
        }
        if bit_number % block_length != 0 {
            return Err(GeneralError::new(format!(
                "bit_number ({}) is not a multiple of block length ({})",
                bit_number, block_length
            ))
            .into());
        }

        let self_arc = Arc::new(self.clone());
        let key_arc = Arc::new(e_key.clone());

        let (bit_blocks, disguised_blocks, disguises) = self
            .disguised_cut_into_blocks(e_key, ct.clone(), block_length, bit_number / block_length)
            .await?;

        let bit_blocks: Vec<_> = bit_blocks
            .into_iter()
            .enumerate()
            .map(|(index, block)| {
                println!(
                    "bit block {} {}",
                    index,
                    Cryptosystem::decrypt(&DEBUG_KEYS.1, block.clone())
                        .unwrap()
                        .plaintext
                        .in_radix(2)
                );
                println!(
                    "bit block {} {}",
                    index,
                    Cryptosystem::decrypt(&DEBUG_KEYS.1, block.clone())
                        .unwrap()
                        .plaintext
                );
                let self_arc1 = self_arc.clone();
                let self_arc2 = self_arc.clone();
                let key_arc1 = key_arc.clone();
                let key_arc2 = key_arc.clone();
                let block1 = block.clone();

                let future_carry_0 = tokio::spawn(async move {
                    return self_arc1
                        .disguised_get_bits(
                            key_arc1.as_ref(),
                            block1,
                            block_length,
                            bits_per_communication,
                        )
                        .await
                        .map(|(bits, _)| bits);
                });

                let future_carry_1 = tokio::spawn(
                    async move {
                        if index != 0 {
                            let ct2 = self_arc2.add(
                                key_arc2.as_ref(),
                                block.clone(),
                                IntPlaintext::one()?,
                            );
                            self_arc2
                                .disguised_get_bits(
                                    key_arc2.as_ref(),
                                    ct2,
                                    block_length,
                                    bits_per_communication,
                                )
                                .await
                                .map(|(bits, _)| bits)
                        } else {
                            Ok(vec![])
                        }
                    }
                    .in_current_span(),
                );

                return (future_carry_0, future_carry_1);
            })
            .collect();

        let mut res: Vec<IntCiphertext> = vec![];
        let mut index = 0;
        let mut carry: IntCiphertext = Cryptosystem::encrypt(e_key, IntPlaintext::zero()?);

        for block in bit_blocks {
            let block_span = info_span!("bit block");
            let _guard = block_span.enter();

            let (assume_carry_0, assume_carry_1) = block;
            let assume_carry_0 = assume_carry_0.await??;
            let assume_carry_1 = assume_carry_1.await??;

            if index == 0 {
                res.append(&mut assume_carry_0.clone());
            } else {
                let inverse_carry = self.sub(e_key, IntPlaintext::one()?, carry.clone())?;
                let mut set: JoinSet<Result<(usize, IntCiphertext<'_>)>> = JoinSet::new();

                zip(assume_carry_0.iter(), assume_carry_1.iter())
                    .collect::<Vec<_>>()
                    .into_iter()
                    .enumerate()
                    .for_each(|(index, (ct1, ct2))| {
                        let self_arc = self_arc.clone();
                        let key_arc = key_arc.clone();
                        let ct1 = ct1.clone();
                        let ct2 = ct2.clone();
                        let inverse_carry = inverse_carry.clone();
                        let carry = carry.clone();
                        let block_span1 = block_span.clone();
                        let block_span2 = block_span.clone();
                        set.spawn(async move {
                            let self_arc_clone = self_arc.clone();
                            let key_arc_clone = key_arc.clone();
                            let future_mul_0 = tokio::spawn(
                                async move {
                                    self_arc_clone
                                        .mul_protocol(key_arc_clone.deref(), ct1, inverse_carry)
                                        .await
                                }
                                .instrument(block_span1.clone()),
                            );
                            let self_arc_clone = self_arc.clone();
                            let key_arc_clone = key_arc.clone();

                            let future_mul_1 = tokio::spawn(
                                async move {
                                    self_arc_clone
                                        .mul_protocol(key_arc_clone.deref(), ct2, carry)
                                        .await
                                }
                                .instrument(block_span2.clone()),
                            );

                            let futures = try_join!(future_mul_0, future_mul_1);
                            let (mul_0, mul_1) = futures?;
                            let mul_0 = mul_0?;
                            let mul_1 = mul_1?;

                            Ok((index, self_arc.add(key_arc.deref(), mul_0, mul_1)))
                        });
                    });

                let mut bits = set
                    .join_all()
                    .await
                    .into_iter()
                    .flatten()
                    .sorted_by_key(|(index, _value)| *index)
                    .map(|(_index, value)| value)
                    .collect();

                res.append(&mut bits);
            }

            let combined_bits =
                self.combine_ciphertexts(e_key, res.clone(), 1, SmallIndexIsSmallValue)?;

            let combined_disguised_ct = self.combine_ciphertexts(
                e_key,
                disguised_blocks[0..index + 1].to_vec(),
                block_length,
                SmallIndexIsSmallValue,
            )?;

            let mut combined_disguise = IBig::ZERO;
            for i in 0..index + 1 {
                combined_disguise += disguises.get(i).expect("disguises is unexpectedly short");
            }
            let combined_disguised_ct_with_carry = self.add(
                e_key,
                combined_bits,
                IntPlaintext::from_plaintext(combined_disguise)?,
            );

            let shifted_carry = self.sub(
                e_key,
                combined_disguised_ct_with_carry.clone(),
                combined_disguised_ct,
            )?;

            carry = self
                .disguised_shift_right(e_key, shifted_carry, block_length * (index + 1))
                .await?;

            index += 1;
        }

        println!(
            "{}",
            Cryptosystem::decrypt(
                &DEBUG_KEYS.1,
                self.combine_ciphertexts(e_key, res.clone(), 1, SmallIndexIsSmallValue)?
            )?
            .plaintext
            .in_radix(2)
        );
        println!(
            "{}",
            Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)?
                .plaintext
                .in_radix(2)
        );

        Ok(res)
    }

    #[instrument]
    pub async fn disguised_cut_into_blocks<'a>(
        self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        block_length: usize,
        block_num: usize,
    ) -> Result<(Vec<IntCiphertext<'a>>, Vec<IntCiphertext<'a>>, Vec<IBig>)> {
        let bit_number = block_length * block_num;
        if bit_number == 0 {
            return Ok((vec![], vec![], vec![]));
        }
        if bit_number % block_length != 0 {
            return Err(GeneralError::new(format!(
                "bit_number ({}) is not a multiple of block length ({})",
                bit_number, block_length
            ))
            .into());
        }

        let randomness = RANDOMNESS_PROVIDER.get_randomness();

        let encoded_disguise = self.generate_encoded_disguise(None)?;

        let disguised_ct = self.add(e_key, ct, encoded_disguise.clone()).to_static();

        let e_key_arc = Arc::new(e_key.clone());
        let blocks = tokio::spawn(
            async move {
                self.mock_communication
                    .split_ciphertext(
                        disguised_ct.rerandomize(&e_key_arc.clone(), randomness.await?),
                        block_length,
                        block_num,
                    )
                    .await
            }
            .in_current_span(),
        );

        let mask = IBig::from((1u64 << block_length) - 1);
        let disguise_blocks: Vec<_> = (0..block_num)
            .into_par_iter()
            .map(|i| {
                let shift_amount = i * block_length;
                (&encoded_disguise.plaintext >> shift_amount) & &mask
            })
            .collect();

        let blocks = blocks.await??;

        let ct_blocks: Vec<_> = blocks
            .clone()
            .into_par_iter()
            .zip(disguise_blocks.clone())
            .map(|(disguised_block, disguise)| {
                disguise.bit_len();
                self.sub(
                    e_key,
                    disguised_block.clone(),
                    IntPlaintext::from_plaintext(disguise.clone())?,
                )
            })
            .flatten()
            .collect();

        Ok((ct_blocks, blocks, disguise_blocks))
    }

    #[instrument]
    pub fn decrease_exponent_to<'a>(
        &self,
        e_key: &EncryptionKey,
        ciphertext: FloatCiphertext<'a>,
        exponent: isize,
    ) -> Result<FloatCiphertext<'a>> {
        assert!(ciphertext.exponent >= exponent);
        let diff = ciphertext.exponent.abs_diff(exponent);
        let e = exponent;
        let mantissa_ciphertext = ciphertext.mantissa_ciphertext;
        let m = self.mul(
            e_key,
            mantissa_ciphertext,
            IntPlaintext::from_plaintext(IBig::ONE << diff)?,
        );
        let res = FloatCiphertext {
            exponent: e,
            mantissa_ciphertext: m,
        };
        Ok(res)
    }

    #[instrument]
    pub async fn scale_ciphertext_to_range<'a>(
        &self,
        e_key: &EncryptionKey,
        ct: FloatCiphertext<'a>,
    ) -> Result<FloatCiphertext<'a>> {
        let res = if ct.exponent > 0 {
            self.decrease_exponent_to(e_key, ct, 0)
        } else if ct.exponent < -self.max_bit_accuracy {
            let new_mantissa = self
                .disguised_shift_right(
                    e_key,
                    ct.mantissa_ciphertext,
                    (-self.max_bit_accuracy).abs_diff(ct.exponent),
                )
                .await?;
            let new_exponent = -self.max_bit_accuracy;
            let res = FloatCiphertext {
                exponent: new_exponent,
                mantissa_ciphertext: new_mantissa,
            };
            Ok(res)
        } else {
            Ok(ct)
        };
        res
    }

    #[instrument]
    pub async fn scale_plaintext_to_range<'a>(
        &self,
        plaintext: FloatPlaintext,
    ) -> Result<FloatPlaintext> {
        if plaintext.exponent > 0 {
            plaintext.change_exponent_to(0)
        } else if plaintext.exponent < -self.max_bit_accuracy {
            plaintext.change_exponent_to(-self.max_bit_accuracy)
        } else {
            Ok(plaintext)
        }
    }

    #[instrument]
    pub async fn approx_sqrt_from_bits<'a>(
        &self,
        e_key: &EncryptionKey,
        bits: Vec<IntCiphertext<'a>>,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        let self_arc = Arc::new(self.clone());
        let key_arc = Arc::new(e_key.clone());

        let mut set = JoinSet::new();

        for (i, bit_pair) in bits.chunks_exact(2).enumerate() {
            let b1 = bit_pair[0].to_static();
            let b2 = bit_pair[1].to_static();
            let self_arc = self_arc.clone();
            let key_arc = key_arc.clone();
            set.spawn(
                async move {
                    let res = self_arc.or_protocol(key_arc.as_ref(), b1, b2).await;
                    (i, res)
                }
                .in_current_span(),
            );
        }

        let mut results: Vec<_> = set
            .join_all()
            .await
            .into_iter()
            .map(|(index, ct_res)| ct_res.map(|ct| (index, ct)))
            .collect::<Result<_>>()?;

        results.sort_by_key(|(i, _)| *i);

        Ok(results.into_iter().map(|(_, ct_res)| ct_res).collect())
    }

    #[instrument]
    pub async fn approx_sqrt_christian<'a>(
        self,
        e_key: &EncryptionKey,
        ct: IntCiphertext<'a>,
        modified_randomness: Option<usize>,
    ) -> Result<IntCiphertext<'a>> {
        let randomness = RANDOMNESS_PROVIDER.get_randomness();
        let disguise = match modified_randomness {
            Some(max_1_bits) => {
                let mut disguise_number =
                    Self::generate_disguise_number(self.max_bit_accuracy as usize);

                let bl = disguise_number.bit_len();
                let mut count = 0;
                for i in 0..bl {
                    if count <= max_1_bits {
                        if disguise_number.bit(i) {
                            count += 1;
                        }
                    } else {
                        disguise_number.clear_bit(i);
                        count = 0;
                    }
                }

                IntPlaintext::from_plaintext(disguise_number.into())?
            }
            None => self.generate_encoded_disguise(None)?,
        };

        let disguise_pt = disguise.plaintext.clone();
        let disguised = self.add(e_key, ct, disguise).to_static();
        let e_key_arc = Arc::new(e_key.clone());
        let bits = tokio::spawn(
            async move {
                self.mock_communication
                    .get_all_bits(
                        disguised.rerandomize(&e_key_arc.clone(), randomness.await?),
                        self.max_bit_accuracy as usize,
                    )
                    .await
            }
            .in_current_span(),
        );

        let bits = bits.await??;
        let inverse_bits = bits
            .clone()
            .into_par_iter()
            .map(|bit_ct| self.xor(e_key, bit_ct, IntPlaintext::one()?))
            .flatten()
            .collect::<Vec<IntCiphertext>>();

        let choose_bits: Vec<_> = zip(bits, inverse_bits)
            .enumerate()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(
                |(index, (bit, inv_bit))| {
                    if disguise_pt.bit(index) {
                        inv_bit
                    } else {
                        bit
                    }
                },
            )
            .collect();

        let elements: Vec<IntCiphertext> = choose_bits
            .chunks(2)
            .enumerate()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(index, chunk)| {
                let added = self.add(e_key, chunk[0].clone(), chunk[1].clone());
                let factor = IBig::ONE << index;
                let res = self.mul(e_key, added, IntPlaintext::from_plaintext(factor)?);
                Result::from(Ok(res))
            })
            .flatten()
            .collect();

        let res: Result<_> = elements
            .into_iter()
            .reduce(|x, x1| self.add(e_key, x, x1))
            .ok_or(GeneralError::new("Addition of elements failed").into());

        let res = res?;

        Ok(res)
    }

    #[instrument]
    pub async fn isolate_highest_bit<'a>(
        &self,
        e_key: &EncryptionKey,
        bits: Vec<IntCiphertext<'a>>,
    ) -> Result<Vec<IntCiphertext<'a>>> {
        let mut res = vec![bits[bits.len() - 1].clone()];

        let mut highest_bit_found = bits[bits.len() - 1].clone();

        for i in (0..bits.len() - 1).rev() {
            let curr = &bits[i];

            let not_highest_bit_found =
                self.xor(e_key, highest_bit_found.clone(), IntPlaintext::one()?)?;

            let updated_curr = self
                .and_protocol(e_key, not_highest_bit_found, curr.clone())
                .await?;

            res.insert(0, updated_curr);

            highest_bit_found = self
                .or_protocol(e_key, highest_bit_found.clone(), curr.clone())
                .await?;
        }

        Ok(res)
    }

    #[instrument]
    pub async fn approximate_inverse<'a: 'static>(
        self,
        e_key: &EncryptionKey,
        bits: Vec<IntCiphertext<'a>>,

        // the lowest bit in the input will be converted to 2^bit_exponent
        // the highest bit in the input will be converted to 2^(bit_exponent - len(bits))
        bit_exponent: usize,

        // if 1 => exponents are 64,63,62...,
        // if 2 => exponents are 64,62,60...,
        bit_factor: usize,
        //flag if vec had a bit 1 , result value
    ) -> Result<(IntCiphertext<'a>, IntCiphertext<'a>)> {
        if bits.len() == 1 {
            let one = IntPlaintext::one()?;
            let exp = (one << bit_exponent)?;
            let dependent_value = self.mul(e_key, bits[0].clone(), exp);

            return Ok((bits[0].clone(), dependent_value));
        }

        if bits.len() % 2 != 0 {
            return Err(GeneralError::new(format!(
                "The number of bits must be divisible by 2 (bit_length = {:?})",
                bits.len()
            ))
            .into());
        }
        let (bits_a, bits_b) = bits.split_at(bits.len() / 2);

        let bits_a = bits_a.to_owned();
        let bits_a_length = bits_a.len();
        let bits_b = bits_b.to_owned();
        let e_key_a = e_key.to_owned();

        let e_key_b = e_key.to_owned();

        let (result_a, result_b) = tokio::join!(
            Box::pin(self.approximate_inverse(&e_key_a, bits_a, bit_exponent, bit_factor)),
            Box::pin(self.approximate_inverse(
                &e_key_b,
                bits_b,
                bit_exponent - (bits_a_length * bit_factor),
                bit_factor,
            ))
        );

        let (flag_a, value_a) = result_a?;
        let (flag_b, value_b) = result_b?;

        let flag_b1 = flag_b.clone();
        let e_key1 = e_key.clone();
        let new_flag = tokio::spawn(
            async move { self.or_protocol(&e_key1, flag_a, flag_b1).await }.in_current_span(),
        );

        //value_b + (not flag_b) * value_a

        let not_flag_b = self.xor(&e_key, flag_b.clone(), IntPlaintext::one()?)?;

        let not_flag_b1 = not_flag_b.clone();
        let e_key2 = e_key.clone();
        let mult = tokio::spawn(
            async move { self.mul_protocol(&e_key2, not_flag_b1, value_a).await }.in_current_span(),
        );

        let new_value = self.add(e_key, value_b, mult.await??);

        let res = (new_flag.await??, new_value);

        Ok(res)
    }
}

pub fn default_enc_key() -> EncryptionKey {
    DEBUG_KEYS.0.clone()
}
pub fn default_dec_key() -> DecryptionKey {
    DEBUG_KEYS.1.clone()
}

pub static TESTING: bool = false;
pub static KEY_BIT_LENGTH: usize = if TESTING {
    1024
} else {
    3072 // 128-bit security
};

pub static DEBUG_KEYS: Lazy<(EncryptionKey, DecryptionKey)> =
    Lazy::new(|| Paillier::keypair_with_modulus_size(KEY_BIT_LENGTH).keys());

pub static MODULUS: Lazy<BigInt> = Lazy::new(|| DEBUG_KEYS.0.n.clone());

pub static RANDOMNESS_PROVIDER: Lazy<RandomnessProvider> = Lazy::new(|| RandomnessProvider::new(3));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TestSetup {
    #[serde(skip, default = "default_enc_key")]
    pub e_key: EncryptionKey,
    #[serde(skip, default = "default_dec_key")]
    pub d_key: DecryptionKey,
    pub cryptosystem: Cryptosystem,
}

impl TestSetup {
    pub fn new(round_trip_time: u64) -> Self {
        let mock_comm = MockCommunication {
            delay: Duration::from_millis(round_trip_time),
        };

        let cryptosystem = Cryptosystem {
            mock_communication: mock_comm,
            disguise_length: 128,
            max_bit_accuracy: 64,
        };

        TestSetup {
            e_key: DEBUG_KEYS.0.clone(),
            d_key: DEBUG_KEYS.1.clone(),
            cryptosystem,
        }
    }
}
