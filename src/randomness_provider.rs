use crate::paillier_crypto::DEBUG_KEYS;
use crate::traits::Result;
use paillier_common::{EncryptionKey, Paillier, PrecomputeRandomness, PrecomputedRandomness};
use rust_bigint::traits::Samplable;
use rust_bigint::BigInt;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct RandomnessProvider {
    size: usize,
    values: Arc<Mutex<VecDeque<PrecomputedRandomness>>>,
}

impl RandomnessProvider {
    pub(crate) fn new(size: usize) -> Self {
        let values = VecDeque::with_capacity(size);
        let values_arc = Arc::new(Mutex::new(values));

        for _ in 0..size {
            Self::start_random_gen(&values_arc);
        }

        RandomnessProvider {
            values: values_arc,
            size,
        }
    }

    fn start_random_gen(values_arc: &Arc<Mutex<VecDeque<PrecomputedRandomness>>>) {
        let values_arc_clone = values_arc.clone();
        tokio::spawn({
            async move {
                let randomness = Self::precompute_randomness(&DEBUG_KEYS.0);
                let mut values = values_arc_clone.lock().await;
                values.push_back(randomness.await.expect("Failed to compute randomness"));
            }
        });
    }

    pub async fn get_randomness(&self) -> Result<PrecomputedRandomness> {
        let mut values = self.values.lock().await;
        while values.is_empty() {
            drop(values);
            tokio::time::sleep(Duration::from_micros(500)).await;
            values = self.values.lock().await;
        }

        let result = values.pop_back().expect("No randomness available");

        if values.len() < self.size {
            let to_compute = self.size - values.len();

            for _ in 0..to_compute {
                Self::start_random_gen(&self.values);
            }
        }

        Ok(result)
    }
    fn precompute_randomness(e_key: &EncryptionKey) -> JoinHandle<PrecomputedRandomness> {
        let e_key_arc = Arc::new(e_key.clone());
        tokio::spawn(async move {
            let r = BigInt::sample_below(&e_key_arc.n);
            Paillier::precompute(e_key_arc.as_ref(), &r)
        })
    }
}
