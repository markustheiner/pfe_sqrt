use crate::benchmarks::benchmark_newton_inv_sqrt;
use crate::float::FloatPlaintext;
use crate::newton::InvSqrtApproximationSettings;
use crate::paillier_crypto::{Cryptosystem, GetBitsSettings, TestSetup};
use crate::traits::{CryptoEncrypt, Result};
use itertools::Either::Left;
use rand::{distributions::Uniform, thread_rng, Rng};

mod benchmarks;
mod big_int_extension;
mod debug;
mod encoding;
mod float;
mod integer;
mod newton;
mod paillier_crypto;
mod randomness_provider;
mod tests;
mod traits;


#[tokio::main]
async fn main() -> Result<()> {
    benchmarks().await
}



async fn benchmarks() -> Result<()> {
    let t = TestSetup::new(20);
    let e_key = &t.e_key.clone();
    let range: Vec<f64> = (0..100)
        .map(|_| thread_rng().sample(Uniform::new(0.0, 2.0f64.powf(2.0))))
        .collect();

    let n1 = range;
    let v1: Vec<_> = n1
        .iter()
        .map(|&x| Cryptosystem::encrypt(e_key, FloatPlaintext::from_plaintext(x).unwrap()))
        .collect();

    let value_options = v1;
    let iteration_options = vec![1,2,3,4,5,6,7,8,9,10];
    let test_setups = vec![TestSetup::new(20)];

    let inv_sqrt_starting_values = vec![
        Left(InvSqrtApproximationSettings::ApproxSqrtAndInv {
            get_bits: GetBitsSettings::Simple {
                bits_per_communication: 1
            },
            advanced_inverse_approximation: Some(false)
        }),
        Left(InvSqrtApproximationSettings::ApproxSqrtAndInv {
            get_bits: GetBitsSettings::Simple {
                bits_per_communication: 1
            },
            advanced_inverse_approximation: Some(true)
        }),
        Left(InvSqrtApproximationSettings::ApproxSqrtAndInv {
            get_bits: GetBitsSettings::Approximation {},
            advanced_inverse_approximation: Some(false)
        }),
        Left(InvSqrtApproximationSettings::ApproxSqrtAndInv {
            get_bits: GetBitsSettings::Approximation {},
            advanced_inverse_approximation: Some(true)
        })
    ];

    println!("\n--- Inv Sqrt Benchmark ---");

    let inv_sqrt_results = benchmark_newton_inv_sqrt(
        value_options,
        iteration_options,
        inv_sqrt_starting_values,
        test_setups,
        1,
    )
        .await?;

    for x in inv_sqrt_results.combine_by_iterations_and_starting_value() {
        println!("Starting Value, Iterations: {:?}", x.0);
        x.1.print_combined_results();
        println!();
    }
    Ok(())
}
