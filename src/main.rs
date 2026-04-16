use crate::benchmarks::benchmark_newton_inv_sqrt;
use crate::float::FloatPlaintext;
use crate::newton::InvSqrtApproximationSettings;
use crate::paillier_crypto::{Cryptosystem, GetBitsSettings, TestSetup, DEBUG_KEYS};
use crate::traits::{CryptoEncrypt, Result};
use itertools::Either::Left;
use rand::{distributions::Uniform, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::from_reader;
use std::fs::File;
use std::io::BufReader;
use either::Either;

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

    let file = File::open("settings.json")?;
    let reader = BufReader::new(file);
    let settings: Vec<BenchmarkSettings> = from_reader(reader)?;


    for setting in settings {
        benchmarks(setting).await?
    }
    Ok(())
}

fn map_simple_starting_value(s: &SimpleStartingValueOptions) -> Either<InvSqrtApproximationSettings,f64> {

    let get_bits = match s.get_bits {
        SimpleBitOptions::Simple { bits_per_communication } => {
            GetBitsSettings::Simple {
                bits_per_communication
            }
        }
        SimpleBitOptions::Approximation {} => {
            GetBitsSettings::Approximation {}
        }
    };

    Left(InvSqrtApproximationSettings::ApproxSqrtAndInv {
        get_bits,
        advanced_inverse_approximation: Some(s.advanced_inverse_approximation)
    })


}

async fn benchmarks(settings: BenchmarkSettings) -> Result<()> {

    let e_key = &DEBUG_KEYS.0.clone();
    let range: Vec<f64> = (0..settings.random_value_count)
        .map(|_| thread_rng().sample(Uniform::new(0.0, 2.0f64.powf(2.0))))
        .collect();

    let n1 = range;
    let v1: Vec<_> = n1
        .iter()
        .map(|&x| Cryptosystem::encrypt(e_key, FloatPlaintext::from_plaintext(x).unwrap()))
        .collect();

    let value_options = v1;
    let iteration_options = settings.iteration_options;
    let mut test_setups = vec![];
    for delay_option in settings.delay_options {
        test_setups.push(TestSetup::new(delay_option))
    }
    let inv_sqrt_starting_values: Vec<_> = settings.starting_values.iter().map(map_simple_starting_value).collect();

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


#[derive(Serialize,Deserialize, Debug)]
enum SimpleBitOptions {
    Simple {
        bits_per_communication: usize,
    },
    Approximation {},
}
#[derive(Serialize,Deserialize, Debug)]
struct SimpleStartingValueOptions{
    get_bits: SimpleBitOptions,
    advanced_inverse_approximation: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct BenchmarkSettings{
    random_value_count: usize,
    runs_per_value: usize,
    iteration_options: Vec<usize>,
    delay_options: Vec<u64>,
    starting_values: Vec<SimpleStartingValueOptions>
}