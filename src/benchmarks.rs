use std::io::Write;
use crate::float::{FloatCiphertext, FloatPlaintext};
use crate::newton::{
    newton_inv_sqrt, newton_sqrt, InvSqrtApproximationSettings, SqrtApproximationSettings,
};
use crate::paillier_crypto::{Cryptosystem, TestSetup, DEBUG_KEYS};
use indicatif::{ProgressBar, ProgressStyle};
use itertools::Either;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::OpenOptions;
use crate::traits::CryptoDecrypt;
use crate::traits::Result;
use itertools::Either::{Left, Right};
use std::time::Instant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct BenchmarkResult {
    pub value: FloatPlaintext,
    pub iterations: usize,
    pub starting_value:
        Either<Either<SqrtApproximationSettings, f64>, Either<InvSqrtApproximationSettings, f64>>,
    pub test_setup: TestSetup,
    pub average_duration: f64,
    pub percentage_deviation: f64,
}

#[derive(Debug, Clone)]
pub struct BenchmarkResultSet {
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkResultSet {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    pub fn combine_by_iterations(&self) -> Vec<(usize, BenchmarkResultSet)> {
        let mut iteration_groups: HashMap<_, _> = HashMap::new();
        for benchmark in &self.results {
            iteration_groups
                .entry(benchmark.iterations)
                .or_insert_with(|| BenchmarkResultSet::new())
                .add_result(benchmark.clone());
        }

        let mut result: Vec<_> = iteration_groups.into_iter().collect();
        result.sort_by_key(|(iterations, _)| *iterations);

        result
    }

    pub fn combine_by_starting_value(
        &self,
    ) -> Vec<(String, BenchmarkResultSet)> {
        let mut starting_value_groups: HashMap<_, _> = HashMap::new();
        for benchmark in &self.results {
            let starting_value = match &benchmark.starting_value {
                Left(value) => {
                    match value {
                        Left(approx_settings) => {
                            format!("{:?}", approx_settings)
                        }
                        Right(float) => {
                            format!("{:?}", float)
                        }
                    }
                }
                Right(value) => {
                    match value {
                        Left(approx_settings) => {
                            format!("{:?}", approx_settings)
                        }
                        Right(float) => {
                            format!("{:?}", float)
                        }
                    }
                }
            };

            starting_value_groups
                .entry(starting_value)
                .or_insert_with(|| BenchmarkResultSet::new())
                .add_result(benchmark.clone());
        }

        let result: Vec<_> = starting_value_groups.into_iter().collect();
        result
    }
    pub fn combine_by_iterations_and_starting_value(
        &self,
    ) -> Vec<((String,usize), BenchmarkResultSet)> {
        let mut groups: HashMap<_, _> = HashMap::new();
        for benchmark in &self.results {
            let starting_value = match &benchmark.starting_value {
                Left(value) => match value {
                    Left(approx_settings) => format!("{:?}", approx_settings),
                    Right(float) => format!("{:?}", float),
                },
                Right(value) => match value {
                    Left(approx_settings) => format!("{:?}", approx_settings),
                    Right(float) => format!("{:?}", float),
                },
            };

            groups
                .entry((starting_value,benchmark.iterations))
                .or_insert_with(|| BenchmarkResultSet::new())
                .add_result(benchmark.clone());
        }

        let mut result: Vec<_> = groups.into_iter().collect();
        result.sort_by_key(|((starting_value,iterations), _)| {
            (starting_value.clone(),*iterations)
        });

        result
    }

    pub fn min_duration(&self) -> f64 {
        self.results
            .iter()
            .map(|res| res.average_duration)
            .reduce(|acc, n| acc.min(n))
            .unwrap_or(-1.0)
    }
    pub fn avg_duration(&self) -> f64 {
        if self.results.is_empty() {
            return -1.0;
        }

        let sum: f64 = self.results.iter().map(|r| r.average_duration).sum();
        sum / self.results.len() as f64
    }

    pub fn max_duration(&self) -> f64 {
        self.results
            .iter()
            .map(|res| res.average_duration)
            .reduce(|acc, n| acc.max(n))
            .unwrap_or(-1.0)
    }

    pub fn min_percentage_deviation(&self) -> f64 {
        self.results
            .iter()
            .map(|res| res.percentage_deviation)
            .reduce(|acc, n| acc.min(n))
            .unwrap_or(-1.0)
    }
    pub fn avg_percentage_deviation(&self) -> f64 {
        if self.results.is_empty() {
            return -1.0;
        }

        let sum: f64 = self.results.iter().map(|r| r.percentage_deviation).sum();
        sum / self.results.len() as f64
    }
    pub fn max_percentage_deviation(&self) -> f64 {
        self.results
            .iter()
            .map(|res| res.percentage_deviation)
            .reduce(|acc, n| acc.max(n))
            .unwrap_or(-1.0)
    }

    pub fn print_combined_results(&self) {
        println!(
            "Combined - Results: {}, Duration (Min,Avg,Max): ({:.3}s, {:.3}s, {:.3}s), Percentage Deviation (Min,Avg,Max): ({:.15}%, {:.15}%, {:.15}%)",
            self.results.len(),
            self.min_duration(),
            self.avg_duration(),
            self.max_duration(),
            self.min_percentage_deviation(),
            self.avg_percentage_deviation(),
            self.max_percentage_deviation()
        );
    }

    pub fn dump_results(&self) {
        for result in self.results.clone(){
            println!("{:?}",result)
        }

    }
}
pub async fn benchmark_newton_sqrt<'a: 'static>(
    value_options: Vec<FloatCiphertext<'a>>,
    iteration_options: Vec<usize>,
    starting_values: Vec<Either<SqrtApproximationSettings, f64>>,
    test_setups: Vec<TestSetup>,
    runs_per_benchmark: usize,
) -> Result<BenchmarkResultSet> {
    let mut result_set = BenchmarkResultSet::new();

    let total_iterations = value_options.len()
        * iteration_options.len()
        * starting_values.len()
        * test_setups.len()
        * runs_per_benchmark;

    let progress_bar = ProgressBar::new(total_iterations as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] ({eta_precise}) {pos}/{len} {msg}")?
            .progress_chars("#>-"),
    );
    progress_bar.set_message("Running Newton sqrt benchmarks");

    let mut file = OpenOptions::new().append(true).create(true).open("newton_sqrt.json")?;

    for value in &value_options {
        for iterations in &iteration_options {
            for starting_value in &starting_values {
                for test_setup in &test_setups {
                    let mut total_duration = 0.0;
                    let mut max_duration: f64 = 0.0;
                    let mut percentage_deviation = 0.0;
                    for _ in 0..runs_per_benchmark {
                        let start_time = Instant::now();
                        let result = newton_sqrt(
                            *iterations,
                            value.clone(),
                            starting_value.clone(),
                            test_setup.clone(),
                        )
                            .await?;
                        let duration = start_time.elapsed().as_secs_f64();
                        total_duration += duration;
                        max_duration = max_duration.max(duration);

                        let decrypted_value =
                            Cryptosystem::decrypt(&DEBUG_KEYS.1, value.clone())?.to_plaintext();
                        let reference_sqrt = decrypted_value.sqrt().abs();
                        let result_value = result.to_f64().value().abs();
                        let deviation =
                            ((result_value - reference_sqrt).abs() / reference_sqrt) * 100.0;

                        percentage_deviation += deviation;

                        progress_bar.inc(1);
                    }
                    let average_duration = total_duration / runs_per_benchmark as f64;
                    percentage_deviation /= runs_per_benchmark as f64;

                    let benchmark_result = BenchmarkResult {
                        value: Cryptosystem::decrypt(&DEBUG_KEYS.1,value.clone())?,
                        iterations: *iterations,

                        starting_value: Left(starting_value.clone()),
                        test_setup: test_setup.clone(),
                        percentage_deviation,
                        average_duration,
                    };

                    let serialized = serde_json::to_string(&benchmark_result)?;
                    writeln!(file, "{}", serialized)?;

                    result_set.add_result(benchmark_result);
                }
            }
        }
    }

    progress_bar.finish_with_message("Newton sqrt benchmarks completed");

    Ok(result_set)
}

pub async fn benchmark_newton_inv_sqrt<'a: 'static>(
    value_options: Vec<FloatCiphertext<'a>>,
    iteration_options: Vec<usize>,
    starting_values: Vec<Either<InvSqrtApproximationSettings, f64>>,
    test_setups: Vec<TestSetup>,
    runs_per_benchmark: usize,
) -> Result<BenchmarkResultSet> {
    let mut result_set = BenchmarkResultSet::new();

    let total_iterations = value_options.len()
        * iteration_options.len()
        * starting_values.len()
        * test_setups.len()
        * runs_per_benchmark;

    let progress_bar = ProgressBar::new(total_iterations as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] ({eta_precise}) {pos}/{len} {msg}")?
            .progress_chars("#>-"),
    );
    progress_bar.set_message("Running Newton inverse sqrt benchmarks");


    let mut file = OpenOptions::new().append(true).create(true).open("newton_inverse_sqrt.json")?;

    for value in &value_options {
        for iterations in &iteration_options {
            for starting_value in &starting_values {
                for test_setup in &test_setups {
                    let mut total_duration = 0.0;
                    let mut max_duration: f64 = 0.0;
                    let mut percentage_deviation = 0.0;
                    for _ in 0..runs_per_benchmark {
                        let start_time = Instant::now();
                        let result = newton_inv_sqrt(
                            *iterations,
                            value.clone(),
                            starting_value.clone(),
                            test_setup.clone(),
                        )
                            .await?;
                        let duration = start_time.elapsed().as_secs_f64();
                        total_duration += duration;
                        max_duration = max_duration.max(duration);

                        let decrypted_value =
                            Cryptosystem::decrypt(&DEBUG_KEYS.1, value.clone())?.to_plaintext();
                        let reference_sqrt = decrypted_value.sqrt().abs();
                        let result_value = result.to_f64().value().abs();
                        let deviation =
                            ((result_value - reference_sqrt).abs() / reference_sqrt) * 100.0;
                        percentage_deviation += deviation;

                        progress_bar.inc(1);
                    }
                    let average_duration = total_duration / runs_per_benchmark as f64;
                    percentage_deviation /= runs_per_benchmark as f64;

                    let benchmark_result = BenchmarkResult {
                        value: Cryptosystem::decrypt(&DEBUG_KEYS.1,value.clone())?,
                        iterations: *iterations,
                        starting_value: Right(starting_value.clone()),
                        test_setup: test_setup.clone(),
                        percentage_deviation,
                        average_duration,
                    };

                    let serialized = serde_json::to_string(&benchmark_result)?;
                    writeln!(file, "{}", serialized)?;

                    result_set.add_result(benchmark_result);
                }
            }
        }
    }

    progress_bar.finish_with_message("Newton inverse sqrt benchmarks completed");

    Ok(result_set)
}
