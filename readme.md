# Enhancing Private Function Evaluation via Interactive Protocols

This artifact contains benchmarks designed to measure the **performance** and **accuracy** of our interactive protocols for private square root calculation.

## System Requirements

* **Tested Operating Systems:** Ubuntu 20.04 LTS and Ubuntu 24.04 LTS.
* **Rust:** The [Rust toolchain](https://rust-lang.org/tools/install/) is required for compilation.
* **Dendencies:** The code relies on the GNU Multiple Precision Arithmetic Library and standard build tools.
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential libgmp3-dev
   ```



## Build and Execution

To build the benchmarks:
```bash
cargo build -r
```

To run the benchmarks:
```bash
./target/release/PFE_square_root
```

**Execution Path Requirement:** The binary expects the `settings.json` file to be located in your **current working directory** (the location from which you run it).



## Configuration (`settings.json`)

The configuration is provided as a JSON array of objects. Each object represents a batch of benchmark tests. Below is the mapping of the configuration fields used by the protocol.
The provided `settings.json` file contains the settings, we used for our evaluation.

### Benchmark Configuration
| JSON Key | Type | Description |
| :--- | :--- | :--- |
| `random_value_count` | Integer | Number of unique inputs generated for the test. |
| `random_value_low` | Float | The minimum value for generated inputs. |
| `random_value_high` | Float | The maximum value for generated inputs. |
| `runs_per_value` | Integer | Runs per value to determine average performance. |
| `iteration_options` | Array (Int) | A list of newton iteration counts to evaluate (e.g., `[2, 4, 8]`). |
| `delay_options` | Array (Int) | Simulated network latencies in milliseconds. |
| `starting_values` | Array (Obj) | A list of starting value calculation strategies (see below). |
| `file_name` | String | Path for the resulting data file. |

### Starting Values
The protocol requires an initial approximation to begin. The `starting_values` array accepts objects with the following structures:

**1. Bitwise Strategy**
This strategy initializes based on the bit-length of the input.
* `Bitwise`:
    * `get_bits`: You must choose *one* of the following two alternatives
        * `Simple`: Uses our exact conversion from encrypted integer to encrypted bits
          *  `bits_per_communication`: `Integer` - How many bits should be sent per communication (optimized variant of the bit conversion algorithm)
        * `Approximation`: `{}` - Uses our bit-approximation algorithm.
    * `advanced_inverse_approximation`: `Boolean` - When true, uses our optimized divide-and-conquer approach.

```json
{
  "Bitwise": {
    "get_bits": {
      "Simple": {
        "bits_per_communication": 1
      }
    },
    "advanced_inverse_approximation": false
  }
}
```


**2. Linear Approximation**
This strategy uses a linear function ($y = mx + b$) to determine the starting value.
* `Linear`:
    * `slope`: `Float` - The $m$ coefficient.
    * `offset`: `Float` - The $b$ constant.

```json
{
  "Linear": {
    "slope": 0.0,
    "offset": 0.09
  }
}
```


## Results

Results are output in **JSON Lines (.jsonl)** format. Each line is an independent JSON object. If a file already exists at the specified `file_name`, the benchmark will append new results to the end of that file.

### Output Data Schema
Each result line contains the following keys mapping to the protocol's output:

* **`value`**: The plaintext input value being processed.
* **`iterations`**: The number of newton iterations performed in this run.
* **`starting_value`**: A description of the approximation parameters used for this run.
* **`test_setup`**: A collection of metadata describing the used test setup.
* **`average_duration`**: The mean runtime for this setup (see `runs_per_value`).
* **`percentage_deviation`**: The error between the private result and the actual square root.

Because the output is appended line-by-line, you can safely analyze partial results even if the benchmark process is interrupted or stopped before completion.
