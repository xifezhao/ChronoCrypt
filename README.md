# ChronoCrypt: A Stateful Ultra-Lightweight Cryptosystem - Simulation Prototype

This repository contains the Python simulation prototype for **ChronoCrypt**, a novel stateful, ultra-lightweight cryptosystem designed for resilient Industrial Cyber-Physical Systems (ICPS).

This code serves as the reference implementation for the experiments and performance evaluations presented in the paper *"ChronoCrypt: A Stateful Ultra-Lightweight Cryptosystem for Resilient Industrial Cyber-Physical Systems"*.

## Table of Contents
- [About ChronoCrypt](#about-chronocrypt)
- [Repository Structure](#repository-structure)
- [Features of the Prototype](#features-of-the-prototype)
- [Dependencies](#dependencies)
- [How to Run](#how-to-run)
- [Evaluation Results](#evaluation-results)
- [Citing This Work](#citing-this-work)

## About ChronoCrypt

ChronoCrypt is a stateful cryptosystem that provides endogenous security by intrinsically binding cryptographic operations to the physical reality of an asset. Its core innovation is a **temporal-stateful key generation mechanism** that derives ephemeral cryptographic keys from a combination of a master secret, a high-precision timestamp, and real-time physical state variables (e.g., temperature, pressure, RPM).

This design transforms the security primitive itself from a mere data protector into an active detector of cyber-physical anomalies, making it resilient against sophisticated attacks like false data injection and replay attacks.

This prototype implements ChronoCrypt as a full AEAD (Authenticated Encryption with Associated Data) scheme and benchmarks its performance against the NIST standard lightweight cipher, **Ascon-128**.

## Repository Structure

```
.
├── chronocrypt_simulation.py  # Main Python script with all logic and evaluations
├── ascon.py                   # Dependency: Python implementation of Ascon cipher
├── requirements.txt           # List of Python dependencies
├── README.md                  # This README file
└── (Generated Plots)/         # Directory where output plots will be saved
    ├── 1_latency_comparison.pdf
    ├── 2_overhead_composition.pdf
    ├── 3_memory_footprint.pdf
    ├── 4_sensitivity_analysis.pdf
    └── 5_throughput_analysis_with_intervals.pdf
```

## Features of the Prototype

This Python script (`chronocrypt_simulation.py`) includes:

1.  **Core ChronoCrypt Engine**:
    *   An adaptive Substitution-Permutation Network (SPN) block cipher.
    *   A stateful key derivation function using SHA-256 for domain separation to generate encryption keys, MAC keys, and the adaptive `theta` parameter.
    *   A full AEAD scheme using an Encrypt-then-MAC construction with HMAC-SHA256.

2.  **Comprehensive Evaluation Suite**:
    *   **Performance Benchmark**: Measures and compares the end-to-end latency of ChronoCrypt and Ascon-128 for encryption and decryption.
    *   **Overhead Analysis**: Isolates and quantifies the latency overhead introduced by ChronoCrypt's stateful-binding mechanism.
    *   **Memory Footprint Estimation**: Calculates the approximate RAM usage for key materials.
    *   **Cryptographic Security Validation**: Conducts a sensitivity analysis to measure the avalanche effect of the key derivation function.
    *   **Scalability Analysis**: Evaluates and compares the encryption throughput of ChronoCrypt and Ascon-128 across various payload sizes.

3.  **Visualization**:
    *   Automatically generates and saves all evaluation results as high-quality PDF plots for easy analysis.

## Dependencies

The script requires the following Python libraries:

-   `matplotlib`
-   `numpy`

An implementation of the Ascon cipher is also required. A suitable version is included in this repository (`ascon.py`).

You can install the necessary packages using pip:
```bash
pip install -r requirements.txt
```

*(Note: The `requirements.txt` file should contain `matplotlib` and `numpy`.)*

## How to Run

To run the full evaluation and generate all result plots, simply execute the main Python script from your terminal:

```bash
python chronocrypt_simulation.py
```

The script will print its progress for each evaluation phase to the console and will automatically display and save the five generated plots as PDF files in the same directory.

## Evaluation Results

Running the script will reproduce the key figures presented in the paper. Here are the expected outputs:

### 1. Latency Comparison
Compares the average encryption and decryption latency of ChronoCrypt against Ascon-128. ChronoCrypt demonstrates significantly lower latency and higher consistency (smaller error bars).
<p align="center">
  <img src="https://i.imgur.com/example-latency.png" alt="Latency Comparison Plot" width="600"/>
  <!-- Replace with actual path to generated plot: 1_latency_comparison.pdf -->
</p>

### 2. Stateful Overhead Composition
Decomposes ChronoCrypt's encryption latency into the core AEAD operation and the marginal overhead from the stateful-binding mechanism (~2.92%).
<p align="center">
  <img src="https://i.imgur.com/example-overhead.png" alt="Overhead Composition Plot" width="600"/>
  <!-- Replace with actual path to generated plot: 2_overhead_composition.pdf -->
</p>

### 3. RAM Memory Footprint
Estimates the dynamic RAM required per transaction, showing ChronoCrypt's suitability for resource-constrained devices.
<p align="center">
  <img src="https://i.imgur.com/example-memory.png" alt="Memory Footprint Plot" width="600"/>
  <!-- Replace with actual path to generated plot: 3_memory_footprint.pdf -->
</p>

### 4. Key Sensitivity (Avalanche Effect)
Validates the cryptographic robustness of the key derivation function, showing a near-perfect avalanche effect (~50% bit difference ratio) for minor changes in state or time.
<p align="center">
  <img src="https://i.imgur.com/example-sensitivity.png" alt="Sensitivity Analysis Plot" width="600"/>
  <!-- Replace with actual path to generated plot: 4_sensitivity_analysis.pdf -->
</p>

### 5. Throughput vs. Payload Size
Demonstrates ChronoCrypt's superior performance and scalability across a wide range of payload sizes, including confidence intervals (±1 std).
<p align="center">
  <img src="https://i.imgur.com/example-throughput.png" alt="Throughput Analysis Plot" width="600"/>
  <!-- Replace with actual path to generated plot: 5_throughput_analysis_with_intervals.pdf -->
</p>

*(Note: The placeholder images above should be replaced with the actual plots generated by the script for a complete README.)*

## Citing This Work

If you use this work in your research, please cite the original paper:

```bibtex
@article{zhao2025chronocrypt,
  title={ChronoCrypt: A Stateful Ultra-Lightweight Cryptosystem for Resilient Industrial Cyber-Physical Systems},
  author={Zhao, Xiaofei and Wang, Hua and Guo, Fanglin and Ding, Jieqiong and Su, Yunqi and Wang, Ying},
  journal={Security and Safety},
  year={2025},
  publisher={EDP Sciences}
  % Note: Add volume, pages, and DOI once published
}
