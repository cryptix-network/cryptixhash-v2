# CryptixHash v2 — Cryptix OX8

> Experimental multi-dimensional hashing algorithm focused on hardware resistance and balanced performance.

![License](https://img.shields.io/badge/license-MIT-green)

---

## Overview

**CryptixHash v2**, also known as **Cryptix OX8 (Octonion 8 Dimensions)**, is a modern hashing algorithm designed for deterministic hashing and encryption across multiple programming languages and hardware platforms.

The algorithm focuses on **resistance against specialized hardware (ASICs / FPGAs)** while maintaining **efficient and balanced execution on CPUs and GPUs**.

---

## Design Goals

- Minimize efficiency on ASICs and FPGAs  
- Maintain balanced CPU ↔ GPU performance  
- Ensure high entropy and unpredictability  
- Introduce strong non-linear computation patterns  
- Improve resistance to side-channel and low-level attacks  

---

## Memory Strategy

Unlike traditional **memory-hard algorithms**, Cryptix OX8 avoids excessive memory usage.

Instead of focusing on *how much* memory is used, the algorithm focuses on:

> **How memory is accessed, manipulated, and randomized**

### Typical Usage

| Hardware | Memory Usage |
|----------|------------|
| GPU      | ~200–300 MB |
| CPU      | Mostly within L1–L3 cache |

### Why not memory-hard?

- Penalizes CPUs and GPUs unnecessarily  
- Breaks CPU/GPU performance balance  
- Limits compatibility with older hardware  

---

## Anti-Specialized Hardware Techniques

Cryptix OX8 introduces complex, dependency-heavy computation patterns to limit optimization on ASICs and FPGAs.

### Core Techniques

- Integer type switching (`u8`, `u16`, `u32`, `i64`, etc.)  
- Conditional and nested branching  
- Byte-level and nibble-level manipulation  
- Dynamic XOR and rotation values  
- Irregular iteration patterns (*illiterations*)  
- Strong dependency on previous computation steps  
- Pseudo-random memory access  
- Runtime-dependent calculations  

### Result

- Reduced parallelization efficiency  
- Limited pipelining potential  
- Increased execution unpredictability  

---

## Octonion-Based Hashing

Cryptix OX8 introduces an experimental approach based on **Octonion algebra (8D)**.

### Key Properties

- Non-commutative operations  
- High entropy generation  
- Non-linear transformations  
- Resistance to reverse computation  

This represents a novel direction in hashing, combining abstract algebra and physics-inspired computation.

---

## Future Directions

- Expansion of Octonion-based cryptographic primitives  
- Evaluation as a potential alternative to SHA-3 (research phase)  
- Exploration of higher dimensions (e.g. Sedenions / 16D)  

>  Sedenion-based approaches currently face unresolved issues such as zero-divisors.


---

## Implementations

- Rust  
- Cuda (C++)
- OpenCL (C)
- Go  
- C#
- WASM

---

## License

MIT License
