## TODO


- GPU Miner / CUDA ✅

- CPU Miner  ✅

- Rust Node ✅

- Miningcore 🔄

- Go Node 🚧

- Stratum Bridge 🚧


-----


# Cryptixhash v2 | Cryptix OX8


CryptixHash v2, named Cryptix OX8 (Octonion 8 Dimensions), is a modern hashing algorithm written in Rust, Go, C++, and C#. It enables deterministic hashing and encryption across various programming languages and devices.


The primary focus is security against attacks from specialized hardware while ensuring balanced execution across different hardware types. This means that the computation should be inefficient on ASICs and FPGAs while remaining more efficient on CPUs and GPUs. Additionally, the balance between CPU and GPU performance should be better than in other hashing algorithms.


Another key focus is achieving high unpredictability through maximum entropy and non-linear behavior. This enhances protection against side-channel attacks and low-level attacks.


The most common approach to resisting specialized hardware is high memory consumption (memory hardness), which prevents efficient execution on ASICs and FPGAs. However, we deliberately chose not to follow this path, as it unnecessarily stresses CPUs and GPUs, making calculations extremely hardware-intensive. Furthermore, maintaining a balanced execution between CPU and GPU becomes nearly impossible, and older GPUs may lack the required memory capacity.


For an efficient hashing algorithm with balanced hardware execution and high hardware compatibility, excessive memory consumption is the wrong approach. Instead of focusing on the amount of memory used, Cryptix OX8 focuses on how memory is filled, manipulated, and accessed.


Cryptix OX8 uses only 200–300 MB of memory on most GPUs (depending on the number of threads). CPUs consume even less, as most threads can fit directly into L1, L2, and L3 caches.


Advanced Anti-Specialized Hardware Techniques

Cryptix OX8 implements various complex methods designed to introduce highly dependent, non-linear computational behavior while restricting parallelization in a balanced manner. The algorithm employs specific techniques that are difficult for specialized hardware like FPGAs and ASICs to utilize efficiently, such as:

- Switching between different integer types (e.g., u8, u16, u32, i64, etc.)

- Branching and nested branching

- Byte separation and nibble usage

- Dynamic XOR and rotate values

- Irregular iterations (Illiterations)

- Calculation dependencies on previous computations

- Pseudo-random memory accesses

- Runtime-based calculations

- And more


These techniques create challenges for FPGAs, particularly in parallelization and pipelining, without requiring excessive memory usage or extreme hardware load. The non-linear execution pattern introduces timing variations, making execution lighter and preventing hardware from running at full load continuously.

This also enables hardware optimizations such as undervolting and overclocking, further improving efficiency.
Octonion-Based Hashing – A New Mathematical Approach

Cryptix OX8 introduces an innovative hashing method based on Octonion mathematics and physics. Unlike traditional hashing algorithms, which operate in 2 dimensions, Cryptix OX8 expands to 8 dimensions using Octonion Algebra.

By leveraging Octonions, Cryptix OX8 achieves high entropy and resistance to reverse computation. The calculations are non-recursive and non-commutative. This marks the first-ever attempt at integrating Octonions into hashing algorithms.

Future developments may include using Octonions to replace SHA-3 in Cryptix, though further research and testing are required to expand the Octonion function. Additionally, there is potential for extending the approach to 16 dimensions (Sedenions). However, overcoming zero-multiplication challenges in Sedenion algebra remains an open problem.
