// For understanding: The biggest weakness of FPGAs and ASICs is memory bandwidth and memory access time. This is especially true when low-quality boards are used, but even with high-quality boards, these limitations still exist.
// While ASICs and FPGAs are extremely efficient at performing calculations that can be parallelized (e.g., simple mathematical operations or streaming data through an algorithm), they are more limited when it comes to complex memory operations.
// When an algorithm requires reading and writing large amounts of data from memory (for example, by repeatedly accessing and updating large arrays or matrices), the hardware faces memory bandwidth bottlenecks. FPGAs, in particular, have less internal memory bandwidth compared to CPUs, making them slower for memory-intensive tasks, even though they might theoretically be faster than CPUs for simple computations.
// To significantly limit or potentially block ASICs/FPGA performance, the following steps should be considered:

// Implement unpredictable or dynamic calculations.
// Branches and conditional logic.
// Push hardware to its limits with memory-intensive or non-parallel tasks.
// Overload or flood memory channels (large-volume memory access).
// Prevent parallelization.
// High latency memory accesses
// Irregular memory access
// Data that is not well cached.
// Utilize dynamic memory access patterns.
// Unpredictable algorithms

//  In particular, cheaply produced hardware or hardware with outdated technology can quickly become overwhelmed. 


// First Idea / Example: 



// Constants for the final transformations 
const FINAL_C: [u8; 32] = [
    0x1A, 0xC3, 0xF5, 0xE7, 0xB1, 0x45, 0x62, 0x9B,
    0xD0, 0x72, 0x87, 0x5D, 0xF4, 0x33, 0x5B, 0xE1,
    0xC5, 0x9A, 0xA4, 0x7D, 0xA9, 0x12, 0xB7, 0xDA,
    0x73, 0x90, 0xFB, 0x91, 0x80, 0x62, 0xF6, 0xC1,
];

const FINAL_R: [u8; 32] = [
    0x9F, 0xB1, 0xF8, 0x2D, 0x34, 0x6A, 0x1B, 0x9E,
    0xE4, 0x51, 0x8A, 0x63, 0xD7, 0x72, 0x9B, 0x67,
    0x54, 0x38, 0x2C, 0x85, 0x77, 0xC0, 0xA7, 0x3F,
    0x63, 0x24, 0x44, 0xBB, 0x29, 0x0F, 0x9D, 0xA2,
];

const FINAL_Y: [u8; 32] = [
    0x4F, 0x67, 0xA3, 0x9B, 0x8A, 0x5C, 0xD1, 0x71,
    0x0C, 0x99, 0xF3, 0xA6, 0x80, 0x9F, 0x7D, 0x56,
    0x2F, 0x4A, 0x7A, 0x9E, 0xD6, 0xC3, 0xAF, 0x0D,
    0x81, 0x5B, 0x64, 0xB1, 0xF0, 0x28, 0xB5, 0x73,
];

const FINAL_P: [u8; 32] = [
    0x8A, 0x35, 0x1E, 0x6F, 0x57, 0x5E, 0x93, 0x29,
    0xBF, 0x61, 0x0A, 0x74, 0x5C, 0x41, 0xD5, 0x81,
    0xAD, 0x56, 0x44, 0x3D, 0x8E, 0x89, 0xFF, 0x2C,
    0x9A, 0x8C, 0x4B, 0x90, 0x63, 0x61, 0xB2, 0x78,
];

const FINAL_T: [u8; 32] = [
    0x93, 0xC0, 0x1A, 0x8C, 0xF2, 0x72, 0x7E, 0x94,
    0xAB, 0xC7, 0x7F, 0x82, 0x1D, 0xE0, 0x4B, 0x15,
    0xF1, 0x5A, 0x34, 0x96, 0xA9, 0x40, 0x70, 0xE2,
    0x3C, 0xB4, 0x65, 0x59, 0x58, 0xCB, 0xA1, 0x56,
];

const FINAL_I: [u8; 32] = [
    0xB4, 0x8F, 0x51, 0xDC, 0xD8, 0x7A, 0x8C, 0x35,
    0x9A, 0x8D, 0x13, 0x51, 0x45, 0xAA, 0x39, 0x30,
    0x6B, 0x60, 0x73, 0x9E, 0xBB, 0x62, 0x79, 0x71,
    0xA4, 0x60, 0x7B, 0xD1, 0xEC, 0x5B, 0x78, 0xD2,
];

const FINAL_X: [u8; 32] = [
    0x3F, 0xC2, 0xF2, 0xE2, 0xD1, 0x55, 0x81, 0x92,
    0xA0, 0x6B, 0xF5, 0x3F, 0x5A, 0x70, 0x32, 0xB4,
    0xE4, 0x84, 0xE4, 0xCB, 0x81, 0x73, 0xE7, 0xE0,
    0xD2, 0x7F, 0x8C, 0x55, 0xAD, 0x8C, 0x60, 0x8F,
];

// S-Boxes for substitution
fn s_box_1(value: u8) -> u8 {
    let s_box = [
        0x63, 0x7C, 0x77, 0x7B, 0xF0, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0x2A, 0xAF, 0x99, 0x68, 0x28, 0xD4, 0xA1, 0xDB, 0xFC, 0xA0, 0xD3, 0xE6, 0xF6, 0xF7, 0xFE,
    ];
    s_box[(value & 0xFF) as usize]
}

fn s_box_2(value: u8) -> u8 {
    let s_box = [
        0x37, 0x59, 0x9B, 0xA7, 0x5E, 0x2B, 0xB1, 0x8D, 0xF1, 0xC7, 0xBB, 0x4A, 0xB5, 0x0F, 0xD2, 0x63,
        0x56, 0x7A, 0x3C, 0x31, 0x79, 0x41, 0xD9, 0xC1, 0xF3, 0x8E, 0x62, 0xC9, 0xD3, 0x6E, 0x45, 0x6A,
    ];
    s_box[(value & 0xFF) as usize]
}

fn s_box_3(value: u8) -> u8 {
    let s_box = [
        0x1F, 0xA9, 0xCB, 0xE8, 0xD5, 0x91, 0x60, 0x8C, 0xFA, 0x64, 0xB7, 0x53, 0x2D, 0x74, 0x56, 0x20,
        0xF6, 0x4E, 0x81, 0x95, 0xC0, 0x76, 0x83, 0x4C, 0xBE, 0x7B, 0x6B, 0xD3, 0x38, 0x45, 0xB3, 0x92,
    ];
    s_box[(value & 0xFF) as usize]
}

fn s_box_4(value: u8) -> u8 {
    let s_box = [
        0x2B, 0x3A, 0x9E, 0x84, 0xA3, 0xF4, 0x74, 0xD5, 0x7F, 0xD2, 0x67, 0x92, 0x16, 0x55, 0xFB, 0x2F,
        0x8D, 0x39, 0x51, 0xAD, 0x8A, 0xF1, 0x69, 0x68, 0x29, 0x11, 0x64, 0x9C, 0x99, 0xC8, 0x54, 0x46,
    ];
    s_box[(value & 0xFF) as usize]
}

// Multi-layer S-Box 
fn multi_layer_s_box(value: u8) -> u8 {
    let x1 = s_box_1(value);
    let x2 = s_box_2(x1);
    let x3 = s_box_3(x2);
    let x4 = s_box_4(x3);
    s_box_3(x4)
}

// Dynamic S-Box based on the block hash
fn generate_dynamic_s_box(block_hash: &[u8]) -> [u8; 256] {
    let mut s_box = [0u8; 256];
    for i in 0..256 {
        s_box[i] = block_hash[i % block_hash.len()] ^ i as u8;
    }
    s_box
}

// The hash function with memory usage and dynamic rounds
pub fn heavy_hash(block_hash: Hash) -> Hash {
    // Convert the hash into nibbles
    let nibbles: [u8; 64] = {
        let o_bytes = block_hash.as_bytes();
        let mut arr = [0u8; 64];
        for (i, &byte) in o_bytes.iter().enumerate() {
            arr[2 * i] = byte >> 4; // Upper nibble
            arr[2 * i + 1] = byte & 0x0F; // Lower nibble
        }
        arr
    };

    // Dynamically calculate the number of rounds
    let dynamic_loops = (block_hash.as_bytes().iter().fold(0u8, |acc, &x| acc.wrapping_add(x))) % 64 + 64;

     // Dynamically calculate the number of rounds (increase to max 512 rounds)
     // let dynamic_loops = (block_hash.as_bytes().iter().fold(0u8, |acc, &x| acc.wrapping_add(x))) % 256 + 256;

    // Memory hard (using larger memory to simulate memory usage)
    let mut memory: Vec<u8> = vec![0; 32 * 1024 * 1024]; // 64MB  ### Change to multiple GB for constantly access slow external memory.


    // Initialize the memory based on hash
    for i in 0..memory.len() {
        memory[i] = (block_hash.as_bytes()[i % block_hash.len()] ^ (i as u8)) % 256;
    }

    // Main loop for dynamic rounds
    let mut product = [0u8; 32];

    for _ in 0..dynamic_loops {
        for i in 0..32 {
            let mut sum1 = 0u16;
            let mut sum2 = 0u16;

            // Interactions with memory and nibbles
            for j in 0..64 {
                let elem = nibbles[j] as u16;
                sum1 += (self.0[2 * i][j] as u16).wrapping_mul(elem);
                sum2 += (self.0[2 * i + 1][j] as u16).wrapping_mul(elem);
            }

            // Modify memory dynamically
            let mem_value = memory[(i + 5) % memory.len()];
            sum1 = sum1.wrapping_add(mem_value as u16);
            sum2 = sum2.wrapping_add(mem_value as u16);

            // Apply non-linear transformations
            let a_nibble = multi_layer_s_box((sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF));
            let b_nibble = multi_layer_s_box((sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF));

            product[i] = ((a_nibble << 4) | b_nibble) as u8;
        }

        // Modify memory
        let new_memory_value = (block_hash.as_bytes()[0] ^ block_hash.as_bytes()[1]) & 0xFF;
        memory[(block_hash.as_bytes()[0] as usize) % memory.len()] = new_memory_value;
    }

    // Final XOR operation
    product.iter_mut().zip(block_hash.as_bytes()).for_each(|(p, h)| *p ^= h);

    // Apply final transformations
    let transformations = [
        &FINAL_C, &FINAL_R, &FINAL_Y, &FINAL_P,
        &FINAL_T, &FINAL_I, &FINAL_X,
    ];

    let mut result = product;
    for final_transformation in transformations.iter() {
        for i in 0..32 {
            result[i] ^= final_transformation[i];
        }
    }

    // Return the final hash
    CryptixHash::hash(Hash::from_bytes(result))
}


// Todo:

// Add more 32-bit and 64-bit multiplications.
// Add dynamic modulo operations.
// More branches (if conditions based on hash values).
// More dynamic jumps based on hash values.
// Every operation should depend on the entire previous state.
// More irreversible mixing
// Dynamic values ​​for the transformations based on previous values
// Add Churn-Elements 



// More SIMD-friendly operations (e.g. AVX-512 for CPUs or CUDA for GPUs). To support the hardware and instead of slowing down ASICs and FPGAs, improve the hardware that is allowed.


// Randomly overwrite memory with new values
// memory[rand_index] = memory[rand_index].wrapping_mul(13).wrapping_add(7);

// Add additional multiplications, S-boxes and non-linear operations.
// Change memory accesses to non-sequential (randomized) jumps to break cache optimizations.
// If the FPGA has multiple cores, start multiple simultaneous calculations using threads or SIMD.

// A few "if" branches?

// Idea:
// Include the Hash-DLL with flow obfuscation and code obfuscation (signed?)
// Add Race Conditions / High Latence Ways for Bitstreams

// Algorithmic modification every X blocks?

// if block_height % 10000 == 0:
//   CURRENT_ALGORITHM = upgraded_algorithm()

// Fix:
// Exclude Ram out of bound
// Make memory accesses non-skippable

// Info:
// 224 MB on-chip RAM (its ddr3 ram)
// 8 GB !!! HBM2 with 420 GB/s
// Dual-Core Cortex-A9 !!!
// From 2018 !!!


// Memory fragmentation and random accesses: Frequent writing and reading in random patterns on the external HBM2 memory would overstretch the memory access bandwidth, as HBM2 offers very fast bandwidths of 420 GB/s but is not optimally used in random access patterns. This would lead to an overload of the memory access mechanisms.

// RAM consumption: Increasing the required memory to several gigabytes (based on dynamic memory requirements, as in the code with the 32 MB base and the ability to scale to several GB) can overload the on-chip memory (224 MB DDR3). This could force the processor to constantly access the slow external memory (HBM2), causing significant delays and performance bottlenecks.

// Continuous high-bandwidth memory access: If the algorithm is constantly sending large amounts of data back and forth between the 8 GB HBM2 and the processor, especially with intensive non-sequential access patterns, this can put extreme strain on the 420 GB/s bandwidth. Even though this bandwidth is high, it could be overwhelmed by the CPU during extreme access patterns and high data usage.

// Chaining several cryptographic hash functions: If you chain several cryptographic functions together (e.g. SHA3-256, then BLAKE3, then Heavy Hash) without relieving the processor, the Cortex-A9 can be heavily loaded by the constant calculations and hashing processes. In addition, a stronger nesting of cryptography algorithms could further reduce performance.

// Constantly high data rate between the cores and external memory: If each individual processor core manages large amounts of data via the external memory buses, and there is also constant interprocessor communication, the communication between the cores and the external hardware can severely affect the data transfer bandwidth and the computing power. This leads to the processor and the system as a whole being overwhelmed.


// ---------------------------------------------


// ###### v2.1 Latest

// Todo:
// More Bitmanipulations
// More Random Accesses
// Think about worst case optimizations 
// Control Flow Dependency
// Serial calculations
// Cache-Busting
// Incorporate random cache hits and misses


    // JIT 
    // Yes, we know we could use JIT, but we don't need to, you are not competent enough to develop an efficient FPGA for this hash anyway.
    // if let Some(jit_result) = try_jit_optimization() {
    //     return Uint256::from_le_bytes(jit_result.as_bytes());
    // }



#[inline]
#[must_use]
/// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    let hash = self.hasher.clone().finalize_with_nonce(nonce);
    let hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");

    // Initial SHA3-256 Hash
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(hash_bytes);
    let mut sha3_hash = sha3_hasher.finalize();
    let mut sha3_hash_bytes: [u8; 32] = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");

    // Bit manipulations based on NONCE
    for i in 0..32 {
        sha3_hash_bytes[i] ^= (nonce as u8).wrapping_add(i as u8);
    }

    // First BLAKE3 Hash
    let blake3_first = blake3_hash(sha3_hash_bytes);
    let mut blake3_first_bytes: [u8; 32] = blake3_first.as_bytes().try_into().expect("BLAKE3 output length mismatch");

    // Dynamic number of BLAKE3 rounds (2-4) based on hash values
    let num_b3_rounds = ((u32::from_le_bytes(blake3_first_bytes[4..8].try_into().expect("BLAKE3 slice error")) % 3) + 2) as usize;
    
    let mut blake3_hash = blake3_first_bytes;
    for _ in 0..num_b3_rounds {
        let blake3_result = blake3_hash(blake3_hash);
        blake3_hash = blake3_result.as_bytes().try_into().expect("BLAKE3 output length mismatch");

        // Byte swaps based on hash values
        let swap_index_1 = (blake3_hash[0] as usize) % 32;
        let swap_index_2 = (blake3_hash[4] as usize) % 32;
        let swap_index_3 = (blake3_hash[8] as usize) % 32;
        let swap_index_4 = (blake3_hash[12] as usize) % 32;
        blake3_hash.swap(swap_index_1, swap_index_2);
        blake3_hash.swap(swap_index_3, swap_index_4);
    }

    // Dynamic SHA3-256 based on BLAKE3 output
    let num_sha3_rounds = ((u32::from_le_bytes(blake3_hash[8..12].try_into().expect("BLAKE3 slice error")) % 3) + 2) as usize;
    
    let mut sha3_hash = blake3_hash;
    for _ in 0..num_sha3_rounds {
        let mut sha3_hasher = Sha3_256::new();
        sha3_hasher.update(sha3_hash);
        sha3_hash = sha3_hasher.finalize().as_slice().try_into().expect("SHA-3 output length mismatch");

        // Additional bit manipulations to disrupt optimization
        for i in (0..32).step_by(4) {
            sha3_hash[i] ^= sha3_hash[i + 1];
        }
    }

    // Random memory accesses → HBM can no longer stream efficiently
    let mut temp_buf = [0u8; 64];
    for i in 0..64 {
        let rand_index = (sha3_hash[i % 32] as usize + blake3_hash[(i + 5) % 32] as usize) % 64;
        temp_buf[rand_index] ^= sha3_hash[i % 32] ^ blake3_hash[(i + 7) % 32];
    }
    let _ = Sha3_256::digest(&temp_buf);


    // Final Heavy Hash
    let final_hash = self.matrix.heavy_hash(Hash::from(sha3_hash));

    // Convert to Uint256
    Uint256::from_le_bytes(final_hash.as_bytes())
}



// ---------------------------------------------

// ##### V 2.0 Backup



use blake3::hash as blake3_hash;
use sha3::{Digest, Sha3_256};
use cryptix_hashes::Hash;
use blake3::Hasher as Blake3Hasher;

#[inline]
#[must_use]
/// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    let hash = self.hasher.clone().finalize_with_nonce(nonce);
    let hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");

    //  SHA3-256 Fixed
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(hash_bytes);
    let sha3_hash = sha3_hasher.finalize();
    let sha3_hash_bytes: [u8; 32] = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");

    // Blake 3 Fixed
    let blake3_first = blake3_hash(sha3_hash_bytes);
    let blake3_first_bytes: [u8; 32] = blake3_first.as_bytes().try_into().expect("BLAKE3 output length mismatch");

    // Additional BLAKE3 runs based on the first BLAKE3 hash (1-3)
    let num_b3_rounds = (u32::from_le_bytes(blake3_first_bytes[0..4].try_into().expect("BLAKE3 slice error")) % 3) + 1;

    let mut blake3_hash = blake3_first_bytes;
    for _ in 0..num_b3_rounds {
        let blake3_result = blake3_hash(blake3_hash);
        blake3_hash = blake3_result.as_bytes().try_into().expect("BLAKE3 output length mismatch");
    }

    // Additional SHA3-256 rounds based on the same BLAKE3 result (1-3)
    let num_sha3_rounds = (u32::from_le_bytes(blake3_hash[0..4].try_into().expect("BLAKE3 slice error")) % 3) + 1;
    let mut sha3_hash = blake3_hash;
    for _ in 0..num_sha3_rounds {
        let mut sha3_hasher = Sha3_256::new();
        sha3_hasher.update(sha3_hash);
        sha3_hash = sha3_hasher.finalize().as_slice().try_into().expect("SHA-3 output length mismatch");
    }

    //  Pass to heavy_hash
    let final_hash = self.matrix.heavy_hash(Hash::from(sha3_hash));

    // Convert to Uint256
    Uint256::from_le_bytes(final_hash.as_bytes())
}


// Combination of algorithms
// More iterations
// Dynamic number of iterations
// More non-linear behavior / non-deterministic pipelines

// Idea:
// Maybee Integrate a illiterations with scrypt, Argon2???
// Add a MiniPOW for validate the Nonces? 


