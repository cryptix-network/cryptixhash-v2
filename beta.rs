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

// Nonlinear transformation
fn triple_s_box(value: u8) -> u8 {
    let s_box = [
        0x63, 0x7C, 0x77, 0x7B, 0xF0, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0x2A, 0xAF, 0x99, 0x68, 0x28, 0xD4, 0xA1, 0xDB, 0xFC, 0xA0, 0xD3, 0xE6, 0xF6, 0xF7, 0xFE,
    ];
    let x1 = s_box[(value & 0xFF) as usize];
    let x2 = s_box[(x1 & 0xFF) as usize]; // Double S-Box  non-linearity
    s_box[(x2 & 0xFF) as usize] // Triple S-Box cascade
}

pub fn heavy_hash(&self, block_hash: Hash) -> Hash {
    // Hash to nibbles
    let nibbles: [u8; 64] = {
        let o_bytes = block_hash.as_bytes();
        let mut arr = [0u8; 64];
        for (i, &byte) in o_bytes.iter().enumerate() {
            arr[2 * i] = byte >> 4; // upper nibble
            arr[2 * i + 1] = byte & 0x0F; // lower nibble
        }
        arr
    };

    // Initial complex calculations
    let mut product = [0u8; 32];

    // Using block hash for dynamic_loops in a deterministic way
    let dynamic_loops = (block_hash.as_bytes().iter().fold(0u8, |acc, &x| acc.wrapping_add(x))) % 64 + 64; // 64 to 127 rounds

    // Memory-Hard
    let mut memory: Vec<u8> = vec![0; 16 * 1024 * 1024];  // 16 MB test

    for _ in 0..dynamic_loops {
        for i in 0..32 {
            let mut sum1 = 0u16;
            let mut sum2 = 0u16;

            // Multidimensional access to the nibbles with dynamic memory influence
            for j in 0..64 {
                let elem = nibbles[j] as u16;

                // S-Box 
                sum1 += (self.0[2 * i][j] as u16).wrapping_mul(elem);
                sum2 += (self.0[2 * i + 1][j] as u16).wrapping_mul(elem);
            }

            // complex dynamic memory interaction
            let mem_value = memory[(i + 5) % memory.len()];
            sum1 = sum1.wrapping_add(mem_value as u16);
            sum2 = sum2.wrapping_add(mem_value as u16);

            // nonlinear transformations via S-box
            let a_nibble = triple_s_box((sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF));
            let b_nibble = triple_s_box((sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF));

            product[i] = ((a_nibble << 4) | b_nibble) as u8;
        }

        // Dynamically modify memory 
        let new_memory_value = (block_hash.as_bytes()[0] ^ block_hash.as_bytes()[1]) & 0xFF;
        memory[(block_hash.as_bytes()[0] as usize) % memory.len()] = new_memory_value;
    }

    // XOR from block_hash
    product.iter_mut().zip(block_hash.as_bytes()).for_each(|(p, h)| *p ^= h);

    // transformations
    let transformations = [
        &FINAL_C, &FINAL_R, &FINAL_Y, &FINAL_P, 
        &FINAL_T, &FINAL_I, &FINAL_X,
    ];

    // transformation
    let mut result = product;
    for final_transformation in transformations.iter() {
        for i in 0..32 {
            result[i] ^= final_transformation[i];
        }
    }

    // final hash
    CryptixHash::hash(Hash::from_bytes(result))
}



// Todo:
// - Functions to overload memory bandwidth
// - Include the Hash-DLL with flow obfuscation and code obfuscation (signed?)


---------------



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

    // Apply SHA3-256
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(hash_bytes);
    let sha3_hash = sha3_hasher.finalize();
    let sha3_hash_bytes: [u8; 32] = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");

    // First BLAKE3
    let blake3_first = blake3_hash(sha3_hash_bytes);
    let blake3_first_bytes: [u8; 32] = blake3_first.as_bytes().try_into().expect("BLAKE3 output length mismatch");

    // Second BLAKE3
    let blake3_second = blake3_hash(blake3_first_bytes);
    let blake3_second_bytes: [u8; 32] = blake3_second.as_bytes().try_into().expect("BLAKE3 output length mismatch");

    // Pass to heavy_hash
    let final_hash = self.matrix.heavy_hash(Hash::from(blake3_second_bytes));

    Uint256::from_le_bytes(final_hash.as_bytes())
}



// Todo:
// - Maybee Integrate a illiterations with scrypt, Argon2???
