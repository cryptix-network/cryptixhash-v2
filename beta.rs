

// ### Matrix.rs 
// ###### v2.0


// Todo:

// Add more 32-bit and 64-bit multiplications.
// Add dynamic modulo operations.
// More branches (if conditions based on hash values).
// More dynamic jumps based on hash values.
// Every operation should depend on the entire previous state.
// More irreversible mixing
// Change memory accesses to non-sequential (randomized) jumps to break cache optimizations.
// Dynamic values ​​for the transformations based on previous values
// Add Churn-Elements 
// A few "if" branches?

// Randomly overwrite memory with new values
// memory[rand_index] = memory[rand_index].wrapping_mul(13).wrapping_add(7);

// Add additional multiplications, S-boxes and non-linear operations.

// Improvements in error handling and code quality

// Fix:
// Exclude Ram out of bound
// Make memory accesses non-skippable

// Idea:
// Include the Hash-DLL with flow obfuscation and code obfuscation (signed?) ### v3 Hash

// if block_height % 10000 == 0:
//   CURRENT_ALGORITHM = upgraded_algorithm()  ### v3 Hash


//  dynamic S-Box with mixing
// fn dynamic_s_box_with_mixing(block_hash: &[u8]) -> [u8; 256] {
//   let mut s_box = [0u8; 256];
//    let mut mix_value = 0u8;
//    for i in 0..256 {
        // Mix
//       mix_value = (block_hash[i % block_hash.len()] ^ i as u8) + mix_value;
//       s_box[i] = mix_value.rotate_left(3); // Rotation ?
//   }
//    s_box
//  }




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
    s_box[(value & 0x1F) as usize]
}

fn s_box_2(value: u8) -> u8 {
    let s_box = [
        0x37, 0x59, 0x9B, 0xA7, 0x5E, 0x2B, 0xB1, 0x8D, 0xF1, 0xC7, 0xBB, 0x4A, 0xB5, 0x0F, 0xD2, 0x63,
        0x56, 0x7A, 0x3C, 0x31, 0x79, 0x41, 0xD9, 0xC1, 0xF3, 0x8E, 0x62, 0xC9, 0xD3, 0x6E, 0x45, 0x6A,
    ];
    s_box[(value & 0x1F) as usize]
}

fn s_box_3(value: u8) -> u8 {
    let s_box = [
        0x1F, 0xA9, 0xCB, 0xE8, 0xD5, 0x91, 0x60, 0x8C, 0xFA, 0x64, 0xB7, 0x53, 0x2D, 0x74, 0x56, 0x20,
        0xF6, 0x4E, 0x81, 0x95, 0xC0, 0x76, 0x83, 0x4C, 0xBE, 0x7B, 0x6B, 0xD3, 0x38, 0x45, 0xB3, 0x92,
    ];
    s_box[(value & 0x1F) as usize]
}

fn s_box_4(value: u8) -> u8 {
    let s_box = [
        0x2B, 0x3A, 0x9E, 0x84, 0xA3, 0xF4, 0x74, 0xD5, 0x7F, 0xD2, 0x67, 0x92, 0x16, 0x55, 0xFB, 0x2F,
        0x8D, 0x39, 0x51, 0xAD, 0x8A, 0xF1, 0x69, 0x68, 0x29, 0x11, 0x64, 0x9C, 0x99, 0xC8, 0x54, 0x46,
    ];
    s_box[(value & 0x1F) as usize]
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

    // Memory hard (using larger memory to simulate memory usage)
    let mut memory = vec![0u8; 32 * 1024 * 1024]; // 32MB Test

    println!("Memory size: {} bytes", memory.len());

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
                sum1 += (memory[2 * i] as u16).wrapping_mul(elem); // Access to memory[2 * i]
                sum2 += (memory[2 * i + 1] as u16).wrapping_mul(elem); // Access to memory[2 * i + 1]
            }

            // Modify memory dynamically
            let mem_value = memory[(i + 5) % memory.len()];
            sum1 = sum1.wrapping_add(mem_value as u16);
            sum2 = sum2.wrapping_add(mem_value as u16);

            // Apply non-linear transformations
            let a_nibble = multi_layer_s_box((sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF));
            let b_nibble = multi_layer_s_box((sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF));

            product[i] = (product[i] + ((a_nibble << 4) | b_nibble)) as u8;
        }

        // Modify memory in a dynamic way
        let new_memory_value = (block_hash.as_bytes()[0] ^ block_hash.as_bytes()[1]) & 0xFF;
        memory[(block_hash.as_bytes()[0] as usize) % memory.len()] = new_memory_value; // based on hash
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


// ---------------------------------------------

// ### Lib.rs 
// ###### v2.2

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
pub fn calculate_pow(&self, nonce: u64) -> Result<Uint256, String> {
    let hash = self.hasher.clone().finalize_with_nonce(nonce);
    let hash_bytes: [u8; 32] = match hash.as_bytes().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return Err("Hash output length mismatch".into()),
    };

    // Initial SHA3-256 Hash
    let sha3_hash = match self.sha3_hash(&hash_bytes) {
        Ok(hash) => hash,
        Err(_) => return Err("SHA3-256 hashing failed".into()),
    };

    // Bit manipulations based on NONCE
    let mut sha3_hash_bytes = sha3_hash;
    for i in 0..32 {
        sha3_hash_bytes[i] ^= (nonce as u8).wrapping_add(i as u8);
    }

    // First BLAKE3 Hash
    let blake3_first = match self.blake3_hash(sha3_hash_bytes) {
        Ok(hash) => hash,
        Err(_) => return Err("BLAKE3 hashing failed".into()),
    };
    let mut blake3_first_bytes = blake3_first;

    // Dynamic number of BLAKE3 rounds (2-4) based on hash values
    let num_b3_rounds = self.calculate_b3_rounds(&blake3_first_bytes);
    let mut blake3_hash = blake3_first_bytes;
    for _ in 0..num_b3_rounds {
        let blake3_result = match self.blake3_hash(blake3_hash) {
            Ok(result) => result,
            Err(_) => return Err("BLAKE3 round hashing failed".into()),
        };
        blake3_hash = blake3_result;

        // Byte swaps based on hash values
        self.byte_swap(&mut blake3_hash)?;
    }

    // Dynamic SHA3-256 based on BLAKE3 output
    let num_sha3_rounds = self.calculate_sha3_rounds(&blake3_hash);
    let mut sha3_hash = blake3_hash;
    for _ in 0..num_sha3_rounds {
        let sha3_result = match self.sha3_hash(&sha3_hash) {
            Ok(result) => result,
            Err(_) => return Err("SHA3-256 round hashing failed".into()),
        };
        sha3_hash = sha3_result;

        // Additional bit manipulations
        self.bit_manipulations(&mut sha3_hash);
    }

    // Random memory accesses
    let temp_buf = self.random_memory_accesses(&sha3_hash, &blake3_hash)?;
    use_temp_buf(temp_buf);

    // Final Heavy Hash
    let final_hash = self.matrix.heavy_hash(Hash::from(sha3_hash));

    // Convert to Uint256
    Ok(Uint256::from_le_bytes(final_hash.as_bytes()))
}


// ### Related functions

// Hash functions
fn sha3_hash(&self, input: &[u8; 32]) -> Result<[u8; 32], String> {
    // Computes SHA-3-256
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(input);
    let hash = sha3_hasher.finalize();
    hash.as_slice().try_into().map_err(|_| "SHA-3 output length mismatch".into())
}

fn blake3_hash(&self, input: [u8; 32]) -> Result<[u8; 32], String> {
    // Computes BLAKE3
    let hash = blake3::hash(&input);
    let hash_bytes = hash.as_bytes().try_into().map_err(|_| "BLAKE3 output length mismatch".into())?;
    Ok(hash_bytes)
}

// Rounds calculation based on input bytes
fn calculate_b3_rounds(&self, input: &[u8; 32]) -> usize {
    // Determines number of rounds for BLAKE3
    ((u32::from_le_bytes(input[4..8].try_into().unwrap_or_default()) % 3) + 2) as usize
}

fn calculate_sha3_rounds(&self, input: &[u8; 32]) -> usize {
    // Determines number of rounds for SHA3
    ((u32::from_le_bytes(input[8..12].try_into().unwrap_or_default()) % 3) + 2) as usize
}

// Swaps bytes at calculated indices
fn byte_swap(&self, data: &mut [u8; 32]) -> Result<(), String> {
    // Swaps bytes
    let swap_index_1 = (data[0] as usize) % 32;
    let swap_index_2 = (data[4] as usize) % 32;
    let swap_index_3 = (data[8] as usize) % 32;
    let swap_index_4 = (data[12] as usize) % 32;
    data.swap(swap_index_1, swap_index_2);
    data.swap(swap_index_3, swap_index_4);
    Ok(())
}

// Bitwise manipulation
fn bit_manipulations(&self, sha3_hash: &mut [u8; 32]) {
    // Performs XOR bit manipulation on SHA3 hash bytes
    for i in (0..32).step_by(4) {
        sha3_hash[i] ^= sha3_hash[i + 1];
    }
}

// Memory access based on SHA3 and BLAKE3
fn random_memory_accesses(&self, sha3_hash: &[u8; 32], blake3_hash: &[u8; 32]) -> Result<[u8; 64], String> {
    // Random memory accesses and XOR operations
    let mut temp_buf = [0u8; 64];
    for i in 0..64 {
        let rand_index = (sha3_hash[i % 32] as usize + blake3_hash[(i + 5) % 32] as usize) % 64;
        temp_buf[rand_index] ^= sha3_hash[i % 32] ^ blake3_hash[(i + 7) % 32];
    }
    Ok(temp_buf)
}



// ---------------------------------------------


// ###### v2.1


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

// ##### v2.0



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
