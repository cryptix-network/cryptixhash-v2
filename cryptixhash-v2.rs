

// ### Matrix.rs 
// ###### v2.1


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
fn s_box_1(value: u8) -> Result<u8, &'static str> {
    let s_box = [
        0x63, 0x7C, 0x77, 0x7B, 0xF0, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0x2A, 0xAF, 0x99, 0x68, 0x28, 0xD4, 0xA1, 0xDB, 0xFC, 0xA0, 0xD3, 0xE6, 0xF6, 0xF7, 0xFE,
    ];

    // Check if the value is within the valid range
    if value > 0x1F {
        return Err("Value for s_box_1 is out of valid range");
    }

    Ok(s_box[(value & 0x1F) as usize])
}

fn s_box_2(value: u8) -> Result<u8, &'static str> {
    let s_box = [
        0x37, 0x59, 0x9B, 0xA7, 0x5E, 0x2B, 0xB1, 0x8D, 0xF1, 0xC7, 0xBB, 0x4A, 0xB5, 0x0F, 0xD2, 0x63,
        0x56, 0x7A, 0x3C, 0x31, 0x79, 0x41, 0xD9, 0xC1, 0xF3, 0x8E, 0x62, 0xC9, 0xD3, 0x6E, 0x45, 0x6A,
    ];

    
    if value > 0x1F {
        return Err("Value for s_box_2 is out of valid range");
    }

    Ok(s_box[(value & 0x1F) as usize])
}

fn s_box_3(value: u8) -> Result<u8, &'static str> {
    let s_box = [
        0x1F, 0xA9, 0xCB, 0xE8, 0xD5, 0x91, 0x60, 0x8C, 0xFA, 0x64, 0xB7, 0x53, 0x2D, 0x74, 0x56, 0x20,
        0xF6, 0x4E, 0x81, 0x95, 0xC0, 0x76, 0x83, 0x4C, 0xBE, 0x7B, 0x6B, 0xD3, 0x38, 0x45, 0xB3, 0x92,
    ];

    
    if value > 0x1F {
        return Err("Value for s_box_3 is out of valid range");
    }

    Ok(s_box[(value & 0x1F) as usize])
}

fn s_box_4(value: u8) -> Result<u8, &'static str> {
    let s_box = [
        0x2B, 0x3A, 0x9E, 0x84, 0xA3, 0xF4, 0x74, 0xD5, 0x7F, 0xD2, 0x67, 0x92, 0x16, 0x55, 0xFB, 0x2F,
        0x8D, 0x39, 0x51, 0xAD, 0x8A, 0xF1, 0x69, 0x68, 0x29, 0x11, 0x64, 0x9C, 0x99, 0xC8, 0x54, 0x46,
    ];

    
    if value > 0x1F {
        return Err("Value for s_box_4 is out of valid range");
    }

    Ok(s_box[(value & 0x1F) as usize])
}

// Multi-layer S-Box 
fn multi_layer_s_box(value: u8) -> Result<u8, &'static str> {
    let x1 = s_box_1(value)?;
    let x2 = s_box_2(x1)?;
    let x3 = s_box_3(x2)?;
    let x4 = s_box_4(x3)?;
    s_box_3(x4)
}

// Dynamic S-Box based on the block hash
fn generate_dynamic_s_box(block_hash: &[u8]) -> Result<[u8; 256], &'static str> {
    if block_hash.is_empty() {
        return Err("Block hash cannot be empty");
    }

    let mut s_box = [0u8; 256];
    for i in 0..256 {
        s_box[i] = block_hash[i % block_hash.len()] ^ i as u8;
    }

    Ok(s_box)
}

pub fn heavy_hash(block_hash: Hash) -> Result<Hash, String> {
    // Check if the input hash is empty
    let block_hash_bytes = block_hash.as_bytes();
    if block_hash_bytes.is_empty() {
        return Err("Input hash cannot be empty".to_string());
    }

    // Convert the hash into nibbles
    let nibbles: [u8; 64] = {
        let o_bytes = block_hash_bytes;
        if o_bytes.len() != 32 {
            return Err("Block hash must be exactly 32 bytes long".to_string());
        }

        let mut arr = [0u8; 64];
        for (i, &byte) in o_bytes.iter().enumerate() {
            arr[2 * i] = byte >> 4; // Upper nibble
            arr[2 * i + 1] = byte & 0x0F; // Lower nibble
        }
        arr
    };

    // Dynamically calculate the number of rounds
    let dynamic_loops = (block_hash_bytes.iter().fold(0u8, |acc, &x| acc.wrapping_add(x))) % 64 + 64;

    // Memory hard (using larger memory to simulate memory usage)
    let mut memory = vec![0u8; 16 * 1024 * 1024]; // 16 MB for better L3 Cache

    println!("Memory size: {} bytes", memory.len());

    // Initialize the memory based on hash
    for i in 0..memory.len() {
        memory[i] = (block_hash_bytes[i % block_hash_bytes.len()] ^ (i as u8)) % 256;
    }

    // Main loop for dynamic rounds
    let mut product = [0u8; 32];

    for round in 0..dynamic_loops {
        for i in 0..32 {
            let mut sum1 = 0u16;
            let mut sum2 = 0u16;

            // Interactions with memory and nibbles
            if nibbles.len() < 64 {
                return Err("Nibbles array must contain at least 64 elements".to_string());
            }
            
            for j in 0..64 {
                let elem = nibbles[j] as u16;

                // Ensure indices are valid
                if 2 * i + 1 >= memory.len() {
                    return Err(format!("Memory index out of bounds (2 * i + 1) during round {}", round).to_string());
                }

                sum1 = sum1.wrapping_add((memory[2 * i] as u16).wrapping_mul(elem)); // Access to memory[2 * i]
                sum2 = sum2.wrapping_add((memory[2 * i + 1] as u16).wrapping_mul(elem)); // Access to memory[2 * i + 1]
            }

            // Modify memory dynamically
            let mem_value = memory[i % memory.len()];
            sum1 = sum1.wrapping_add(mem_value as u16);
            sum2 = sum2.wrapping_add(mem_value as u16);

            // Apply non-linear transformations
            let a_nibble = match multi_layer_s_box((sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF)) {
                Ok(val) => val,
                Err(e) => return Err(format!("Error in multi-layer S-Box (a_nibble) during round {}: {}", round, e)),
            };
            let b_nibble = match multi_layer_s_box((sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF)) {
                Ok(val) => val,
                Err(e) => return Err(format!("Error in multi-layer S-Box (b_nibble) during round {}: {}", round, e)),
            };

            product[i] = (product[i] + ((a_nibble << 4) | b_nibble)) as u8;
        }

        // Modify memory in a dynamic way
        if memory.is_empty() {
            return Err("Memory is empty, cannot update memory values".to_string());
        }

        // block_hash_bytes has enough elements
        if block_hash_bytes.len() < 2 {
            return Err("block_hash_bytes should contain at least two bytes".to_string());
        }

        let new_memory_value = (block_hash_bytes[0] ^ block_hash_bytes[1]) & 0xFF;

        // index is within bounds
        let index = (block_hash_bytes[0] as usize) % memory.len();
        if index >= memory.len() {
            return Err(format!("Memory index out of bounds while modifying memory during round {}", round).to_string());
        }

        memory[index] = new_memory_value;
    }

    // Final XOR operation
    product.iter_mut().zip(block_hash_bytes.iter()).for_each(|(p, h)| *p ^= *h);

    // Apply final transformations
    let transformations = [
        &FINAL_C, &FINAL_R, &FINAL_Y, &FINAL_P,
        &FINAL_T, &FINAL_I, &FINAL_X,
    ];

    let mut result = product;
    for final_transformation in transformations.iter() {
        if final_transformation.len() != 32 {
            return Err(format!("Final transformation array length is not 32, found {}", final_transformation.len()).to_string());
        }
        for i in 0..32 {
            result[i] ^= final_transformation[i];
        }
    }

    // Return the final hash
    match CryptixHash::hash(Hash::from_bytes(result)) {
        Ok(hash) => Ok(hash),
        Err(_) => Err("Error occurred during final hash generation".to_string()),
    }
}



// ------------- TESTS


#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to generate a Hash
    fn generate_sample_hash() -> Hash {
        let sample_bytes: [u8; 32] = [
            0xAB, 0xC1, 0xD2, 0xE3, 0xF4, 0xA5, 0xB6, 0xC7, 
            0xD8, 0xE9, 0xF0, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 
            0xF6, 0xA7, 0xB8, 0xC9, 0xD0, 0xE1, 0xF2, 0xA3, 
            0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0xA9, 0xB0, 0xC1
        ];
        Hash::from_bytes(sample_bytes.to_vec())
    }

    // Test the heavy_hash function
    #[test]
    fn test_heavy_hash_valid_input() {
        let block_hash = generate_sample_hash();
        

        match heavy_hash(block_hash) {
            Ok(result) => {
                assert!(result.as_bytes().len() == 32);
                println!("Generated hash: {:?}", result.as_bytes());
            },
            Err(e) => panic!("Test failed: {}", e),
        }
    }

    #[test]
    fn test_heavy_hash_empty_input() {
        let block_hash = Hash::from_bytes(Vec::new());

        match heavy_hash(block_hash) {
            Ok(_) => panic!("Test failed: expected error for empty input"),
            Err(e) => assert_eq!(e, "Input hash cannot be empty"),
        }
    }

    #[test]
    fn test_heavy_hash_invalid_length() {
        let block_hash = Hash::from_bytes(vec![0xAB, 0xC1]); // Invalid length
        
        match heavy_hash(block_hash) {
            Ok(_) => panic!("Test failed: expected error for invalid length input"),
            Err(e) => assert_eq!(e, "Block hash must be exactly 32 bytes long"),
        }
    }

    #[test]
    fn test_heavy_hash_edge_case() {
        let block_hash = Hash::from_bytes(vec![0x00; 32]); // Edge case, all zeros
        

        match heavy_hash(block_hash) {
            Ok(result) => {
                // The result should be 32 bytes long
                assert!(result.as_bytes().len() == 32);
                println!("Generated hash for edge case: {:?}", result.as_bytes());
            },
            Err(e) => panic!("Test failed: {}", e),
        }
    }
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
        use_temp_buf(temp_buf); // think about where to use 
    
        // Final Heavy Hash
        let final_hash = self.matrix.heavy_hash(Hash::from(sha3_hash));
    
        // Convert to Uint256
        Ok(Uint256::from_le_bytes(final_hash.as_bytes()))
    }
    
    
    // ### Helper functions
    
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
        if input.len() < 8 {
            return 2; // Fallback if the length is not enough
        }
        let rounds = u32::from_le_bytes(input[4..8].try_into().map_err(|_| "Invalid slice for rounds")?);
        ((rounds % 3) + 2) as usize
    }
    
    fn calculate_sha3_rounds(&self, input: &[u8; 32]) -> usize {
        // Determines number of rounds for SHA3
        if input.len() < 12 {
            return 2; 
        }
        let rounds = u32::from_le_bytes(input[8..12].try_into().map_err(|_| "Invalid slice for rounds")?);
        ((rounds % 3) + 2) as usize
    }
    
    // Swaps bytes at calculated indices
    fn byte_swap(&self, data: &mut [u8; 32]) -> Result<(), String> {
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
        for i in (0..32).step_by(4) {
            if i + 1 < 32 { // Avoid accessing out-of-bounds
                sha3_hash[i] ^= sha3_hash[i + 1];
            }
        }
    }
    
    // Memory access based on SHA3 and BLAKE3
    fn random_memory_accesses(&self, sha3_hash: &[u8; 32], blake3_hash: &[u8; 32]) -> Result<[u8; 64], String> {
        let mut temp_buf = [0u8; 64];
        for i in 0..64 {
            let rand_index = (sha3_hash[i % 32] as usize + blake3_hash[(i + 5) % 32] as usize) % 64;
            if rand_index < 64 {
                temp_buf[rand_index] ^= sha3_hash[i % 32] ^ blake3_hash[(i + 7) % 32];
            } else {
                return Err("Calculated random index out of bounds".into());
            }
        }
        Ok(temp_buf)
    }
    
// ---- Test


#[cfg(test)]
mod tests {
    use super::*; /
    use std::collections::HashMap;


    struct MockHasher {

        mock_hash: HashMap<u64, [u8; 32]>,
    }

    impl MockHasher {
        fn new() -> Self {
            let mut mock_hash = HashMap::new();
            mock_hash.insert(1, [0u8; 32]); // nonce 1 gives a zeroed hash
            mock_hash.insert(2, [1u8; 32]); // nonce 2 gives a hash of all ones
            Self { mock_hash }
        }
    }

    impl Hasher for MockHasher {
        fn finalize_with_nonce(&self, nonce: u64) -> [u8; 32] {
            *self.mock_hash.get(&nonce).unwrap_or(&[0u8; 32]) // Return mock hash based on nonce
        }
    }

    #[test]
    fn test_calculate_pow_success() {
        let hasher = MockHasher::new();
        let pow_calculator = PowCalculator { hasher };

        let nonce: u64 = 1; // Test with nonce 1
        let result = pow_calculator.calculate_pow(nonce);

        // Assert: Verify the result
        assert!(result.is_ok(), "Expected success, got: {:?}", result);
        let hash = result.unwrap();
        assert_eq!(hash.as_bytes(), &[0u8; 32], "Expected hash bytes to be zeroed");
    }

    #[test]
    fn test_calculate_pow_with_different_nonce() {
        let hasher = MockHasher::new();
        let pow_calculator = PowCalculator { hasher };

        let nonce: u64 = 2; // Test with nonce 2
        let result = pow_calculator.calculate_pow(nonce);

        // Assert: Verify the result
        assert!(result.is_ok(), "Expected success, got: {:?}", result);
        let hash = result.unwrap();
        assert_eq!(hash.as_bytes(), &[1u8; 32], "Expected hash bytes to be all ones");
    }

    #[test]
    fn test_calculate_pow_error_invalid_nonce() {
        let hasher = MockHasher::new();
        let pow_calculator = PowCalculator { hasher };

        let nonce: u64 = 999; // This nonce is not defined in the mock
        let result = pow_calculator.calculate_pow(nonce);

        // Assert: Verify that we get an error
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        assert_eq!(result.unwrap_err(), "Hash output length mismatch", "Unexpected error message");
    }
    
    // Test for SHA3 and BLAKE3 failure cases
    #[test]
    fn test_sha3_hash_error() {

        let mock_hasher = MockHasher::new();
        let pow_calculator = PowCalculator { hasher: mock_hasher };

        let invalid_hash_bytes: [u8; 32] = [0xFF; 32]; // Just an example

        let result = pow_calculator.sha3_hash(&invalid_hash_bytes);
        assert!(result.is_err(), "Expected error in SHA3 hashing, got: {:?}", result);
    }

    #[test]
    fn test_blake3_hash_error() {

        let mock_hasher = MockHasher::new();
        let pow_calculator = PowCalculator { hasher: mock_hasher };

        let invalid_input: [u8; 32] = [0xAB; 32]; // Just an example

        let result = pow_calculator.blake3_hash(invalid_input);
        assert!(result.is_err(), "Expected error in BLAKE3 hashing, got: {:?}", result);
    }
}

