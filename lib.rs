// ### V 2.2

// ## Use

use sha3::{Sha3_256, Digest};
use blake3::hash;
use cryptix::CryptixHash;
use cryptix::Hash;
use cryptix::Uint256;

// ### Constants

const H_MEM: usize = 4 * 1024 * 1024; // Memory size 4MB
const H_MEM_U32: usize = H_MEM / 4; // Memory size in u32 elements

// ### Helper

// Dynamic S-Box based on hash
fn generate_sbox(block_hash: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = block_hash[i] ^ block_hash[(i + 1) % 32] ^ block_hash[(i + 31) % 32]; // Create S-box using XOR with neighbors
    }
    output
}

// Convert `seed` into a `u32` array
fn convert_seed_to_u32(seed: &[u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for i in 0..8 {
        let offset = i * 4;
        result[i] = u32::from_le_bytes([
            seed[offset],
            seed[offset + 1],
            seed[offset + 2],
            seed[offset + 3],
        ]);
    }
    result
}

fn xorshift32(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

fn fill_memory(seed: &[u8; 32], memory: &mut Vec<u8>) {
    assert!(memory.len() % 4 == 0, "Memory length must be a multiple of 4 bytes");

    // Derive initial state using all 32 bytes
    let mut state = 0u32;
    for i in (0..32).step_by(4) {
        let chunk = u32::from_le_bytes([
            seed[i],
            seed[i + 1],
            seed[i + 2],
            seed[i + 3],
        ]);
        state ^= chunk; // XOR each 4-byte chunk into the state
    }

    let num_elements = H_MEM_U32;

    // Fill memory with u32 values as bytes
    for i in 0..num_elements {
        let value = xorshift32(&mut state);
        let offset = i * 4;
        memory[offset]     = (value & 0xFF) as u8;
        memory[offset + 1] = ((value >> 8) & 0xFF) as u8;
        memory[offset + 2] = ((value >> 16) & 0xFF) as u8;
        memory[offset + 3] = ((value >> 24) & 0xFF) as u8;
    }
}

// Convert u32 to u8 array
fn u32_array_to_u8_array(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &value) in input.iter().enumerate() {
        let bytes = value.to_le_bytes();
        let offset = i * 4;
        output[offset..offset + 4].copy_from_slice(&bytes); // Convert each u32 to bytes and store in output
    }
    output
}

// memory index and position
fn calculate_mem_index_and_pos(result_value: u32, prev_result_value: u32) -> (u32, usize) {
    let mem_index = ((result_value >> 3) ^ (prev_result_value << 2)) % H_MEM_U32 as u32;
    let pos = mem_index as usize * 4;
    (mem_index, pos)
}

// memory chunk in place
fn process_memory_chunk_in_place(
    memory: &mut Vec<u8>,
    pos: usize,
    hash_bytes_sum: u32,
    result_value: u32,
    sbox: &[u8; 32]
) -> Result<u32, String> {
    if let Some(chunk) = memory.get(pos..pos + 4) {
        let mut v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        v = v.wrapping_add(hash_bytes_sum);
        v ^= result_value;
        v = v.rotate_left((result_value & 0x1F) as u32);

        // S-Box Transformation
        let b: [u8; 4] = v.to_le_bytes();
        v = u32::from_le_bytes([
            sbox[b[0] as usize & 0x1F], 
            sbox[b[1] as usize & 0x1F],
            sbox[b[2] as usize & 0x1F],
            sbox[b[3] as usize & 0x1F],
        ]);

        if let Some(mem_chunk) = memory.get_mut(pos..pos + 4) {
            mem_chunk.copy_from_slice(&v.to_le_bytes());
        }

        Ok(v)
    } else {
        Err("Memory slice out of bounds".to_string())
    }
}

// Memory randomization step
fn randomize_memory(memory: &mut Vec<u8>, mem_index: u32, hash_bytes_sum: u32) -> Result<(), String> {
    let alt_index = (mem_index ^ (hash_bytes_sum % H_MEM_U32 as u32)) % H_MEM_U32 as u32;
    let alt_pos = alt_index as usize * 4;

    if let Some(alt_chunk) = memory.get_mut(alt_pos..alt_pos + 4) {
        let mut alt_v = u32::from_le_bytes([alt_chunk[0], alt_chunk[1], alt_chunk[2], alt_chunk[3]]);
        alt_v ^= u32::from_le_bytes(alt_chunk); // XOR with the previously processed memory value
        alt_chunk.copy_from_slice(&alt_v.to_le_bytes());
    }

    Ok(())
}


/*
// Process memory with cases - with much love
fn process_memory_and_update_result(
    i: usize,
    result: &mut [u32; 8],
    memory: &mut Vec<u8>,
    hash_bytes_sum: u32,
    sbox: &[u8; 32]
) -> Result<(), String> {
    // Calculate the memory index and position
    let (mem_index, pos) = calculate_mem_index_and_pos(result[i], result[(i + 3) % 8]);

    // Process the memory chunk
    let processed_value = process_memory_chunk_in_place(memory, pos, hash_bytes_sum, result[i], sbox)?;

    // Branch based on result[i] % 20 to support 20 different cases (0 through 19)
    match result[i] % 20 {
        0 => {
            // Case 0: XOR with a constant, then multiply with another constant
            result[i] ^= 0xDEADBEEF;
            result[i] = result[i].wrapping_mul(0xACDCACDC);
        },
        1 => {
            // Case 1: Bitwise NOT operation followed by an AND with a mask
            result[i] = !processed_value;
            result[i] &= 0xFF00FF00;
        },
        2 => {
            // Case 2: Add hash byte sum and multiply by a constant, then rotate left
            result[i] = processed_value.wrapping_add(hash_bytes_sum);
            result[i] = result[i].wrapping_mul(0x12345678);
            result[i] = result[i].rotate_left(5);
        },
        3 => {
            // Case 3: Divide by a constant and apply modulo operation
            result[i] = processed_value / 0x9A3D2F5B;
            result[i] = result[i] % 0xABCDEF01;
        },
        4 => {
            // Case 4: Add the index, XOR with the processed value, and shift
            result[i] = processed_value.wrapping_add(i as u32);
            result[i] ^= processed_value.rotate_left(12);
            result[i] = result[i].rotate_right(8);
        },
        5 => {
            // Case 5: Apply a complex XOR between memory sum and hash bytes
            let memory_sum: u32 = memory.iter().map(|&x| x as u32).sum();
            result[i] ^= memory_sum;
            result[i] ^= (hash_bytes_sum.rotate_left(8) ^ processed_value);
        },
        6 => {
            // Case 6: Subtract a constant and apply bitwise OR with a mask
            result[i] = processed_value.wrapping_sub(0x7A3F0D1E);
            result[i] |= 0xFF00FF00;
        },
        7 => {
            // Case 7: Shift and mask operations followed by a modulo
            result[i] = processed_value.rotate_right(16);
            result[i] &= 0x0F0F0F0F;
            result[i] = result[i] % 0x1F1F1F1F;
        },
        8 => {
            // Case 8: XOR with the index and add a small constant
            result[i] ^= i as u32;
            result[i] = result[i].wrapping_add(0x9F9F9F9F);
        },
        9 => {
            // Case 9: Shift, multiply by a constant, and XOR with processed value
            result[i] = processed_value.rotate_left(8);
            result[i] = result[i].wrapping_mul(0x7E1F9C3D);
            result[i] ^= processed_value;
        },
        10 => {
            // Case 10: Apply modulo and multiply by a large constant
            result[i] = processed_value % 0xABCD1234;
            result[i] = result[i].wrapping_mul(0x13579BDF);
        },
        11 => {
            // Case 11: Apply an AND operation and shift left by 12 bits
            result[i] &= 0xFFFF00FF;
            result[i] = result[i].rotate_left(12);
        },
        12 => {
            // Case 12: Add a constant value and rotate right by 16 bits
            result[i] = processed_value.wrapping_add(0xCAFEBABE);
            result[i] = result[i].rotate_right(16);
        },
        13 => {
            // Case 13: XOR with a random constant and rotate left by i bits
            result[i] ^= 0xBADC0FFEE;
            result[i] = result[i].rotate_left(i as u32);
        },
        14 => {
            // Case 14: Shift left, then XOR with a large number
            result[i] = processed_value.rotate_left(4);
            result[i] ^= 0xF0F0F0F0;
        },
        15 => {
            // Case 15: Use a custom mask and multiply by another constant
            result[i] &= 0xFFFFFF00;
            result[i] = result[i].wrapping_mul(0x5A5A5A5A);
        },
        16 => {
            // Case 16: Apply a complex bitwise shift followed by an addition
            result[i] = processed_value.rotate_right(8);
            result[i] = result[i].wrapping_add(0x1A2B3C4D);
        },
        17 => {
            // Case 17: XOR with a constant and apply a rotate right by 5
            result[i] ^= 0x0F0F0F0F;
            result[i] = result[i].rotate_right(5);
        },
        18 => {
            // Case 18: Bitwise OR with mask, followed by an addition and shift
            result[i] |= 0xF0F0F0F0;
            result[i] = result[i].wrapping_add(0x8A7B6C5D);
            result[i] = result[i].rotate_left(10);
        },
        19 => {
            // Case 19: Combine the hash byte sum with the processed value and rotate
            result[i] = processed_value.wrapping_add(hash_bytes_sum);
            result[i] = result[i].rotate_left(i as u32);
            result[i] ^= 0x1234ABCD;
        },
        _ => {
            // Default case: No change if something unexpected happens
            result[i] = processed_value;
        }
    }

    // Perform an additional complex bitwise operation on the processed value
    let complex_op = processed_value.wrapping_mul(0xABCDEF);
    result[i] ^= complex_op.rotate_right(8);

    // Randomize memory based on the memory index and hash byte sum
    randomize_memory(memory, mem_index, hash_bytes_sum)?;

    // Update the result array with the processed value
    result[i] = processed_value;

    Ok(())
}
*/


// Process memory with cases - with much more love
fn process_memory_and_update_result(
    i: usize,
    result: &mut [u32; 8],
    memory: &mut Vec<u8>,
    hash_bytes_sum: u32,
    sbox: &[u8; 32]
) -> Result<(), String> {
    // Calculate the memory index and position
    let (mem_index, pos) = calculate_mem_index_and_pos(result[i], result[(i + 3) % 8]);

    // Process the memory chunk
    let processed_value = process_memory_chunk_in_place(memory, pos, hash_bytes_sum, result[i], sbox)?;

    // Branch based on result[i] % 20 to support 20 different cases (0 through 19)
    match result[i] % 20 {
        0 => {
            // Case 0: Intentional XOR misalignment and high-latency multiplication
            result[i] ^= 0xDEADBEEF;
            result[i] = result[i].wrapping_mul(0xACDCACDC);
        },
        1 => {
            // Case 1: Bitwise NOT followed by unpredictable AND mask
            result[i] = !processed_value;
            result[i] &= (hash_bytes_sum | 0xFF00FF00);
        },
        2 => {
            // Case 2: Chained dependencies - addition, multiplication, and rotation
            result[i] = processed_value.wrapping_add(hash_bytes_sum);
            result[i] = result[i].wrapping_mul(0x12345678);
            result[i] = result[i].rotate_left(result[i] as u32 % 31);
        },
        3 => {
            // Case 3: Memory-dependent modulo and division 
            result[i] = processed_value / (memory[mem_index % memory.len()] as u32 + 1);
            result[i] = result[i] % 0xABCDEF01;
        },
        4 => {
            // Case 4: Hash-dependent shifting and unpredictable XOR
            result[i] = processed_value.wrapping_add(i as u32);
            result[i] ^= processed_value.rotate_left(hash_bytes_sum as u32 % 17);
            result[i] = result[i].rotate_right((memory[pos % memory.len()] % 8) as u32);
        },
        5 => {
            // Case 5: Forced global memory dependencies
            let memory_sum: u32 = memory.iter().map(|&x| x as u32).sum();
            result[i] ^= memory_sum;
            result[i] ^= (hash_bytes_sum.rotate_left(8) ^ processed_value);
        },
        6 => {
            // Case 6: XOR cascade combined with volatile memory-based mask
            result[i] = processed_value.wrapping_sub(0x7A3F0D1E);
            result[i] |= memory[mem_index % memory.len()] as u32;
        },
        7 => {
            // Case 7: FPGA-hostile dynamic shifting and unpredictable masking
            result[i] = processed_value.rotate_right((result[(i + 2) % 8] % 16) as u32);
            result[i] &= (hash_bytes_sum | 0x0F0F0F0F);
        },
        8 => {
            // Case 8: Self-referential XOR and memory-seeded arithmetic
            result[i] ^= i as u32;
            result[i] = result[i].wrapping_add(memory[(mem_index / 2) % memory.len()] as u32);
        },
        9 => {
            // Case 9: Multi-stage rotation and multiplication with non-trivial XOR
            result[i] = processed_value.rotate_left((memory[mem_index % memory.len()] % 24) as u32);
            result[i] = result[i].wrapping_mul(0x7E1F9C3D);
            result[i] ^= processed_value;
        },
        10 => {
            // Case 10: Memory-driven modulo, forcing unpredictable routing
            result[i] = processed_value % (memory[pos % memory.len()] as u32 + 1);
            result[i] = result[i].wrapping_mul(0x13579BDF);
        },
        11 => {
            // Case 11: Memory sum hash blending with rotation-based scrambling
            let memory_sum: u32 = memory.iter().map(|&x| x as u32).sum();
            result[i] ^= memory_sum;
            result[i] = result[i].rotate_left((hash_bytes_sum % 14) as u32);
        },
        12 => {
            // Case 12: Constant addition followed by shifting chaos
            result[i] = processed_value.wrapping_add(0xCAFEBABE);
            result[i] = result[i].rotate_right(result[(i + 1) % 8] % 32);
        },
        13 => {
            // Case 13: Deep bitwise XOR mixing with non-trivial rotation
            result[i] ^= 0xBADC0FFEE;
            result[i] = result[i].rotate_left(i as u32 ^ (memory[mem_index % memory.len()] as u32));
        },
        14 => {
            // Case 14: Bitwise inversion and floating mask application
            result[i] = !processed_value;
            result[i] ^= memory[(mem_index * 3) % memory.len()] as u32;
        },
        15 => {
            // Case 15: XOR-based mutation and forced AND dependency
            result[i] &= 0xFFFFFF00;
            result[i] = result[i].wrapping_mul((processed_value % 0x5A5A5A5A) + 1);
        },
        16 => {
            // Case 16: Highly variable rotation depth based on processed data
            result[i] = processed_value.rotate_right((result[i] % 31) as u32);
            result[i] = result[i].wrapping_add(0x1A2B3C4D);
        },
        17 => {
            // Case 17: Recursive shifting pattern with XOR scrambling
            result[i] ^= 0x0F0F0F0F;
            result[i] = result[i].rotate_right(((processed_value & 7) + 1) as u32);
        },
        18 => {
            // Case 18: Unpredictable OR masking, addition, and rotation
            result[i] |= 0xF0F0F0F0;
            result[i] = result[i].wrapping_add(memory[(mem_index / 4) % memory.len()] as u32);
            result[i] = result[i].rotate_left(10);
        },
        19 => {
            // Case 19: Hash-based unpredictable scrambling
            result[i] = processed_value.wrapping_add(hash_bytes_sum);
            result[i] = result[i].rotate_left((i as u32 + hash_bytes_sum) % 32);
            result[i] ^= 0x1234ABCD;
        },
        _ => {
            // Default case: No change if something unexpected happens
            result[i] = processed_value;
        }
    }

    // Extra unpredictable bitwise mutation
    let complex_op = processed_value.wrapping_mul(0xABCDEF);
    result[i] ^= complex_op.rotate_right(8);

    // Memory chaos to break parallel processing
    randomize_memory(memory, mem_index, hash_bytes_sum)?;

    // Update result array
    result[i] = processed_value;

    Ok(())
}




// Main heavy_hash function
pub fn heavy_hash(block_hash: Hash) -> Result<Hash, String> {
    let mut memory = vec![0u8; H_MEM]; // Allocate memory buffer
    let mut result = [0u32; 8]; // Store intermediate hash values

    let block_hash_bytes = block_hash.as_bytes();
    if block_hash_bytes.len() != 32 {
        return Err("Invalid block hash length: Expected 32 bytes".to_string());
    }

    let hash_bytes_sum = compute_hash_bytes_sum(block_hash_bytes); // Compute the hash byte sum
    let sbox = generate_sbox_from_hash(block_hash_bytes); // Generate the S-Box

    // Fill memory with initial state based on block hash
    fill_memory(block_hash_bytes, &mut memory)?;

    // Calculate the dynamic number of rounds
    let dynamic_loops = calculate_dynamic_loops(&memory)?;

    // Initialize result with block hash bytes
    for i in 0..8 {
        let pos = i * 4;
        result[i] = u32::from_le_bytes(block_hash_bytes[pos..pos + 4].try_into().unwrap());
    }

    // Main processing loop with randomized memory access
    for _ in 0..dynamic_loops {
        for i in 0..8 {
            // Process memory and update result
            process_memory_and_update_result(i, &mut result, &mut memory, hash_bytes_sum, &sbox)?;
        }
    }

    // Compute final SHA3 hash and return the result
    Ok(CryptixHash::hash(Hash::from_bytes(u32_array_to_u8_array(result))))
}



// ### Lib.rs

    use blake3;

    // Constants for the offsets
    const SHA3_ROUND_OFFSET: usize = 8;
    const B3_ROUND_OFFSET: usize = 4;
    const ROUND_RANGE_SIZE: usize = 4;

    // SHA3-256 Hash Function
    fn sha3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
        let mut sha3_hasher = Sha3_256::new();
        sha3_hasher.update(&input);
        let hash = sha3_hasher.finalize();
        Ok(hash.into())
    }

    // Blake3 Hash Function
    fn blake3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
        let hash = blake3::hash(&input);
        Ok(hash.into()) 
    }

    // Calculate Blake3 rounds based on input
    fn calculate_b3_rounds(input: [u8; 32]) -> Result<usize, String> {
        let slice = &input[4..8];

        if slice.len() == 4 {
            let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
            Ok((value % 3 + 1) as usize) // Rounds between 1 and 3
        } else {
            Err("Input slice for Blake3 rounds is invalid".to_string())
        }
    }

    // Calculate SHA3 rounds based on input
    fn calculate_sha3_rounds(input: [u8; 32]) -> Result<usize, String> {
        let slice = &input[8..12];

        if slice.len() == 4 {
            let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
            Ok((value % 3 + 1) as usize) // Rounds between 1 and 3
        } else {
            Err("Input slice for SHA3 rounds is invalid".to_string())
        }
    }

    // Bitwise manipulations on data
    fn bit_manipulations(data: &mut [u8; 32]) {
        for i in 0..32 {
            data[i] ^= data[(i + 1) % 32]; // XOR with the next byte (circularly)
            data[i] = data[i].rotate_left(3); // Rotate left by 3 bits
            data[i] ^= i as u8; // XOR with the index value (removed unnecessary parentheses)
        }
    }

    // Mix SHA3 and Blake3 hashes by XORing their bytes.
    fn byte_mixing(sha3_hash: &[u8; 32], b3_hash: &[u8; 32]) -> [u8; 32] {
        let mut temp_buf = [0u8; 32];
        for i in 0..32 {
            temp_buf[i] = sha3_hash[i] ^ b3_hash[i]; // XOR byte by byte
        }
        temp_buf
    }

    // Proof-of-Work function
    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // cSHAKE256("ProofOfWorkHash") - Initial SHA3 hash to start the process
        let hash = self.hasher.clone().finalize_with_nonce(nonce);

        let mut hash_bytes: [u8; 32];
        match hash.as_bytes().try_into() {
            Ok(bytes) => hash_bytes = bytes,
            Err(_) => {
                println!("Hash output length mismatch");
                return Uint256::default();  
            }
        }

        // Complex manipulation based on the nonce
        for i in 0..32 {
            // XOR the byte with the nonce, adding an index-based offset
            hash_bytes[i] ^= (nonce as u8).wrapping_add(i as u8);
            
            // Apply a 4-bit left rotation to further mix the byte
            hash_bytes[i] = hash_bytes[i].rotate_left(4); // Rotate by 4 bits to the left
        }

        // Calculate the number of rounds for both Blake3 and SHA3
        let b3_rounds = State::calculate_b3_rounds(hash_bytes).unwrap_or(1);
        let sha3_rounds = State::calculate_sha3_rounds(hash_bytes).unwrap_or(1);

        let sha3_hash: [u8; 32];
        let b3_hash: [u8; 32];
        let m_hash: [u8; 32];

        // Perform Blake3 rounds with bitwise manipulations
        for _ in 0..b3_rounds {
            // Apply Blake3 hash to the current hash bytes
            hash_bytes = Self::blake3_hash(hash_bytes).unwrap_or([0; 32]);
            // Apply additional bit manipulations to the hash
            Self::bit_manipulations(&mut hash_bytes);
        }

        b3_hash = hash_bytes; // Store the result of the Blake3 hash

        // Perform SHA3 rounds with bitwise manipulations
        for _ in 0..sha3_rounds {
            // Apply SHA3 hash to the current hash bytes
            hash_bytes = Self::sha3_hash(hash_bytes).unwrap_or([0; 32]);
            // Apply additional bit manipulations to the hash
            Self::bit_manipulations(&mut hash_bytes);
        }

        sha3_hash = hash_bytes; // Store the result of the SHA3 hash

        // Mix the results from SHA3 and Blake3 to combine the outputs
        m_hash = Self::byte_mixing(&sha3_hash, &b3_hash);

        // Perform the final heavy hash transformation on the mixed result
        let final_hash = self.matrix.heavy_hash(cryptix_hashes::Hash::from(m_hash));

        // Convert the final hash to Uint256 and return the result
        Uint256::from_le_bytes(final_hash.as_bytes())

    }  

// -----------------------------

// # v2.1
// Using XOR and rotation for additional manipulations
// Complex storage filling function
// Extension of the bit_manipulations function

use sha3::{Sha3_256, Digest};
use blake3::hash;
use cryptix::CryptixHash;
use cryptix::Hash;
use cryptix::Uint256;

const H_MEM: usize = 4 * 1024 * 1024; // Memory size 4MB
const H_MEM_U32: usize = H_MEM / 4;
const H_MUL: u32 = 1664525;
const H_INC: u32 = 1013904223;

// SHA3-256 Hash Function
fn sha3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(&input);
    let hash = sha3_hasher.finalize();
    hash.as_slice().try_into().map_err(|_| "SHA-3 output length mismatch".to_string())
}


// Blake3 Hash Function
fn blake3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
    let hash = blake3::hash(&input);
    hash.as_bytes().try_into().map_err(|_| "BLAKE3 output length mismatch".to_string())
}


// Calculate Blake3 rounds based on input
fn calculate_b3_rounds(input: [u8; 32]) -> Result<usize, String> {
    let slice = &input[4..8];

    if slice.len() == 4 {
        let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
        Ok((value % 3 + 1) as usize) 
    } else {
        Err("Input slice for Blake3 rounds is invalid".to_string()) 
    }
}


// Calculate SHA3 rounds based on input
fn calculate_sha3_rounds(input: [u8; 32]) -> Result<usize, String> {
    let slice = &input[8..12];

    if slice.len() == 4 {
        let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
        Ok((value % 3 + 1) as usize) 
    } else {
        Err("Input slice for SHA3 rounds is invalid".to_string())
    }
}


// Bitwise manipulations on data
fn bit_manipulations(data: &mut [u8; 32]) {
    for i in 0..32 {
        data[i] ^= data[(i + 1) % 32];
        data[i] = data[i].rotate_left(3); 
        data[i] ^= (i as u8);
    }
}

// Mix SHA3 and Blake3 hashes by XORing their bytes.
fn byte_mixing(sha3_hash: &[u8; 32], b3_hash: &[u8; 32]) -> [u8; 32] {
    let mut temp_buf = [0u8; 32];
    for i in 0..32 {
        temp_buf[i] = sha3_hash[i] ^ b3_hash[i];
    }
    temp_buf
}

// Dynamic S-Box based on hash
fn generate_sbox(block_hash: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = block_hash[i] ^ block_hash[(i + 1) % 32] ^ block_hash[(i + 31) % 32];
    }
    output
}

/*
// Memory filling with state
fn fill_memory(seed: &[u8; 32], memory: &mut Vec<u8>) -> Result<(), &'static str> {
    if memory.len() % 4 != 0 {
        return Err("Memory length must be a multiple of 4 bytes");
    }

    let mut state: u32 = ((seed[0] as u32) << 24)
        | ((seed[1] as u32) << 16)
        | ((seed[2] as u32) << 8)
        | (seed[3] as u32);

    let num_elements = H_MEM_U32;

    if memory.len() < H_MEM {
        return Err("Memory buffer is too small");
    }

    for i in 0..num_elements {
        let offset = i * 4;
        
        state = state.wrapping_mul(H_MUL).wrapping_add(H_INC);    
    
        let start_idx = (i % 32);
        let end_idx = (start_idx + 4) % 32;
    
        let slice = if end_idx > start_idx {
            &seed[start_idx..end_idx]
        } else {
            [&seed[start_idx..], &seed[..end_idx]].concat()
        };
    
        state ^= u32::from_le_bytes(slice.try_into().unwrap_or_default());
    
        memory[offset] = (state & 0xFF) as u8;
        memory[offset + 1] = ((state >> 8) & 0xFF) as u8;
        memory[offset + 2] = ((state >> 16) & 0xFF) as u8;
        memory[offset + 3] = ((state >> 24) & 0xFF) as u8;
    }
    

    Ok(())
}
*/

// Convert `seed` into a `u32`
fn convert_seed_to_u32(seed: &[u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for i in 0..8 {
        let offset = i * 4;
        result[i] = u32::from_le_bytes([
            seed[offset],
            seed[offset + 1],
            seed[offset + 2],
            seed[offset + 3],
        ]);
    }
    result
}

// Memory filling with state
fn fill_memory(seed: &[u8; 32], memory: &mut Vec<u8>) -> Result<(), String> {
    if memory.len() % 4 != 0 {
        return Err("Memory length must be a multiple of 4 bytes".to_string());
    }

    let seed_words = convert_seed_to_u32(seed);
    let num_elements = H_MEM_U32;

    if memory.len() < H_MEM {
        return Err("Memory buffer is too small".to_string());
    }

    let mut state: u32 = seed_words[0];

    for i in 0..num_elements {
        let offset = i * 4;
        state = state.wrapping_mul(H_MUL).wrapping_add(H_INC);
        state ^= seed_words[i % 8];

        let chunk = &mut memory[offset..offset + 4];
        chunk.copy_from_slice(&state.to_le_bytes());
    }

    Ok(())
}


// Convert u32 to u8
fn u32_array_to_u8_array(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &value) in input.iter().enumerate() {
        let bytes = value.to_le_bytes();
        let offset = i * 4;
        output[offset..offset + 4].copy_from_slice(&bytes);
    }
    output
}

// Heavy Hash function
pub fn heavy_hash(block_hash: Hash) -> Result<Hash, String> {
    let mut memory = vec![0u8; H_MEM];
    let mut result = [0u32; 8];

    let block_hash_bytes = block_hash.as_bytes();

    if block_hash_bytes.len() != 32 {
        return Err("Invalid block hash length: Expected 32 bytes".to_string());
    }


    let hash_bytes_sum: u32 = block_hash_bytes.iter().map(|&x| x as u32).sum(); // max 8160
    let sbox: [u8; 32] = generate_sbox(block_hash_bytes);

    // Fill memory based on block_hash
    fill_memory(&block_hash_bytes, &mut memory)
        .map_err(|e| format!("Error filling memory: {}", e))?;

    // Calculating the number of loops
    let dynamic_loops = memory.get(0..4)
        .ok_or_else(|| "Memory slice out of bounds".to_string())?
        .try_into()
        .map(u32::from_le_bytes)
        .map(|v| (v % 128) + 128) // Adding variability in loops
        .map_err(|_| "Failed to convert memory slice to u32")?;

    // Initial values ​​for randomized indices
    for i in 0..8 {
        let pos = i * 4;
        let chunk = block_hash_bytes.get(pos..pos + 4)
            .ok_or_else(|| "Index out of bounds while initializing result".to_string())?;
        result[i] = u32::from_le_bytes([
            chunk[0],
            chunk[1],
            chunk[2],
            chunk[3],
        ]);
    }

    // Loop through dynamic rounds
    for _ in 0..dynamic_loops {
        for i in 0..8 {
            // Indirect memory addressing: Get random u32 from memory
            let mem_index = result[i] % H_MEM_U32 as u32;
            let pos = mem_index as usize * 4;

            if let Some(chunk) = memory.get(pos..pos + 4) {
                let mut v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

                v = v.wrapping_add(hash_bytes_sum);
                v ^= result[i];

                // Safely write back to memory
                if let Some(mem_chunk) = memory.get_mut(pos..pos + 4) {
                    mem_chunk.copy_from_slice(&v.to_le_bytes());
                } else {
                    return Err(format!("Memory index out of bounds at position: {}", pos));
                }

                // S-Box Transformation
                let b: [u8; 4] = v.to_le_bytes();
                v = u32::from_le_bytes([
                    sbox[b[0] as usize & 0x1F],
                    sbox[b[1] as usize & 0x1F],
                    sbox[b[2] as usize & 0x1F],
                    sbox[b[3] as usize & 0x1F],
                ]);

                result[i] = v;
            } else {
                return Err(format!("Memory index out of bounds at position: {}", pos));
            }
        }
    }

    // Final SHA3 Hash
    Ok(CryptixHash::hash(Hash::from_bytes(u32_array_to_u8_array(result))))
}

// Proof-of-Work function
#[inline]
#[must_use]
/// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    // cSHAKE256("ProofOfWorkHash") - Initial SHA3 hash to start the process
    let hash = self.hasher.clone().finalize_with_nonce(nonce);

    let mut hash_bytes: [u8; 32];
    match hash.as_bytes().try_into() {
        Ok(bytes) => hash_bytes = bytes,
        Err(_) => {
            println!("Hash output length mismatch");
            return Uint256::default();  
        }
    }

    // Complex manipulation based on the nonce
    for i in 0..32 {
        // XOR the byte with the nonce, adding an index-based offset
        hash_bytes[i] ^= (nonce as u8).wrapping_add(i as u8);
        
        // Apply a 4-bit left rotation to further mix the byte
        hash_bytes[i] = hash_bytes[i].rotate_left(4); // Rotate by 4 bits to the left
    }

    // Calculate the number of rounds for both Blake3 and SHA3
    let b3_rounds = calculate_b3_rounds(hash_bytes);
    let sha3_rounds = calculate_sha3_rounds(hash_bytes);

    let mut sha3_hash: [u8; 32];
    let mut b3_hash: [u8; 32];
    let mut m_hash: [u8; 32];

    // Perform Blake3 rounds with bitwise manipulations
    for _ in 0..b3_rounds {
        // Apply Blake3 hash to the current hash bytes
        hash_bytes = blake3_hash(hash_bytes);
        // Apply additional bit manipulations to the hash
        bit_manipulations(&mut hash_bytes);
    }

    b3_hash = hash_bytes; // Store the result of the Blake3 hash

    // Perform SHA3 rounds with bitwise manipulations
    for _ in 0..sha3_rounds {
        // Apply SHA3 hash to the current hash bytes
        hash_bytes = sha3_hash(hash_bytes);
        // Apply additional bit manipulations to the hash
        bit_manipulations(&mut hash_bytes);
    }

    sha3_hash = hash_bytes; // Store the result of the SHA3 hash

    // Mix the results from SHA3 and Blake3 to combine the outputs
    m_hash = byte_mixing(&sha3_hash, &b3_hash);

    // Perform the final heavy hash transformation on the mixed result
    let final_hash = heavy_hash(Hash::from(m_hash));

    // Convert the final hash to Uint256 and return the result
    Uint256::from_le_bytes(final_hash.as_bytes())
}