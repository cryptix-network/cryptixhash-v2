// ### V 2.2

use sha3::{Sha3_256, Digest};
use blake3::hash;
use cryptix::CryptixHash;
use cryptix::Hash;
use cryptix::Uint256;

const H_MEM: usize = 4 * 1024 * 1024; // Memory size 4MB
const H_MEM_U32: usize = H_MEM / 4; // Memory size in u32 elements

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
        data[i] ^= (i as u8); // XOR with the index value
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

// Dynamic S-Box based on hash
fn generate_sbox(block_hash: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = block_hash[i] ^ block_hash[(i + 1) % 32] ^ block_hash[(i + 31) % 32]; // Create S-box using XOR with neighbors
    }
    output
}

fn derive_dynamic_values(block_hash: [u8; 32]) -> (u32, u32) {
    // Split the block hash into two parts (e.g., 16 bytes for H_MUL and 16 bytes for H_INC)
    let part1 = &block_hash[0..16];
    let part2 = &block_hash[16..32];

    // Convert the parts into u32 values
    let h_mul = u32::from_le_bytes(part1.try_into().expect("Failed to convert part1"));
    let h_inc = u32::from_le_bytes(part2.try_into().expect("Failed to convert part2"));

    // H_MUL and H_INC
    (h_mul, h_inc)
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

// Memory filling with state
fn fill_memory(seed: &[u8; 32], memory: &mut Vec<u8>, block_hash: [u8; 32]) -> Result<(), String> {
    let (h_mul, h_inc) = derive_dynamic_values(block_hash);

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
        state = state.wrapping_mul(h_mul).wrapping_add(h_inc); 
        state ^= seed_words[i % 8];

        let chunk = &mut memory[offset..offset + 4];
        chunk.copy_from_slice(&state.to_le_bytes());
    }

    Ok(())
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

// Heavy Hash function
pub fn heavy_hash(block_hash: Hash) -> Result<Hash, String> {
    let mut memory = vec![0u8; H_MEM]; // Allocate memory buffer
    let mut result = [0u32; 8]; // Store intermediate hash values

    let block_hash_bytes = block_hash.as_bytes();
    if block_hash_bytes.len() != 32 {
        return Err("Invalid block hash length: Expected 32 bytes".to_string());
    }

    let hash_bytes_sum: u32 = block_hash_bytes.iter().map(|&x| x as u32).sum();
    let sbox: [u8; 32] = generate_sbox(block_hash_bytes); // Generate S-Box

    // Fill memory with initial state based on the block hash
    fill_memory(&block_hash_bytes, &mut memory)?;

    // Generate a more dynamic number of rounds using multiple memory slices
    let dynamic_loops = {
        let slice1 = memory.get(4..8).ok_or("Memory slice out of bounds")?;
        let slice2 = memory.get(12..16).ok_or("Memory slice out of bounds")?;
        let value1 = u32::from_le_bytes(slice1.try_into().map_err(|_| "Failed to convert slice1")?);
        let value2 = u32::from_le_bytes(slice2.try_into().map_err(|_| "Failed to convert slice2")?);
        let combined = value1.wrapping_mul(17) ^ value2.wrapping_add(31);
        (combined % 96 + 160) as usize // Rounds between 160 and 256
    };

    // Initialize result with block hash bytes
    for i in 0..8 {
        let pos = i * 4;
        result[i] = u32::from_le_bytes(block_hash_bytes[pos..pos + 4].try_into().unwrap());
    }

    // Main processing loop with randomized memory access
    for _ in 0..dynamic_loops {
        for i in 0..8 {
            let mem_index = ((result[i] >> 3) ^ (result[(i + 3) % 8] << 2)) % H_MEM_U32 as u32;
            let pos = mem_index as usize * 4;

            if let Some(chunk) = memory.get(pos..pos + 4) {
                let mut v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                v = v.wrapping_add(hash_bytes_sum);
                v ^= result[i];
                v = v.rotate_left((result[(i + 5) % 8] & 0x1F) as u32);

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

                // memory randomization step
                let alt_index = (mem_index ^ (hash_bytes_sum % H_MEM_U32 as u32)) % H_MEM_U32 as u32;
                let alt_pos = alt_index as usize * 4;
                if let Some(alt_chunk) = memory.get_mut(alt_pos..alt_pos + 4) {
                    let mut alt_v = u32::from_le_bytes([alt_chunk[0], alt_chunk[1], alt_chunk[2], alt_chunk[3]]);
                    alt_v ^= v; // XOR with the previously processed memory value
                    alt_chunk.copy_from_slice(&alt_v.to_le_bytes());
                }

                result[i] = v;
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



// --------------------------------------------
// ## v2.0

use sha3::{Sha3_256, Digest};
use blake3::hash;
use cryptix::CryptixHash;
use cryptix::Hash;
use cryptix::Uint256;

const H_MEM: usize = 4 * 1024 * 1024; // Memory size 4MB
const H_MEM_U32: usize = H_MEM / 4;
const H_MUL: u32 = 1664525;
const H_INC: u32 = 1013904223;

// Helpers

fn sha3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(&input);
    let hash = sha3_hasher.finalize();

    hash.as_slice().try_into().map_err(|_| "SHA-3 output length mismatch".to_string())
}


fn blake3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
    let hash = blake3::hash(&input);
    hash.as_bytes().try_into().map_err(|_| "BLAKE3 output length mismatch".to_string())
}


fn calculate_b3_rounds(input: [u8; 32]) -> usize {
    ((u32::from_le_bytes(input[4..8].try_into().unwrap_or_default()) % 3) + 2) as usize
}

fn calculate_sha3_rounds(input: [u8; 32]) -> usize {
    ((u32::from_le_bytes(input[8..12].try_into().unwrap_or_default()) % 3) + 2) as usize
}

fn bit_manipulations(data: &mut [u8; 32]) {
    for i in (0..32).step_by(4) {
        data[i] ^= data[i + 1];
    }
}

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

        memory[offset] = (state & 0xFF) as u8;
        memory[offset + 1] = ((state >> 8) & 0xFF) as u8;
        memory[offset + 2] = ((state >> 16) & 0xFF) as u8;
        memory[offset + 3] = ((state >> 24) & 0xFF) as u8;
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
        .map(|v| (v % 128) + 128)
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

    for _ in 0..dynamic_loops {
        for i in 0..8 {
            // Get random u32 from memory
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
    // cSHAKE256("ProofOfWorkHash") - initial sha3
    let hash = self.hasher.clone().finalize_with_nonce(nonce);

    let mut hash_bytes: [u8; 32];
    match hash.as_bytes().try_into() {
        Ok(bytes) => hash_bytes = bytes,
        Err(_) => {
            println!("Hash output length mismatch");
            return Uint256::default(); 
        }
    }

    // Apply nonce-based manipulation on hash bytes
    for i in 0..32 {
        hash_bytes[i] ^= (nonce as u8).wrapping_add(i as u8);
    }

    // Calculate the number of rounds for both Blake3 and SHA3
    let b3_rounds = calculate_b3_rounds(hash_bytes);
    let sha3_rounds = calculate_sha3_rounds(hash_bytes);

    let mut sha3_hash: [u8; 32];
    let mut b3_hash: [u8; 32];
    let mut m_hash: [u8; 32];

    // Perform Blake3 rounds with bit manipulations
    for _ in 0..b3_rounds {
        hash_bytes = blake3_hash(hash_bytes);
        bit_manipulations(&mut hash_bytes);
    }

    b3_hash = hash_bytes; // Store the result of Blake3 rounds

    // Perform SHA3 rounds with bit manipulations
    for _ in 0..sha3_rounds {
        hash_bytes = sha3_hash(hash_bytes);
        bit_manipulations(&mut hash_bytes);
    }

    sha3_hash = hash_bytes; // Store the result of SHA3 rounds

    // Mix the results from SHA3 and Blake3
    m_hash = byte_mixing(&sha3_hash, &b3_hash);

    // Final heavy hash transformation
    let final_hash = heavy_hash(Hash::from(m_hash));

    // Convert final hash to Uint256 and return
    Uint256::from_le_bytes(final_hash.as_bytes())
}
