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
fn sha3_hash(input: [u8; 32]) -> [u8; 32] {
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(&input);
    let hash = sha3_hasher.finalize();
    hash.as_slice().try_into().expect("SHA-3 output length mismatch")
}

// Blake3 Hash Function
fn blake3_hash(input: [u8; 32]) -> [u8; 32] {
    let hash = blake3::hash(&input);
    hash.as_bytes().try_into().expect("BLAKE3 output length mismatch")
}

// Calculate Blake3 rounds based on input
fn calculate_b3_rounds(input: [u8; 32]) -> usize {
    let slice = &input[4..8];
    if slice.len() == 4 {
        let value = u32::from_le_bytes(slice.try_into().unwrap());
        (value % 3 + 2) as usize
    } else {
        panic!("Input slice for Blake3 rounds is invalid");
    }
}

// Calculate SHA3 rounds based on input
fn calculate_sha3_rounds(input: [u8; 32]) -> usize {
    let slice = &input[8..12];
    if slice.len() == 4 {
        let value = u32::from_le_bytes(slice.try_into().unwrap());
        (value % 3 + 2) as usize
    } else {
        panic!("Input slice for SHA3 rounds is invalid");
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
        
        state ^= u32::from_le_bytes(seed[(i % 32)..(i % 32 + 4)].try_into().unwrap_or_default());

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

    let mut hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");

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

fn sha3_hash(input: [u8; 32]) -> [u8; 32] {
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(&input);
    let hash = sha3_hasher.finalize();
    hash.as_slice().try_into().expect("SHA-3 output length mismatch")
}

fn blake3_hash(input: [u8; 32]) -> [u8; 32] {
    let hash = blake3::hash(&input);
    hash.as_bytes().try_into().expect("BLAKE3 output length mismatch")
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

    let mut hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");

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
