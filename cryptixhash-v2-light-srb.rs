const H_MEM: usize = 4 * 1024 * 1024;
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

// Dynamic S-Box based on the block hash
fn generate_sbox(block_hash: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];

    for i in 0..32 {
        output[i] = block_hash[i] ^ block_hash[(i + 1) % 32] ^ block_hash[(i + 31) % 32];
    }

    output
}

fn fill_memory(seed: &[u8; 32], memory: &mut Vec<u8>) {
    // Ensure memory length is a multiple of 4 (since each u32 is 4 bytes)
    if memory.len() % 4 != 0 {
        panic!("Memory length must be a multiple of 4 bytes");
    }

    // Initialize state from the first 4 bytes of the seed
    let mut state: u32 = ((seed[0] as u32) << 24) | ((seed[1] as u32) << 16) | ((seed[2] as u32) << 8) | (seed[3] as u32);
    let num_elements = H_MEM_U32;

    // Ensure memory size is sufficient
    if memory.len() < H_MEM {
        panic!("Memory buffer is too small, expected size: {}, found: {}", H_MEM, memory.len());
    }

    // Treat memory as a slice of u8 and write u32 values as bytes
    for i in 0..num_elements {
        let offset = i * 4;
        state = state.wrapping_mul(H_MUL).wrapping_add(H_INC);

        // Write the u32 state as 4 bytes (LE)
        memory[offset] = (state & 0xFF) as u8;
        memory[offset + 1] = ((state >> 8) & 0xFF) as u8;
        memory[offset + 2] = ((state >> 16) & 0xFF) as u8;
        memory[offset + 3] = ((state >> 24) & 0xFF) as u8;
    }
}

fn u32_array_to_u8_array(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0u8; 32];

    for (i, &value) in input.iter().enumerate() {
        let bytes = value.to_le_bytes();
        let offset = i * 4;
        output[offset..offset + 4].copy_from_slice(&bytes);
    }

    output
}

pub fn heavy_hash(block_hash: Hash) -> Hash {
    let mut memory = vec![0u8; H_MEM];
    let mut result = [0u32; 8];

    let block_hash_bytes = block_hash.as_bytes();

    // Ensure the block hash length is correct
    if block_hash_bytes.len() != 32 {
        panic!("Expected block hash of length 32 bytes, found: {}", block_hash_bytes.len());
    }

    let hash_bytes_sum: u32 = block_hash_bytes.iter().map(|&x| x as u32).sum(); // max 8160

    let sbox: [u8; 32] = generate_sbox(block_hash_bytes);

    // Fill memory based on block_hash
    fill_memory(&block_hash_bytes, &mut memory);

    // Calculate the number of rounds [128 - 256]
    let dynamic_loops = (u32::from_le_bytes(memory[0..4].try_into().unwrap_or_default()) % 128) + 128;

    // Initial values for random indexes
    for i in 0..8 {
        let pos = i * 4;
        if pos + 3 >= block_hash_bytes.len() {
            panic!("Index out of bounds while initializing result at index: {}", i);
        }
        result[i] = u32::from_le_bytes([
            block_hash_bytes[pos],
            block_hash_bytes[pos + 1],
            block_hash_bytes[pos + 2],
            block_hash_bytes[pos + 3],
        ]);
    }

    for _ in 0..dynamic_loops {
        for i in 0..8 {
            // Get random u32 from memory
            let mem_index = result[i] % H_MEM_U32 as u32;
            let pos = mem_index as usize * 4;

            // Out of bounds protection
            if pos + 3 >= memory.len() {
                panic!("Memory index out of bounds at position: {}", pos);
            }

            let mut v = u32::from_le_bytes([memory[pos], memory[pos + 1], memory[pos + 2], memory[pos + 3]]);

            v = v.wrapping_add(hash_bytes_sum);
            v ^= result[i];

            // Write back new value to memory at same index
            memory[pos] = (v & 0xFF) as u8;
            memory[pos + 1] = ((v >> 8) & 0xFF) as u8;
            memory[pos + 2] = ((v >> 16) & 0xFF) as u8;
            memory[pos + 3] = ((v >> 24) & 0xFF) as u8;

            // Simple S-box
            let b: [u8; 4] = v.to_le_bytes();
            v = u32::from_le_bytes([
                sbox[b[0] as usize & 0x1F],
                sbox[b[1] as usize & 0x1F],
                sbox[b[2] as usize & 0x1F],
                sbox[b[3] as usize & 0x1F],
            ]);

            result[i] = v;
        }
    }

    // cSHAKE256("HeavyHash") - final sha3
    CryptixHash::hash(Hash::from_bytes(u32_array_to_u8_array(result)))
}


// https://github.com/cryptix-network/rusty-cryptix/blob/main/consensus/pow/src/lib.rs

#[inline]
#[must_use]
/// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    //https://github.com/cryptix-network/rusty-cryptix/blob/main/crypto/hashes/src/pow_hashers.rs#L52
    // cSHAKE256("ProofOfWorkHash") - initial sha3
    let hash = self.hasher.clone().finalize_with_nonce(nonce);

    // Ensure the hash is exactly 32 bytes
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
