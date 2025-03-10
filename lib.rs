// public for benchmarks
#[doc(hidden)]
pub mod matrix;
#[cfg(feature = "wasm32-sdk")]
pub mod wasm;
#[doc(hidden)]
pub mod xoshiro;

use std::cmp::max;

use crate::matrix::Matrix;
use cryptix_consensus_core::{hashing, header::Header, BlockLevel};
use cryptix_hashes::PowHash;
use cryptix_math::Uint256;
use sha3::{Digest, Sha3_256};
use blake3;

/// State is an intermediate data structure with pre-computed values to speed up mining.
pub struct State {
    pub(crate) matrix: Matrix,
    pub(crate) target: Uint256,
    // PRE_POW_HASH || TIME || 32 zero byte padding; without NONCE
    pub(crate) hasher: PowHash,
}

impl State {
    #[inline]
    pub fn new(header: &Header) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        // Zero out the time and nonce.
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, header.timestamp);
        let matrix = Matrix::generate(pre_pow_hash);

        Self { matrix, target, hasher }
    }

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

    #[inline]
    #[must_use]
    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        let pow = self.calculate_pow(nonce);
        // The pow hash must be less or equal than the claimed target.
        (pow <= self.target, pow)
    }
}

pub fn calc_block_level(header: &Header, max_block_level: BlockLevel) -> BlockLevel {
    if header.parents_by_level.is_empty() {
        return max_block_level; // Genesis has the max block level
    }

    let state = State::new(header);
    let (_, pow) = state.check_pow(header.nonce);
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
