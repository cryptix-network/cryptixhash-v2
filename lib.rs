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


// Constants for the offsets
const SHA3_ROUND_OFFSET: usize = 8;
const B3_ROUND_OFFSET: usize = 4;
const ROUND_RANGE_SIZE: usize = 4;

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
        let slice = &input[B3_ROUND_OFFSET..B3_ROUND_OFFSET + ROUND_RANGE_SIZE];
        let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
        Ok((value % 3 + 1) as usize) // Rounds between 1 and 3
    }

    // Calculate SHA3 rounds based on input    
    fn calculate_sha3_rounds(input: [u8; 32]) -> Result<usize, String> {
        let slice = &input[SHA3_ROUND_OFFSET..SHA3_ROUND_OFFSET + ROUND_RANGE_SIZE];
        let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
        Ok((value % 3 + 1) as usize) // Rounds between 1 and 3
    }
    
    // Bitwise manipulations on data
    fn bit_manipulations(data: &mut [u8; 32]) {
        for i in 0..32 {
            data[i] ^= data[(i + 1) % 32]; // XOR with the next byte 
            data[i] = data[i].rotate_left(3); // Rotate left by 3 bits
            data[i] ^= i as u8; // XOR with the index value 
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

        // Branches for Byte Manipulation
        for i in 0..32 {
            match (hash_bytes[i] ^ (self.nonce as u8)) % 6 {
                0 => hash_bytes[i] = hash_bytes[i].wrapping_add(13),
                1 => hash_bytes[i] = hash_bytes[i].rotate_left(3),
                2 => hash_bytes[i] ^= 0x5A,
                3 => hash_bytes[i] = hash_bytes[i].wrapping_mul(17),
                4 => hash_bytes[i] = hash_bytes[i].wrapping_sub(29),
                5 => hash_bytes[i] = hash_bytes[i].wrapping_add(0xAA ^ self.nonce as u8),
                _ => unreachable!(),
            }
        }

        // **Bitmanipulation**
        Self::bit_manipulations(&mut hash_bytes);

        let b3_rounds = State::calculate_b3_rounds(hash_bytes).unwrap_or(1);
        let sha3_rounds = State::calculate_sha3_rounds(hash_bytes).unwrap_or(1);

        let extra_rounds = (hash_bytes[0] % 7) as usize;  // dynamic rounds

        let sha3_hash: [u8; 32];
        let b3_hash: [u8; 32];
        let m_hash: [u8; 32];

        // **Dynamic Number of Rounds for Blake3**
        for _ in 0..(b3_rounds + extra_rounds) {
            hash_bytes = Self::blake3_hash(hash_bytes).unwrap_or([0; 32]);

            // Branching inside hash calculation
            if hash_bytes[5] % 2 == 0 {
                hash_bytes[10] ^= 0xAA;
            } else {
                hash_bytes[15] = hash_bytes[15].wrapping_add(23);
            }
        }

        b3_hash = hash_bytes;

        // **Dynamic Number of Rounds for SHA3**
        for _ in 0..(sha3_rounds + extra_rounds) {
            hash_bytes = Self::sha3_hash(hash_bytes).unwrap_or([0; 32]);

            // ASIC-unfriendly conditions
            if hash_bytes[3] % 3 == 0 {
                hash_bytes[20] ^= 0x55;
            } else if hash_bytes[7] % 5 == 0 {
                hash_bytes[25] = hash_bytes[25].rotate_left(7);
            }
        }

        sha3_hash = hash_bytes;

        // Mix SHA3 and Blake3 hash results
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
