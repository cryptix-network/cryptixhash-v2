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

        if slice.len() == ROUND_RANGE_SIZE {
            let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
            Ok((value % 5 + 1) as usize) // Rounds between 1 and 5
        } else {
            Err("Input slice for Blake3 rounds is invalid".to_string())
        }
    }

    // Calculate SHA3 rounds based on input
    fn calculate_sha3_rounds(input: [u8; 32]) -> Result<usize, String> {
        let slice = &input[SHA3_ROUND_OFFSET..SHA3_ROUND_OFFSET + ROUND_RANGE_SIZE];

        if slice.len() == ROUND_RANGE_SIZE {
            let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
            Ok((value % 4 + 1) as usize) // Rounds between 1 and 4
        } else {
            Err("Input slice for SHA3 rounds is invalid".to_string())
        }
    }

    // Bitwise manipulations on data
    fn bit_manipulations(data: &mut [u8; 32]) {
        for i in 0..32 {
            // Non-linear manipulations with pseudo-random patterns
            let a = data[i];
            let b = data[(i + 1) % 32];
            data[i] ^= b; // XOR with next byte
            data[i] = data[i].rotate_left(3); // Rotation
            data[i] = data[i].wrapping_add(0x9F); // Random constant
            data[i] &= 0xFE; // AND with mask to set certain bits
            data[i] ^= (i as u8) << 2; // XOR with index shifted
        }
    }

    fn byte_mixing(sha3_hash: &[u8; 32], b3_hash: &[u8; 32]) -> [u8; 32] {
        let mut temp_buf = [0u8; 32];
        for i in 0..32 {
            let a = sha3_hash[i];
            let b = b3_hash[i];
            
            // bitwise AND and OR
            let and_result = a & b;
            let or_result = a | b;
            
            // bitwise rotation and shift
            let rotated = or_result.rotate_left(5);  // Rotate left by 5 bits
            let shifted = and_result.wrapping_shl(3);  // Shift left by 3 bits
            
            // Combine the results
            let mixed = rotated ^ shifted;  // XOR the results
            
            temp_buf[i] = mixed;  // Store the result in the temporary buffer
        }
        temp_buf
    }

    // Proof-of-Work function
    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
    
        let mut hash_bytes: [u8; 32];
        match hash.as_bytes().try_into() {
            Ok(bytes) => hash_bytes = bytes,
            Err(_) => {
                println!("Hash output length mismatch");
                return Uint256::default();  
            }
        }
    
        // **Branches for Byte Manipulation**
        for i in 0..32 {
            let condition = (hash_bytes[i] ^ (nonce as u8)) % 6;
            match condition {
                0 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_add(13);
                    hash_bytes[i] = hash_bytes[i].rotate_left(3);
                },
                1 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_sub(7);
                    hash_bytes[i] = hash_bytes[i].rotate_left(5);
                },
                2 => {
                    hash_bytes[i] ^= 0x5A;
                    hash_bytes[i] = hash_bytes[i].wrapping_add(0xAC);
                },
                3 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_mul(17);
                    hash_bytes[i] ^= 0xAA;
                },
                4 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_sub(29);
                    hash_bytes[i] = hash_bytes[i].rotate_left(1);
                },
                5 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_add(0xAA ^ nonce as u8);
                    hash_bytes[i] ^= 0x45;
                },
                _ => unreachable!(),
            }
        }

        // **Bitmanipulation**
        Self::bit_manipulations(&mut hash_bytes);

        let b3_rounds = State::calculate_b3_rounds(hash_bytes).unwrap_or(1);
        let sha3_rounds = State::calculate_sha3_rounds(hash_bytes).unwrap_or(1);

        let extra_rounds = (hash_bytes[0] % 6) as usize;  // Dynamic rounds

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
    
        // Final computation with matrix.heavy_hash
        let final_hash = self.matrix.heavy_hash(cryptix_hashes::Hash::from(m_hash));
    
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
