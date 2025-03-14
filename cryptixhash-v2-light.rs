    // TODO:
    // Better filling of the cache - Scattering is not sufficient
    // Better filling of the Memory hard function - Scattering is not sufficient
    // Performance optimization of illiterations.
    // Correct values ​​for the cache & memory

    // IDEA:
    // Consider bottlenecking the LUTS with 64-bit values, which would overload at least 1,000,000 LUTs. But this needs to be considered first. The current LUT usage must also be calculated with Vivado Studio.

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

    // **Calculate Blake3 rounds based on input**
    fn calculate_b3_rounds(input: [u8; 32]) -> Result<usize, String> {
        // Extract the slice from input based on the B3_ROUND_OFFSET and ROUND_RANGE_SIZE
        let slice = &input[B3_ROUND_OFFSET..B3_ROUND_OFFSET + ROUND_RANGE_SIZE];

        if slice.len() == ROUND_RANGE_SIZE {
            let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
            Ok((value % 5 + 1) as usize) // Returns rounds between 1 and 5
        } else {
            Err("Input slice for Blake3 rounds is invalid".to_string()) // Slice length error
        }
    }

    // **Calculate SHA3 rounds based on input**
    fn calculate_sha3_rounds(input: [u8; 32]) -> Result<usize, String> {
        // Extract the slice from input based on the SHA3_ROUND_OFFSET and ROUND_RANGE_SIZE
        let slice = &input[SHA3_ROUND_OFFSET..SHA3_ROUND_OFFSET + ROUND_RANGE_SIZE];

        if slice.len() == ROUND_RANGE_SIZE {
            let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
            Ok((value % 4 + 1) as usize) // Returns rounds between 1 and 4
        } else {
            Err("Input slice for SHA3 rounds is invalid".to_string())  // Slice length error
        }
    }

    // Bitwise manipulations on data
    fn bit_manipulations(data: &mut [u8; 32]) {
        for i in 0..32 {
            // Non-linear manipulations with pseudo-random patterns
            let b = data[(i + 1) % 32];
            data[i] ^= b; // XOR with next byte
            data[i] = data[i].rotate_left(3); // Rotation
            data[i] = data[i].wrapping_add(0x9F); // Random constant
            data[i] &= 0xFE; // AND with mask to set certain bits
            data[i] ^= (i as u8) << 2; // XOR with index shifted
        }
    }
    
    //Byte Mixing
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
        for i in 0..16 {
            let condition = (hash_bytes[i] ^ (nonce as u8)) % 6; // 6 Cases
            match condition {
                0 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_add(13); // Add 13
                    hash_bytes[i] = hash_bytes[i].rotate_left(3);  // Rotate left by 3 bits
                },
                1 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_sub(7);  // Subtract 7
                    hash_bytes[i] = hash_bytes[i].rotate_left(5);   // Rotate left by 5 bits
                },
                2 => {
                    hash_bytes[i] ^= 0x5A;                         // XOR with 0x5A
                    hash_bytes[i] = hash_bytes[i].wrapping_add(0xAC); // Add 0xAC
                },
                3 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_mul(17); // Multiply by 17
                    hash_bytes[i] ^= 0xAA;                          // XOR with 0xAA
                },
                4 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_sub(29); // Subtract 29
                    hash_bytes[i] = hash_bytes[i].rotate_left(1);  // Rotate left by 1 bit
                },
                5 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_add(0xAA ^ nonce as u8); // Add XOR of 0xAA and nonce
                    hash_bytes[i] ^= 0x45;                          // XOR with 0x45
                },
                _ => unreachable!(), // Should never happens
            }
        }

        // **Bitmanipulation**
        Self::bit_manipulations(&mut hash_bytes);

        let b3_rounds = State::calculate_b3_rounds(hash_bytes).unwrap_or(1); // default 1
        let sha3_rounds = State::calculate_sha3_rounds(hash_bytes).unwrap_or(1); // default 1

        let extra_rounds = (hash_bytes[0] % 6) as usize;  // Dynamic rounds 0 - 5

        let sha3_hash: [u8; 32];
        let b3_hash: [u8; 32];
        let m_hash: [u8; 32];

        // **Dynamic Number of Rounds for Blake3**
        for _ in 0..(b3_rounds + extra_rounds) {
            hash_bytes = Self::blake3_hash(hash_bytes).unwrap_or([0; 32]); // Apply Blake3 hash

            // Branching based on hash value
            if hash_bytes[5] % 2 == 0 { 
                hash_bytes[10] ^= 0xAA; // XOR with 0xAA if byte 5 is even
            } else {
                hash_bytes[15] = hash_bytes[15].wrapping_add(23); // Add 23 if byte 5 is odd
            }
        }

        b3_hash = hash_bytes; // Store final Blake3 hash

        // **Dynamic Number of Rounds for SHA3**
        for _ in 0..(sha3_rounds + extra_rounds) {
            hash_bytes = Self::sha3_hash(hash_bytes).unwrap_or([0; 32]); // Apply SHA3 hash

            // ASIC-unfriendly conditions
            if hash_bytes[3] % 3 == 0 { 
                hash_bytes[20] ^= 0x55; // XOR with 0x55 if byte 3 is divisible by 3
            } else if hash_bytes[7] % 5 == 0 { 
                hash_bytes[25] = hash_bytes[25].rotate_left(7); // Rotate left by 7 if byte 7 is divisible by 5
            }
        }

        sha3_hash = hash_bytes; // Store final sha3 hash

        // Mix SHA3 and Blake3 hash results
        m_hash = Self::byte_mixing(&sha3_hash, &b3_hash);
    
        // Final computation with matrix.heavy_hash
        let final_hash = self.matrix.heavy_hash(cryptix_hashes::Hash::from(m_hash));
        
        // Finally 
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

impl Matrix {
    // pub fn generate(hash: Hash) -> Self {
    //     let mut generator = XoShiRo256PlusPlus::new(hash);
    //     let mut mat = Matrix([[0u16; 64]; 64]);
    //     loop {
    //         for i in 0..64 {
    //             for j in (0..64).step_by(16) {
    //                 let val = generator.u64();
    //                 for shift in 0..16 {
    //                     mat.0[i][j + shift] = (val >> (4 * shift) & 0x0F) as u16;
    //                 }
    //             }
    //         }
    //         if mat.compute_rank() == 64 {
    //             return mat;
    //         }
    //     }
    // }

    #[inline(always)]
    pub fn generate(hash: Hash) -> Self {
        let mut generator = XoShiRo256PlusPlus::new(hash);
        loop {
            let mat = Self::rand_matrix_no_rank_check(&mut generator);
            if mat.compute_rank() == 64 {
                return mat;
            }
        }
    }

    #[inline(always)]
    fn rand_matrix_no_rank_check(generator: &mut XoShiRo256PlusPlus) -> Self {
        Self(array_from_fn(|_| {
            let mut val = 0;
            array_from_fn(|j| {
                let shift = j % 16;
                if shift == 0 {
                    val = generator.u64();
                }
                (val >> (4 * shift) & 0x0F) as u16
            })
        }))
    }

    #[inline(always)]
    fn convert_to_float(&self) -> [[f64; 64]; 64] {
        // SAFETY: An uninitialized MaybeUninit is always safe.
        let mut out: [[MaybeUninit<f64>; 64]; 64] = unsafe { MaybeUninit::uninit().assume_init() };

        out.iter_mut().zip(self.0.iter()).for_each(|(out_row, mat_row)| {
            out_row.iter_mut().zip(mat_row).for_each(|(out_element, &element)| {
                out_element.write(f64::from(element));
            })
        });
        // SAFETY: The loop above wrote into all indexes.
        unsafe { std::mem::transmute(out) }
    }

    pub fn compute_rank(&self) -> usize {
        const EPS: f64 = 1e-9;
        let mut mat_float = self.convert_to_float();
        let mut rank = 0;
        let mut row_selected = [false; 64];
        for i in 0..64 {
            if i >= 64 {
                // Required for optimization, See https://github.com/rust-lang/rust/issues/90794
                unreachable!()
            }
            let mut j = 0;
            while j < 64 {
                if !row_selected[j] && mat_float[j][i].abs() > EPS {
                    break;
                }
                j += 1;
            }
            if j != 64 {
                rank += 1;
                row_selected[j] = true;
                for p in (i + 1)..64 {
                    mat_float[j][p] /= mat_float[j][i];
                }
                for k in 0..64 {
                    if k != j && mat_float[k][i].abs() > EPS {
                        for p in (i + 1)..64 {
                            mat_float[k][p] -= mat_float[j][p] * mat_float[k][i];
                        }
                    }
                }
            }
        }
        rank
    }

    // Const Final Cryptix
    const FINAL_CRYPTIX: [u8; 32] = [
        0xE4, 0x7F, 0x3F, 0x73, 
        0xB4, 0xF2, 0xD2, 0x8C, 
        0x55, 0xD1, 0xE7, 0x6B, 
        0xE0, 0xAD, 0x70, 0x55, 
        0xCB, 0x3F, 0x8C, 0x8F, 
        0xF5, 0xA0, 0xE2, 0x60, 
        0x81, 0xC2, 0x5A, 0x84, 
        0x32, 0x81, 0xE4, 0x92,
    ];   

    // Anti-ASIC cache
    pub fn anti_asic_cache(product: &mut [u8; 32]) {
        // const CACHE_SIZE: usize = 16384; // 16 KB Cache
        const CACHE_SIZE: usize = 8192;  // 8 KB
        let mut cache = [0u8; CACHE_SIZE];

        let mut index: usize = 0;

        // Cache initialization
        let mut hash_value = 0u8;
        for i in 0..CACHE_SIZE { 
            // Combine product values with cache indices
            hash_value = (product[i % 32] ^ i as u8).wrapping_add(hash_value);
            cache[i] = hash_value;  // starting pattern
        }
        
        for _ in 0..8 { 
            for i in 0..8 {
                // XOR for destructive cache effect
                index = (index.rotate_left(5) ^ product[i] as usize * 17) % CACHE_SIZE;
                cache[index] ^= product[i]; 
                
                // Unpredictable index mapping
                index = (index.wrapping_add(product[i] as usize * 23) ^ cache[(index * 7) % CACHE_SIZE] as usize) % CACHE_SIZE;
                cache[index] ^= product[(i + 11) % 32];

                // Data-Dependent Memory Access
                let dynamic_offset = ((cache[index] as usize * 37) ^ (product[i] as usize * 19)) % CACHE_SIZE;
                cache[dynamic_offset] ^= product[(i + 3) % 32];
            }
        }

        // Link cache values ​​back to product
        for i in 0..8 {
            let shift_val = (product[i] as usize * 47 + i) % CACHE_SIZE;
            product[i] ^= cache[shift_val];
        }
    }

    // Non linear sbox
    pub fn generate_non_linear_sbox(input: u8, key: u8) -> u8 {
        let mut result = input;
    
        // A combination of multiplication and bitwise permutation
        result = result.wrapping_mul(key);          // Multiply by the key
        result = (result >> 3) | (result << 5);    // Bitwise permutation (rotation)
        result ^= 0x5A;                             // XOR
    
        // Modulo operation
        result = result & 0xFF;  
    
        result
    }
     
    // Heavy Hash
    pub fn heavy_hash(&self, hash: Hash) -> Hash {
        let hash_bytes = hash.as_bytes(); 

        let nibbles: [u8; 64] = {
            let o_bytes = hash.as_bytes();
            let mut arr = [0u8; 64];
            for (i, &byte) in o_bytes.iter().enumerate() {
                arr[2 * i]     = byte >> 4;
                arr[2 * i + 1] = byte & 0x0F;
            }
            arr
        };
    
        let mut product = [0u8; 32];
    
        for i in 0..32 {
            let mut sum1 = 0u16;
            let mut sum2 = 0u16;
            for j in 0..64 {
                let elem = nibbles[j] as u16;
                sum1 += self.0[2 * i][j] * elem;
                sum2 += self.0[2 * i + 1][j] * elem;
            }
    
            let a_nibble = (sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF);
            let b_nibble = (sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF);
    
            product[i] = ((a_nibble << 4) | b_nibble) as u8;
        }
    
        product.iter_mut().zip(hash.as_bytes()).for_each(|(p, h)| *p ^= h);
    
        // **Memory-Hard**
        let mut memory_table = vec![0u8; 1024 * 16]; // 16 KB
        let mut index: usize = 0;

        // Repeat calculations and manipulations on memory
        for i in 0..32 {
            let mut sum = 0u16;
            for j in 0..64 {
                sum += nibbles[j] as u16 * self.0[2 * i][j] as u16;
            }

            // ** non-linear memory accesses:**
            for _ in 0..6 { 
                index ^= (memory_table[(index * 7 + i) % memory_table.len()] as usize * 19) ^ ((i * 53) % 13);
                index = (index * 73 + i * 41) % memory_table.len(); 

                // Index paths
                let shifted = (index.wrapping_add(i * 13)) % memory_table.len();
                memory_table[shifted] ^= (sum & 0xFF) as u8;
            }
        }

        // Final memory-hash result
        for i in 0..32 {
            let shift_val = (product[i] as usize * 47 + i) % memory_table.len();
            product[i] ^= memory_table[shift_val];
        }

        // final xor
        for i in 0..16 {
            product[i] ^= Self::FINAL_CRYPTIX[i];
        }

        // **Anti-ASIC Cache **
        Self::anti_asic_cache(&mut product);               

        // **Apply nonlinear S-Box**
        let mut sbox: [u8; 256] = [0; 256];

        // Calculate S-Box with the product value and hash values
        for _ in 0..6 {  
            for i in 0..32 {
                let mut value = i as u8;
                value = Self::generate_non_linear_sbox(value, hash_bytes[i % hash_bytes.len()]);
                value ^= (value << 4) | (value >> 2); 
                sbox[i] = value;
            }
        }
        
        // Apply S-Box to the product
        for i in 0..32 {
            product[i] = sbox[product[i] as usize];
        }     
    
        // Back to Home
        CryptixHash::hash(Hash::from_bytes(product))
    }
    
}
