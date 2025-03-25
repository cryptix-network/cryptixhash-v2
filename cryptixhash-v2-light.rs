
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

    // #[inline]
    // #[must_use]
    // /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    // pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    //     // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing
    //     let hash = self.hasher.clone().finalize_with_nonce(nonce);
        // let hash = self.matrix.heavy_hash(hash);
    //     Uint256::from_le_bytes(hash.as_bytes())
    // }

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Calculate the hash with the nonce
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");
    
        // Use the first byte of the hash to determine the number of iterations
        let iterations = (hash_bytes[0] % 2) + 1;  // The first byte modulo 3, plus 1 for the range [1, 2]
    
        // Iterative SHA-3 process
        let mut sha3_hasher = Sha3_256::new();
        let mut current_hash = hash_bytes;
    
        // Iterate according to the number of iterations
        for _ in 0..iterations {
            sha3_hasher.update(&current_hash);
            let sha3_hash = sha3_hasher.finalize_reset();
            current_hash = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");
        }
    
        // Final computation with matrix.cryptix_hash
        let final_hash = self.matrix.cryptix_hash(cryptix_hashes::Hash::from(current_hash));
    
        // Return the final result as Uint256
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

    /* 
    // ### Cryptixhash v3

    // generate_non_linear_sbox method
    pub fn generate_non_linear_sbox(input: u8, key: u8) -> u8 {
        let mut result = input;

        // Calculate the inverse in GF(2^8)
        result = Self::gf_invert(result);

        // Affine transformation (left rotation, XOR with constant 0x63)
        result = Self::affine_transform(result);

        // XOR with the key for additional diffusion
        result ^= key;

        result
    }

    // Inverse calculation and affine transformation
    fn gf_invert(value: u8) -> u8 {
        if value == 0 {
            return 0; // The inverse of 0 is 0
        }

        let mut t = 0u8;
        let r: u16 = 0x11b; // The irreducible polynomial as u16
        let mut v = value;
        let mut u: u16 = 1; // 1 in GF(2^8)

        // Extended Euclidean algorithm
        for _ in 0..8 {
            if v & 1 == 1 {
                t ^= u as u8; // Cast the result as u8
            }

            v >>= 1;
            u = (u << 1) ^ (if v & 0x80 != 0 { r } else { 0 });

            if u & 0x100 != 0 {
                u ^= 0x11b; // XOR with irreducible polynomial
            }
        }

        t
    }

    // Affine Transformation (left rotation + XOR with constant 0x63)
    fn affine_transform(value: u8) -> u8 {
        let mut result = value;
        result = result.rotate_left(4) ^ result; // Left rotation + XOR with itself (for diffusion)
        result ^= 0x63; // XOR with a constant (similar to AES)
        result
    }*/

    // Non-linear S-box generation
    pub fn generate_non_linear_sbox(input: u8, key: u8) -> u8 {
        let mut result = input;

        // Combination of multiplication and bitwise permutation
        result = result.wrapping_mul(key);          // Multiply by the key
        result = (result >> 3) | (result << 5);    // Bitwise permutation (Rotation)
        result ^= 0x5A;                             // XOR with 0x5A

        result
    }

    pub fn cryptix_hash(&self, hash: Hash) -> Hash {
        // Convert the hash to its byte representation
        let hash_bytes = hash.as_bytes();

        // Create an array containing the nibbles (4-bit halves of the bytes)
        let nibbles: [u8; 64] = {
            let o_bytes = hash.as_bytes();
            let mut arr = [0u8; 64];
            for (i, &byte) in o_bytes.iter().enumerate() {
                arr[2 * i]     = byte >> 4;               // Store the high nibble
                arr[2 * i + 1] = byte & 0x0F;             // Store the low nibble
            }
            arr
        };
    
        let mut product = [0u8; 32];
    
        for i in 0..32 {
            let mut sum1 = 0u16;
            let mut sum2 = 0u16;
            for j in 0..64 {
                let elem = nibbles[j] as u16;
                sum1 += self.0[2 * i][j] * elem;   // Matrix multiplication
                sum2 += self.0[2 * i + 1][j] * elem;
            }
            
            // Combine the nibbles back into bytes
            let a_nibble = (sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF); // Combine the bits
            let b_nibble = (sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF);
    
            product[i] = ((a_nibble << 4) | b_nibble) as u8; // Combine to form final byte
        }

        // XOR the product with the original hash   
        product.iter_mut().zip(hash.as_bytes()).for_each(|(p, h)| *p ^= h); // Apply XOR with the hash
        
        // ### Memory Hard

        // **Apply nonlinear S-Box**
        let mut sbox: [u8; 256] = [0; 256];

        // Fill the S-box using the bytes of the hash
        for i in 0..256 {
            sbox[i] = hash_bytes[i % hash_bytes.len()]; // Wrap around the hash bytes
        }

        // Number of iterations depends on the first byte of the product
        let iterations = 3 + (product[0] % 7);  // Modulo 7 gives values ​​from 0 to 6 → +3 gives 3 to 9

        for _ in 0..iterations {  
            let mut temp_sbox = sbox;
            
            for i in 0..256 { 
                let mut value = temp_sbox[i];  
                
                // Generate nonlinear value based on Hash + Product
                value = Self::generate_non_linear_sbox(value, hash_bytes[i % hash_bytes.len()] ^ product[i % product.len()]); 
                
                // Bitwise rotation + XOR
                value ^= value.rotate_left(4) | value.rotate_right(2); 
                temp_sbox[i] = value; 
            }

            sbox = temp_sbox; // Update the S-Box after the round
        }

        // Apply the final S-Box transformation to the product with XOR
        for i in 0..32 {
            product[i] ^= sbox[product[i] as usize]; // XOR product with S-Box values
        }

        // **Branches for Byte Manipulation**
        for i in 0..32 {
            // Nonce from s-box product
            let cryptix_nonce = product[i];
            let condition = (product[i] ^ (hash_bytes[i % hash_bytes.len()] ^ cryptix_nonce)) % 9;
            
            match condition {
                0 => {
                    // Main case 0
                    product[i] = product[i].wrapping_add(13);  // Add 13
                    product[i] = product[i].rotate_left(3);    // Rotate left by 3 bits
                    
                    // Nested cases in case 0
                    if product[i] > 100 {
                        product[i] = product[i].wrapping_add(0x20);  // Add 0x20 if greater than 100
                    } else {
                        product[i] = product[i].wrapping_sub(0x10);  // Subtract 0x10 if not
                    }
                },
                1 => {
                    // Main case 1
                    product[i] = product[i].wrapping_sub(7);   // Subtract 7
                    product[i] = product[i].rotate_left(5);    // Rotate left by 5 bits
                    
                    // Nested case inside case 1
                    if product[i] % 2 == 0 {
                        product[i] = product[i].wrapping_add(0x11); // Add 0x11 if even
                    } else {
                        product[i] = product[i].wrapping_sub(0x05); // Subtract 0x05 if odd
                    }
                },
                2 => {
                    // Main case 2
                    product[i] ^= 0x5A;                       // XOR with 0x5A
                    product[i] = product[i].wrapping_add(0xAC); // Add 0xAC
                    
                    // Nested case inside case 2
                    if product[i] > 0x50 {
                        product[i] = product[i].wrapping_mul(2);   // Multiply by 2 if greater than 0x50
                    } else {
                        product[i] = product[i].wrapping_div(3);   // Divide by 3 if not
                    }
                },
                3 => {
                    // Main case 3
                    product[i] = product[i].wrapping_mul(17);   // Multiply by 17
                    product[i] ^= 0xAA;                        // XOR with 0xAA
                    
                    // Nested case inside case 3
                    if product[i] % 4 == 0 {
                        product[i] = product[i].rotate_left(4); // Rotate left by 4 bits if divisible by 4
                    } else {
                        product[i] = product[i].rotate_right(2); // Rotate right by 2 bits if not
                    }
                },
                4 => {
                    // Main case 4
                    product[i] = product[i].wrapping_sub(29);   // Subtract 29
                    product[i] = product[i].rotate_left(1);     // Rotate left by 1 bit
                    
                    // Nested case inside case 4
                    if product[i] < 50 {
                        product[i] = product[i].wrapping_add(0x55); // Add 0x55 if less than 50
                    } else {
                        product[i] = product[i].wrapping_sub(0x22); // Subtract 0x22 if not
                    }
                },
                5 => {
                    // Main case 5
                    product[i] = product[i].wrapping_add(0xAA ^ cryptix_nonce as u8); // Add XOR of 0xAA and nonce
                    product[i] ^= 0x45;                        // XOR with 0x45
                    
                    // Nested case inside case 5
                    if product[i] & 0x0F == 0 {
                        product[i] = product[i].rotate_left(6); // Rotate left by 6 bits if lower nibble is 0
                    } else {
                        product[i] = product[i].rotate_right(3); // Rotate right by 3 bits if not
                    }
                },
                6 => {
                    // Main case 6
                    product[i] = product[i].wrapping_add(0x33);  // Add 0x33
                    product[i] = product[i].rotate_right(4);     // Rotate right by 4 bits
                    
                    // Nested case inside case 6
                    if product[i] < 0x80 {
                        product[i] = product[i].wrapping_sub(0x22); // Subtract 0x22 if less than 0x80
                    } else {
                        product[i] = product[i].wrapping_add(0x44); // Add 0x44 if not
                    }
                },
                7 => {
                    // Main case 7
                    product[i] = product[i].wrapping_mul(3);     // Multiply by 3
                    product[i] = product[i].rotate_left(2);      // Rotate left by 2 bits
                    
                    // Nested case inside case 7
                    if product[i] > 0x50 {
                        product[i] = product[i].wrapping_add(0x11); // Add 0x11 if greater than 0x50
                    } else {
                        product[i] = product[i].wrapping_sub(0x11); // Subtract 0x11 if not
                    }
                },
                8 => {
                    // Main case 8
                    product[i] = product[i].wrapping_sub(0x10);   // Subtract 0x10
                    product[i] = product[i].rotate_right(3);      // Rotate right by 3 bits
                    
                    // Nested case inside case 8
                    if product[i] % 3 == 0 {
                        product[i] = product[i].wrapping_add(0x55); // Add 0x55 if divisible by 3
                    } else {
                        product[i] = product[i].wrapping_sub(0x33); // Subtract 0x33 if not
                    }
                },
                _ => unreachable!(), // This should never happen
            }
        }

        // Final Cryptixhash v2
        CryptixHashV2::hash(Hash::from_bytes(product)) // Return
    }
}


