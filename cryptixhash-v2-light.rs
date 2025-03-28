
#[inline]
#[must_use]
/// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    // Calculate hash with nonce
    let hash = self.hasher.clone().finalize_with_nonce(nonce);
    let hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");

    // Determine number of iterations from the first byte of the hash
    let iterations = (hash_bytes[0] % 2) + 1;  // 1 or 2 iterations based on first byte
    
    // Start iterative SHA-3 process
    let mut sha3_hasher = Sha3_256::new();
    let mut current_hash = hash_bytes;

    // Perform iterations based on the first byte of the hash
    for i in 0..iterations {
        sha3_hasher.update(&current_hash);
        let sha3_hash = sha3_hasher.finalize_reset();
        current_hash = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");

        // Perform dynamic hash transformation based on conditions
        if current_hash[1] % 4 == 0 {
            // Calculate the number of iterations based on byte 2 (mod 4), ensuring it is between 1 and 4
            let repeat = (current_hash[2] % 4) + 1; // 1-4 iterations based on the value of byte 2
            
            for _ in 0..repeat {
                // Dynamically select the byte to modify based on a combination of hash bytes and iteration
                let target_byte = ((current_hash[1] as usize) + (i as u8) as usize) % 32; // Dynamic byte position for XOR
                let xor_value = current_hash[(i % 16) as usize] ^ 0xA5; // Dynamic XOR value based on iteration index and hash
                current_hash[target_byte] ^= xor_value;  // XOR on dynamically selected byte

                // Dynamically choose the byte to calculate rotation based on the current iteration
                let rotation_byte = current_hash[(i % 32) as usize];  // Use different byte based on iteration index
                let rotation_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 2; // Combined rotation calculation
                
                // Perform rotation based on whether the rotation byte is even or odd
                if rotation_byte % 2 == 0 {
                    // Rotate byte at dynamic position to the left by 'rotation_amount' positions
                    current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount);
                } else {
                    // Rotate byte at dynamic position to the right by 'rotation_amount' positions
                    current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount);
                }

                // Perform additional bitwise manipulation on the target byte using a shift
                let shift_amount = ((current_hash[5] as u32) + (current_hash[1] as u32)) % 3 + 1; // Combined shift calculation
                current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount); // XOR with rotated value
            }
        } else if current_hash[3] % 3 == 0 {
            let repeat = (current_hash[4] % 5) + 1;
            for _ in 0..repeat {
                let target_byte = ((current_hash[6] as usize) + (i as u8) as usize) % 32; 
                let xor_value = current_hash[(i % 16) as usize] ^ 0x55;
                current_hash[target_byte] ^= xor_value;

                let rotation_byte = current_hash[(i % 32) as usize];
                let rotation_amount = ((current_hash[7] as u32) + (current_hash[2] as u32)) % 6 + 1;
                if rotation_byte % 2 == 0 {
                    current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                } else {
                    current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                }

                let shift_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 1; 
                current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount);
            }
        } else if current_hash[2] % 6 == 0 {
            let repeat = (current_hash[6] % 4) + 1;
            for _ in 0..repeat {
                let target_byte = ((current_hash[10] as usize) + (i as u8) as usize) % 32; 
                let xor_value = current_hash[(i % 16) as usize] ^ 0xFF;
                current_hash[target_byte] ^= xor_value;

                let rotation_byte = current_hash[(i % 32) as usize];  
                let rotation_amount = ((current_hash[7] as u32) + (current_hash[7] as u32)) % 7 + 1;
                if rotation_byte % 2 == 0 {
                    current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                } else {
                    current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                }

                let shift_amount = ((current_hash[3] as u32) + (current_hash[5] as u32)) % 5 + 2; 
                current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount as u32);
            }
        } else if current_hash[7] % 5 == 0 {
            let repeat = (current_hash[8] % 4) + 1;
            for _ in 0..repeat {
                let target_byte = ((current_hash[25] as usize) + (i as u8) as usize) % 32; 
                let xor_value = current_hash[(i % 16) as usize] ^ 0x66;
                current_hash[target_byte] ^= xor_value;

                let rotation_byte = current_hash[(i % 32) as usize]; 
                let rotation_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 2;
                if rotation_byte % 2 == 0 {
                    current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                } else {
                    current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                }

                let shift_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 1; 
                current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount as u32);
            }
        } else if current_hash[8] % 7 == 0 {
            let repeat = (current_hash[9] % 5) + 1;
            for _ in 0..repeat {
                let target_byte = ((current_hash[30] as usize) + (i as u8) as usize) % 32; 
                let xor_value = current_hash[(i % 16) as usize] ^ 0x77; 
                current_hash[target_byte] ^= xor_value;

                let rotation_byte = current_hash[(i % 32) as usize];  
                let rotation_amount = ((current_hash[2] as u32) + (current_hash[5] as u32)) % 5 + 1;
                if rotation_byte % 2 == 0 {
                    current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                } else {
                    current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                }

                let shift_amount = ((current_hash[7] as u32) + (current_hash[9] as u32)) % 6 + 2; 
                current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount as u32);
            }
        }
    }

    // Final computation using matrix.cryptix_hash
    let final_hash = self.matrix.cryptix_hash(cryptix_hashes::Hash::from(current_hash));

    // Return the final result as Uint256
    Uint256::from_le_bytes(final_hash.as_bytes())
}


    // Octionion Multiply
    fn octonion_multiply(a: &[i64; 8], b: &[i64; 8]) -> [i64; 8] {
        let mut result = [0; 8];

        /*
            Multiplication table of octonions (non-commutative):

                ×    |  1   e₁   e₂   e₃   e₄   e₅   e₆   e₇  
                ------------------------------------------------
                1    |  1   e₁   e₂   e₃   e₄   e₅   e₆   e₇  
                e₁   | e₁  -1   e₃  -e₂   e₅  -e₆   e₄  -e₇  
                e₂   | e₂  -e₃  -1    e₁   e₆   e₄  -e₅   e₇  
                e₃   | e₃   e₂  -e₁  -1    e₄  -e₇   e₆  -e₅  
                e₄   | e₄  -e₅  -e₆  -e₄  -1    e₇   e₂   e₃  
                e₅   | e₅   e₆   e₄   e₇  -e₇  -1   -e₃   e₂  
                e₆   | e₆  -e₄  -e₅   e₆  -e₂   e₃  -1    e₁  
                e₇   | e₇   e₄  -e₇   e₅  -e₃  -e₂   e₁  -1  

        
        // The rules for multiplying octonions
        result[0] = a[0] * b[0] - a[1] * b[1] - a[2] * b[2] - a[3] * b[3] - a[4] * b[4] - a[5] * b[5] - a[6] * b[6] - a[7] * b[7];
        result[1] = a[0] * b[1] + a[1] * b[0] + a[2] * b[3] - a[3] * b[2] + a[4] * b[5] - a[5] * b[4] - a[6] * b[7] + a[7] * b[6];
        result[2] = a[0] * b[2] - a[1] * b[3] + a[2] * b[0] + a[3] * b[1] + a[4] * b[6] - a[5] * b[7] + a[6] * b[4] - a[7] * b[5];
        result[3] = a[0] * b[3] + a[1] * b[2] - a[2] * b[1] + a[3] * b[0] + a[4] * b[7] + a[5] * b[6] - a[6] * b[5] + a[7] * b[4];
        result[4] = a[0] * b[4] - a[1] * b[5] - a[2] * b[6] - a[3] * b[7] + a[4] * b[0] + a[5] * b[1] + a[6] * b[2] + a[7] * b[3];
        result[5] = a[0] * b[5] + a[1] * b[4] - a[2] * b[7] + a[3] * b[6] - a[4] * b[1] + a[5] * b[0] + a[6] * b[3] + a[7] * b[2];
        result[6] = a[0] * b[6] + a[1] * b[7] + a[2] * b[4] - a[3] * b[5] - a[4] * b[2] + a[5] * b[3] + a[6] * b[0] + a[7] * b[1];
        result[7] = a[0] * b[7] - a[1] * b[6] + a[2] * b[5] + a[3] * b[4] - a[4] * b[3] + a[5] * b[2] + a[6] * b[1] + a[7] * b[0];

        result
        */
        
         // e0
        result[0] = a[0].wrapping_mul(b[0])
            .wrapping_sub(a[1].wrapping_mul(b[1]))
            .wrapping_sub(a[2].wrapping_mul(b[2]))
            .wrapping_sub(a[3].wrapping_mul(b[3]))
            .wrapping_sub(a[4].wrapping_mul(b[4]))
            .wrapping_sub(a[5].wrapping_mul(b[5]))
            .wrapping_sub(a[6].wrapping_mul(b[6]))
            .wrapping_sub(a[7].wrapping_mul(b[7]));
        
         // e1
        result[1] = a[0].wrapping_mul(b[1])
            .wrapping_add(a[1].wrapping_mul(b[0]))
            .wrapping_add(a[2].wrapping_mul(b[3]))
            .wrapping_sub(a[3].wrapping_mul(b[2]))
            .wrapping_add(a[4].wrapping_mul(b[5]))
            .wrapping_sub(a[5].wrapping_mul(b[4]))
            .wrapping_sub(a[6].wrapping_mul(b[7]))
            .wrapping_add(a[7].wrapping_mul(b[6]));

         // e2
        result[2] = a[0].wrapping_mul(b[2])
            .wrapping_sub(a[1].wrapping_mul(b[3]))
            .wrapping_add(a[2].wrapping_mul(b[0]))
            .wrapping_add(a[3].wrapping_mul(b[1]))
            .wrapping_add(a[4].wrapping_mul(b[6]))
            .wrapping_sub(a[5].wrapping_mul(b[7]))
            .wrapping_add(a[6].wrapping_mul(b[4]))
            .wrapping_sub(a[7].wrapping_mul(b[5]));

       // e3
        result[3] = a[0].wrapping_mul(b[3])
            .wrapping_add(a[1].wrapping_mul(b[2]))
            .wrapping_sub(a[2].wrapping_mul(b[1]))
            .wrapping_add(a[3].wrapping_mul(b[0]))
            .wrapping_add(a[4].wrapping_mul(b[7]))
            .wrapping_add(a[5].wrapping_mul(b[6]))
            .wrapping_sub(a[6].wrapping_mul(b[5]))
            .wrapping_add(a[7].wrapping_mul(b[4]));
    
         // e4
        result[4] = a[0].wrapping_mul(b[4])
            .wrapping_sub(a[1].wrapping_mul(b[5]))
            .wrapping_sub(a[2].wrapping_mul(b[6]))
            .wrapping_sub(a[3].wrapping_mul(b[7]))
            .wrapping_add(a[4].wrapping_mul(b[0]))
            .wrapping_add(a[5].wrapping_mul(b[1]))
            .wrapping_add(a[6].wrapping_mul(b[2]))
            .wrapping_add(a[7].wrapping_mul(b[3]));
    
         // e5
        result[5] = a[0].wrapping_mul(b[5])
            .wrapping_add(a[1].wrapping_mul(b[4]))
            .wrapping_sub(a[2].wrapping_mul(b[7]))
            .wrapping_add(a[3].wrapping_mul(b[6]))
            .wrapping_sub(a[4].wrapping_mul(b[1]))
            .wrapping_add(a[5].wrapping_mul(b[0]))
            .wrapping_add(a[6].wrapping_mul(b[3]))
            .wrapping_add(a[7].wrapping_mul(b[2]));
    
         // e6
        result[6] = a[0].wrapping_mul(b[6])
            .wrapping_add(a[1].wrapping_mul(b[7]))
            .wrapping_add(a[2].wrapping_mul(b[4]))
            .wrapping_sub(a[3].wrapping_mul(b[5]))
            .wrapping_sub(a[4].wrapping_mul(b[2]))
            .wrapping_add(a[5].wrapping_mul(b[3]))
            .wrapping_add(a[6].wrapping_mul(b[0]))
            .wrapping_add(a[7].wrapping_mul(b[1]));

         // e7
        result[7] = a[0].wrapping_mul(b[7])
            .wrapping_sub(a[1].wrapping_mul(b[6]))
            .wrapping_add(a[2].wrapping_mul(b[5]))
            .wrapping_add(a[3].wrapping_mul(b[4]))
            .wrapping_sub(a[4].wrapping_mul(b[3]))
            .wrapping_add(a[5].wrapping_mul(b[2]))
            .wrapping_add(a[6].wrapping_mul(b[1]))
            .wrapping_add(a[7].wrapping_mul(b[0]));
        
        // Result
        return result;
    }

    // Octonion Hash
    fn octonion_hash(input_hash: &[u8; 32]) -> [i64; 8] {

        // Initialize the octonion with the first 8 bytes of the input_hash
        let mut oct = [
            input_hash[0] as i64,  // e0
            input_hash[1] as i64,  // e1
            input_hash[2] as i64,  // e2
            input_hash[3] as i64,  // e3
            input_hash[4] as i64,  // e4
            input_hash[5] as i64,  // e5
            input_hash[6] as i64,  // e6
            input_hash[7] as i64,  // e7
        ];

        // Loop through the remaining bytes of the input_hash        
        for i in 8..input_hash.len() {
            let rotation = [
                input_hash[i % 32] as i64,        // e0
                input_hash[(i + 1) % 32] as i64,  // e1
                input_hash[(i + 2) % 32] as i64,  // e2
                input_hash[(i + 3) % 32] as i64,  // e3
                input_hash[(i + 4) % 32] as i64,  // e4
                input_hash[(i + 5) % 32] as i64,  // e5
                input_hash[(i + 6) % 32] as i64,  // e6
                input_hash[(i + 7) % 32] as i64,  // e7
            ];

             // Perform octonion multiplication with the current rotation
            oct = Self::octonion_multiply(&oct, &rotation);
        }
    
        // Return the resulting octonion after applying all rotations
        oct
    }    

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
        

        // ** Octonion Function **
        let octonion_result = Self::octonion_hash(&product); // Compute the octonion hash of the product
        
        // XOR with u64 values - convert to u8
        for i in 0..32 {
            let oct_value = octonion_result[i / 8];
            
            // Extract the relevant byte from the u64 value
            let oct_value_u8 = ((oct_value >> (8 * (i % 8))) & 0xFF) as u8; 

            // XOR the values and store the result in the product
            product[i] ^= oct_value_u8;
        }
                
        // **Apply nonlinear S-Box**
        let mut sbox: [u8; 256] = [0; 256];

        // Fill the S-box using the bytes of the hash
        for i in 0..256 {
            sbox[i] = hash_bytes[i % hash_bytes.len()]; // Wrap around the hash bytes
        }

        // Number of iterations depends on the first byte of the product
        let iterations = 3 + (product[0] % 4);  // Modulo 4 gives values ​​from 0 to 3 → +3 gives 3 to 6

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

        // Final Cryptixhash v2
        CryptixHashV2::hash(Hash::from_bytes(product)) // Return
    }
}
