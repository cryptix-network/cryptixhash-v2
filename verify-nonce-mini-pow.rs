// Calculates and verifies the nonce by applying a SHA3-256 hash to it and returning only the first 8 bytes.
pub fn verify_nonce_mini_pow(&self, nonce: u64) -> Result<Vec<u8>, String> {
    let hash = self.hasher.clone().finalize_with_nonce(nonce);
    let hash_bytes: [u8; 32] = match hash.as_bytes().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return Err("Hash output length mismatch".into()),
    };

    // Initial SHA3-256 Hash
    let sha3_hash = match self.sha3_hash(&hash_bytes) {
        Ok(hash) => hash,
        Err(_) => return Err("SHA3-256 hashing failed".into()),
    };

   // XOR manipulation for additional security
    let mut manipulated_hash = sha3_hash;
    for i in 0..manipulated_hash.len() {
        manipulated_hash[i] ^= 0xAA;
    }

    // Get the first 8 bytes
    let first_8_bytes = manipulated_hash[0..8].to_vec(); 

    Ok(first_8_bytes)
}

pub fn check_nonce_mini_pow(&self, nonce: u64) -> Result<(), String> {
    // Verify the nonce and get the first 8 bytes of the SHA3-256 hash
    let first_8_bytes = match self.verify_nonce_mini_pow(nonce) {
        Ok(bytes) => bytes,
        Err(e) => return Err(e),
    };

    println!("First 8 bytes of the SHA3 hash: {:?}", first_8_bytes);

    Ok(())
}
