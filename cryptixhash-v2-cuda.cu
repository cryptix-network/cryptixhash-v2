#include<stdint.h>
#include <assert.h>
#include "keccak-tiny.c"
#include "xoshiro256starstar.c"
#include "sha3.c"

typedef uint8_t u8; 
typedef uint64_t u64; 
typedef int64_t i64; 

typedef uint8_t Hash[32];

typedef union _uint256_t {
    uint64_t number[4];
    uint8_t hash[32];
} uint256_t;

#define BLOCKDIM 1024
#define MATRIX_SIZE 64
#define HALF_MATRIX_SIZE 32
#define QUARTER_MATRIX_SIZE 16
#define HASH_HEADER_SIZE 72

#define RANDOM_LEAN 0
#define RANDOM_XOSHIRO 1

#define LT_U256(X,Y) (X.number[3] != Y.number[3] ? X.number[3] < Y.number[3] : X.number[2] != Y.number[2] ? X.number[2] < Y.number[2] : X.number[1] != Y.number[1] ? X.number[1] < Y.number[1] : X.number[0] < Y.number[0])

__constant__ uint8_t matrix[MATRIX_SIZE][MATRIX_SIZE];
__constant__ uint8_t hash_header[HASH_HEADER_SIZE];
__constant__ uint256_t target;
__constant__ static const uint8_t powP[Plen] = { 0x3d, 0xd8, 0xf6, 0xa1, 0x0d, 0xff, 0x3c, 0x11, 0x3c, 0x7e, 0x02, 0xb7, 0x55, 0x88, 0xbf, 0x29, 0xd2, 0x44, 0xfb, 0x0e, 0x72, 0x2e, 0x5f, 0x1e, 0xa0, 0x69, 0x98, 0xf5, 0xa3, 0xa4, 0xa5, 0x1b, 0x65, 0x2d, 0x5e, 0x87, 0xca, 0xaf, 0x2f, 0x7b, 0x46, 0xe2, 0xdc, 0x29, 0xd6, 0x61, 0xef, 0x4a, 0x10, 0x5b, 0x41, 0xad, 0x1e, 0x98, 0x3a, 0x18, 0x9c, 0xc2, 0x9b, 0x78, 0x0c, 0xf6, 0x6b, 0x77, 0x40, 0x31, 0x66, 0x88, 0x33, 0xf1, 0xeb, 0xf8, 0xf0, 0x5f, 0x28, 0x43, 0x3c, 0x1c, 0x65, 0x2e, 0x0a, 0x4a, 0xf1, 0x40, 0x05, 0x07, 0x96, 0x0f, 0x52, 0x91, 0x29, 0x5b, 0x87, 0x67, 0xe3, 0x44, 0x15, 0x37, 0xb1, 0x25, 0xa4, 0xf1, 0x70, 0xec, 0x89, 0xda, 0xe9, 0x82, 0x8f, 0x5d, 0xc8, 0xe6, 0x23, 0xb2, 0xb4, 0x85, 0x1f, 0x60, 0x1a, 0xb2, 0x46, 0x6a, 0xa3, 0x64, 0x90, 0x54, 0x85, 0x34, 0x1a, 0x85, 0x2f, 0x7a, 0x1c, 0xdd, 0x06, 0x0f, 0x42, 0xb1, 0x3b, 0x56, 0x1d, 0x02, 0xa2, 0xc1, 0xe4, 0x68, 0x16, 0x45, 0xe4, 0xe5, 0x1d, 0xba, 0x8d, 0x5f, 0x09, 0x05, 0x41, 0x57, 0x02, 0xd1, 0x4a, 0xcf, 0xce, 0x9b, 0x84, 0x4e, 0xca, 0x89, 0xdb, 0x2e, 0x74, 0xa8, 0x27, 0x94, 0xb0, 0x48, 0x72, 0x52, 0x8b, 0xe7, 0x9c, 0xce, 0xfc, 0xb1, 0xbc, 0xa5, 0xaf, 0x82, 0xcf, 0x29, 0x11, 0x5d, 0x83, 0x43, 0x82, 0x6f, 0x78, 0x7c, 0xb9, 0x02 };
__constant__ static const uint8_t heavyP[Plen] = { 0x09, 0x85, 0x24, 0xb2, 0x52, 0x4c, 0xd7, 0x3a, 0x16, 0x42, 0x9f, 0x2f, 0x0e, 0x9b, 0x62, 0x79, 0xee, 0xf8, 0xc7, 0x16, 0x48, 0xff, 0x14, 0x7a, 0x98, 0x64, 0x05, 0x80, 0x4c, 0x5f, 0xa7, 0x11, 0xda, 0xce, 0xee, 0x44, 0xdf, 0xe0, 0x20, 0xe7, 0x69, 0x40, 0xf3, 0x14, 0x2e, 0xd8, 0xc7, 0x72, 0xba, 0x35, 0x89, 0x93, 0x2a, 0xff, 0x00, 0xc1, 0x62, 0xc4, 0x0f, 0x25, 0x40, 0x90, 0x21, 0x5e, 0x48, 0x6a, 0xcf, 0x0d, 0xa6, 0xf9, 0x39, 0x80, 0x0c, 0x3d, 0x2a, 0x79, 0x9f, 0xaa, 0xbc, 0xa0, 0x26, 0xa2, 0xa9, 0xd0, 0x5d, 0xc0, 0x31, 0xf4, 0x3f, 0x8c, 0xc1, 0x54, 0xc3, 0x4c, 0x1f, 0xd3, 0x3d, 0xcc, 0x69, 0xa7, 0x01, 0x7d, 0x6b, 0x6c, 0xe4, 0x93, 0x24, 0x56, 0xd3, 0x5b, 0xc6, 0x2e, 0x44, 0xb0, 0xcd, 0x99, 0x3a, 0x4b, 0xf7, 0x4e, 0xb0, 0xf2, 0x34, 0x54, 0x83, 0x86, 0x4c, 0x77, 0x16, 0x94, 0xbc, 0x36, 0xb0, 0x61, 0xe9, 0x07, 0x07, 0xcc, 0x65, 0x77, 0xb1, 0x1d, 0x8f, 0x7e, 0x39, 0x6d, 0xc4, 0xba, 0x80, 0xdb, 0x8f, 0xea, 0x58, 0xca, 0x34, 0x7b, 0xd3, 0xf2, 0x92, 0xb9, 0x57, 0xb9, 0x81, 0x84, 0x04, 0xc5, 0x76, 0xc7, 0x2e, 0xc2, 0x12, 0x51, 0x67, 0x9f, 0xc3, 0x47, 0x0a, 0x0c, 0x29, 0xb5, 0x9d, 0x39, 0xbb, 0x92, 0x15, 0xc6, 0x9f, 0x2f, 0x31, 0xe0, 0x9a, 0x54, 0x35, 0xda, 0xb9, 0x10, 0x7d, 0x32, 0x19, 0x16 };

__device__ __inline__ void amul4bit(uint32_t packed_vec1[32], uint32_t packed_vec2[32], uint32_t *ret) {
    unsigned int res = 0;
    #if __CUDA_ARCH__ < 610
    char4 *a4 = (char4*)packed_vec1;
    char4 *b4 = (char4*)packed_vec2;
    #endif
    #pragma unroll
    for (int i = 0; i < QUARTER_MATRIX_SIZE; i++) {
        #if __CUDA_ARCH__ >= 610
        res = __dp4a(packed_vec1[i], packed_vec2[i], res);
        #else
        res += a4[i].x * b4[i].x;
        res += a4[i].y * b4[i].y;
        res += a4[i].z * b4[i].z;
        res += a4[i].w * b4[i].w;
        #endif
    }
    *ret = res;
}

// Rotate left
__device__ __inline__ uint8_t rotate_left(uint8_t value, int shift) {
    return (value << shift) | (value >> (8 - shift));
}

// Rotate right
__device__ __inline__ uint8_t rotate_right(uint8_t value, int shift) {
    return (value >> shift) | (value << (8 - shift));
}

// Wrapping Mul
__device__ u64 wrapping_mul(i64 a, i64 b) {
    i64 high, low;
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(low) : "l"(a), "l"(b));
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(high) : "l"(a), "l"(b));
    return low;  
}

// Octonion
__device__ void octonion_multiply(const i64 *a, const i64 *b, i64 *result) {
    volatile i64 res[8];

    
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
        */

    res[0] = wrapping_mul(a[0], b[0]) - wrapping_mul(a[1], b[1]) - wrapping_mul(a[2], b[2]) - wrapping_mul(a[3], b[3]) 
             - wrapping_mul(a[4], b[4]) - wrapping_mul(a[5], b[5]) - wrapping_mul(a[6], b[6]) - wrapping_mul(a[7], b[7]);

    res[1] = wrapping_mul(a[0], b[1]) + wrapping_mul(a[1], b[0]) + wrapping_mul(a[2], b[3]) - wrapping_mul(a[3], b[2]) 
             + wrapping_mul(a[4], b[5]) - wrapping_mul(a[5], b[4]) - wrapping_mul(a[6], b[7]) + wrapping_mul(a[7], b[6]);

    res[2] = wrapping_mul(a[0], b[2]) - wrapping_mul(a[1], b[3]) + wrapping_mul(a[2], b[0]) + wrapping_mul(a[3], b[1]) 
             + wrapping_mul(a[4], b[6]) - wrapping_mul(a[5], b[7]) + wrapping_mul(a[6], b[4]) - wrapping_mul(a[7], b[5]);

    res[3] = wrapping_mul(a[0], b[3]) + wrapping_mul(a[1], b[2]) - wrapping_mul(a[2], b[1]) + wrapping_mul(a[3], b[0]) 
             + wrapping_mul(a[4], b[7]) + wrapping_mul(a[5], b[6]) - wrapping_mul(a[6], b[5]) + wrapping_mul(a[7], b[4]);

    res[4] = wrapping_mul(a[0], b[4]) - wrapping_mul(a[1], b[5]) - wrapping_mul(a[2], b[6]) - wrapping_mul(a[3], b[7]) 
             + wrapping_mul(a[4], b[0]) + wrapping_mul(a[5], b[1]) + wrapping_mul(a[6], b[2]) + wrapping_mul(a[7], b[3]);

    res[5] = wrapping_mul(a[0], b[5]) + wrapping_mul(a[1], b[4]) - wrapping_mul(a[2], b[7]) + wrapping_mul(a[3], b[6]) 
             - wrapping_mul(a[4], b[1]) + wrapping_mul(a[5], b[0]) + wrapping_mul(a[6], b[3]) + wrapping_mul(a[7], b[2]);

    res[6] = wrapping_mul(a[0], b[6]) + wrapping_mul(a[1], b[7]) + wrapping_mul(a[2], b[4]) - wrapping_mul(a[3], b[5]) 
             - wrapping_mul(a[4], b[2]) + wrapping_mul(a[5], b[3]) + wrapping_mul(a[6], b[0]) + wrapping_mul(a[7], b[1]);

    res[7] = wrapping_mul(a[0], b[7]) - wrapping_mul(a[1], b[6]) + wrapping_mul(a[2], b[5]) + wrapping_mul(a[3], b[4]) 
             - wrapping_mul(a[4], b[3]) + wrapping_mul(a[5], b[2]) + wrapping_mul(a[6], b[1]) + wrapping_mul(a[7], b[0]);

    for (int i = 0; i < 8; i++) {
        result[i] = res[i];
    }
}

// Octonion Hash
__device__ void octonion_hash(const u8 *input_hash, i64 *oct) {

    for (int i = 0; i < 8; i++) {
        oct[i] = static_cast<i64>(input_hash[i]);
    }

    for (int i = 8; i < 32; i++) {
        i64 rotation[8];

        for (int j = 0; j < 8; j++) {
            rotation[j] = static_cast<i64>(input_hash[(i + j) % 32]);
        }

        i64 result[8];
        octonion_multiply(oct, rotation, result);

        for (int j = 0; j < 8; j++) {
            oct[j] = result[j];
        }
    }
}

// Main
extern "C" {
    __global__ void heavy_hash(const uint64_t nonce_mask, const uint64_t nonce_fixed, const uint64_t nonces_len, uint8_t random_type, void* states, uint64_t *final_nonce) {
        
        uint8_t sha3_hash[32];
        
        int nonceId = threadIdx.x + blockIdx.x * blockDim.x;
        if (nonceId < nonces_len) {
            if (nonceId == 0) *final_nonce = 0;
            uint64_t nonce;
            switch (random_type) {
                case RANDOM_LEAN:
                    nonce = ((uint64_t *)states)[0] ^ nonceId;
                    break;
                case RANDOM_XOSHIRO:
                default:
                    nonce = xoshiro256_next(((ulonglong4 *)states) + nonceId);
                    break;
            }
            nonce = (nonce & nonce_mask) | nonce_fixed;

            uint8_t input[80];
            memcpy(input, hash_header, HASH_HEADER_SIZE);

            uint256_t hash_;
            memcpy(input + HASH_HEADER_SIZE, (uint8_t *)(&nonce), 8);
            hash(powP, hash_.hash, input);

            // Sha3 - The first byte modulo 2, plus 1 for the range [1 - 3]
            uint8_t first_byte = hash_.hash[0]; 
            uint8_t iteration_count = (uint8_t)((first_byte % 3) + 1); 
            

            #pragma unroll
            for (int i = 0; i < 32; i++) {
                sha3_hash[i] = hash_.hash[i];
            }
            
            // Iterative SHA3 process
            for (uint8_t i = 0; i < iteration_count; ++i) {
                sha3(sha3_hash, 32, sha3_hash, 32);  // Perform SHA3 operation on sha3_hash

                // Dynamic hash transformation based on conditions
                if (sha3_hash[1] % 4 == 0) {
                    uint8_t repeat = (sha3_hash[2] % 4) + 1; // 1-4 iterations based on the value of byte 2
                    for (uint8_t j = 0; j < repeat; ++j) {
                        // Dynamically select the byte to modify based on a combination of hash bytes and iteration
                        uint8_t target_byte = ((sha3_hash[1] + i) % 32);  // Dynamic byte position for XOR
                        uint8_t xor_value = sha3_hash[i % 16] ^ 0xA5; // Dynamic XOR value based on iteration index and hash
                        sha3_hash[target_byte] ^= xor_value;  // XOR on dynamically selected byte

                        // Dynamically choose the byte to calculate rotation based on the current iteration
                        uint8_t rotation_byte = sha3_hash[i % 32];  // Use different byte based on iteration index
                        uint8_t rotation_amount = (sha3_hash[1] + sha3_hash[3]) % 4 + 2; // Combined rotation calculation

                        // Perform rotation based on whether the rotation byte is even or odd
                        if (rotation_byte % 2 == 0) {
                            // Rotate byte at dynamic position to the left by 'rotation_amount' positions
                            sha3_hash[target_byte] = rotate_left(sha3_hash[target_byte], rotation_amount);
                        } else {
                            // Rotate byte at dynamic position to the right by 'rotation_amount' positions
                            sha3_hash[target_byte] = rotate_right(sha3_hash[target_byte], rotation_amount);
                        }

                        // Perform additional bitwise manipulation on the target byte using a shift
                        uint8_t shift_amount = (sha3_hash[5] + sha3_hash[1]) % 3 + 1; // Combined shift calculation
                        sha3_hash[target_byte] ^= rotate_left(sha3_hash[target_byte], shift_amount); // XOR with rotated value
                    }
                } else if (sha3_hash[3] % 3 == 0) {
                    uint8_t repeat = (sha3_hash[4] % 5) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        uint8_t target_byte = ((sha3_hash[6] + i) % 32); 
                        uint8_t xor_value = sha3_hash[i % 16] ^ 0x55;
                        sha3_hash[target_byte] ^= xor_value;

                        uint8_t rotation_byte = sha3_hash[i % 32];
                        uint8_t rotation_amount = (sha3_hash[7] + sha3_hash[2]) % 6 + 1;
                        if (rotation_byte % 2 == 0) {
                            sha3_hash[target_byte] = rotate_left(sha3_hash[target_byte], rotation_amount);
                        } else {
                            sha3_hash[target_byte] = rotate_right(sha3_hash[target_byte], rotation_amount);
                        }

                        uint8_t shift_amount = (sha3_hash[1] + sha3_hash[3]) % 4 + 1; 
                        sha3_hash[target_byte] ^= rotate_left(sha3_hash[target_byte], shift_amount);
                    }
                } else if (sha3_hash[2] % 6 == 0) {
                    uint8_t repeat = (sha3_hash[6] % 4) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        uint8_t target_byte = ((sha3_hash[10] + i) % 32); 
                        uint8_t xor_value = sha3_hash[i % 16] ^ 0xFF;
                        sha3_hash[target_byte] ^= xor_value;

                        uint8_t rotation_byte = sha3_hash[i % 32];  
                        uint8_t rotation_amount = (sha3_hash[7] + sha3_hash[7]) % 7 + 1;
                        if (rotation_byte % 2 == 0) {
                            sha3_hash[target_byte] = rotate_left(sha3_hash[target_byte], rotation_amount);
                        } else {
                            sha3_hash[target_byte] = rotate_right(sha3_hash[target_byte], rotation_amount);
                        }

                        uint8_t shift_amount = (sha3_hash[3] + sha3_hash[5]) % 5 + 2; 
                        sha3_hash[target_byte] ^= rotate_left(sha3_hash[target_byte], shift_amount);
                    }
                } else if (sha3_hash[7] % 5 == 0) {
                    uint8_t repeat = (sha3_hash[8] % 4) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        uint8_t target_byte = ((sha3_hash[25] + i) % 32); 
                        uint8_t xor_value = sha3_hash[i % 16] ^ 0x66;
                        sha3_hash[target_byte] ^= xor_value;

                        uint8_t rotation_byte = sha3_hash[i % 32]; 
                        uint8_t rotation_amount = (sha3_hash[1] + sha3_hash[3]) % 4 + 2;
                        if (rotation_byte % 2 == 0) {
                            sha3_hash[target_byte] = rotate_left(sha3_hash[target_byte], rotation_amount);
                        } else {
                            sha3_hash[target_byte] = rotate_right(sha3_hash[target_byte], rotation_amount);
                        }

                        uint8_t shift_amount = (sha3_hash[1] + sha3_hash[3]) % 4 + 1; 
                        sha3_hash[target_byte] ^= rotate_left(sha3_hash[target_byte], shift_amount);
                    }
                } else if (sha3_hash[8] % 7 == 0) {
                    uint8_t repeat = (sha3_hash[9] % 5) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        uint8_t target_byte = ((sha3_hash[30] + i) % 32); 
                        uint8_t xor_value = sha3_hash[i % 16] ^ 0x77; 
                        sha3_hash[target_byte] ^= xor_value;

                        uint8_t rotation_byte = sha3_hash[i % 32];  
                        uint8_t rotation_amount = (sha3_hash[2] + sha3_hash[5]) % 5 + 1;
                        if (rotation_byte % 2 == 0) {
                            sha3_hash[target_byte] = rotate_left(sha3_hash[target_byte], rotation_amount);
                        } else {
                            sha3_hash[target_byte] = rotate_right(sha3_hash[target_byte], rotation_amount);
                        }

                        uint8_t shift_amount = (sha3_hash[7] + sha3_hash[9]) % 6 + 2; 
                        sha3_hash[target_byte] ^= rotate_left(sha3_hash[target_byte], shift_amount);
                    }
                }
            }

            // **Matrix Transformation**
            uchar4 packed_hash[QUARTER_MATRIX_SIZE];
            #pragma unroll
            for (int i = 0; i < QUARTER_MATRIX_SIZE; i++) {
                uint8_t h1 = sha3_hash[2 * i], h2 = sha3_hash[2 * i + 1];
                packed_hash[i] = make_uchar4((h1 >> 4), (h1 & 0xF), (h2 >> 4), (h2 & 0xF));
            }

            uint8_t product[32] = {0};
            uint8_t nibble_product[32] = {0};
            
            #pragma unroll
            for (int rowId = 0; rowId < HALF_MATRIX_SIZE; rowId++) {
                uint32_t product1, product2, product3, product4;
                amul4bit((uint32_t *)(matrix[(2 * rowId)]), (uint32_t *)(packed_hash), &product1);
                amul4bit((uint32_t *)(matrix[(2 * rowId + 1)]), (uint32_t *)(packed_hash), &product2);
                amul4bit((uint32_t *)(matrix[(1 * rowId + 2)]), (uint32_t *)(packed_hash), &product3);
                amul4bit((uint32_t *)(matrix[(1 * rowId + 3)]), (uint32_t *)(packed_hash), &product4);
                
                // Calculate a_nibble and b_nibble for product
                uint8_t a_nibble = (product1 & 0xF) ^ ((product2 >> 4) & 0xF) ^ ((product3 >> 8) & 0xF);
                uint8_t b_nibble = (product2 & 0xF) ^ ((product1 >> 4) & 0xF) ^ ((product4 >> 8) & 0xF);
            
                // Store in product array
                product[rowId] = ((a_nibble << 4) | b_nibble);
            
                // Calculate c_nibble and d_nibble for nibble_product
                uint8_t c_nibble = (product3 & 0xF) ^ ((product2 >> 4) & 0xF) ^ ((product2 >> 8) & 0xF);
                uint8_t d_nibble = (product1 & 0xF) ^ ((product4 >> 4) & 0xF) ^ ((product1 >> 8) & 0xF);
            
                // Store in nibble_product array
                nibble_product[rowId] = ((c_nibble << 4) | d_nibble);
            }

            uint8_t product_before_oct[32]; 

            // XOR the product with the original hash   
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                product[i] ^= sha3_hash[i];
                product_before_oct[i] = product[i];
            }

            // ** Octonion**
            i64 octonion_result[8];
            octonion_hash(product, octonion_result);
            
            for (int i = 0; i < 32; i++) {
                i64 oct_value = octonion_result[i / 8];
            
                u8 oct_value_u8 = (u8)((oct_value >> (8 * (i % 8))) & 0xFF);
            
                product[i] ^= oct_value_u8;
            }

            // **Non-Linear S-Box**
            #pragma unroll
            uint8_t sbox[256];

            for (int i = 0; i < 256; i++) {
                uint8_t i_u8 = (uint8_t)i;
            
                uint8_t* source_array;
                uint8_t rotate_left_val, rotate_right_val;
            
                if (i_u8 < 16) { source_array = product; rotate_left_val = nibble_product[3] ^ 0x4F; rotate_right_val = sha3_hash[2] ^ 0xD3; }
                    else if (i_u8 < 32) { source_array = sha3_hash; rotate_left_val = product[7] ^ 0xA6; rotate_right_val = nibble_product[5] ^ 0x5B; }
                    else if (i_u8 < 48) { source_array = nibble_product; rotate_left_val = product_before_oct[1] ^ 0x9C; rotate_right_val = product[0] ^ 0x8E; }
                    else if (i_u8 < 64) { source_array = sha3_hash; rotate_left_val = product[6] ^ 0x71; rotate_right_val = product_before_oct[3] ^ 0x2F; }
                    else if (i_u8 < 80) { source_array = product_before_oct; rotate_left_val = nibble_product[4] ^ 0xB2; rotate_right_val = sha3_hash[7] ^ 0x6D; }
                    else if (i_u8 < 96) { source_array = sha3_hash; rotate_left_val = product[0] ^ 0x58; rotate_right_val = nibble_product[1] ^ 0xEE; }
                    else if (i_u8 < 112) { source_array = product; rotate_left_val = product_before_oct[2] ^ 0x37; rotate_right_val = sha3_hash[6] ^ 0x44; }
                    else if (i_u8 < 128) { source_array = sha3_hash; rotate_left_val = product[5] ^ 0x1A; rotate_right_val = sha3_hash[4] ^ 0x7C; }
                    else if (i_u8 < 144) { source_array = product_before_oct; rotate_left_val = nibble_product[3] ^ 0x93; rotate_right_val = product[2] ^ 0xAF; }
                    else if (i_u8 < 160) { source_array = sha3_hash; rotate_left_val = product[7] ^ 0x29; rotate_right_val = nibble_product[5] ^ 0xDC; }
                    else if (i_u8 < 176) { source_array = nibble_product; rotate_left_val = product_before_oct[1] ^ 0x4E; rotate_right_val = sha3_hash[0] ^ 0x8B; }
                    else if (i_u8 < 192) { source_array = sha3_hash; rotate_left_val = nibble_product[6] ^ 0xF3; rotate_right_val = product_before_oct[3] ^ 0x62; }
                    else if (i_u8 < 208) { source_array = product_before_oct; rotate_left_val = product[4] ^ 0xB7; rotate_right_val = product[7] ^ 0x15; }
                    else if (i_u8 < 224) { source_array = sha3_hash; rotate_left_val = product[0] ^ 0x2D; rotate_right_val = product_before_oct[1] ^ 0xC8; }
                    else if (i_u8 < 240) { source_array = product; rotate_left_val = product_before_oct[2] ^ 0x6F; rotate_right_val = nibble_product[6] ^ 0x99; }
                    else { source_array = sha3_hash; rotate_left_val = nibble_product[5] ^ 0xE1; rotate_right_val = sha3_hash[4] ^ 0x3B; }
                
            
                uint8_t value = (i_u8 < 16) ? product[i_u8 % 32] ^ 0xAA :
                    (i_u8 < 32) ? sha3_hash[(i_u8 - 16) % 32] ^ 0xBB :
                    (i_u8 < 48) ? product_before_oct[(i_u8 - 32) % 32] ^ 0xCC :
                    (i_u8 < 64) ? nibble_product[(i_u8 - 48) % 32] ^ 0xDD :
                    (i_u8 < 80) ? product[(i_u8 - 64) % 32] ^ 0xEE :
                    (i_u8 < 96) ? sha3_hash[(i_u8 - 80) % 32] ^ 0xFF :
                    (i_u8 < 112) ? product_before_oct[(i_u8 - 96) % 32] ^ 0x11 :
                    (i_u8 < 128) ? nibble_product[(i_u8 - 112) % 32] ^ 0x22 :
                    (i_u8 < 144) ? product[(i_u8 - 128) % 32] ^ 0x33 :
                    (i_u8 < 160) ? sha3_hash[(i_u8 - 144) % 32] ^ 0x44 :
                    (i_u8 < 176) ? product_before_oct[(i_u8 - 160) % 32] ^ 0x55 :
                    (i_u8 < 192) ? nibble_product[(i_u8 - 176) % 32] ^ 0x66 :
                    (i_u8 < 208) ? product[(i_u8 - 192) % 32] ^ 0x77 :
                    (i_u8 < 224) ? sha3_hash[(i_u8 - 208) % 32] ^ 0x88 :
                    (i_u8 < 240) ? product_before_oct[(i_u8 - 224) % 32] ^ 0x99 :
                                   nibble_product[(i_u8 - 240) % 32] ^ 0xAA;

            
                int rotate_left_shift = (product[(i + 1) % 32] + i) % 8;
                int rotate_right_shift = (sha3_hash[(i + 2) % 32] + i) % 8;
            
                int rotation_left = (rotate_left_val << rotate_left_shift) | (rotate_left_val >> (8 - rotate_left_shift));
                int rotation_right = (rotate_right_val >> rotate_right_shift) | (rotate_right_val << (8 - rotate_right_shift));
            
                rotation_left &= 0xFF;
                rotation_right &= 0xFF;
            
                int index = (i + rotation_left + rotation_right) % 32;
                sbox[i] = source_array[index] ^ value;
            }
            
            // Update Sbox Values
            int iterations = 1 + (product[0] % 3);

            uint8_t temp_sbox[256];
            
            for (int iter = 0; iter < iterations; iter++) {
                memcpy(temp_sbox, sbox, 256);

                for (int i = 0; i < 256; i++) {
                    uint8_t value = temp_sbox[i];

                    uint8_t rotate_left_shift = (product[(i + 1) % 32] + i + (i * 3)) % 8;
                    uint8_t rotate_right_shift = (sha3_hash[(i + 2) % 32] + i + (i * 5)) % 8;

                    uint8_t rotated_value = rotate_left(value, rotate_left_shift) | rotate_right(value, rotate_right_shift);

                    uint8_t base_value = static_cast<uint8_t>((i + (product[(i * 3) % 32] ^ sha3_hash[(i * 7) % 32])) & 0xFF) ^ 0xA5;
                    uint8_t shifted_value = rotate_left(base_value, static_cast<uint32_t>(i % 8));
                    uint8_t xor_value = shifted_value ^ 0x55;

                    value ^= rotated_value ^ xor_value;

                    temp_sbox[i] = value;
                }

                memcpy(sbox, temp_sbox, 256);
            }

            // **Apply S-Box**
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                int array_selector = (i * 31) % 4;
                const uint8_t* ref_array;

                switch (array_selector) {
                    case 0: ref_array = nibble_product; break;
                    case 1: ref_array = sha3_hash; break;
                    case 2: ref_array = product; break;
                    default: ref_array = product_before_oct; break;
                }

                int byte_val = ref_array[(i * 13) % 32];  

                int index = (byte_val 
                            + product[(i * 31) % 32] 
                            + sha3_hash[(i * 19) % 32] 
                            + i * 41) % 256;  

                product[i] ^= sbox[index];
            }


            memset(input, 0, 80);
            memcpy(input, product, 32);
            hash(heavyP, hash_.hash, input);

            if (LT_U256(hash_, target)) {
                atomicCAS((unsigned long long int*)final_nonce, 0, (unsigned long long int)nonce);
            }
        }
    }
}