#include<stdint.h>
#include <assert.h>
#include "keccak-tiny.c"
#include "xoshiro256starstar.c"
#include "sha3.c"

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

// Memory Hard
#define MEMORY_TABLE_SIZE (16 * 1024) // 16 KB

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

__device__ __inline__ uint8_t generate_non_linear_sbox(uint8_t input, uint8_t key) {
    uint8_t result = input;
    result = result * key;  
    result = (result >> 3) | (result << 5);  
    result ^= 0x5A;  
    return result;
}

__device__ __inline__ uint8_t rotate_left(uint8_t value, int shift) {
    return (value << shift) | (value >> (8 - shift));
}

__device__ __inline__ uint8_t rotate_right(uint8_t value, int shift) {
    return (value >> shift) | (value << (8 - shift));
}

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

            // Use the first byte of the calculated hash to determine the number of iterations
            uint8_t first_byte = hash_.hash[0]; 
            uint8_t iteration_count = (uint8_t)((first_byte % 2) + 1); 

            memcpy(sha3_hash, hash_.hash, 32); // Copy the input hash to start

            for (uint8_t i = 0; i < iteration_count; ++i) {
                sha3(sha3_hash, 32, sha3_hash, 32); // SHA-3 calculation and saving the result in sha3_hash
            }

            // **Matrix Transformation**
            uchar4 packed_hash[QUARTER_MATRIX_SIZE] = {0};
            #pragma unroll
            for (int i = 0; i < QUARTER_MATRIX_SIZE; i++) {
                packed_hash[i] = make_uchar4(
                    (sha3_hash[2 * i] & 0xF0) >> 4,
                    (sha3_hash[2 * i] & 0x0F),
                    (sha3_hash[2 * i + 1] & 0xF0) >> 4,
                    (sha3_hash[2 * i + 1] & 0x0F)
                );
            }

            uint32_t product1, product2;
            uint8_t product[32] = {0};
            #pragma unroll
            for (int rowId = 0; rowId < HALF_MATRIX_SIZE; rowId++) {
                amul4bit((uint32_t *)(matrix[(2 * rowId)]), (uint32_t *)(packed_hash), &product1);
                amul4bit((uint32_t *)(matrix[(2 * rowId + 1)]), (uint32_t *)(packed_hash), &product2);

                uint8_t a_nibble = ((product1 & 0xF) ^ ((product2 >> 4) & 0xF) ^ ((product1 >> 8) & 0xF));
                uint8_t b_nibble = ((product2 & 0xF) ^ ((product1 >> 4) & 0xF) ^ ((product2 >> 8) & 0xF));

                product[rowId] = (a_nibble << 4) | b_nibble;
            }

            for (int i = 0; i < 32; i++) {
                product[i] ^= sha3_hash[i];
            }

             // ### Memory Hard

            // **Non-Linear S-Box**
            uint8_t sbox[256];
            for (int i = 0; i < 256; i++) {
                sbox[i] = sha3_hash[i % 32];  
            }

            // Calculate dynamic number of iterations (between 3 and 9)
            int iterations = 3 + (product[0] % 7);  

            for (int iter = 0; iter < iterations; iter++) {
                uint8_t temp_sbox[256];
                for (int i = 0; i < 256; i++) {
                    uint8_t value = sbox[i];
                    value = generate_non_linear_sbox(value, sha3_hash[i % 32] ^ product[i % 32]);
                    value ^= rotate_left(value, 4) | rotate_right(value, 2);
                    temp_sbox[i] = value;
                }
                memcpy(sbox, temp_sbox, 256);
            }

            // **Apply S-Box**
            for (int i = 0; i < 32; i++) {
                product[i] ^= sbox[product[i]];
            }

            //Branches
            for (int i = 0; i < 32; i++) {
                uint8_t cryptix_nonce = product[i];
                uint8_t condition = ((product[i] ^ sha3_hash[i % 32]) ^ cryptix_nonce) % 9; // 9 cases

                switch (condition) {
                    case 0:
                        // Main case 0
                        product[i] = (product[i] + 13) % 256;
                        product[i] = rotate_left(product[i], 3);  // Rotate left by 3 bits
        
                        // Nested logic in case 0
                        if (product[i] > 100) {
                            product[i] = (product[i] + 0x20) % 256;  // Add 0x20 if greater than 100
                        } else {
                            product[i] = (product[i] - 0x10) % 256;  // Subtract 0x10 if not
                        }
                        break;
                    case 1:
                        // Main case 1
                        product[i] = (product[i] - 7) % 256; 
                        product[i] = rotate_left(product[i], 5);  // Rotate left by 5 bits
        
                        // Nested logic in case 1
                        if (product[i] % 2 == 0) {
                            product[i] = (product[i] + 0x11) % 256;  // Add 0x11 if even
                        } else {
                            product[i] = (product[i] - 0x05) % 256;  // Subtract 0x05 if odd
                        }
                        break;
                    case 2:
                        // Main case 2
                        product[i] ^= 0x5A;                       // XOR with 0x5A
                        product[i] = (product[i] + 0xAC) % 256;   // Add 0xAC
        
                        // Nested logic in case 2
                        if (product[i] > 0x50) {
                            product[i] = (product[i] * 2) % 256;   // Multiply by 2 if greater than 0x50
                        } else {
                            product[i] = (product[i] / 3) % 256;   // Divide by 3 if not
                        }
                        break;
                    case 3:
                        // Main case 3
                        product[i] = (product[i] * 17) % 256;   // Multiply by 17
                        product[i] ^= 0xAA;                      // XOR with 0xAA
        
                        // Nested logic in case 3
                        if (product[i] % 4 == 0) {
                            product[i] = rotate_left(product[i], 4);  // Rotate left by 4 bits if divisible by 4
                        } else {
                            product[i] = rotate_right(product[i], 2); // Rotate right by 2 bits if not
                        }
                        break;
                    case 4:
                        // Main case 4
                        product[i] = (product[i] - 29) % 256;  // Subtract 29
                        product[i] = rotate_left(product[i], 1); // Rotate left by 1 bit
        
                        // Nested logic in case 4
                        if (product[i] < 50) {
                            product[i] = (product[i] + 0x55) % 256;  // Add 0x55 if less than 50
                        } else {
                            product[i] = (product[i] - 0x22) % 256;  // Subtract 0x22 if not
                        }
                        break;
                    case 5:
                        // Main case 5
                        product[i] = (product[i] + (0xAA ^ cryptix_nonce)) % 256; // Add XOR of 0xAA and nonce
                        product[i] ^= 0x45;  // XOR with 0x45
        
                        // Nested logic in case 5
                        if (product[i] & 0x0F == 0) {
                            product[i] = rotate_left(product[i], 6);  // Rotate left by 6 bits if lower nibble is 0
                        } else {
                            product[i] = rotate_right(product[i], 3); // Rotate right by 3 bits if not
                        }
                        break;
                    case 6:
                        // Main case 6
                        product[i] = (product[i] + 0x33) % 256;  // Add 0x33
                        product[i] = rotate_right(product[i], 4); // Rotate right by 4 bits
        
                        // Nested logic in case 6
                        if (product[i] < 0x80) {
                            product[i] = (product[i] - 0x22) % 256;  // Subtract 0x22 if less than 0x80
                        } else {
                            product[i] = (product[i] + 0x44) % 256;  // Add 0x44 if not
                        }
                        break;
                    case 7:
                        // Main case 7
                        product[i] = (product[i] * 3) % 256;    // Multiply by 3
                        product[i] = rotate_left(product[i], 2); // Rotate left by 2 bits
        
                        // Nested logic in case 7
                        if (product[i] > 0x50) {
                            product[i] = (product[i] + 0x11) % 256; // Add 0x11 if greater than 0x50
                        } else {
                            product[i] = (product[i] - 0x11) % 256; // Subtract 0x11 if not
                        }
                        break;
                    case 8:
                        // Main case 8
                        product[i] = (product[i] - 0x10) % 256;  // Subtract 0x10
                        product[i] = rotate_right(product[i], 3); // Rotate right by 3 bits
        
                        // Nested logic in case 8
                        if (product[i] % 3 == 0) {
                            product[i] = (product[i] + 0x55) % 256; // Add 0x55 if divisible by 3
                        } else {
                            product[i] = (product[i] - 0x33) % 256; // Subtract 0x33 if not
                        }
                        break;
                    default:
                        break;
                }
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



