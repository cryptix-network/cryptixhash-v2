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
// Sbox
__device__ __inline__ uint8_t generate_non_linear_sbox(uint8_t input, uint8_t key) {
    input *= key;
    input = (input >> 3) | (input << 5);
    return input ^ 0x5A;
}

// Rotate left
__device__ __inline__ uint8_t rotate_left(uint8_t value, int shift) {
    return (value << shift) | (value >> (8 - shift));
}

// Rotate right
__device__ __inline__ uint8_t rotate_right(uint8_t value, int shift) {
    return (value >> shift) | (value << (8 - shift));
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

            // Sha3 - The first byte modulo 2, plus 1 for the range [1, 2]
            uint8_t first_byte = hash_.hash[0]; 
            uint8_t iteration_count = (uint8_t)((first_byte % 2) + 1); 

            #pragma unroll
            for (int i = 0; i < 32; i++) {
                sha3_hash[i] = hash_.hash[i];
            }
            
            // Iterative SHA3 process
            for (uint8_t i = 0; i < iteration_count; ++i) {
                sha3(sha3_hash, 32, sha3_hash, 32);  // Perform SHA3 operation on sha3_hash

                // Conditions based on hash values
                if (sha3_hash[3] % 3 == 0) { 
                    uint8_t repeat = (sha3_hash[4] % 3) + 1; // 1-3 iterations
                    for (uint8_t j = 0; j < repeat; ++j) {
                        sha3_hash[20] ^= 0x55; // XOR with 0x55
                    }
                } 
                else if (sha3_hash[7] % 5 == 0) { 
                    uint8_t repeat = (sha3_hash[8] % 3) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        sha3_hash[25] = rotate_left(sha3_hash[25], 7); // Rotate left by 7
                    }
                } 
                else if (sha3_hash[5] % 2 == 0) { 
                    uint8_t repeat = (sha3_hash[6] % 3) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        sha3_hash[10] ^= 0xAA; // XOR with 0xAA
                    }
                } 
                else if (sha3_hash[6] % 4 == 0) {
                    uint8_t repeat = (sha3_hash[7] % 3) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        sha3_hash[15] = rotate_left(sha3_hash[15], 3); // Rotate left by 3
                    }
                } 
                else if (sha3_hash[8] % 7 == 0) {
                    uint8_t repeat = (sha3_hash[9] % 3) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        sha3_hash[30] ^= 0xFF; // XOR with 0xFF
                    }
                } 
                else if (sha3_hash[9] % 11 == 0) {
                    uint8_t repeat = (sha3_hash[10] % 3) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        sha3_hash[5] = rotate_right(sha3_hash[5], 4); // Rotate right by 4
                    }
                } 
                else if (sha3_hash[12] % 13 == 0) {
                    uint8_t repeat = (sha3_hash[13] % 3) + 1;
                    for (uint8_t j = 0; j < repeat; ++j) {
                        sha3_hash[18] = rotate_left(sha3_hash[18], 2); // Rotate left by 2
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

            uint32_t product1, product2;
            uint8_t product[32] = {0};
            #pragma unroll
            for (int rowId = 0; rowId < HALF_MATRIX_SIZE; rowId++) {
                uint32_t product1, product2;
                amul4bit((uint32_t *)(matrix[(2 * rowId)]), (uint32_t *)(packed_hash), &product1);
                amul4bit((uint32_t *)(matrix[(2 * rowId + 1)]), (uint32_t *)(packed_hash), &product2);
        
                product[rowId] = (((product1 & 0xF) ^ ((product2 >> 4) & 0xF) ^ ((product1 >> 8) & 0xF)) << 4) |
                                 ((product2 & 0xF) ^ ((product1 >> 4) & 0xF) ^ ((product2 >> 8) & 0xF));
            }

            // XOR the product with the original hash   
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                product[i] ^= sha3_hash[i];
            }

             // ### Memory Hard

            // **Non-Linear S-Box**
            #pragma unroll
            uint8_t sbox[256];
            for (int i = 0; i < 256; i++) {
                sbox[i] = sha3_hash[i % 32];  
            }

            // Calculate dynamic number of iterations
            int iterations = 3 + (product[0] % 4);  // 3 - 6

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
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                product[i] ^= sbox[product[i]];
            }

            #pragma unroll
            for (int i = 0; i < 32; i++) {
                uint8_t cryptix_nonce = product[i];
                uint8_t condition = ((product[i] ^ sha3_hash[i % 32]) ^ cryptix_nonce) % 9;
            
                uint8_t p = product[i];
            
                if (condition == 0) {
                    p = (p + 13) % 256;
                    p = rotate_left(p, 3);
                    if (p > 100) {
                        p += 0x20;
                    } else {
                        p -= 0x10;
                    }
                } else if (condition == 1) {
                    p = (p - 7) % 256;
                    p = rotate_left(p, 5);
                    if (p % 2 == 0) {
                        p += 0x11;
                    } else {
                        p -= 0x05;
                    }
                } else if (condition == 2) {
                    p ^= 0x5A;
                    p = (p + 0xAC) % 256;
                    if (p > 0x50) {
                        p = (p * 2) % 256;
                    } else {
                        p = (p / 3) % 256;
                    }
                } else if (condition == 3) {
                    p = (p * 17) % 256;
                    p ^= 0xAA;
                    if (p % 4 == 0) {
                        p = rotate_left(p, 4);
                    } else {
                        p = rotate_right(p, 2);
                    }
                } else if (condition == 4) {
                    p = (p - 29) % 256;
                    p = rotate_left(p, 1);
                    if (p < 50) {
                        p += 0x55;
                    } else {
                        p -= 0x22;
                    }
                } else if (condition == 5) {
                    p = (p + (0xAA ^ cryptix_nonce)) % 256;
                    p ^= 0x45;
                    if ((p & 0x0F) == 0) {
                        p = rotate_left(p, 6);
                    } else {
                        p = rotate_right(p, 3);
                    }
                } else if (condition == 6) {
                    p = (p + 0x33) % 256;
                    p = rotate_right(p, 4);
                    if (p < 0x80) {
                        p -= 0x22;
                    } else {
                        p += 0x44;
                    }
                } else if (condition == 7) {
                    p = (p * 3) % 256;
                    p = rotate_left(p, 2);
                    if (p > 0x50) {
                        p += 0x11;
                    } else {
                        p -= 0x11;
                    }
                } else if (condition == 8) {
                    p = (p - 0x10) % 256;
                    p = rotate_right(p, 3);
                    if (p % 3 == 0) {
                        p += 0x55;
                    } else {
                        p -= 0x33;
                    }
                }
            
                product[i] = p;
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