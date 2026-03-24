#include <stdint.h>
#include <string.h>

#include "xoshiro256starstar.c"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef union _uint256_t {
    u64 number[4];
    u8 hash[32];
} uint256_t;

#define MATRIX_SIZE 64
#define HASH_HEADER_SIZE 72
#define MATRIX_ELEMS (MATRIX_SIZE * MATRIX_SIZE)

#define RANDOM_LEAN 0
#define RANDOM_XOSHIRO 1

__constant__ u8 matrix[MATRIX_SIZE][MATRIX_SIZE];
__constant__ u8 hash_header[HASH_HEADER_SIZE];
__constant__ uint256_t target;
__device__ __constant__ static const u64 POW_HASH_INITIAL_STATE[25] = {
    1242148031264380989ULL, 3008272977830772284ULL, 2188519011337848018ULL, 1992179434288343456ULL,
    8876506674959887717ULL, 5399642050693751366ULL, 1745875063082670864ULL, 8605242046444978844ULL,
    17936695144567157056ULL, 3343109343542796272ULL, 1123092876221303306ULL, 4963925045340115282ULL,
    17037383077651887893ULL, 16629644495023626889ULL, 12833675776649114147ULL, 3784524041015224902ULL,
    1082795874807940378ULL, 13952716920571277634ULL, 13411128033953605860ULL, 15060696040649351053ULL,
    9928834659948351306ULL, 5237849264682708699ULL, 12825353012139217522ULL, 6706187291358897596ULL,
    196324915476054915ULL
};
__device__ __constant__ static const u64 HEAVY_HASH_INITIAL_STATE[25] = {
    4239941492252378377ULL, 8746723911537738262ULL, 8796936657246353646ULL, 1272090201925444760ULL,
    16654558671554924250ULL, 8270816933120786537ULL, 13907396207649043898ULL, 6782861118970774626ULL,
    9239690602118867528ULL, 11582319943599406348ULL, 17596056728278508070ULL, 15212962468105129023ULL,
    7812475424661425213ULL, 3370482334374859748ULL, 5690099369266491460ULL, 8596393687355028144ULL,
    570094237299545110ULL, 9119540418498120711ULL, 16901969272480492857ULL, 13372017233735502424ULL,
    14372891883993151831ULL, 5171152063242093102ULL, 10573107899694386186ULL, 6096431547456407061ULL,
    1592359455985097269ULL
};
__device__ __constant__ static const u64 KECCAK_RNDC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
__device__ __constant__ static const u32 KECCAK_PI_LANES[24] = {
    10U, 7U, 11U, 17U, 18U, 3U, 5U, 16U, 8U, 21U, 24U, 4U,
    15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U, 6U, 1U
};
__device__ __constant__ static const u32 KECCAK_RHO_PI_ROT[24] = {
    1U, 3U, 6U, 10U, 15U, 21U, 28U, 36U, 45U, 55U, 2U, 14U,
    27U, 41U, 56U, 8U, 25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
};

__device__ __constant__ static const u8 SBOX_SOURCE_SELECTORS[16] = {
    0, 1, 2, 1, 3, 1, 0, 1, 3, 1, 2, 1, 3, 1, 0, 1
};
__device__ __constant__ static const u8 SBOX_VALUE_SELECTORS[16] = {
    0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2
};
__device__ __constant__ static const u8 SBOX_VALUE_MULTIPLIERS[16] = {
    0x03, 0x05, 0x07, 0x0F, 0x11, 0x13, 0x17, 0x19,
    0x1D, 0x1F, 0x23, 0x29, 0x2F, 0x31, 0x37, 0x3F
};
__device__ __constant__ static const u8 SBOX_VALUE_ADDERS[16] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA
};
__device__ __constant__ static const u32 BLAKE3_IV[8] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
};
__device__ __constant__ static const u32 BLAKE3_MSG_PERMUTATION[16] = {
    2, 6, 3, 10, 7, 0, 4, 13,
    1, 11, 12, 5, 9, 14, 15, 8
};
__device__ __constant__ static const u8 AFTER_COMP_LUT[256] = {
    0x75, 0x7C, 0xEB, 0x87, 0x24, 0xE7, 0x3D, 0x07, 0x48, 0x32, 0xB2, 0xEE, 0xEF, 0x97, 0xC2, 0x2B,
    0xE9, 0x4B, 0xE2, 0xAF, 0x2F, 0xF3, 0x19, 0xE7, 0x83, 0x94, 0xB9, 0x4B, 0x09, 0x78, 0x95, 0x69,
    0x55, 0xF7, 0xF7, 0x9F, 0x67, 0x01, 0x4A, 0xCE, 0xD1, 0x57, 0x64, 0x03, 0xE1, 0x72, 0x8D, 0xCD,
    0x67, 0x41, 0x6A, 0x10, 0xC0, 0x55, 0x42, 0xBD, 0x28, 0x26, 0xEE, 0x75, 0x51, 0x2B, 0x7B, 0xE6,
    0xE0, 0x38, 0xD7, 0x1D, 0x48, 0x7D, 0x6C, 0x17, 0x53, 0xFA, 0x7A, 0x89, 0x09, 0x8A, 0x43, 0x7B,
    0x3B, 0xEE, 0x9F, 0x09, 0xD9, 0x07, 0xD6, 0x66, 0x23, 0x13, 0x82, 0x5B, 0x4B, 0x6B, 0xC2, 0xAF,
    0xFD, 0xD8, 0x92, 0x0E, 0x40, 0x89, 0x32, 0xEE, 0x14, 0x9A, 0xA4, 0xAC, 0xEC, 0xF9, 0x9D, 0x3A,
    0xBC, 0x51, 0x05, 0x6A, 0x11, 0xA7, 0xAC, 0x1B, 0x71, 0x40, 0x0D, 0x05, 0xD0, 0x61, 0x05, 0xE2,
    0x5A, 0x1D, 0xCA, 0x4C, 0x56, 0x40, 0x2A, 0x49, 0x67, 0x61, 0x69, 0x21, 0x80, 0x85, 0x59, 0xB8,
    0x2C, 0xD0, 0x20, 0xDA, 0x88, 0xAC, 0xCC, 0xD1, 0x70, 0x76, 0x98, 0x7F, 0x7C, 0x55, 0xD0, 0xD6,
    0x2B, 0xA5, 0xB7, 0x03, 0x9E, 0x37, 0x9B, 0xB9, 0xF1, 0xE8, 0x1F, 0xE0, 0x42, 0x6B, 0x62, 0x63,
    0xB7, 0xDC, 0x8E, 0xCC, 0x6C, 0xB7, 0x76, 0x27, 0xC1, 0xEC, 0x72, 0x17, 0xCE, 0x76, 0x65, 0x8C,
    0x9F, 0x16, 0xDB, 0xB2, 0x5F, 0x7F, 0x14, 0x5A, 0x42, 0x89, 0xEC, 0x1D, 0xC5, 0xC9, 0xA0, 0x30,
    0xDD, 0x3C, 0xDC, 0x7B, 0x8A, 0x47, 0x3E, 0xB5, 0xEA, 0xA9, 0xA9, 0x6A, 0x89, 0x65, 0x4D, 0x3A,
    0xC8, 0xAD, 0xBB, 0xAD, 0xA0, 0xE5, 0xB8, 0xF6, 0xCD, 0x08, 0xA3, 0xE8, 0xA0, 0x5E, 0x18, 0xA6,
    0x65, 0x27, 0x26, 0x5C, 0x21, 0xA8, 0xF4, 0x3C, 0xCA, 0x95, 0x15, 0xFC, 0x9C, 0x1B, 0x9A, 0x0B
};

__device__ __forceinline__ u8 rotl8(u8 value, u32 shift) {
    shift &= 7U;
    return (u8)((value << shift) | (value >> ((8U - shift) & 7U)));
}
__device__ __forceinline__ u8 rotr8(u8 value, u32 shift) {
    shift &= 7U;
    return (u8)((value >> shift) | (value << ((8U - shift) & 7U)));
}
__device__ __forceinline__ u32 rotl32(u32 value, u32 shift) {
    shift &= 31U;
    return (value << shift) | (value >> ((32U - shift) & 31U));
}
__device__ __forceinline__ u32 rotr32(u32 value, u32 shift) {
    shift &= 31U;
    return (value >> shift) | (value << ((32U - shift) & 31U));
}
__device__ __forceinline__ u64 rotl64(u64 value, u32 shift) {
    shift &= 63U;
    return (value << shift) | (value >> ((64U - shift) & 63U));
}
__device__ __forceinline__ u64 load64_le(const u8* in, u32 offset) {
    const u32 base = offset;
    return ((u64)in[base + 0]) |
           ((u64)in[base + 1] << 8) |
           ((u64)in[base + 2] << 16) |
           ((u64)in[base + 3] << 24) |
           ((u64)in[base + 4] << 32) |
           ((u64)in[base + 5] << 40) |
           ((u64)in[base + 6] << 48) |
           ((u64)in[base + 7] << 56);
}
__device__ __forceinline__ u32 load32_le(const u8* in, u32 offset) {
    const u32 base = offset;
    return ((u32)in[base + 0]) |
           ((u32)in[base + 1] << 8) |
           ((u32)in[base + 2] << 16) |
           ((u32)in[base + 3] << 24);
}
__device__ __forceinline__ void store64_le(u64 value, u8* out, u32 offset) {
    const u32 base = offset;
    out[base + 0] = (u8)(value & 0xFFULL);
    out[base + 1] = (u8)((value >> 8) & 0xFFULL);
    out[base + 2] = (u8)((value >> 16) & 0xFFULL);
    out[base + 3] = (u8)((value >> 24) & 0xFFULL);
    out[base + 4] = (u8)((value >> 32) & 0xFFULL);
    out[base + 5] = (u8)((value >> 40) & 0xFFULL);
    out[base + 6] = (u8)((value >> 48) & 0xFFULL);
    out[base + 7] = (u8)((value >> 56) & 0xFFULL);
}
__device__ __forceinline__ void store32_le(u32 value, u8* out, u32 offset) {
    const u32 base = offset;
    out[base + 0] = (u8)(value & 0xFFU);
    out[base + 1] = (u8)((value >> 8) & 0xFFU);
    out[base + 2] = (u8)((value >> 16) & 0xFFU);
    out[base + 3] = (u8)((value >> 24) & 0xFFU);
}
__device__ __forceinline__ u64 mul64_parts_by_u32(u32 a_lo, u32 a_hi, u32 b32) {
    const u32 lo_lo = a_lo * b32;
    const u32 lo_hi = __umulhi(a_lo, b32);
    const u32 hi_lo = a_hi * b32;
    const u32 upper = lo_hi + hi_lo;
    return ((u64)lo_lo) | ((u64)upper << 32);
}
__device__ __forceinline__ u32 dot4_acc(u32 sum, const u8* row4, const u8* nib4) {
#if __CUDA_ARCH__ >= 610
    const u32 row_packed = ((u32)row4[0]) | ((u32)row4[1] << 8) | ((u32)row4[2] << 16) | ((u32)row4[3] << 24);
    const u32 nib_packed = ((u32)nib4[0]) | ((u32)nib4[1] << 8) | ((u32)nib4[2] << 16) | ((u32)nib4[3] << 24);
    return (u32)__dp4a((int)row_packed, (int)nib_packed, (int)sum);
#else
    return sum +
           (u32)row4[0] * (u32)nib4[0] +
           (u32)row4[1] * (u32)nib4[1] +
           (u32)row4[2] * (u32)nib4[2] +
           (u32)row4[3] * (u32)nib4[3];
#endif
}

__device__ __forceinline__ void keccak_f1600(u64 st[25]) {
#pragma unroll
    for (u32 round = 0; round < 24; round++) {
        const u64 c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        const u64 c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        const u64 c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        const u64 c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        const u64 c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        const u64 d0 = c4 ^ rotl64(c1, 1U);
        const u64 d1 = c0 ^ rotl64(c2, 1U);
        const u64 d2 = c1 ^ rotl64(c3, 1U);
        const u64 d3 = c2 ^ rotl64(c4, 1U);
        const u64 d4 = c3 ^ rotl64(c0, 1U);

        st[0] ^= d0; st[5] ^= d0; st[10] ^= d0; st[15] ^= d0; st[20] ^= d0;
        st[1] ^= d1; st[6] ^= d1; st[11] ^= d1; st[16] ^= d1; st[21] ^= d1;
        st[2] ^= d2; st[7] ^= d2; st[12] ^= d2; st[17] ^= d2; st[22] ^= d2;
        st[3] ^= d3; st[8] ^= d3; st[13] ^= d3; st[18] ^= d3; st[23] ^= d3;
        st[4] ^= d4; st[9] ^= d4; st[14] ^= d4; st[19] ^= d4; st[24] ^= d4;

        u64 t = st[1];
#pragma unroll
        for (u32 i = 0; i < 24; i++) {
            const u32 lane = KECCAK_PI_LANES[i];
            const u64 next = st[lane];
            st[lane] = rotl64(t, KECCAK_RHO_PI_ROT[i]);
            t = next;
        }

#pragma unroll
        for (u32 row = 0; row < 25; row += 5U) {
            const u64 r0 = st[row + 0U];
            const u64 r1 = st[row + 1U];
            const u64 r2 = st[row + 2U];
            const u64 r3 = st[row + 3U];
            const u64 r4 = st[row + 4U];
            st[row + 0U] = r0 ^ ((~r1) & r2);
            st[row + 1U] = r1 ^ ((~r2) & r3);
            st[row + 2U] = r2 ^ ((~r3) & r4);
            st[row + 3U] = r3 ^ ((~r4) & r0);
            st[row + 4U] = r4 ^ ((~r0) & r1);
        }

        st[0] ^= KECCAK_RNDC[round];
    }
}

__device__ __forceinline__ void sha3_256_32bytes(const u8 input[32], u8 output[32]) {
    u64 st[25];
#pragma unroll
    for (u32 i = 0; i < 25; i++) st[i] = 0ULL;

    st[0] ^= load64_le(input, 0);
    st[1] ^= load64_le(input, 8);
    st[2] ^= load64_le(input, 16);
    st[3] ^= load64_le(input, 24);
    st[4] ^= 0x06ULL;
    st[16] ^= (0x80ULL << 56);

    keccak_f1600(st);

    store64_le(st[0], output, 0);
    store64_le(st[1], output, 8);
    store64_le(st[2], output, 16);
    store64_le(st[3], output, 24);
}

__device__ __forceinline__ void blake3_permute(u32 m[16]) {
    u32 p[16];
#pragma unroll
    for (u32 i = 0; i < 16; i++) p[i] = m[BLAKE3_MSG_PERMUTATION[i]];
#pragma unroll
    for (u32 i = 0; i < 16; i++) m[i] = p[i];
}
__device__ __forceinline__ void blake3_g(u32 v[16], u32 a, u32 b, u32 c, u32 d, u32 mx, u32 my) {
    v[a] = v[a] + v[b] + mx;
    v[d] = rotr32(v[d] ^ v[a], 16U);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 12U);
    v[a] = v[a] + v[b] + my;
    v[d] = rotr32(v[d] ^ v[a], 8U);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 7U);
}
__device__ __forceinline__ void blake3_round(u32 v[16], u32 m[16]) {
    blake3_g(v, 0, 4, 8, 12, m[0], m[1]);
    blake3_g(v, 1, 5, 9, 13, m[2], m[3]);
    blake3_g(v, 2, 6, 10, 14, m[4], m[5]);
    blake3_g(v, 3, 7, 11, 15, m[6], m[7]);
    blake3_g(v, 0, 5, 10, 15, m[8], m[9]);
    blake3_g(v, 1, 6, 11, 12, m[10], m[11]);
    blake3_g(v, 2, 7, 8, 13, m[12], m[13]);
    blake3_g(v, 3, 4, 9, 14, m[14], m[15]);
}
__device__ __forceinline__ void blake3_compress_32(const u8 input[32], u8 output[32]) {
    u32 m[16];
    u32 v[16];
#pragma unroll
    for (u32 i = 0; i < 16; i++) m[i] = 0U;
#pragma unroll
    for (u32 i = 0; i < 8; i++) m[i] = load32_le(input, i * 4U);
#pragma unroll
    for (u32 i = 0; i < 8; i++) v[i] = BLAKE3_IV[i];

    v[8] = BLAKE3_IV[0];
    v[9] = BLAKE3_IV[1];
    v[10] = BLAKE3_IV[2];
    v[11] = BLAKE3_IV[3];
    v[12] = 0U;
    v[13] = 0U;
    v[14] = 32U;
    v[15] = 1U | 2U | 8U;

#pragma unroll
    for (u32 round = 0; round < 7; round++) {
        blake3_round(v, m);
        if (round + 1U < 7U) blake3_permute(m);
    }
#pragma unroll
    for (u32 i = 0; i < 8; i++) store32_le(v[i] ^ v[i + 8], output, i * 4U);
}

__device__ __forceinline__ void octonion_hash(const u8 input_hash[32], u64 out_oct[8]) {
    u64 a0 = (u64)input_hash[0], a1 = (u64)input_hash[1], a2 = (u64)input_hash[2], a3 = (u64)input_hash[3];
    u64 a4 = (u64)input_hash[4], a5 = (u64)input_hash[5], a6 = (u64)input_hash[6], a7 = (u64)input_hash[7];
    u8 b0 = input_hash[8], b1 = input_hash[9], b2 = input_hash[10], b3 = input_hash[11];
    u8 b4 = input_hash[12], b5 = input_hash[13], b6 = input_hash[14], b7 = input_hash[15];

#pragma unroll
    for (u32 i = 8; i < 32; i++) {
        const u32 a0_lo = (u32)a0, a0_hi = (u32)(a0 >> 32);
        const u32 a1_lo = (u32)a1, a1_hi = (u32)(a1 >> 32);
        const u32 a2_lo = (u32)a2, a2_hi = (u32)(a2 >> 32);
        const u32 a3_lo = (u32)a3, a3_hi = (u32)(a3 >> 32);
        const u32 a4_lo = (u32)a4, a4_hi = (u32)(a4 >> 32);
        const u32 a5_lo = (u32)a5, a5_hi = (u32)(a5 >> 32);
        const u32 a6_lo = (u32)a6, a6_hi = (u32)(a6 >> 32);
        const u32 a7_lo = (u32)a7, a7_hi = (u32)(a7 >> 32);
        const u32 b0_u = (u32)b0, b1_u = (u32)b1, b2_u = (u32)b2, b3_u = (u32)b3;
        const u32 b4_u = (u32)b4, b5_u = (u32)b5, b6_u = (u32)b6, b7_u = (u32)b7;

        const u64 r0 = mul64_parts_by_u32(a0_lo, a0_hi, b0_u) - mul64_parts_by_u32(a1_lo, a1_hi, b1_u)
                     - mul64_parts_by_u32(a2_lo, a2_hi, b2_u) - mul64_parts_by_u32(a3_lo, a3_hi, b3_u)
                     - mul64_parts_by_u32(a4_lo, a4_hi, b4_u) - mul64_parts_by_u32(a5_lo, a5_hi, b5_u)
                     - mul64_parts_by_u32(a6_lo, a6_hi, b6_u) - mul64_parts_by_u32(a7_lo, a7_hi, b7_u);
        const u64 r1 = mul64_parts_by_u32(a0_lo, a0_hi, b1_u) + mul64_parts_by_u32(a1_lo, a1_hi, b0_u)
                     + mul64_parts_by_u32(a2_lo, a2_hi, b3_u) - mul64_parts_by_u32(a3_lo, a3_hi, b2_u)
                     + mul64_parts_by_u32(a4_lo, a4_hi, b5_u) - mul64_parts_by_u32(a5_lo, a5_hi, b4_u)
                     - mul64_parts_by_u32(a6_lo, a6_hi, b7_u) + mul64_parts_by_u32(a7_lo, a7_hi, b6_u);
        const u64 r2 = mul64_parts_by_u32(a0_lo, a0_hi, b2_u) - mul64_parts_by_u32(a1_lo, a1_hi, b3_u)
                     + mul64_parts_by_u32(a2_lo, a2_hi, b0_u) + mul64_parts_by_u32(a3_lo, a3_hi, b1_u)
                     + mul64_parts_by_u32(a4_lo, a4_hi, b6_u) - mul64_parts_by_u32(a5_lo, a5_hi, b7_u)
                     + mul64_parts_by_u32(a6_lo, a6_hi, b4_u) - mul64_parts_by_u32(a7_lo, a7_hi, b5_u);
        const u64 r3 = mul64_parts_by_u32(a0_lo, a0_hi, b3_u) + mul64_parts_by_u32(a1_lo, a1_hi, b2_u)
                     - mul64_parts_by_u32(a2_lo, a2_hi, b1_u) + mul64_parts_by_u32(a3_lo, a3_hi, b0_u)
                     + mul64_parts_by_u32(a4_lo, a4_hi, b7_u) + mul64_parts_by_u32(a5_lo, a5_hi, b6_u)
                     - mul64_parts_by_u32(a6_lo, a6_hi, b5_u) + mul64_parts_by_u32(a7_lo, a7_hi, b4_u);
        const u64 r4 = mul64_parts_by_u32(a0_lo, a0_hi, b4_u) - mul64_parts_by_u32(a1_lo, a1_hi, b5_u)
                     - mul64_parts_by_u32(a2_lo, a2_hi, b6_u) - mul64_parts_by_u32(a3_lo, a3_hi, b7_u)
                     + mul64_parts_by_u32(a4_lo, a4_hi, b0_u) + mul64_parts_by_u32(a5_lo, a5_hi, b1_u)
                     + mul64_parts_by_u32(a6_lo, a6_hi, b2_u) + mul64_parts_by_u32(a7_lo, a7_hi, b3_u);
        const u64 r5 = mul64_parts_by_u32(a0_lo, a0_hi, b5_u) + mul64_parts_by_u32(a1_lo, a1_hi, b4_u)
                     - mul64_parts_by_u32(a2_lo, a2_hi, b7_u) + mul64_parts_by_u32(a3_lo, a3_hi, b6_u)
                     - mul64_parts_by_u32(a4_lo, a4_hi, b1_u) + mul64_parts_by_u32(a5_lo, a5_hi, b0_u)
                     + mul64_parts_by_u32(a6_lo, a6_hi, b3_u) + mul64_parts_by_u32(a7_lo, a7_hi, b2_u);
        const u64 r6 = mul64_parts_by_u32(a0_lo, a0_hi, b6_u) + mul64_parts_by_u32(a1_lo, a1_hi, b7_u)
                     + mul64_parts_by_u32(a2_lo, a2_hi, b4_u) - mul64_parts_by_u32(a3_lo, a3_hi, b5_u)
                     - mul64_parts_by_u32(a4_lo, a4_hi, b2_u) + mul64_parts_by_u32(a5_lo, a5_hi, b3_u)
                     + mul64_parts_by_u32(a6_lo, a6_hi, b0_u) + mul64_parts_by_u32(a7_lo, a7_hi, b1_u);
        const u64 r7 = mul64_parts_by_u32(a0_lo, a0_hi, b7_u) - mul64_parts_by_u32(a1_lo, a1_hi, b6_u)
                     + mul64_parts_by_u32(a2_lo, a2_hi, b5_u) + mul64_parts_by_u32(a3_lo, a3_hi, b4_u)
                     - mul64_parts_by_u32(a4_lo, a4_hi, b3_u) + mul64_parts_by_u32(a5_lo, a5_hi, b2_u)
                     + mul64_parts_by_u32(a6_lo, a6_hi, b1_u) + mul64_parts_by_u32(a7_lo, a7_hi, b0_u);
        a0 = r0; a1 = r1; a2 = r2; a3 = r3; a4 = r4; a5 = r5; a6 = r6; a7 = r7;

        if (i < 31U) {
            b0 = b1; b1 = b2; b2 = b3; b3 = b4;
            b4 = b5; b5 = b6; b6 = b7;
            b7 = input_hash[(i + 8U) & 31U];
        }
    }
    out_oct[0] = a0; out_oct[1] = a1; out_oct[2] = a2; out_oct[3] = a3;
    out_oct[4] = a4; out_oct[5] = a5; out_oct[6] = a6; out_oct[7] = a7;
}

__device__ __forceinline__ u8 pick_ref_value(u8 ref_type, u32 idx, const u8 nibble_product[32], const u8 product_before_oct[32], const u8 product[32], const u8 hash_bytes[32]) {
    switch (ref_type) {
        case 0: return nibble_product[idx];
        case 1: return product_before_oct[idx];
        case 2: return product[idx];
        default: return hash_bytes[idx];
    }
}
__device__ __forceinline__ u8 pick_array_byte(u8 selector, u32 idx, const u8 product[32], const u8 hash_bytes[32], const u8 nibble_product[32], const u8 product_before_oct[32]) {
    switch (selector) {
        case 0: return product[idx];
        case 1: return hash_bytes[idx];
        case 2: return nibble_product[idx];
        default: return product_before_oct[idx];
    }
}
__device__ __forceinline__ u8 compute_sbox_entry(
    u32 sbox_idx,
    const u8 rotate_left_bases[16],
    const u8 rotate_right_bases[16],
    const u8 product[32],
    const u8 hash_bytes[32],
    const u8 nibble_product[32],
    const u8 product_before_oct[32],
    u32 sbox_iterations
) {
    const u32 segment = sbox_idx >> 4;
    const u32 lane = sbox_idx & 15U;
    const u8 p1 = product[(sbox_idx + 1U) & 31U];
    const u8 h2 = hash_bytes[(sbox_idx + 2U) & 31U];

    u8 value = (u8)(
        pick_array_byte(SBOX_VALUE_SELECTORS[segment], lane, product, hash_bytes, nibble_product, product_before_oct) *
            SBOX_VALUE_MULTIPLIERS[segment] +
        (u8)(lane * SBOX_VALUE_ADDERS[segment])
    );
    const u8 rotation_left = rotl8(rotate_left_bases[segment], (((u32)p1) + sbox_idx) & 7U);
    const u8 rotation_right = rotr8(rotate_right_bases[segment], (((u32)h2) + sbox_idx) & 7U);
    const u32 source_index = (sbox_idx + (u32)rotation_left + (u32)rotation_right) & 31U;
    value ^= pick_array_byte(SBOX_SOURCE_SELECTORS[segment], source_index, product, hash_bytes, nibble_product, product_before_oct);

    const u32 rotate_left_shift2 = (((u32)p1) + (sbox_idx << 2U)) & 7U;
    const u32 rotate_right_shift2 = (((u32)h2) + (sbox_idx * 6U)) & 7U;
    const u8 base_value = (u8)(sbox_idx + (u32)(product[(sbox_idx * 3U) & 31U] ^ hash_bytes[(sbox_idx * 7U) & 31U])) ^ (u8)0xA5;
    const u8 xor_value = rotl8(base_value, sbox_idx & 7U) ^ (u8)0x55;

    u8 rotated_value = (u8)(rotl8(value, rotate_left_shift2) | rotr8(value, rotate_right_shift2));
    value ^= rotated_value ^ xor_value;
    if (sbox_iterations == 2U) {
        rotated_value = (u8)(rotl8(value, rotate_left_shift2) | rotr8(value, rotate_right_shift2));
        value ^= rotated_value ^ xor_value;
    }
    return value;
}

__device__ __forceinline__ void cryptix_hash_v2_hash(const u8 input[32], u8 output[32]) {
    u64 st[25];
#pragma unroll
    for (u32 i = 0; i < 25; i++) st[i] = HEAVY_HASH_INITIAL_STATE[i];

    st[0] ^= load64_le(input, 0);
    st[1] ^= load64_le(input, 8);
    st[2] ^= load64_le(input, 16);
    st[3] ^= load64_le(input, 24);
    keccak_f1600(st);

    store64_le(st[0], output, 0);
    store64_le(st[1], output, 8);
    store64_le(st[2], output, 16);
    store64_le(st[3], output, 24);
}

__device__ __forceinline__ void cryptix_hash_matrix(const u8* matrix_local, const u8 hash_bytes[32], u8 output[32]) {
    u8 product[32];
    u8 nibble_product[32];
    const u8* row_ptr0 = matrix_local;
    const u8* row_ptr1 = matrix_local + 64U;
    const u8* row_ptr2 = matrix_local + 128U;
    const u8* row_ptr3 = matrix_local + 192U;

#pragma unroll
    for (u32 i = 0; i < 32; i++) {
        u32 sum1 = 0U, sum2 = 0U, sum3 = 0U, sum4 = 0U;
#pragma unroll
        for (u32 block = 0; block < 16U; block++) {
            const u32 hidx = block << 1U;
            const u8 hb0 = hash_bytes[hidx];
            const u8 hb1 = hash_bytes[hidx + 1U];
            u8 nib[4] = {(u8)(hb0 >> 4), (u8)(hb0 & 0x0FU), (u8)(hb1 >> 4), (u8)(hb1 & 0x0FU)};

            const u8* row_vec = row_ptr0 + (block << 2U); sum1 = dot4_acc(sum1, row_vec, nib);
            row_vec = row_ptr1 + (block << 2U); sum2 = dot4_acc(sum2, row_vec, nib);
            row_vec = row_ptr2 + (block << 2U); sum3 = dot4_acc(sum3, row_vec, nib);
            row_vec = row_ptr3 + (block << 2U); sum4 = dot4_acc(sum4, row_vec, nib);
        }
        row_ptr0 += 128U; row_ptr1 += 128U; row_ptr2 += 64U; row_ptr3 += 64U;

        const u32 a_nibble = (sum1 & 0xFU) ^ ((sum2 >> 4) & 0xFU) ^ ((sum3 >> 8) & 0xFU)
            ^ ((sum1 * 0xABCDU >> 12) & 0xFU) ^ ((sum1 * 0x1234U >> 8) & 0xFU)
            ^ ((sum2 * 0x5678U >> 16) & 0xFU) ^ ((sum3 * 0x9ABCU >> 4) & 0xFU)
            ^ ((rotl32(sum1, 3U) & 0xFU) ^ (rotr32(sum3, 5U) & 0xFU));
        const u32 b_nibble = (sum2 & 0xFU) ^ ((sum1 >> 4) & 0xFU) ^ ((sum4 >> 8) & 0xFU)
            ^ ((sum2 * 0xDCBAU >> 14) & 0xFU) ^ ((sum2 * 0x8765U >> 10) & 0xFU)
            ^ ((sum1 * 0x4321U >> 6) & 0xFU) ^ ((rotl32(sum4, 2U) ^ rotr32(sum1, 1U)) & 0xFU);
        const u32 c_nibble = (sum3 & 0xFU) ^ ((sum2 >> 4) & 0xFU) ^ ((sum2 >> 8) & 0xFU)
            ^ ((sum3 * 0xF135U >> 10) & 0xFU) ^ ((sum3 * 0x2468U >> 12) & 0xFU)
            ^ ((sum4 * 0xACEFU >> 8) & 0xFU) ^ ((sum2 * 0x1357U >> 4) & 0xFU)
            ^ ((rotl32(sum3, 5U) & 0xFU) ^ (rotr32(sum1, 7U) & 0xFU));
        const u32 d_nibble = (sum1 & 0xFU) ^ ((sum4 >> 4) & 0xFU) ^ ((sum1 >> 8) & 0xFU)
            ^ ((sum4 * 0x57A3U >> 6) & 0xFU) ^ ((sum3 * 0xD4E3U >> 12) & 0xFU)
            ^ ((sum1 * 0x9F8BU >> 10) & 0xFU) ^ ((rotl32(sum4, 4U) ^ (sum1 + sum2)) & 0xFU);

        const u8 h = hash_bytes[i];
        nibble_product[i] = (u8)((((c_nibble & 0xFU) << 4) | (d_nibble & 0xFU)) ^ h);
        product[i] = (u8)((((a_nibble & 0xFU) << 4) | (b_nibble & 0xFU)) ^ h);
    }

    u8 product_before_oct[32];
#pragma unroll
    for (u32 i = 0; i < 32; i++) product_before_oct[i] = product[i];

    u64 oct_result[8];
    octonion_hash(product, oct_result);
#pragma unroll
    for (u32 i = 0; i < 4; i++) {
        const u32 off = i * 8U;
        store64_le(load64_le(product, off) ^ oct_result[i], product, off);
    }

    const u8 rotate_left_bases[16] = {
        (u8)((nibble_product[3] ^ (u8)0x4F) * (u8)3), (u8)((product[7] ^ (u8)0xA6) * (u8)2),
        (u8)((product_before_oct[1] ^ (u8)0x9C) * (u8)9), (u8)((product[6] ^ (u8)0x71) * (u8)4),
        (u8)((nibble_product[4] ^ (u8)0xB2) * (u8)3), (u8)((product[0] ^ (u8)0x58) * (u8)6),
        (u8)((product_before_oct[2] ^ (u8)0x37) * (u8)2), (u8)((product[5] ^ (u8)0x1A) * (u8)5),
        (u8)((nibble_product[3] ^ (u8)0x93) * (u8)7), (u8)((product[7] ^ (u8)0x29) * (u8)9),
        (u8)((product_before_oct[1] ^ (u8)0x4E) * (u8)4), (u8)((nibble_product[6] ^ (u8)0xF3) * (u8)5),
        (u8)((product[4] ^ (u8)0xB7) * (u8)6), (u8)((product[0] ^ (u8)0x2D) * (u8)8),
        (u8)((product_before_oct[2] ^ (u8)0x6F) * (u8)3), (u8)((nibble_product[5] ^ (u8)0xE1) * (u8)7)
    };
    const u8 rotate_right_bases[16] = {
        (u8)((hash_bytes[2] ^ (u8)0xD3) * (u8)5), (u8)((nibble_product[5] ^ (u8)0x5B) * (u8)7),
        (u8)((product[0] ^ (u8)0x8E) * (u8)3), (u8)((product_before_oct[3] ^ (u8)0x2F) * (u8)5),
        (u8)((hash_bytes[7] ^ (u8)0x6D) * (u8)7), (u8)((nibble_product[1] ^ (u8)0xEE) * (u8)9),
        (u8)((hash_bytes[6] ^ (u8)0x44) * (u8)6), (u8)((hash_bytes[4] ^ (u8)0x7C) * (u8)8),
        (u8)((product[2] ^ (u8)0xAF) * (u8)3), (u8)((nibble_product[5] ^ (u8)0xDC) * (u8)2),
        (u8)((hash_bytes[0] ^ (u8)0x8B) * (u8)3), (u8)((product_before_oct[3] ^ (u8)0x62) * (u8)8),
        (u8)((product[7] ^ (u8)0x15) * (u8)2), (u8)((product_before_oct[1] ^ (u8)0xC8) * (u8)7),
        (u8)((nibble_product[6] ^ (u8)0x99) * (u8)9), (u8)((hash_bytes[4] ^ (u8)0x3B) * (u8)5)
    };

    const u32 update_index = ((u32)(product_before_oct[2] & (u8)7U)) + 1U;
    const u32 sbox_iterations = 1U + ((u32)(product[update_index] & (u8)1U));
    const u32 index_blake = ((u32)(product_before_oct[5] & (u8)7U)) + 1U;
    const u32 iterations_blake = 1U + ((u32)(product[index_blake] % (u8)3));

#pragma unroll
    for (u32 i = 0; i < 32; i++) output[i] = product[i];

    if (iterations_blake == 1U) {
        blake3_compress_32(output, output);
    } else if (iterations_blake == 2U) {
        blake3_compress_32(output, output);
        blake3_compress_32(output, output);
    } else {
        blake3_compress_32(output, output);
        blake3_compress_32(output, output);
        blake3_compress_32(output, output);
    }

    u32 ref_idx = 0U, product_idx = 0U, hash_idx = 0U, mix_term = 0U;
#pragma unroll
    for (u32 i = 0; i < 32; i++) {
        const u8 ref_val = pick_ref_value((u8)(i & 3U), ref_idx, nibble_product, product_before_oct, product, hash_bytes);
        const u32 index = ((u32)ref_val + (u32)product[product_idx] + (u32)hash_bytes[hash_idx] + mix_term) & 255U;
        const u8 sbox_byte = compute_sbox_entry(index, rotate_left_bases, rotate_right_bases, product, hash_bytes, nibble_product, product_before_oct, sbox_iterations);
        output[i] ^= sbox_byte ^ AFTER_COMP_LUT[(u32)product[i]];
        ref_idx = (ref_idx + 13U) & 31U;
        product_idx = (product_idx + 31U) & 31U;
        hash_idx = (hash_idx + 19U) & 31U;
        mix_term = (mix_term + 41U) & 255U;
    }

    cryptix_hash_v2_hash(output, output);
}

__device__ __forceinline__ void pow_hash_finalize_from_header(const u8* header, u64 nonce, u8 output[32]) {
    u64 st[25];
#pragma unroll
    for (u32 i = 0; i < 25; i++) st[i] = POW_HASH_INITIAL_STATE[i];

#pragma unroll
    for (u32 i = 0; i < 9; i++) st[i] ^= load64_le(header, i * 8U);
    st[9] ^= nonce;
    keccak_f1600(st);

    store64_le(st[0], output, 0);
    store64_le(st[1], output, 8);
    store64_le(st[2], output, 16);
    store64_le(st[3], output, 24);
}

__device__ __forceinline__ void calculate_pow_pre_matrix_from_header(const u8* header, u64 nonce, u8 output[32]) {
    u8 current_hash[32];
    pow_hash_finalize_from_header(header, nonce, current_hash);
    const u32 iterations = ((u32)current_hash[0] & 1U) + 1U;

#pragma unroll
    for (u32 i = 0; i < 2U; i++) {
        if (i >= iterations) break;
        sha3_256_32bytes(current_hash, current_hash);

        if ((current_hash[1] & (u8)3U) == 0U) {
            const u32 repeat = ((u32)(current_hash[2] & (u8)3U)) + 1U;
#pragma unroll
            for (u32 r = 0; r < 4U; r++) {
                if (r >= repeat) break;
                const u32 target_byte = (((u32)current_hash[1]) + i) & 31U;
                current_hash[target_byte] ^= (current_hash[i & 15U] ^ (u8)0xA5);
                const u8 rotation_byte = current_hash[i & 31U];
                const u32 rotation_amount = (((u32)current_hash[1] + (u32)current_hash[3]) & 3U) + 2U;
                current_hash[target_byte] = ((rotation_byte & 1U) == 0U) ? rotl8(current_hash[target_byte], rotation_amount) : rotr8(current_hash[target_byte], rotation_amount);
                const u32 shift_amount = (((u32)current_hash[5] + (u32)current_hash[1]) % 3U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[3] % (u8)3) == 0) {
            const u32 repeat = ((u32)(current_hash[4] % (u8)5)) + 1U;
#pragma unroll
            for (u32 r = 0; r < 5U; r++) {
                if (r >= repeat) break;
                const u32 target_byte = (((u32)current_hash[6]) + i) & 31U;
                current_hash[target_byte] ^= (current_hash[i & 15U] ^ (u8)0x55);
                const u8 rotation_byte = current_hash[i & 31U];
                const u32 rotation_amount = (((u32)current_hash[7] + (u32)current_hash[2]) % 6U) + 1U;
                current_hash[target_byte] = ((rotation_byte & 1U) == 0U) ? rotl8(current_hash[target_byte], rotation_amount) : rotr8(current_hash[target_byte], rotation_amount);
                const u32 shift_amount = (((u32)current_hash[1] + (u32)current_hash[3]) % 4U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[2] % (u8)6) == 0) {
            const u32 repeat = ((u32)(current_hash[6] & (u8)3U)) + 1U;
#pragma unroll
            for (u32 r = 0; r < 4U; r++) {
                if (r >= repeat) break;
                const u32 target_byte = (((u32)current_hash[10]) + i) & 31U;
                current_hash[target_byte] ^= (current_hash[i & 15U] ^ (u8)0xFF);
                const u8 rotation_byte = current_hash[i & 31U];
                const u32 rotation_amount = (((u32)current_hash[7] + (u32)current_hash[7]) % 7U) + 1U;
                current_hash[target_byte] = ((rotation_byte & 1U) == 0U) ? rotl8(current_hash[target_byte], rotation_amount) : rotr8(current_hash[target_byte], rotation_amount);
                const u32 shift_amount = (((u32)current_hash[3] + (u32)current_hash[5]) % 5U) + 2U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[7] % (u8)5) == 0) {
            const u32 repeat = ((u32)(current_hash[8] & (u8)3U)) + 1U;
#pragma unroll
            for (u32 r = 0; r < 4U; r++) {
                if (r >= repeat) break;
                const u32 target_byte = (((u32)current_hash[25]) + i) & 31U;
                current_hash[target_byte] ^= (current_hash[i & 15U] ^ (u8)0x66);
                const u8 rotation_byte = current_hash[i & 31U];
                const u32 rotation_amount = (((u32)current_hash[1] + (u32)current_hash[3]) & 3U) + 2U;
                current_hash[target_byte] = ((rotation_byte & 1U) == 0U) ? rotl8(current_hash[target_byte], rotation_amount) : rotr8(current_hash[target_byte], rotation_amount);
                const u32 shift_amount = (((u32)current_hash[1] + (u32)current_hash[3]) & 3U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[8] % (u8)7) == 0) {
            const u32 repeat = ((u32)(current_hash[9] % (u8)5)) + 1U;
#pragma unroll
            for (u32 r = 0; r < 5U; r++) {
                if (r >= repeat) break;
                const u32 target_byte = (((u32)current_hash[30]) + i) & 31U;
                current_hash[target_byte] ^= (current_hash[i & 15U] ^ (u8)0x77);
                const u8 rotation_byte = current_hash[i & 31U];
                const u32 rotation_amount = (((u32)current_hash[2] + (u32)current_hash[5]) % 5U) + 1U;
                current_hash[target_byte] = ((rotation_byte & 1U) == 0U) ? rotl8(current_hash[target_byte], rotation_amount) : rotr8(current_hash[target_byte], rotation_amount);
                const u32 shift_amount = (((u32)current_hash[7] + (u32)current_hash[9]) % 6U) + 2U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        }
    }
#pragma unroll
    for (u32 i = 0; i < 32; i++) output[i] = current_hash[i];
}

__device__ __forceinline__ void calculate_pow_with_header_and_matrix(const u8* matrix_local, const u8* header, u64 nonce, u8 output[32]) {
    u8 current_hash[32];
    calculate_pow_pre_matrix_from_header(header, nonce, current_hash);
    cryptix_hash_matrix(matrix_local, current_hash, output);
}

__device__ __forceinline__ int hash_meets_target_words(const u8 hash_bytes[32], const u64 target_words[4]) {
    for (int i = 3; i >= 0; i--) {
        const u64 hash_word = load64_le(hash_bytes, (u32)(i * 8));
        const u64 target_word = target_words[i];
        if (hash_word < target_word) return 1;
        if (hash_word > target_word) return 0;
    }
    return 1;
}

extern "C" {
__global__ void heavy_hash(const u64 nonce_mask, const u64 nonce_fixed, const u64 nonces_len, u8 random_type, void* states, u64* final_nonce) {
    const u64 gid = (u64)threadIdx.x + (u64)blockIdx.x * (u64)blockDim.x;
    if (gid >= nonces_len) return;
    if (*(volatile u64*)final_nonce != 0ULL) return;

    __shared__ u8 matrix_local[MATRIX_ELEMS];
    for (u32 idx = threadIdx.x; idx < MATRIX_ELEMS; idx += blockDim.x) {
        matrix_local[idx] = ((const u8*)matrix)[idx];
    }
    __syncthreads();

    u64 nonce;
    if (random_type == (u8)RANDOM_LEAN) nonce = ((u64*)states)[0] ^ gid;
    else nonce = xoshiro256_next(((ulonglong4*)states) + gid);

    nonce = (nonce & nonce_mask) | nonce_fixed;

    u8 result[32];
    calculate_pow_with_header_and_matrix(matrix_local, hash_header, nonce, result);
    if (!hash_meets_target_words(result, target.number)) return;
    atomicCAS((unsigned long long int*)final_nonce, 0ULL, (unsigned long long int)nonce);
}
}
