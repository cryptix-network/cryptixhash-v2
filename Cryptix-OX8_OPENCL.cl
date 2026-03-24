// Cryptis OX8 OpenCL kernel (OpenCL 1.2)
// Portable path for NVIDIA / AMD / Intel / onboard GPUs.

__constant ulong POW_HASH_INITIAL_STATE[25] = {
    1242148031264380989UL,
    3008272977830772284UL,
    2188519011337848018UL,
    1992179434288343456UL,
    8876506674959887717UL,
    5399642050693751366UL,
    1745875063082670864UL,
    8605242046444978844UL,
    17936695144567157056UL,
    3343109343542796272UL,
    1123092876221303306UL,
    4963925045340115282UL,
    17037383077651887893UL,
    16629644495023626889UL,
    12833675776649114147UL,
    3784524041015224902UL,
    1082795874807940378UL,
    13952716920571277634UL,
    13411128033953605860UL,
    15060696040649351053UL,
    9928834659948351306UL,
    5237849264682708699UL,
    12825353012139217522UL,
    6706187291358897596UL,
    196324915476054915UL
};

__constant ulong HEAVY_HASH_INITIAL_STATE[25] = {
    4239941492252378377UL,
    8746723911537738262UL,
    8796936657246353646UL,
    1272090201925444760UL,
    16654558671554924250UL,
    8270816933120786537UL,
    13907396207649043898UL,
    6782861118970774626UL,
    9239690602118867528UL,
    11582319943599406348UL,
    17596056728278508070UL,
    15212962468105129023UL,
    7812475424661425213UL,
    3370482334374859748UL,
    5690099369266491460UL,
    8596393687355028144UL,
    570094237299545110UL,
    9119540418498120711UL,
    16901969272480492857UL,
    13372017233735502424UL,
    14372891883993151831UL,
    5171152063242093102UL,
    10573107899694386186UL,
    6096431547456407061UL,
    1592359455985097269UL
};

__constant uchar SBOX_SOURCE_SELECTORS[16] = {
    0, 1, 2, 1, 3, 1, 0, 1, 3, 1, 2, 1, 3, 1, 0, 1
};

__constant uchar SBOX_VALUE_SELECTORS[16] = {
    0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2
};

__constant uchar SBOX_VALUE_MULTIPLIERS[16] = {
    0x03, 0x05, 0x07, 0x0F, 0x11, 0x13, 0x17, 0x19,
    0x1D, 0x1F, 0x23, 0x29, 0x2F, 0x31, 0x37, 0x3F
};

__constant uchar SBOX_VALUE_ADDERS[16] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA
};

__constant ulong KECCAK_RNDC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

__constant uint KECCAK_RHO[25] = {
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
};

// In-place Rho/Pi traversal order (lane indices) for the alternate Keccak path.
__constant uint KECCAK_PI_LANES[24] = {
    10U, 7U, 11U, 17U, 18U, 3U, 5U, 16U,
    8U, 21U, 24U, 4U, 15U, 23U, 19U, 13U,
    12U, 2U, 20U, 14U, 22U, 9U, 6U, 1U
};

// Rotation offsets paired with KECCAK_PI_LANES for in-place Rho/Pi.
__constant uint KECCAK_RHO_PI_ROT[24] = {
    1U, 3U, 6U, 10U, 15U, 21U, 28U, 36U,
    45U, 55U, 2U, 14U, 27U, 41U, 56U, 8U,
    25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
};

__constant uint BLAKE3_IV[8] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
};

__constant uint BLAKE3_MSG_PERMUTATION[16] = {
    2, 6, 3, 10, 7, 0, 4, 13,
    1, 11, 12, 5, 9, 14, 15, 8
};

// Precomputed output of anti_fpga_hash(chaotic_random(x)) & 0xFF for x in [0..255].
__constant uchar AFTER_COMP_LUT[256] = {
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

inline uchar rotl8(uchar value, uint shift) {
    shift &= 7U;
    return (uchar)((value << shift) | (value >> ((8U - shift) & 7U)));
}

inline uchar rotr8(uchar value, uint shift) {
    shift &= 7U;
    return (uchar)((value >> shift) | (value << ((8U - shift) & 7U)));
}

inline uint rotl32(uint value, uint shift) {
    shift &= 31U;
    return (value << shift) | (value >> ((32U - shift) & 31U));
}

inline uint rotr32(uint value, uint shift) {
    shift &= 31U;
    return (value >> shift) | (value << ((32U - shift) & 31U));
}

inline ulong rotl64(ulong value, uint shift) {
    shift &= 63U;
    return (value << shift) | (value >> ((64U - shift) & 63U));
}

inline ulong rotr64(ulong value, uint shift) {
    shift &= 63U;
    return (value >> shift) | (value << ((64U - shift) & 63U));
}

inline ulong mul64_parts_by_u32(uint a_lo, uint a_hi, uint b32) {
    uint lo_lo = a_lo * b32;
    uint lo_hi = mul_hi(a_lo, b32);
    uint hi_lo = a_hi * b32;
    uint upper = lo_hi + hi_lo;
    return ((ulong)lo_lo) | ((ulong)upper << 32);
}

// Equivalent to (a * b) modulo 2^64 for b in [0..255], but uses 32-bit ops.
inline ulong mul64_by_u8(ulong a, uchar b) {
    uint a_lo = (uint)a;
    uint a_hi = (uint)(a >> 32);
    return mul64_parts_by_u32(a_lo, a_hi, (uint)b);
}

inline ulong load64_le_private(const uchar in[32], uint offset) {
    uint base = offset;
    return ((ulong)in[base + 0]) |
        ((ulong)in[base + 1] << 8) |
        ((ulong)in[base + 2] << 16) |
        ((ulong)in[base + 3] << 24) |
        ((ulong)in[base + 4] << 32) |
        ((ulong)in[base + 5] << 40) |
        ((ulong)in[base + 6] << 48) |
        ((ulong)in[base + 7] << 56);
}

inline uint load32_le_private(const uchar in[32], uint offset) {
    uint base = offset;
    return ((uint)in[base + 0]) |
        ((uint)in[base + 1] << 8) |
        ((uint)in[base + 2] << 16) |
        ((uint)in[base + 3] << 24);
}

inline void store64_le_private(ulong value, uchar out[32], uint offset) {
    uint base = offset;
    out[base + 0] = (uchar)(value & 0xFFUL);
    out[base + 1] = (uchar)((value >> 8) & 0xFFUL);
    out[base + 2] = (uchar)((value >> 16) & 0xFFUL);
    out[base + 3] = (uchar)((value >> 24) & 0xFFUL);
    out[base + 4] = (uchar)((value >> 32) & 0xFFUL);
    out[base + 5] = (uchar)((value >> 40) & 0xFFUL);
    out[base + 6] = (uchar)((value >> 48) & 0xFFUL);
    out[base + 7] = (uchar)((value >> 56) & 0xFFUL);
}

inline void store32_le_private(uint value, uchar out[32], uint offset) {
    uint base = offset;
    out[base + 0] = (uchar)(value & 0xFFU);
    out[base + 1] = (uchar)((value >> 8) & 0xFFU);
    out[base + 2] = (uchar)((value >> 16) & 0xFFU);
    out[base + 3] = (uchar)((value >> 24) & 0xFFU);
}

#ifndef CRYPTIS_OPENCL_USE_MAD24
#define CRYPTIS_OPENCL_USE_MAD24 1
#endif

#ifndef CRYPTIS_OPENCL_ROTATE_BASES_ON_DEMAND
#define CRYPTIS_OPENCL_ROTATE_BASES_ON_DEMAND 0
#endif

#ifndef CRYPTIS_OPENCL_KECCAK_ALT
#define CRYPTIS_OPENCL_KECCAK_ALT 1
#endif

inline uint cryptis_dot_acc(uint sum, uint a, uint b) {
#if defined(CRYPTIS_OPENCL_USE_MAD24) && (CRYPTIS_OPENCL_USE_MAD24 != 0)
    return mad24(a, b, sum);
#else
    return sum + (a * b);
#endif
}

inline uint cryptis_dot4_acc(uint sum, uint4 row, uint4 nib) {
#if defined(CRYPTIS_OPENCL_USE_MAD24) && (CRYPTIS_OPENCL_USE_MAD24 != 0)
    sum = mad24(row.s0, nib.s0, sum);
    sum = mad24(row.s1, nib.s1, sum);
    sum = mad24(row.s2, nib.s2, sum);
    sum = mad24(row.s3, nib.s3, sum);
    return sum;
#else
    return sum
        + row.s0 * nib.s0
        + row.s1 * nib.s1
        + row.s2 * nib.s2
        + row.s3 * nib.s3;
#endif
}

inline void keccak_f1600(ulong st[25]) {
#if (CRYPTIS_OPENCL_KECCAK_ALT == 0)
    ulong b[25];

    for (uint round = 0; round < 24; round++) {
        ulong c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        ulong c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        ulong c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        ulong c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        ulong c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong d0 = c4 ^ rotl64(c1, 1U);
        ulong d1 = c0 ^ rotl64(c2, 1U);
        ulong d2 = c1 ^ rotl64(c3, 1U);
        ulong d3 = c2 ^ rotl64(c4, 1U);
        ulong d4 = c3 ^ rotl64(c0, 1U);

        st[0] ^= d0;
        st[5] ^= d0;
        st[10] ^= d0;
        st[15] ^= d0;
        st[20] ^= d0;

        st[1] ^= d1;
        st[6] ^= d1;
        st[11] ^= d1;
        st[16] ^= d1;
        st[21] ^= d1;

        st[2] ^= d2;
        st[7] ^= d2;
        st[12] ^= d2;
        st[17] ^= d2;
        st[22] ^= d2;

        st[3] ^= d3;
        st[8] ^= d3;
        st[13] ^= d3;
        st[18] ^= d3;
        st[23] ^= d3;

        st[4] ^= d4;
        st[9] ^= d4;
        st[14] ^= d4;
        st[19] ^= d4;
        st[24] ^= d4;

        // Rho + Pi with fixed destinations (avoids modulo arithmetic in hot path).
        b[0] = st[0];
        b[10] = rotl64(st[1], 1U);
        b[20] = rotl64(st[2], 62U);
        b[5] = rotl64(st[3], 28U);
        b[15] = rotl64(st[4], 27U);
        b[16] = rotl64(st[5], 36U);
        b[1] = rotl64(st[6], 44U);
        b[11] = rotl64(st[7], 6U);
        b[21] = rotl64(st[8], 55U);
        b[6] = rotl64(st[9], 20U);
        b[7] = rotl64(st[10], 3U);
        b[17] = rotl64(st[11], 10U);
        b[2] = rotl64(st[12], 43U);
        b[12] = rotl64(st[13], 25U);
        b[22] = rotl64(st[14], 39U);
        b[23] = rotl64(st[15], 41U);
        b[8] = rotl64(st[16], 45U);
        b[18] = rotl64(st[17], 15U);
        b[3] = rotl64(st[18], 21U);
        b[13] = rotl64(st[19], 8U);
        b[14] = rotl64(st[20], 18U);
        b[24] = rotl64(st[21], 2U);
        b[9] = rotl64(st[22], 61U);
        b[19] = rotl64(st[23], 56U);
        b[4] = rotl64(st[24], 14U);

        // Chi (row-wise, modulo-free indexing).
        st[0] = b[0] ^ ((~b[1]) & b[2]);
        st[1] = b[1] ^ ((~b[2]) & b[3]);
        st[2] = b[2] ^ ((~b[3]) & b[4]);
        st[3] = b[3] ^ ((~b[4]) & b[0]);
        st[4] = b[4] ^ ((~b[0]) & b[1]);

        st[5] = b[5] ^ ((~b[6]) & b[7]);
        st[6] = b[6] ^ ((~b[7]) & b[8]);
        st[7] = b[7] ^ ((~b[8]) & b[9]);
        st[8] = b[8] ^ ((~b[9]) & b[5]);
        st[9] = b[9] ^ ((~b[5]) & b[6]);

        st[10] = b[10] ^ ((~b[11]) & b[12]);
        st[11] = b[11] ^ ((~b[12]) & b[13]);
        st[12] = b[12] ^ ((~b[13]) & b[14]);
        st[13] = b[13] ^ ((~b[14]) & b[10]);
        st[14] = b[14] ^ ((~b[10]) & b[11]);

        st[15] = b[15] ^ ((~b[16]) & b[17]);
        st[16] = b[16] ^ ((~b[17]) & b[18]);
        st[17] = b[17] ^ ((~b[18]) & b[19]);
        st[18] = b[18] ^ ((~b[19]) & b[15]);
        st[19] = b[19] ^ ((~b[15]) & b[16]);

        st[20] = b[20] ^ ((~b[21]) & b[22]);
        st[21] = b[21] ^ ((~b[22]) & b[23]);
        st[22] = b[22] ^ ((~b[23]) & b[24]);
        st[23] = b[23] ^ ((~b[24]) & b[20]);
        st[24] = b[24] ^ ((~b[20]) & b[21]);

        st[0] ^= KECCAK_RNDC[round];
    }
#else
    for (uint round = 0; round < 24; round++) {
        ulong c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        ulong c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        ulong c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        ulong c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        ulong c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong d0 = c4 ^ rotl64(c1, 1U);
        ulong d1 = c0 ^ rotl64(c2, 1U);
        ulong d2 = c1 ^ rotl64(c3, 1U);
        ulong d3 = c2 ^ rotl64(c4, 1U);
        ulong d4 = c3 ^ rotl64(c0, 1U);

        st[0] ^= d0;
        st[5] ^= d0;
        st[10] ^= d0;
        st[15] ^= d0;
        st[20] ^= d0;

        st[1] ^= d1;
        st[6] ^= d1;
        st[11] ^= d1;
        st[16] ^= d1;
        st[21] ^= d1;

        st[2] ^= d2;
        st[7] ^= d2;
        st[12] ^= d2;
        st[17] ^= d2;
        st[22] ^= d2;

        st[3] ^= d3;
        st[8] ^= d3;
        st[13] ^= d3;
        st[18] ^= d3;
        st[23] ^= d3;

        st[4] ^= d4;
        st[9] ^= d4;
        st[14] ^= d4;
        st[19] ^= d4;
        st[24] ^= d4;

        // In-place Rho/Pi: reduces temporary state pressure versus b[25].
        ulong t = st[1];
        for (uint i = 0; i < 24; i++) {
            uint lane = KECCAK_PI_LANES[i];
            ulong next = st[lane];
            st[lane] = rotl64(t, KECCAK_RHO_PI_ROT[i]);
            t = next;
        }

        // Chi row by row with only five lane temporaries.
        for (uint row = 0; row < 25; row += 5U) {
            ulong r0 = st[row + 0U];
            ulong r1 = st[row + 1U];
            ulong r2 = st[row + 2U];
            ulong r3 = st[row + 3U];
            ulong r4 = st[row + 4U];

            st[row + 0U] = r0 ^ ((~r1) & r2);
            st[row + 1U] = r1 ^ ((~r2) & r3);
            st[row + 2U] = r2 ^ ((~r3) & r4);
            st[row + 3U] = r3 ^ ((~r4) & r0);
            st[row + 4U] = r4 ^ ((~r0) & r1);
        }

        st[0] ^= KECCAK_RNDC[round];
    }
#endif
}

inline void sha3_256_32bytes(const uchar input[32], uchar output[32]) {
    ulong st[25];
    for (uint i = 0; i < 25; i++) {
        st[i] = 0UL;
    }

    st[0] ^= load64_le_private(input, 0);
    st[1] ^= load64_le_private(input, 8);
    st[2] ^= load64_le_private(input, 16);
    st[3] ^= load64_le_private(input, 24);

    st[4] ^= 0x06UL;
    st[16] ^= (0x80UL << 56);

    keccak_f1600(st);

    store64_le_private(st[0], output, 0);
    store64_le_private(st[1], output, 8);
    store64_le_private(st[2], output, 16);
    store64_le_private(st[3], output, 24);
}

inline void octonion_hash(const uchar input_hash[32], ulong out_oct[8]) {
    ulong a0 = (ulong)input_hash[0];
    ulong a1 = (ulong)input_hash[1];
    ulong a2 = (ulong)input_hash[2];
    ulong a3 = (ulong)input_hash[3];
    ulong a4 = (ulong)input_hash[4];
    ulong a5 = (ulong)input_hash[5];
    ulong a6 = (ulong)input_hash[6];
    ulong a7 = (ulong)input_hash[7];

    uchar b0 = input_hash[8];
    uchar b1 = input_hash[9];
    uchar b2 = input_hash[10];
    uchar b3 = input_hash[11];
    uchar b4 = input_hash[12];
    uchar b5 = input_hash[13];
    uchar b6 = input_hash[14];
    uchar b7 = input_hash[15];

    for (uint i = 8; i < 32; i++) {
        uint a0_lo = (uint)a0;
        uint a0_hi = (uint)(a0 >> 32);
        uint a1_lo = (uint)a1;
        uint a1_hi = (uint)(a1 >> 32);
        uint a2_lo = (uint)a2;
        uint a2_hi = (uint)(a2 >> 32);
        uint a3_lo = (uint)a3;
        uint a3_hi = (uint)(a3 >> 32);
        uint a4_lo = (uint)a4;
        uint a4_hi = (uint)(a4 >> 32);
        uint a5_lo = (uint)a5;
        uint a5_hi = (uint)(a5 >> 32);
        uint a6_lo = (uint)a6;
        uint a6_hi = (uint)(a6 >> 32);
        uint a7_lo = (uint)a7;
        uint a7_hi = (uint)(a7 >> 32);

        uint b0_u = (uint)b0;
        uint b1_u = (uint)b1;
        uint b2_u = (uint)b2;
        uint b3_u = (uint)b3;
        uint b4_u = (uint)b4;
        uint b5_u = (uint)b5;
        uint b6_u = (uint)b6;
        uint b7_u = (uint)b7;

        ulong r0 = mul64_parts_by_u32(a0_lo, a0_hi, b0_u) - mul64_parts_by_u32(a1_lo, a1_hi, b1_u)
            - mul64_parts_by_u32(a2_lo, a2_hi, b2_u) - mul64_parts_by_u32(a3_lo, a3_hi, b3_u)
            - mul64_parts_by_u32(a4_lo, a4_hi, b4_u) - mul64_parts_by_u32(a5_lo, a5_hi, b5_u)
            - mul64_parts_by_u32(a6_lo, a6_hi, b6_u) - mul64_parts_by_u32(a7_lo, a7_hi, b7_u);
        ulong r1 = mul64_parts_by_u32(a0_lo, a0_hi, b1_u) + mul64_parts_by_u32(a1_lo, a1_hi, b0_u)
            + mul64_parts_by_u32(a2_lo, a2_hi, b3_u) - mul64_parts_by_u32(a3_lo, a3_hi, b2_u)
            + mul64_parts_by_u32(a4_lo, a4_hi, b5_u) - mul64_parts_by_u32(a5_lo, a5_hi, b4_u)
            - mul64_parts_by_u32(a6_lo, a6_hi, b7_u) + mul64_parts_by_u32(a7_lo, a7_hi, b6_u);
        ulong r2 = mul64_parts_by_u32(a0_lo, a0_hi, b2_u) - mul64_parts_by_u32(a1_lo, a1_hi, b3_u)
            + mul64_parts_by_u32(a2_lo, a2_hi, b0_u) + mul64_parts_by_u32(a3_lo, a3_hi, b1_u)
            + mul64_parts_by_u32(a4_lo, a4_hi, b6_u) - mul64_parts_by_u32(a5_lo, a5_hi, b7_u)
            + mul64_parts_by_u32(a6_lo, a6_hi, b4_u) - mul64_parts_by_u32(a7_lo, a7_hi, b5_u);
        ulong r3 = mul64_parts_by_u32(a0_lo, a0_hi, b3_u) + mul64_parts_by_u32(a1_lo, a1_hi, b2_u)
            - mul64_parts_by_u32(a2_lo, a2_hi, b1_u) + mul64_parts_by_u32(a3_lo, a3_hi, b0_u)
            + mul64_parts_by_u32(a4_lo, a4_hi, b7_u) + mul64_parts_by_u32(a5_lo, a5_hi, b6_u)
            - mul64_parts_by_u32(a6_lo, a6_hi, b5_u) + mul64_parts_by_u32(a7_lo, a7_hi, b4_u);
        ulong r4 = mul64_parts_by_u32(a0_lo, a0_hi, b4_u) - mul64_parts_by_u32(a1_lo, a1_hi, b5_u)
            - mul64_parts_by_u32(a2_lo, a2_hi, b6_u) - mul64_parts_by_u32(a3_lo, a3_hi, b7_u)
            + mul64_parts_by_u32(a4_lo, a4_hi, b0_u) + mul64_parts_by_u32(a5_lo, a5_hi, b1_u)
            + mul64_parts_by_u32(a6_lo, a6_hi, b2_u) + mul64_parts_by_u32(a7_lo, a7_hi, b3_u);
        ulong r5 = mul64_parts_by_u32(a0_lo, a0_hi, b5_u) + mul64_parts_by_u32(a1_lo, a1_hi, b4_u)
            - mul64_parts_by_u32(a2_lo, a2_hi, b7_u) + mul64_parts_by_u32(a3_lo, a3_hi, b6_u)
            - mul64_parts_by_u32(a4_lo, a4_hi, b1_u) + mul64_parts_by_u32(a5_lo, a5_hi, b0_u)
            + mul64_parts_by_u32(a6_lo, a6_hi, b3_u) + mul64_parts_by_u32(a7_lo, a7_hi, b2_u);
        ulong r6 = mul64_parts_by_u32(a0_lo, a0_hi, b6_u) + mul64_parts_by_u32(a1_lo, a1_hi, b7_u)
            + mul64_parts_by_u32(a2_lo, a2_hi, b4_u) - mul64_parts_by_u32(a3_lo, a3_hi, b5_u)
            - mul64_parts_by_u32(a4_lo, a4_hi, b2_u) + mul64_parts_by_u32(a5_lo, a5_hi, b3_u)
            + mul64_parts_by_u32(a6_lo, a6_hi, b0_u) + mul64_parts_by_u32(a7_lo, a7_hi, b1_u);
        ulong r7 = mul64_parts_by_u32(a0_lo, a0_hi, b7_u) - mul64_parts_by_u32(a1_lo, a1_hi, b6_u)
            + mul64_parts_by_u32(a2_lo, a2_hi, b5_u) + mul64_parts_by_u32(a3_lo, a3_hi, b4_u)
            - mul64_parts_by_u32(a4_lo, a4_hi, b3_u) + mul64_parts_by_u32(a5_lo, a5_hi, b2_u)
            + mul64_parts_by_u32(a6_lo, a6_hi, b1_u) + mul64_parts_by_u32(a7_lo, a7_hi, b0_u);

        a0 = r0;
        a1 = r1;
        a2 = r2;
        a3 = r3;
        a4 = r4;
        a5 = r5;
        a6 = r6;
        a7 = r7;

        if (i < 31U) {
            b0 = b1;
            b1 = b2;
            b2 = b3;
            b3 = b4;
            b4 = b5;
            b5 = b6;
            b6 = b7;
            b7 = input_hash[(i + 8U) & 31U];
        }
    }

    out_oct[0] = a0;
    out_oct[1] = a1;
    out_oct[2] = a2;
    out_oct[3] = a3;
    out_oct[4] = a4;
    out_oct[5] = a5;
    out_oct[6] = a6;
    out_oct[7] = a7;
}

inline void blake3_permute(uint m[16]) {
    uint p[16];
    for (uint i = 0; i < 16; i++) {
        p[i] = m[BLAKE3_MSG_PERMUTATION[i]];
    }
    for (uint i = 0; i < 16; i++) {
        m[i] = p[i];
    }
}

inline void blake3_g(uint v[16], uint a, uint b, uint c, uint d, uint mx, uint my) {
    v[a] = v[a] + v[b] + mx;
    v[d] = rotr32(v[d] ^ v[a], 16U);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 12U);
    v[a] = v[a] + v[b] + my;
    v[d] = rotr32(v[d] ^ v[a], 8U);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 7U);
}

inline void blake3_round(uint v[16], uint m[16]) {
    blake3_g(v, 0, 4, 8, 12, m[0], m[1]);
    blake3_g(v, 1, 5, 9, 13, m[2], m[3]);
    blake3_g(v, 2, 6, 10, 14, m[4], m[5]);
    blake3_g(v, 3, 7, 11, 15, m[6], m[7]);

    blake3_g(v, 0, 5, 10, 15, m[8], m[9]);
    blake3_g(v, 1, 6, 11, 12, m[10], m[11]);
    blake3_g(v, 2, 7, 8, 13, m[12], m[13]);
    blake3_g(v, 3, 4, 9, 14, m[14], m[15]);
}

inline void blake3_compress_32(const uchar input[32], uchar output[32]) {
    uint m[16];
    uint cv[8];
    uint v[16];

    for (uint i = 0; i < 8; i++) {
        cv[i] = BLAKE3_IV[i];
    }

    for (uint i = 0; i < 16; i++) {
        m[i] = 0U;
    }

    for (uint i = 0; i < 8; i++) {
        m[i] = load32_le_private(input, i * 4U);
    }

    for (uint i = 0; i < 8; i++) {
        v[i] = cv[i];
    }

    const uint block_len = 32U;
    const uint flags = 1U | 2U | 8U;
    const uint counter_low = 0U;
    const uint counter_high = 0U;

    v[8] = BLAKE3_IV[0];
    v[9] = BLAKE3_IV[1];
    v[10] = BLAKE3_IV[2];
    v[11] = BLAKE3_IV[3];
    v[12] = counter_low;
    v[13] = counter_high;
    v[14] = block_len;
    v[15] = flags;

    for (uint round = 0; round < 7; round++) {
        blake3_round(v, m);
        if (round + 1U < 7U) {
            blake3_permute(m);
        }
    }

    uint out_words[8];
    for (uint i = 0; i < 8; i++) {
        out_words[i] = v[i] ^ v[i + 8];
    }

    for (uint i = 0; i < 8; i++) {
        store32_le_private(out_words[i], output, i * 4U);
    }
}
inline void cryptix_hash_v2_hash(const uchar input[32], uchar output[32]) {
    ulong st[25];
    for (uint i = 0; i < 25; i++) {
        st[i] = HEAVY_HASH_INITIAL_STATE[i];
    }

    st[0] ^= load64_le_private(input, 0);
    st[1] ^= load64_le_private(input, 8);
    st[2] ^= load64_le_private(input, 16);
    st[3] ^= load64_le_private(input, 24);

    keccak_f1600(st);

    store64_le_private(st[0], output, 0);
    store64_le_private(st[1], output, 8);
    store64_le_private(st[2], output, 16);
    store64_le_private(st[3], output, 24);
}

inline uchar pick_ref_value(
    const uchar ref_type,
    const uint idx,
    const uchar nibble_product[32],
    const uchar product_before_oct[32],
    const uchar product[32],
    const uchar hash_bytes[32]
) {
    switch (ref_type) {
        case 0: return nibble_product[idx];
        case 1: return product_before_oct[idx];
        case 2: return product[idx];
        default: return hash_bytes[idx];
    }
}

inline uchar pick_array_byte(
    const uchar selector,
    const uint idx,
    const uchar product[32],
    const uchar hash_bytes[32],
    const uchar nibble_product[32],
    const uchar product_before_oct[32]
) {
    switch (selector) {
        case 0: return product[idx];
        case 1: return hash_bytes[idx];
        case 2: return nibble_product[idx];
        default: return product_before_oct[idx];
    }
}

inline uchar cryptis_rotate_left_base(
    const uint segment,
    const uchar product[32],
    const uchar nibble_product[32],
    const uchar product_before_oct[32]
) {
    switch (segment) {
        case 0: return (uchar)((nibble_product[3] ^ (uchar)0x4F) * (uchar)3);
        case 1: return (uchar)((product[7] ^ (uchar)0xA6) * (uchar)2);
        case 2: return (uchar)((product_before_oct[1] ^ (uchar)0x9C) * (uchar)9);
        case 3: return (uchar)((product[6] ^ (uchar)0x71) * (uchar)4);
        case 4: return (uchar)((nibble_product[4] ^ (uchar)0xB2) * (uchar)3);
        case 5: return (uchar)((product[0] ^ (uchar)0x58) * (uchar)6);
        case 6: return (uchar)((product_before_oct[2] ^ (uchar)0x37) * (uchar)2);
        case 7: return (uchar)((product[5] ^ (uchar)0x1A) * (uchar)5);
        case 8: return (uchar)((nibble_product[3] ^ (uchar)0x93) * (uchar)7);
        case 9: return (uchar)((product[7] ^ (uchar)0x29) * (uchar)9);
        case 10: return (uchar)((product_before_oct[1] ^ (uchar)0x4E) * (uchar)4);
        case 11: return (uchar)((nibble_product[6] ^ (uchar)0xF3) * (uchar)5);
        case 12: return (uchar)((product[4] ^ (uchar)0xB7) * (uchar)6);
        case 13: return (uchar)((product[0] ^ (uchar)0x2D) * (uchar)8);
        case 14: return (uchar)((product_before_oct[2] ^ (uchar)0x6F) * (uchar)3);
        default: return (uchar)((nibble_product[5] ^ (uchar)0xE1) * (uchar)7);
    }
}

inline uchar cryptis_rotate_right_base(
    const uint segment,
    const uchar product[32],
    const uchar hash_bytes[32],
    const uchar nibble_product[32],
    const uchar product_before_oct[32]
) {
    switch (segment) {
        case 0: return (uchar)((hash_bytes[2] ^ (uchar)0xD3) * (uchar)5);
        case 1: return (uchar)((nibble_product[5] ^ (uchar)0x5B) * (uchar)7);
        case 2: return (uchar)((product[0] ^ (uchar)0x8E) * (uchar)3);
        case 3: return (uchar)((product_before_oct[3] ^ (uchar)0x2F) * (uchar)5);
        case 4: return (uchar)((hash_bytes[7] ^ (uchar)0x6D) * (uchar)7);
        case 5: return (uchar)((nibble_product[1] ^ (uchar)0xEE) * (uchar)9);
        case 6: return (uchar)((hash_bytes[6] ^ (uchar)0x44) * (uchar)6);
        case 7: return (uchar)((hash_bytes[4] ^ (uchar)0x7C) * (uchar)8);
        case 8: return (uchar)((product[2] ^ (uchar)0xAF) * (uchar)3);
        case 9: return (uchar)((nibble_product[5] ^ (uchar)0xDC) * (uchar)2);
        case 10: return (uchar)((hash_bytes[0] ^ (uchar)0x8B) * (uchar)3);
        case 11: return (uchar)((product_before_oct[3] ^ (uchar)0x62) * (uchar)8);
        case 12: return (uchar)((product[7] ^ (uchar)0x15) * (uchar)2);
        case 13: return (uchar)((product_before_oct[1] ^ (uchar)0xC8) * (uchar)7);
        case 14: return (uchar)((nibble_product[6] ^ (uchar)0x99) * (uchar)9);
        default: return (uchar)((hash_bytes[4] ^ (uchar)0x3B) * (uchar)5);
    }
}

inline uchar compute_sbox_entry(
    const uint sbox_idx,
#if (CRYPTIS_OPENCL_ROTATE_BASES_ON_DEMAND == 0)
    const uchar rotate_left_bases[16],
    const uchar rotate_right_bases[16],
#endif
    const uchar product[32],
    const uchar hash_bytes[32],
    const uchar nibble_product[32],
    const uchar product_before_oct[32],
    const uint sbox_iterations
) {
    uint segment = sbox_idx >> 4;
    uint lane = sbox_idx & 15U;

    uint idx_plus1 = (sbox_idx + 1U) & 31U;
    uint idx_plus2 = (sbox_idx + 2U) & 31U;
    uchar p1 = product[idx_plus1];
    uchar h2 = hash_bytes[idx_plus2];

    uchar source_selector = SBOX_SOURCE_SELECTORS[segment];
    uchar value_selector = SBOX_VALUE_SELECTORS[segment];
    uchar value_byte = pick_array_byte(
        value_selector,
        lane,
        product,
        hash_bytes,
        nibble_product,
        product_before_oct
    );
    uchar value = (uchar)(
        value_byte * SBOX_VALUE_MULTIPLIERS[segment] +
        (uchar)(lane * SBOX_VALUE_ADDERS[segment])
    );

    uint rotate_left_shift = (((uint)p1) + sbox_idx) & 7U;
    uint rotate_right_shift = (((uint)h2) + sbox_idx) & 7U;
#if (CRYPTIS_OPENCL_ROTATE_BASES_ON_DEMAND == 0)
    uchar rotate_left_base = rotate_left_bases[segment];
    uchar rotate_right_base = rotate_right_bases[segment];
#else
    uchar rotate_left_base =
        cryptis_rotate_left_base(segment, product, nibble_product, product_before_oct);
    uchar rotate_right_base =
        cryptis_rotate_right_base(segment, product, hash_bytes, nibble_product, product_before_oct);
#endif
    uchar rotation_left = rotl8(rotate_left_base, rotate_left_shift);
    uchar rotation_right = rotr8(rotate_right_base, rotate_right_shift);

    uint source_index = (sbox_idx + (uint)rotation_left + (uint)rotation_right) & 31U;
    uchar source_pick = pick_array_byte(
        source_selector,
        source_index,
        product,
        hash_bytes,
        nibble_product,
        product_before_oct
    );
    value = source_pick ^ value;

    uint rotate_left_shift2 = (((uint)p1) + (sbox_idx << 2U)) & 7U;
    uint rotate_right_shift2 = (((uint)h2) + (sbox_idx * 6U)) & 7U;
    uchar base_value =
        (uchar)(sbox_idx + (uint)(product[(sbox_idx * 3U) & 31U] ^ hash_bytes[(sbox_idx * 7U) & 31U])) ^ (uchar)0xA5;
    uchar xor_value = rotl8(base_value, sbox_idx & 7U) ^ (uchar)0x55;

    uchar rotated_value = (uchar)(rotl8(value, rotate_left_shift2) | rotr8(value, rotate_right_shift2));
    value ^= rotated_value ^ xor_value;

    if (sbox_iterations == 2U) {
        rotated_value = (uchar)(rotl8(value, rotate_left_shift2) | rotr8(value, rotate_right_shift2));
        value ^= rotated_value ^ xor_value;
    }

    return value;
}
inline void cryptix_hash_matrix(
    __local const uchar* matrix,
    const uchar hash_bytes[32],
    uchar output[32]
) {
    uchar product[32];
    uchar nibble_product[32];
    const __local uchar* row_ptr0 = matrix;
    const __local uchar* row_ptr1 = matrix + 64U;
    const __local uchar* row_ptr2 = matrix + 128U;
    const __local uchar* row_ptr3 = matrix + 192U;

    for (uint i = 0; i < 32; i++) {
        uint sum1 = 0U;
        uint sum2 = 0U;
        uint sum3 = 0U;
        uint sum4 = 0U;

        #pragma unroll 16
        for (uint block = 0; block < 16U; block++) {
            uint hash_byte_idx = block << 1U;
            uchar hb0 = hash_bytes[hash_byte_idx];
            uchar hb1 = hash_bytes[hash_byte_idx + 1U];

            uint4 nib = (uint4)(
                (uint)(hb0 >> 4),
                (uint)(hb0 & 0x0FU),
                (uint)(hb1 >> 4),
                (uint)(hb1 & 0x0FU)
            );

            uint4 row_vec = convert_uint4(vload4(block, row_ptr0));
            sum1 = cryptis_dot4_acc(sum1, row_vec, nib);

            row_vec = convert_uint4(vload4(block, row_ptr1));
            sum2 = cryptis_dot4_acc(sum2, row_vec, nib);

            row_vec = convert_uint4(vload4(block, row_ptr2));
            sum3 = cryptis_dot4_acc(sum3, row_vec, nib);

            row_vec = convert_uint4(vload4(block, row_ptr3));
            sum4 = cryptis_dot4_acc(sum4, row_vec, nib);
        }

        row_ptr0 += 128U;
        row_ptr1 += 128U;
        row_ptr2 += 64U;
        row_ptr3 += 64U;

        uint a_nibble = (sum1 & 0xFU)
            ^ ((sum2 >> 4) & 0xFU)
            ^ ((sum3 >> 8) & 0xFU)
            ^ ((sum1 * 0xABCDU >> 12) & 0xFU)
            ^ ((sum1 * 0x1234U >> 8) & 0xFU)
            ^ ((sum2 * 0x5678U >> 16) & 0xFU)
            ^ ((sum3 * 0x9ABCU >> 4) & 0xFU)
            ^ ((rotl32(sum1, 3U) & 0xFU) ^ (rotr32(sum3, 5U) & 0xFU));

        uint b_nibble = (sum2 & 0xFU)
            ^ ((sum1 >> 4) & 0xFU)
            ^ ((sum4 >> 8) & 0xFU)
            ^ ((sum2 * 0xDCBAU >> 14) & 0xFU)
            ^ ((sum2 * 0x8765U >> 10) & 0xFU)
            ^ ((sum1 * 0x4321U >> 6) & 0xFU)
            ^ ((rotl32(sum4, 2U) ^ rotr32(sum1, 1U)) & 0xFU);

        uint c_nibble = (sum3 & 0xFU)
            ^ ((sum2 >> 4) & 0xFU)
            ^ ((sum2 >> 8) & 0xFU)
            ^ ((sum3 * 0xF135U >> 10) & 0xFU)
            ^ ((sum3 * 0x2468U >> 12) & 0xFU)
            ^ ((sum4 * 0xACEFU >> 8) & 0xFU)
            ^ ((sum2 * 0x1357U >> 4) & 0xFU)
            ^ ((rotl32(sum3, 5U) & 0xFU) ^ (rotr32(sum1, 7U) & 0xFU));

        uint d_nibble = (sum1 & 0xFU)
            ^ ((sum4 >> 4) & 0xFU)
            ^ ((sum1 >> 8) & 0xFU)
            ^ ((sum4 * 0x57A3U >> 6) & 0xFU)
            ^ ((sum3 * 0xD4E3U >> 12) & 0xFU)
            ^ ((sum1 * 0x9F8BU >> 10) & 0xFU)
            ^ ((rotl32(sum4, 4U) ^ (sum1 + sum2)) & 0xFU);

        uchar hash_byte = hash_bytes[i];
        nibble_product[i] = (uchar)((((c_nibble & 0xFU) << 4) | (d_nibble & 0xFU)) ^ hash_byte);
        product[i] = (uchar)((((a_nibble & 0xFU) << 4) | (b_nibble & 0xFU)) ^ hash_byte);
    }

    uchar product_before_oct[32];
    #pragma unroll 32
    for (uint i = 0; i < 32; i++) {
        product_before_oct[i] = product[i];
    }

    ulong oct_result[8];
    octonion_hash(product, oct_result);

    for (uint i = 0; i < 4; i++) {
        uint offset = i * 8U;
        ulong mixed_word = load64_le_private(product, offset) ^ oct_result[i];
        store64_le_private(mixed_word, product, offset);
    }

#if (CRYPTIS_OPENCL_ROTATE_BASES_ON_DEMAND == 0)
    uchar rotate_left_bases[16] = {
        (uchar)((nibble_product[3] ^ (uchar)0x4F) * (uchar)3),
        (uchar)((product[7] ^ (uchar)0xA6) * (uchar)2),
        (uchar)((product_before_oct[1] ^ (uchar)0x9C) * (uchar)9),
        (uchar)((product[6] ^ (uchar)0x71) * (uchar)4),
        (uchar)((nibble_product[4] ^ (uchar)0xB2) * (uchar)3),
        (uchar)((product[0] ^ (uchar)0x58) * (uchar)6),
        (uchar)((product_before_oct[2] ^ (uchar)0x37) * (uchar)2),
        (uchar)((product[5] ^ (uchar)0x1A) * (uchar)5),
        (uchar)((nibble_product[3] ^ (uchar)0x93) * (uchar)7),
        (uchar)((product[7] ^ (uchar)0x29) * (uchar)9),
        (uchar)((product_before_oct[1] ^ (uchar)0x4E) * (uchar)4),
        (uchar)((nibble_product[6] ^ (uchar)0xF3) * (uchar)5),
        (uchar)((product[4] ^ (uchar)0xB7) * (uchar)6),
        (uchar)((product[0] ^ (uchar)0x2D) * (uchar)8),
        (uchar)((product_before_oct[2] ^ (uchar)0x6F) * (uchar)3),
        (uchar)((nibble_product[5] ^ (uchar)0xE1) * (uchar)7)
    };

    uchar rotate_right_bases[16] = {
        (uchar)((hash_bytes[2] ^ (uchar)0xD3) * (uchar)5),
        (uchar)((nibble_product[5] ^ (uchar)0x5B) * (uchar)7),
        (uchar)((product[0] ^ (uchar)0x8E) * (uchar)3),
        (uchar)((product_before_oct[3] ^ (uchar)0x2F) * (uchar)5),
        (uchar)((hash_bytes[7] ^ (uchar)0x6D) * (uchar)7),
        (uchar)((nibble_product[1] ^ (uchar)0xEE) * (uchar)9),
        (uchar)((hash_bytes[6] ^ (uchar)0x44) * (uchar)6),
        (uchar)((hash_bytes[4] ^ (uchar)0x7C) * (uchar)8),
        (uchar)((product[2] ^ (uchar)0xAF) * (uchar)3),
        (uchar)((nibble_product[5] ^ (uchar)0xDC) * (uchar)2),
        (uchar)((hash_bytes[0] ^ (uchar)0x8B) * (uchar)3),
        (uchar)((product_before_oct[3] ^ (uchar)0x62) * (uchar)8),
        (uchar)((product[7] ^ (uchar)0x15) * (uchar)2),
        (uchar)((product_before_oct[1] ^ (uchar)0xC8) * (uchar)7),
        (uchar)((nibble_product[6] ^ (uchar)0x99) * (uchar)9),
        (uchar)((hash_bytes[4] ^ (uchar)0x3B) * (uchar)5)
    };
#endif

    uint update_index = ((uint)(product_before_oct[2] & (uchar)7U)) + 1U;
    uint sbox_iterations = 1U + ((uint)(product[update_index] & (uchar)1U));


    uint index_blake = ((uint)(product_before_oct[5] & (uchar)7U)) + 1U;
    uint iterations_blake = 1U + ((uint)(product[index_blake] % (uchar)3));

    #pragma unroll 32
    for (uint i = 0; i < 32; i++) {
        output[i] = product[i];
    }

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

    uint ref_idx = 0U;
    uint product_idx = 0U;
    uint hash_idx = 0U;
    uint mix_term = 0U;
    for (uint i = 0; i < 32; i++) {
        uchar ref_val = pick_ref_value((uchar)(i & 3U), ref_idx, nibble_product, product_before_oct, product, hash_bytes);
        uint index = (
            (uint)ref_val +
            (uint)product[product_idx] +
            (uint)hash_bytes[hash_idx] +
            mix_term
        ) & 255U;

        uchar sbox_byte = compute_sbox_entry(
            index,
#if (CRYPTIS_OPENCL_ROTATE_BASES_ON_DEMAND == 0)
            rotate_left_bases,
            rotate_right_bases,
#endif
            product,
            hash_bytes,
            nibble_product,
            product_before_oct,
            sbox_iterations
        );
        output[i] ^= sbox_byte ^ AFTER_COMP_LUT[(uint)product[i]];

        ref_idx = (ref_idx + 13U) & 31U;
        product_idx = (product_idx + 31U) & 31U;
        hash_idx = (hash_idx + 19U) & 31U;
        mix_term = (mix_term + 41U) & 255U;
    }

    cryptix_hash_v2_hash(output, output);
}

inline void pow_hash_finalize(
    __constant const ulong* pow_state_base,
    ulong nonce,
    uchar output[32]
) {
    ulong st[25];
    for (uint i = 0; i < 25; i++) {
        st[i] = pow_state_base[i];
    }

    st[9] ^= nonce;
    keccak_f1600(st);

    store64_le_private(st[0], output, 0);
    store64_le_private(st[1], output, 8);
    store64_le_private(st[2], output, 16);
    store64_le_private(st[3], output, 24);
}

inline void calculate_pow_pre_matrix(
    __constant const ulong* pow_state_base,
    ulong nonce,
    uchar output[32]
) {
    uchar hash_bytes[32];
    pow_hash_finalize(pow_state_base, nonce, hash_bytes);

    uint iterations = ((uint)hash_bytes[0] & 1U) + 1U;

    uchar current_hash[32];
    for (uint i = 0; i < 32; i++) {
        current_hash[i] = hash_bytes[i];
    }

    for (uint i = 0; i < iterations; i++) {
        sha3_256_32bytes(current_hash, current_hash);

        if ((current_hash[1] & (uchar)3U) == 0U) {
            uint repeat = ((uint)(current_hash[2] & (uchar)3U)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[1]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0xA5;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[1] + (uint)current_hash[3]) & 3U) + 2U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[5] + (uint)current_hash[1]) % 3U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[3] % (uchar)3) == 0) {
            uint repeat = ((uint)(current_hash[4] % (uchar)5)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[6]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0x55;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[7] + (uint)current_hash[2]) % 6U) + 1U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[1] + (uint)current_hash[3]) % 4U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[2] % (uchar)6) == 0) {
            uint repeat = ((uint)(current_hash[6] & (uchar)3U)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[10]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0xFF;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[7] + (uint)current_hash[7]) % 7U) + 1U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[3] + (uint)current_hash[5]) % 5U) + 2U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[7] % (uchar)5) == 0) {
            uint repeat = ((uint)(current_hash[8] & (uchar)3U)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[25]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0x66;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[1] + (uint)current_hash[3]) & 3U) + 2U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[1] + (uint)current_hash[3]) & 3U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[8] % (uchar)7) == 0) {
            uint repeat = ((uint)(current_hash[9] % (uchar)5)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[30]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0x77;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[2] + (uint)current_hash[5]) % 5U) + 1U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[7] + (uint)current_hash[9]) % 6U) + 2U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        }
    }

    for (uint i = 0; i < 32; i++) {
        output[i] = current_hash[i];
    }
}
inline void calculate_pow_with_sha3_and_matrix(
    __local const uchar* matrix,
    __constant const ulong* pow_state_base,
    ulong nonce,
    uchar output[32]
) {
    uchar current_hash[32];
    calculate_pow_pre_matrix(pow_state_base, nonce, current_hash);
    cryptix_hash_matrix(matrix, current_hash, output);
}

inline int hash_meets_target_words(const uchar hash[32], __constant const ulong* target_words) {
    for (int i = 3; i >= 0; i--) {
        ulong hash_word = load64_le_private(hash, (uint)(i * 8));
        ulong target_word = target_words[i];
        if (hash_word < target_word) {
            return 1;
        }
        if (hash_word > target_word) {
            return 0;
        }
    }
    return 1;
}

__kernel void cryptix_ox8_pre_matrix_batch(
    __constant const ulong* pow_state_base,
    ulong start_nonce,
    uint nonce_count,
    __global ulong* out_nonces,
    __global uchar* out_hashes
) {
    uint gid = get_global_id(0);
    if (gid >= nonce_count) {
        return;
    }

    ulong nonce = start_nonce + (ulong)gid;
    uchar result[32];
    calculate_pow_pre_matrix(pow_state_base, nonce, result);

    out_nonces[gid] = nonce;
    size_t out_offset = ((size_t)gid) * 32U;
    for (uint i = 0; i < 32; i++) {
        out_hashes[out_offset + i] = result[i];
    }
}

__kernel void cryptix_ox8_hash_batch_raw(
    __constant const uchar* matrix,
    __constant const ulong* pow_state_base,
    ulong start_nonce,
    uint nonce_count,
    __global uchar* out_hashes
) {
    uint gid = get_global_id(0);
    if (gid >= nonce_count) {
        return;
    }

    __local uchar matrix_local[64U * 64U];
    uint lid = get_local_id(0);
    uint lsize = get_local_size(0);
    const uint matrix_bytes = (64U * 64U);
    const uint matrix_vec_count = matrix_bytes / 16U;
    for (uint vec_idx = lid; vec_idx < matrix_vec_count; vec_idx += lsize) {
        uchar16 chunk = vload16(vec_idx, matrix);
        vstore16(chunk, vec_idx, matrix_local);
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    ulong nonce = start_nonce + (ulong)gid;
    uchar result[32];
    calculate_pow_with_sha3_and_matrix(matrix_local, pow_state_base, nonce, result);

    size_t out_offset = ((size_t)gid) * 32U;
    for (uint i = 0; i < 32; i++) {
        out_hashes[out_offset + i] = result[i];
    }
}

__kernel void cryptix_ox8_hash_batch(
    __constant const uchar* matrix,
    __constant const ulong* pow_state_base,
    __constant const ulong* target_words,
    ulong start_nonce,
    uint nonce_count,
    uint max_results,
    __global uint* out_count,
    __global ulong* out_nonces
) {
    uint gid = get_global_id(0);
    if (gid >= nonce_count) {
        return;
    }

    __local uchar matrix_local[64U * 64U];
    uint lid = get_local_id(0);
    uint lsize = get_local_size(0);
    const uint matrix_bytes = (64U * 64U);
    const uint matrix_vec_count = matrix_bytes / 16U;
    for (uint vec_idx = lid; vec_idx < matrix_vec_count; vec_idx += lsize) {
        uchar16 chunk = vload16(vec_idx, matrix);
        vstore16(chunk, vec_idx, matrix_local);
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    ulong nonce = start_nonce + (ulong)gid;
    uchar result[32];
    calculate_pow_with_sha3_and_matrix(matrix_local, pow_state_base, nonce, result);

    if (!hash_meets_target_words(result, target_words)) {
        return;
    }

    uint slot = atomic_inc((volatile __global uint*)out_count);
    if (slot >= max_results) {
        return;
    }

    out_nonces[slot] = nonce;
}
#define RANDOM_LEAN 0
#define RANDOM_XOSHIRO 1

inline ulong load64_le_global_ptr(__global const uchar* in, uint offset) {
    uint base = offset;
    return ((ulong)in[base + 0]) |
        ((ulong)in[base + 1] << 8) |
        ((ulong)in[base + 2] << 16) |
        ((ulong)in[base + 3] << 24) |
        ((ulong)in[base + 4] << 32) |
        ((ulong)in[base + 5] << 40) |
        ((ulong)in[base + 6] << 48) |
        ((ulong)in[base + 7] << 56);
}

inline void pow_hash_finalize_from_header(
    __global const uchar* hash_header,
    ulong nonce,
    uchar output[32]
) {
    ulong st[25];
    for (uint i = 0; i < 25; i++) {
        st[i] = POW_HASH_INITIAL_STATE[i];
    }

    for (uint i = 0; i < 9; i++) {
        st[i] ^= load64_le_global_ptr(hash_header, i * 8U);
    }

    st[9] ^= nonce;
    keccak_f1600(st);

    store64_le_private(st[0], output, 0);
    store64_le_private(st[1], output, 8);
    store64_le_private(st[2], output, 16);
    store64_le_private(st[3], output, 24);
}

inline void calculate_pow_pre_matrix_from_header(
    __global const uchar* hash_header,
    ulong nonce,
    uchar output[32]
) {
    uchar current_hash[32];
    pow_hash_finalize_from_header(hash_header, nonce, current_hash);

    uint iterations = ((uint)current_hash[0] & 1U) + 1U;

    for (uint i = 0; i < iterations; i++) {
        sha3_256_32bytes(current_hash, current_hash);

        if ((current_hash[1] & (uchar)3U) == 0U) {
            uint repeat = ((uint)(current_hash[2] & (uchar)3U)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[1]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0xA5;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[1] + (uint)current_hash[3]) & 3U) + 2U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[5] + (uint)current_hash[1]) % 3U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[3] % (uchar)3) == 0) {
            uint repeat = ((uint)(current_hash[4] % (uchar)5)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[6]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0x55;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[7] + (uint)current_hash[2]) % 6U) + 1U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[1] + (uint)current_hash[3]) % 4U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[2] % (uchar)6) == 0) {
            uint repeat = ((uint)(current_hash[6] & (uchar)3U)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[10]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0xFF;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[7] + (uint)current_hash[7]) % 7U) + 1U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[3] + (uint)current_hash[5]) % 5U) + 2U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[7] % (uchar)5) == 0) {
            uint repeat = ((uint)(current_hash[8] & (uchar)3U)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[25]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0x66;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[1] + (uint)current_hash[3]) & 3U) + 2U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[1] + (uint)current_hash[3]) & 3U) + 1U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
        } else if ((current_hash[8] % (uchar)7) == 0) {
            uint repeat = ((uint)(current_hash[9] % (uchar)5)) + 1U;
            for (uint r = 0; r < repeat; r++) {
                uint target_byte = (((uint)current_hash[30]) + i) & 31U;
                uchar xor_value = current_hash[i & 15U] ^ (uchar)0x77;
                current_hash[target_byte] ^= xor_value;

                uchar rotation_byte = current_hash[i & 31U];
                uint rotation_amount = (((uint)current_hash[2] + (uint)current_hash[5]) % 5U) + 1U;
                if ((rotation_byte & 1U) == 0U) {
                    current_hash[target_byte] = rotl8(current_hash[target_byte], rotation_amount);
                } else {
                    current_hash[target_byte] = rotr8(current_hash[target_byte], rotation_amount);
                }

                uint shift_amount = (((uint)current_hash[7] + (uint)current_hash[9]) % 6U) + 2U;
                current_hash[target_byte] ^= rotl8(current_hash[target_byte], shift_amount);
            }
         }
     }

    for (uint i = 0; i < 32; i++) {
        output[i] = current_hash[i];
    }
}

inline void calculate_pow_with_header_and_matrix(
    __local const uchar* matrix,
    __global const uchar* hash_header,
    ulong nonce,
    uchar output[32]
) {
    uchar current_hash[32];
    calculate_pow_pre_matrix_from_header(hash_header, nonce, current_hash);
    cryptix_hash_matrix(matrix, current_hash, output);
}

inline int hash_meets_target_words_global(const uchar hash[32], __global const ulong* target_words) {
    for (int i = 3; i >= 0; i--) {
        ulong hash_word = load64_le_private(hash, (uint)(i * 8));
        ulong target_word = target_words[i];
        if (hash_word < target_word) {
            return 1;
        }
        if (hash_word > target_word) {
            return 0;
        }
    }
    return 1;
}

inline ulong xoshiro256_next_compat(__global ulong4* state) {
    ulong4 s = *state;
    ulong result = rotl64(s.y * 5UL, 7U) * 9UL;
    ulong t = s.y << 17U;
    s.z ^= s.x;
    s.w ^= s.y;
    s.y ^= s.z;
    s.x ^= s.w;
    s.z ^= t;
    s.w = rotl64(s.w, 45U);
    *state = s;
    return result;
}

__kernel void heavy_hash(const ulong local_size,
                         const ulong nonce_mask,
                         const ulong nonce_fixed,
                         __global const uchar *hash_header,
                         __global const uchar *matrix,
                         __global const ulong *target,
                         uchar random_type,
                         __global ulong *states,
                         __global ulong *final_nonce,
                         __global ulong4 *final_hash) {
    (void)local_size;

    uint gid = get_global_id(0);
    ulong nonce_id = (ulong)gid;

    if (gid == 0U) {
        final_nonce[0] = 0UL;
    }

    __local uchar matrix_local[64U * 64U];
    uint lid = get_local_id(0);
    uint lsize = get_local_size(0);
    const uint matrix_vec_count = (64U * 64U) / 16U;
    for (uint vec_idx = lid; vec_idx < matrix_vec_count; vec_idx += lsize) {
        uchar16 chunk16 = vload16(vec_idx, matrix);
        vstore16(chunk16, vec_idx, matrix_local);
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    ulong nonce;
    if (random_type == (uchar)RANDOM_LEAN) {
        nonce = states[0] ^ nonce_id;
    } else {
        __global ulong4* st4 = (__global ulong4*)states;
        nonce = xoshiro256_next_compat(st4 + nonce_id);
    }

    nonce = (nonce & nonce_mask) | nonce_fixed;

    uchar result[32];
    calculate_pow_with_header_and_matrix(matrix_local, hash_header, nonce, result);

    if (!hash_meets_target_words_global(result, target)) {
        return;
    }

    if (final_nonce[0] == 0UL) {
        final_nonce[0] = nonce;
        final_hash[0] = (ulong4)(
            load64_le_private(result, 0U),
            load64_le_private(result, 8U),
            load64_le_private(result, 16U),
            load64_le_private(result, 24U)
        );
    }
}