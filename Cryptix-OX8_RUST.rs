//! Standalone OX8 CPU integration (full hash implementation + CLI I/O)
//!
//! This file is self-contained for developers who want to integrate OX8 hashing directly.
//! It includes:
//! - full OX8 CPU hash logic
//! - simple CLI input/output glue
//!
//! Usage:
//!   ox8_cpu_integration --pre-pow-hash <64-hex> --timestamp <u64> --nonce <u64>
//!   ox8_cpu_integration --header <80-hex> --nonce <u64>
//!
//! Header format: 32-byte pre_pow_hash + 8-byte little-endian timestamp.

use num_bigint::BigUint;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn from_hex(hex_str: &str) -> std::result::Result<Self, String> {
        let normalized = hex_str.trim().trim_start_matches("0x");
        let bytes = hex::decode(normalized).map_err(|e| format!("hex decode failed: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "invalid hash length: expected 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash256(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(Debug, Clone)]
pub enum MinerError {
    AlgorithmError(String),
}

impl fmt::Display for MinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MinerError::AlgorithmError(msg) => write!(f, "Algorithm error: {}", msg),
        }
    }
}

impl std::error::Error for MinerError {}

pub type Result<T> = std::result::Result<T, MinerError>;
// Cryptix OX8

use sha3::{Digest, Sha3_256};
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::num::Wrapping;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const POW_HASH_INITIAL_STATE: [u64; 25] = [
    1242148031264380989,
    3008272977830772284,
    2188519011337848018,
    1992179434288343456,
    8876506674959887717,
    5399642050693751366,
    1745875063082670864,
    8605242046444978844,
    17936695144567157056,
    3343109343542796272,
    1123092876221303306,
    4963925045340115282,
    17037383077651887893,
    16629644495023626889,
    12833675776649114147,
    3784524041015224902,
    1082795874807940378,
    13952716920571277634,
    13411128033953605860,
    15060696040649351053,
    9928834659948351306,
    5237849264682708699,
    12825353012139217522,
    6706187291358897596,
    196324915476054915,
];

const HEAVY_HASH_INITIAL_STATE: [u64; 25] = [
    4239941492252378377,
    8746723911537738262,
    8796936657246353646,
    1272090201925444760,
    16654558671554924250,
    8270816933120786537,
    13907396207649043898,
    6782861118970774626,
    9239690602118867528,
    11582319943599406348,
    17596056728278508070,
    15212962468105129023,
    7812475424661425213,
    3370482334374859748,
    5690099369266491460,
    8596393687355028144,
    570094237299545110,
    9119540418498120711,
    16901969272480492857,
    13372017233735502424,
    14372891883993151831,
    5171152063242093102,
    10573107899694386186,
    6096431547456407061,
    1592359455985097269,
];

const RANK_EPSILON: f64 = 1e-9;
const MATRIX_CACHE_CAPACITY: usize = 64;
const SEL_PRODUCT: u8 = 0;
const SEL_HASH: u8 = 1;
const SEL_NIBBLE: u8 = 2;
const SEL_BEFORE_OCT: u8 = 3;
const SBOX_SOURCE_SELECTORS: [u8; 16] = [
    SEL_PRODUCT,
    SEL_HASH,
    SEL_NIBBLE,
    SEL_HASH,
    SEL_BEFORE_OCT,
    SEL_HASH,
    SEL_PRODUCT,
    SEL_HASH,
    SEL_BEFORE_OCT,
    SEL_HASH,
    SEL_NIBBLE,
    SEL_HASH,
    SEL_BEFORE_OCT,
    SEL_HASH,
    SEL_PRODUCT,
    SEL_HASH,
];
const SBOX_VALUE_SELECTORS: [u8; 16] = [
    SEL_PRODUCT,
    SEL_HASH,
    SEL_BEFORE_OCT,
    SEL_NIBBLE,
    SEL_PRODUCT,
    SEL_HASH,
    SEL_BEFORE_OCT,
    SEL_NIBBLE,
    SEL_PRODUCT,
    SEL_HASH,
    SEL_BEFORE_OCT,
    SEL_NIBBLE,
    SEL_PRODUCT,
    SEL_HASH,
    SEL_BEFORE_OCT,
    SEL_NIBBLE,
];
const SBOX_VALUE_MULTIPLIERS: [u8; 16] = [
    0x03, 0x05, 0x07, 0x0F, 0x11, 0x13, 0x17, 0x19, 0x1D, 0x1F, 0x23, 0x29, 0x2F, 0x31, 0x37, 0x3F,
];
const SBOX_VALUE_ADDERS: [u8; 16] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
];

fn cache_key(pre_pow_hash: &[u8; 32], timestamp: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(pre_pow_hash);
    key[32..40].copy_from_slice(&timestamp.to_le_bytes());
    key
}

thread_local! {
    static THREAD_LOCAL_OX8_CONTEXT: RefCell<ThreadLocalOx8Context> = RefCell::new(ThreadLocalOx8Context::new());
}

struct ThreadLocalOx8Context {
    cached_pow_state: Option<([u8; 40], PowState)>,
    sha3_hasher: Sha3_256,
}

impl ThreadLocalOx8Context {
    fn new() -> Self {
        Self {
            cached_pow_state: None,
            sha3_hasher: Sha3_256::new(),
        }
    }
}

// 0=auto, 1=force on, 2=force off
static OX8_AVX2_PREFERENCE: AtomicU8 = AtomicU8::new(0);
// 0=unresolved, 1=enabled, 2=disabled
static OX8_AVX2_RUNTIME: AtomicU8 = AtomicU8::new(0);

pub fn set_ox8_avx2_preference(enabled: Option<bool>) {
    let value = match enabled {
        Some(true) => 1,
        Some(false) => 2,
        None => 0,
    };
    OX8_AVX2_PREFERENCE.store(value, Ordering::Relaxed);
    OX8_AVX2_RUNTIME.store(0, Ordering::Relaxed);
}

#[inline(always)]
fn avx2_cpu_supported() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        static HAS_AVX2: OnceLock<bool> = OnceLock::new();
        *HAS_AVX2.get_or_init(|| std::is_x86_feature_detected!("avx2"))
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[inline(always)]
fn avx2_available() -> bool {
    match OX8_AVX2_RUNTIME.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let enabled = match OX8_AVX2_PREFERENCE.load(Ordering::Relaxed) {
                1 => avx2_cpu_supported(),
                2 => false,
                _ => {
                    if std::env::var_os("CRYPTIX_DISABLE_AVX2").is_some() {
                        false
                    } else {
                        avx2_cpu_supported()
                    }
                }
            };
            OX8_AVX2_RUNTIME.store(if enabled { 1 } else { 2 }, Ordering::Relaxed);
            enabled
        }
    }
}

pub fn ox8_backend_description() -> String {
    let cpu_has_avx2 = avx2_cpu_supported();
    match OX8_AVX2_PREFERENCE.load(Ordering::Relaxed) {
        1 => {
            if cpu_has_avx2 {
                "AVX2 (forced on)".to_string()
            } else {
                "scalar (AVX2 forced on but unsupported by CPU)".to_string()
            }
        }
        2 => "scalar (forced off)".to_string(),
        _ => {
            if std::env::var_os("CRYPTIX_DISABLE_AVX2").is_some() {
                "scalar (disabled via CRYPTIX_DISABLE_AVX2)".to_string()
            } else if cpu_has_avx2 {
                "AVX2".to_string()
            } else if cfg!(target_arch = "aarch64") {
                "scalar (ARM64/NEON path not enabled)".to_string()
            } else {
                "scalar".to_string()
            }
        }
    }
}

#[inline(always)]
fn dot_products_4rows(
    row0: &[u8; 64],
    row1: &[u8; 64],
    row2: &[u8; 64],
    row3: &[u8; 64],
    nibbles: &[u8; 64],
    use_avx2: bool,
) -> (u32, u32, u32, u32) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if use_avx2 {
            // SAFETY: AVX2 path is only called when runtime detection confirmed support.
            return unsafe { dot_products_4rows_avx2(row0, row1, row2, row3, nibbles) };
        }
    }

    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut sum3: u32 = 0;
    let mut sum4: u32 = 0;

    let mut j = 0usize;
    while j < 64 {
        let e0 = nibbles[j] as u32;
        let e1 = nibbles[j + 1] as u32;
        let e2 = nibbles[j + 2] as u32;
        let e3 = nibbles[j + 3] as u32;

        sum1 += (row0[j] as u32) * e0
            + (row0[j + 1] as u32) * e1
            + (row0[j + 2] as u32) * e2
            + (row0[j + 3] as u32) * e3;
        sum2 += (row1[j] as u32) * e0
            + (row1[j + 1] as u32) * e1
            + (row1[j + 2] as u32) * e2
            + (row1[j + 3] as u32) * e3;
        sum3 += (row2[j] as u32) * e0
            + (row2[j + 1] as u32) * e1
            + (row2[j + 2] as u32) * e2
            + (row2[j + 3] as u32) * e3;
        sum4 += (row3[j] as u32) * e0
            + (row3[j + 1] as u32) * e1
            + (row3[j + 2] as u32) * e2
            + (row3[j + 3] as u32) * e3;
        j += 4;
    }

    (sum1, sum2, sum3, sum4)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn dot_products_4rows_avx2(
    row0: &[u8; 64],
    row1: &[u8; 64],
    row2: &[u8; 64],
    row3: &[u8; 64],
    nibbles: &[u8; 64],
) -> (u32, u32, u32, u32) {
    let ones = _mm256_set1_epi16(1);
    let n0 = _mm256_loadu_si256(nibbles.as_ptr() as *const __m256i);
    let n1 = _mm256_loadu_si256(nibbles.as_ptr().add(32) as *const __m256i);

    let mut acc0 = _mm256_setzero_si256();
    let mut acc1 = _mm256_setzero_si256();
    let mut acc2 = _mm256_setzero_si256();
    let mut acc3 = _mm256_setzero_si256();

    macro_rules! accum_row_chunk {
        ($acc:ident, $row:expr, $nib:expr, $offset:expr) => {{
            let row_vec = _mm256_loadu_si256($row.as_ptr().add($offset) as *const __m256i);
            let mul16 = _mm256_maddubs_epi16(row_vec, $nib);
            let mul32 = _mm256_madd_epi16(mul16, ones);
            $acc = _mm256_add_epi32($acc, mul32);
        }};
    }

    accum_row_chunk!(acc0, row0, n0, 0);
    accum_row_chunk!(acc1, row1, n0, 0);
    accum_row_chunk!(acc2, row2, n0, 0);
    accum_row_chunk!(acc3, row3, n0, 0);

    accum_row_chunk!(acc0, row0, n1, 32);
    accum_row_chunk!(acc1, row1, n1, 32);
    accum_row_chunk!(acc2, row2, n1, 32);
    accum_row_chunk!(acc3, row3, n1, 32);

    (
        hsum_u32x8_avx2(acc0),
        hsum_u32x8_avx2(acc1),
        hsum_u32x8_avx2(acc2),
        hsum_u32x8_avx2(acc3),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn hsum_u32x8_avx2(v: __m256i) -> u32 {
    let lo = _mm256_castsi256_si128(v);
    let hi = _mm256_extracti128_si256(v, 1);
    let sum128 = _mm_add_epi32(lo, hi);
    let sum64 = _mm_add_epi32(sum128, _mm_srli_si128(sum128, 8));
    let sum32 = _mm_add_epi32(sum64, _mm_srli_si128(sum64, 4));
    _mm_cvtsi128_si32(sum32) as u32
}

// ============================================================
// PowHash
// ============================================================

#[derive(Clone, Copy)]
pub struct PowHash([u64; 25]);

impl PowHash {
    pub fn new(pre_pow_hash: &[u8; 32], timestamp: u64) -> Self {
        let mut state = POW_HASH_INITIAL_STATE;
        for i in 0..4 {
            let word = u64::from_le_bytes(pre_pow_hash[i * 8..i * 8 + 8].try_into().unwrap());
            state[i] ^= word;
        }
        state[4] ^= timestamp;
        Self(state)
    }

    pub fn finalize_with_nonce(&self, nonce: u64) -> [u8; 32] {
        let mut state = self.0;
        state[9] ^= nonce;
        keccak::f1600(&mut state);
        let mut result = [0u8; 32];
        for i in 0..4 {
            result[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        }
        result
    }
}

// ============================================================
// CryptixHashV2
// ============================================================

pub struct CryptixHashV2;

impl CryptixHashV2 {
    pub fn hash(input: &[u8; 32]) -> [u8; 32] {
        let mut state = HEAVY_HASH_INITIAL_STATE;
        for i in 0..4 {
            let word = u64::from_le_bytes(input[i * 8..i * 8 + 8].try_into().unwrap());
            state[i] ^= word;
        }
        keccak::f1600(&mut state);
        let mut result = [0u8; 32];
        for i in 0..4 {
            result[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        }
        result
    }
}

// ============================================================
// XoShiRo256PlusPlus
// ============================================================

pub struct XoShiRo256PlusPlus {
    s0: Wrapping<u64>,
    s1: Wrapping<u64>,
    s2: Wrapping<u64>,
    s3: Wrapping<u64>,
}

impl XoShiRo256PlusPlus {
    pub fn new(hash: &[u8; 32]) -> Self {
        let s0 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let s1 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        let s2 = u64::from_le_bytes(hash[16..24].try_into().unwrap());
        let s3 = u64::from_le_bytes(hash[24..32].try_into().unwrap());
        Self {
            s0: Wrapping(s0),
            s1: Wrapping(s1),
            s2: Wrapping(s2),
            s3: Wrapping(s3),
        }
    }

    /// XoShiRo256++ next u64.
    pub fn u64(&mut self) -> u64 {
        let res = self.s0 + Wrapping((self.s0 + self.s3).0.rotate_left(23));
        let t = self.s1 << 17;
        self.s2 ^= self.s0;
        self.s3 ^= self.s1;
        self.s1 ^= self.s2;
        self.s0 ^= self.s3;
        self.s2 ^= t;
        self.s3 = Wrapping(self.s3.0.rotate_left(45));
        res.0
    }
}

// ============================================================
// Matrix
// ============================================================

pub struct Matrix([[u8; 64]; 64]);

impl Matrix {
    pub fn generate(pre_pow_hash: &[u8; 32]) -> Self {
        let mut generator = XoShiRo256PlusPlus::new(pre_pow_hash);
        loop {
            let mat = Self::rand_matrix_no_rank_check(&mut generator);
            if mat.compute_rank() == 64 {
                return mat;
            }
        }
    }

    fn rand_matrix_no_rank_check(generator: &mut XoShiRo256PlusPlus) -> Self {
        let mut mat = [[0u8; 64]; 64];
        for row in mat.iter_mut() {
            let mut val = 0u64;
            for (j, cell) in row.iter_mut().enumerate() {
                let shift = j % 16;
                if shift == 0 {
                    val = generator.u64();
                }
                *cell = ((val >> (4 * shift)) & 0x0F) as u8;
            }
        }
        Matrix(mat)
    }

    pub fn compute_rank(&self) -> usize {
        let eps = RANK_EPSILON;
        let mut mat_float = [[0.0f64; 64]; 64];
        for i in 0..64 {
            for j in 0..64 {
                mat_float[i][j] = self.0[i][j] as f64;
            }
        }
        let mut rank = 0usize;
        let mut row_selected = [false; 64];
        for i in 0..64 {
            let mut j = 0;
            while j < 64 {
                if !row_selected[j] && mat_float[j][i].abs() > eps {
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
                    if k != j && mat_float[k][i].abs() > eps {
                        for p in (i + 1)..64 {
                            mat_float[k][p] -= mat_float[j][p] * mat_float[k][i];
                        }
                    }
                }
            }
        }
        rank
    }

    // **Anti-FPGA Sidedoor**

    // Chaotic Mul
    fn chaotic_random(x: u32) -> u32 {
        (x.wrapping_mul(362605)) ^ 0xA5A5A5A5
    }

    // Mix the Values
    fn memory_intensive_mix(seed: u32) -> u32 {
        let mut acc = seed;
        for i in 0..32 {
            acc = (acc.wrapping_mul(16625)) ^ i;
        }
        acc
    }

    // Fibonacci
    fn recursive_fibonacci_modulated(mut x: u32) -> u32 {
        let mut a = 1u32;
        let mut b = x | 1;

        for _ in 0..8 {
            let temp = b;
            b = b.wrapping_add(a ^ (x.rotate_left((b % 17) as u32)));
            a = temp;
            x = x.rotate_right((a % 13) as u32) ^ b;
        }

        x
    }

    // Hashing
    fn anti_fpga_hash(input: u32) -> u32 {
        let mut x = input;
        let noise = Self::memory_intensive_mix(x);

        let prime_factor_sum = x.count_ones() as u32;

        x ^= prime_factor_sum;

        x = Self::recursive_fibonacci_modulated(x ^ noise);
        x ^= Self::memory_intensive_mix(x.rotate_left(9));

        x
    }

    fn after_comp_table() -> &'static [u8; 256] {
        static TABLE: OnceLock<[u8; 256]> = OnceLock::new();
        TABLE.get_or_init(|| {
            let mut table = [0u8; 256];
            let mut i = 0usize;
            while i < 256 {
                let normalized_input = i as u32;
                let modified_input = Self::chaotic_random(normalized_input);
                let hashed = Self::anti_fpga_hash(modified_input);
                table[i] = (hashed & 0xFF) as u8;
                i += 1;
            }
            table
        })
    }

    // In and Out - Main
    fn compute_after_comp_product(pre_comp_product: [u8; 32]) -> [u8; 32] {
        let mut after_comp_product = [0u8; 32];
        let table = Self::after_comp_table();

        for i in 0..32 {
            after_comp_product[i] = table[pre_comp_product[i] as usize];
        }

        after_comp_product
    }

    // **Octonion Multiply Function**

    #[inline(always)]
    fn octonion_multiply(a: &[i64; 8], b: &[i64; 8]) -> [i64; 8] {
        let mut result = [0; 8];

        // e0
        result[0] = a[0]
            .wrapping_mul(b[0])
            .wrapping_sub(a[1].wrapping_mul(b[1]))
            .wrapping_sub(a[2].wrapping_mul(b[2]))
            .wrapping_sub(a[3].wrapping_mul(b[3]))
            .wrapping_sub(a[4].wrapping_mul(b[4]))
            .wrapping_sub(a[5].wrapping_mul(b[5]))
            .wrapping_sub(a[6].wrapping_mul(b[6]))
            .wrapping_sub(a[7].wrapping_mul(b[7]));

        // e1
        result[1] = a[0]
            .wrapping_mul(b[1])
            .wrapping_add(a[1].wrapping_mul(b[0]))
            .wrapping_add(a[2].wrapping_mul(b[3]))
            .wrapping_sub(a[3].wrapping_mul(b[2]))
            .wrapping_add(a[4].wrapping_mul(b[5]))
            .wrapping_sub(a[5].wrapping_mul(b[4]))
            .wrapping_sub(a[6].wrapping_mul(b[7]))
            .wrapping_add(a[7].wrapping_mul(b[6]));

        // e2
        result[2] = a[0]
            .wrapping_mul(b[2])
            .wrapping_sub(a[1].wrapping_mul(b[3]))
            .wrapping_add(a[2].wrapping_mul(b[0]))
            .wrapping_add(a[3].wrapping_mul(b[1]))
            .wrapping_add(a[4].wrapping_mul(b[6]))
            .wrapping_sub(a[5].wrapping_mul(b[7]))
            .wrapping_add(a[6].wrapping_mul(b[4]))
            .wrapping_sub(a[7].wrapping_mul(b[5]));

        // e3
        result[3] = a[0]
            .wrapping_mul(b[3])
            .wrapping_add(a[1].wrapping_mul(b[2]))
            .wrapping_sub(a[2].wrapping_mul(b[1]))
            .wrapping_add(a[3].wrapping_mul(b[0]))
            .wrapping_add(a[4].wrapping_mul(b[7]))
            .wrapping_add(a[5].wrapping_mul(b[6]))
            .wrapping_sub(a[6].wrapping_mul(b[5]))
            .wrapping_add(a[7].wrapping_mul(b[4]));

        // e4
        result[4] = a[0]
            .wrapping_mul(b[4])
            .wrapping_sub(a[1].wrapping_mul(b[5]))
            .wrapping_sub(a[2].wrapping_mul(b[6]))
            .wrapping_sub(a[3].wrapping_mul(b[7]))
            .wrapping_add(a[4].wrapping_mul(b[0]))
            .wrapping_add(a[5].wrapping_mul(b[1]))
            .wrapping_add(a[6].wrapping_mul(b[2]))
            .wrapping_add(a[7].wrapping_mul(b[3]));

        // e5
        result[5] = a[0]
            .wrapping_mul(b[5])
            .wrapping_add(a[1].wrapping_mul(b[4]))
            .wrapping_sub(a[2].wrapping_mul(b[7]))
            .wrapping_add(a[3].wrapping_mul(b[6]))
            .wrapping_sub(a[4].wrapping_mul(b[1]))
            .wrapping_add(a[5].wrapping_mul(b[0]))
            .wrapping_add(a[6].wrapping_mul(b[3]))
            .wrapping_add(a[7].wrapping_mul(b[2]));

        // e6
        result[6] = a[0]
            .wrapping_mul(b[6])
            .wrapping_add(a[1].wrapping_mul(b[7]))
            .wrapping_add(a[2].wrapping_mul(b[4]))
            .wrapping_sub(a[3].wrapping_mul(b[5]))
            .wrapping_sub(a[4].wrapping_mul(b[2]))
            .wrapping_add(a[5].wrapping_mul(b[3]))
            .wrapping_add(a[6].wrapping_mul(b[0]))
            .wrapping_add(a[7].wrapping_mul(b[1]));

        // e7
        result[7] = a[0]
            .wrapping_mul(b[7])
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

    // **Octonion Hash Function**

    // Octonion Hash
    #[inline(always)]
    fn octonion_hash(input_hash: &[u8; 32]) -> [i64; 8] {
        let mut oct = [
            input_hash[0] as i64, // e0
            input_hash[1] as i64, // e1
            input_hash[2] as i64, // e2
            input_hash[3] as i64, // e3
            input_hash[4] as i64, // e4
            input_hash[5] as i64, // e5
            input_hash[6] as i64, // e6
            input_hash[7] as i64, // e7
        ];

        for i in 8..input_hash.len() {
            let rotation = [
                input_hash[i & 31] as i64,       // e0
                input_hash[(i + 1) & 31] as i64, // e1
                input_hash[(i + 2) & 31] as i64, // e2
                input_hash[(i + 3) & 31] as i64, // e3
                input_hash[(i + 4) & 31] as i64, // e4
                input_hash[(i + 5) & 31] as i64, // e5
                input_hash[(i + 6) & 31] as i64, // e6
                input_hash[(i + 7) & 31] as i64, // e7
            ];

            oct = Self::octonion_multiply(&oct, &rotation);
        }

        oct
    }

    #[inline(always)]
    pub fn cryptix_hash(&self, hash_bytes: &[u8; 32]) -> [u8; 32] {
        let nibbles: [u8; 64] = {
            let mut arr = [0u8; 64];
            for (i, &byte) in hash_bytes.iter().enumerate() {
                arr[2 * i] = byte >> 4;
                arr[2 * i + 1] = byte & 0x0F;
            }
            arr
        };
        let use_avx2 = avx2_available();

        let mut product = [0u8; 32];
        let mut nibble_product = [0u8; 32];

        for i in 0..32 {
            let row0 = &self.0[2 * i];
            let row1 = &self.0[2 * i + 1];
            let row2 = &self.0[i + 2];
            let row3 = &self.0[i + 3];

            let (sum1, sum2, sum3, sum4) =
                dot_products_4rows(row0, row1, row2, row3, &nibbles, use_avx2);

            // **Nibble Calculations**

            // Nibbles
            //A
            let a_nibble = (sum1 & 0xF)
                ^ ((sum2 >> 4) & 0xF)
                ^ ((sum3 >> 8) & 0xF)
                ^ ((sum1.wrapping_mul(0xABCD) >> 12) & 0xF)
                ^ ((sum1.wrapping_mul(0x1234) >> 8) & 0xF)
                ^ ((sum2.wrapping_mul(0x5678) >> 16) & 0xF)
                ^ ((sum3.wrapping_mul(0x9ABC) >> 4) & 0xF)
                ^ ((sum1.rotate_left(3) & 0xF) ^ (sum3.rotate_right(5) & 0xF));

            // B
            let b_nibble = (sum2 & 0xF)
                ^ ((sum1 >> 4) & 0xF)
                ^ ((sum4 >> 8) & 0xF)
                ^ ((sum2.wrapping_mul(0xDCBA) >> 14) & 0xF)
                ^ ((sum2.wrapping_mul(0x8765) >> 10) & 0xF)
                ^ ((sum1.wrapping_mul(0x4321) >> 6) & 0xF)
                ^ ((sum4.rotate_left(2) ^ sum1.rotate_right(1)) & 0xF);

            // C
            let c_nibble = (sum3 & 0xF)
                ^ ((sum2 >> 4) & 0xF)
                ^ ((sum2 >> 8) & 0xF)
                ^ ((sum3.wrapping_mul(0xF135) >> 10) & 0xF)
                ^ ((sum3.wrapping_mul(0x2468) >> 12) & 0xF)
                ^ ((sum4.wrapping_mul(0xACEF) >> 8) & 0xF)
                ^ ((sum2.wrapping_mul(0x1357) >> 4) & 0xF)
                ^ ((sum3.rotate_left(5) & 0xF) ^ (sum1.rotate_right(7) & 0xF));

            // D
            let d_nibble = (sum1 & 0xF)
                ^ ((sum4 >> 4) & 0xF)
                ^ ((sum1 >> 8) & 0xF)
                ^ ((sum4.wrapping_mul(0x57A3) >> 6) & 0xF)
                ^ ((sum3.wrapping_mul(0xD4E3) >> 12) & 0xF)
                ^ ((sum1.wrapping_mul(0x9F8B) >> 10) & 0xF)
                ^ ((sum4.rotate_left(4) ^ sum1.wrapping_add(sum2)) & 0xF);

            let hash_byte = hash_bytes[i];
            nibble_product[i] = (((c_nibble << 4) | d_nibble) as u8) ^ hash_byte;
            product[i] = (((a_nibble << 4) | b_nibble) as u8) ^ hash_byte;
        }

        // Octonion

        let product_before_oct = product;

        // ** Octonion Function **
        let octonion_result = Self::octonion_hash(&product);

        for i in 0..4 {
            let bytes = octonion_result[i].to_le_bytes();
            for j in 0..8 {
                product[(i * 8) + j] ^= bytes[j];
            }
        }

        // S-Box Transformation

        // **Nonlinear S-Box**
        let mut sbox: [u8; 256] = [0; 256];
        let rotate_left_bases: [u8; 16] = [
            (nibble_product[3] ^ 0x4F).wrapping_mul(3),
            (product[7] ^ 0xA6).wrapping_mul(2),
            (product_before_oct[1] ^ 0x9C).wrapping_mul(9),
            (product[6] ^ 0x71).wrapping_mul(4),
            (nibble_product[4] ^ 0xB2).wrapping_mul(3),
            (product[0] ^ 0x58).wrapping_mul(6),
            (product_before_oct[2] ^ 0x37).wrapping_mul(2),
            (product[5] ^ 0x1A).wrapping_mul(5),
            (nibble_product[3] ^ 0x93).wrapping_mul(7),
            (product[7] ^ 0x29).wrapping_mul(9),
            (product_before_oct[1] ^ 0x4E).wrapping_mul(4),
            (nibble_product[6] ^ 0xF3).wrapping_mul(5),
            (product[4] ^ 0xB7).wrapping_mul(6),
            (product[0] ^ 0x2D).wrapping_mul(8),
            (product_before_oct[2] ^ 0x6F).wrapping_mul(3),
            (nibble_product[5] ^ 0xE1).wrapping_mul(7),
        ];
        let rotate_right_bases: [u8; 16] = [
            (hash_bytes[2] ^ 0xD3).wrapping_mul(5),
            (nibble_product[5] ^ 0x5B).wrapping_mul(7),
            (product[0] ^ 0x8E).wrapping_mul(3),
            (product_before_oct[3] ^ 0x2F).wrapping_mul(5),
            (hash_bytes[7] ^ 0x6D).wrapping_mul(7),
            (nibble_product[1] ^ 0xEE).wrapping_mul(9),
            (hash_bytes[6] ^ 0x44).wrapping_mul(6),
            (hash_bytes[4] ^ 0x7C).wrapping_mul(8),
            (product[2] ^ 0xAF).wrapping_mul(3),
            (nibble_product[5] ^ 0xDC).wrapping_mul(2),
            (hash_bytes[0] ^ 0x8B).wrapping_mul(3),
            (product_before_oct[3] ^ 0x62).wrapping_mul(8),
            (product[7] ^ 0x15).wrapping_mul(2),
            (product_before_oct[1] ^ 0xC8).wrapping_mul(7),
            (nibble_product[6] ^ 0x99).wrapping_mul(9),
            (hash_bytes[4] ^ 0x3B).wrapping_mul(5),
        ];

        for i in 0..256usize {
            let segment = i >> 4;
            let local = i & 15;

            let source_array: &[u8; 32] = match SBOX_SOURCE_SELECTORS[segment] {
                SEL_PRODUCT => &product,
                SEL_HASH => hash_bytes,
                SEL_NIBBLE => &nibble_product,
                _ => &product_before_oct,
            };
            let value_array: &[u8; 32] = match SBOX_VALUE_SELECTORS[segment] {
                SEL_PRODUCT => &product,
                SEL_HASH => hash_bytes,
                SEL_NIBBLE => &nibble_product,
                _ => &product_before_oct,
            };

            let value = value_array[local]
                .wrapping_mul(SBOX_VALUE_MULTIPLIERS[segment])
                .wrapping_add((local as u8).wrapping_mul(SBOX_VALUE_ADDERS[segment]));

            let rotate_left_shift = (product[(i + 1) & 31] as u32 + i as u32) & 7;
            let rotate_right_shift = (hash_bytes[(i + 2) & 31] as u32 + i as u32) & 7;

            let rotation_left = rotate_left_bases[segment].rotate_left(rotate_left_shift);
            let rotation_right = rotate_right_bases[segment].rotate_right(rotate_right_shift);

            let index = (i + rotation_left as usize + rotation_right as usize) & 31;
            sbox[i] = source_array[index] ^ value;
        }

        // **Update S-box Values**

        // Update Sbox Values
        let index = ((product_before_oct[2] % 8) + 1) as usize;
        let iterations = 1 + (product[index] % 2);

        for _ in 0..iterations {
            for i in 0..256 {
                let mut value = sbox[i];

                let rotate_left_shift =
                    (product[(i + 1) & 31] as u32 + i as u32 + (i * 3) as u32) & 7;
                let rotate_right_shift =
                    (hash_bytes[(i + 2) & 31] as u32 + i as u32 + (i * 5) as u32) & 7;

                let rotated_value =
                    value.rotate_left(rotate_left_shift) | value.rotate_right(rotate_right_shift);

                let xor_value = {
                    let base_value = (i as u8)
                        .wrapping_add(product[(i * 3) & 31] ^ hash_bytes[(i * 7) & 31])
                        ^ 0xA5;
                    let shifted_value = base_value.rotate_left((i % 8) as u32);
                    shifted_value ^ 0x55
                };

                value ^= rotated_value ^ xor_value;
                sbox[i] = value;
            }
        }

        // **Anti-FPGA Sidedoor**
        let pre_comp_product: [u8; 32] = product;
        let after_comp_product = Self::compute_after_comp_product(pre_comp_product);

        // ** BLAKE3 Hashing Step **

        // Blake3 Chaining
        let index_blake = ((product_before_oct[5] % 8) + 1) as usize;
        let iterations_blake = 1 + (product[index_blake] % 3);

        let mut b3_hash_array = product;
        for _ in 0..iterations_blake {
            let digest = blake3::hash(&b3_hash_array);
            b3_hash_array.copy_from_slice(digest.as_bytes());
        }

        // ** Apply S-Box to the Product with XOR **

        // Apply S-Box to the product with XOR
        for i in 0..32 {
            let ref_array = match i & 3 {
                0 => &nibble_product,
                1 => &product_before_oct,
                2 => &product,
                _ => hash_bytes,
            };

            let byte_val = ref_array[(i * 13) & 31] as usize;

            let index = (byte_val
                + product[(i * 31) & 31] as usize
                + hash_bytes[(i * 19) & 31] as usize
                + i * 41)
                & 255;

            b3_hash_array[i] ^= sbox[index];
        }

        // Final Xor
        for i in 0..32 {
            b3_hash_array[i] ^= after_comp_product[i];
        }

        // Final CryptixHashV2 v2
        CryptixHashV2::hash(&b3_hash_array)
    }
}

struct MatrixCache {
    order: VecDeque<[u8; 32]>,
    entries: HashMap<[u8; 32], Arc<Matrix>>,
}

impl MatrixCache {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<Arc<Matrix>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: [u8; 32], matrix: Arc<Matrix>) -> Arc<Matrix> {
        self.entries.insert(key, matrix.clone());
        self.order.push_back(key);

        while self.order.len() > MATRIX_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }

        matrix
    }
}

fn matrix_cache() -> &'static Mutex<MatrixCache> {
    static CACHE: OnceLock<Mutex<MatrixCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(MatrixCache::new()))
}

fn get_cached_matrix(pre_pow_hash: &[u8; 32]) -> Arc<Matrix> {
    {
        let cache = matrix_cache().lock().expect("matrix cache mutex poisoned");
        if let Some(matrix) = cache.get(pre_pow_hash) {
            return matrix;
        }
    }

    let built = Arc::new(Matrix::generate(pre_pow_hash));
    let mut cache = matrix_cache().lock().expect("matrix cache mutex poisoned");
    if let Some(existing) = cache.get(pre_pow_hash) {
        return existing;
    }
    cache.insert(*pre_pow_hash, built)
}

/// Pre-compute and cache job matrix before worker threads start hashing.
pub fn prewarm_ox8_job(pre_pow_hash: &[u8; 32]) {
    let _ = get_cached_matrix(pre_pow_hash);
}

#[derive(Debug, Clone)]
pub struct Ox8OpenClJobConstants {
    pub matrix: [u8; 64 * 64],
    pub pow_hash_state: [u64; 25],
}

/// Build OpenCL job constants from the same cached CPU structures used by workers.
/// This guarantees identical matrix/pow-state derivation between CPU and OpenCL paths.
pub fn build_opencl_job_constants(
    pre_pow_hash: &[u8; 32],
    timestamp: u64,
) -> Ox8OpenClJobConstants {
    let matrix = get_cached_matrix(pre_pow_hash);
    let pow_hash = PowHash::new(pre_pow_hash, timestamp);

    let mut flat_matrix = [0u8; 64 * 64];
    for row in 0..64 {
        let src = &matrix.0[row];
        let dst = &mut flat_matrix[row * 64..(row + 1) * 64];
        dst.copy_from_slice(src);
    }

    Ox8OpenClJobConstants {
        matrix: flat_matrix,
        pow_hash_state: pow_hash.0,
    }
}

// ============================================================
// PoolState
// ============================================================

pub struct PowState {
    pub matrix: Arc<Matrix>,
    pub pow_hash: PowHash,
    pub target: [u8; 32],
}

impl PowState {
    pub fn new(pre_pow_hash: &[u8; 32], timestamp: u64, target: [u8; 32]) -> Self {
        let matrix = get_cached_matrix(pre_pow_hash);
        let pow_hash = PowHash::new(pre_pow_hash, timestamp);
        Self {
            matrix,
            pow_hash,
            target,
        }
    }

    #[inline(always)]
    fn calculate_pow_pre_matrix_with_sha3(
        &self,
        nonce: u64,
        sha3_hasher: &mut Sha3_256,
    ) -> [u8; 32] {
        let hash_bytes = self.pow_hash.finalize_with_nonce(nonce);

        let iterations = (hash_bytes[0] % 2) + 1;

        let mut current_hash = hash_bytes;

        for i in 0..iterations {
            sha3_hasher.update(&current_hash);
            let sha3_hash = sha3_hasher.finalize_reset();
            current_hash.copy_from_slice(sha3_hash.as_slice());

            if current_hash[1] % 4 == 0 {
                let repeat = (current_hash[2] % 4) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[1] as usize) + (i as u8) as usize) % 32;
                    let xor_value = current_hash[(i % 16) as usize] ^ 0xA5;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];
                    let rotation_amount =
                        ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 2;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_left(rotation_amount);
                    } else {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_right(rotation_amount);
                    }

                    let shift_amount =
                        ((current_hash[5] as u32) + (current_hash[1] as u32)) % 3 + 1;
                    current_hash[target_byte] ^=
                        current_hash[target_byte].rotate_left(shift_amount);
                }
            } else if current_hash[3] % 3 == 0 {
                let repeat = (current_hash[4] % 5) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[6] as usize) + (i as u8) as usize) % 32;
                    let xor_value = current_hash[(i % 16) as usize] ^ 0x55;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];
                    let rotation_amount =
                        ((current_hash[7] as u32) + (current_hash[2] as u32)) % 6 + 1;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount =
                        ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 1;
                    current_hash[target_byte] ^=
                        current_hash[target_byte].rotate_left(shift_amount);
                }
            } else if current_hash[2] % 6 == 0 {
                let repeat = (current_hash[6] % 4) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[10] as usize) + (i as u8) as usize) % 32;
                    let xor_value = current_hash[(i % 16) as usize] ^ 0xFF;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];
                    let rotation_amount =
                        ((current_hash[7] as u32) + (current_hash[7] as u32)) % 7 + 1;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount =
                        ((current_hash[3] as u32) + (current_hash[5] as u32)) % 5 + 2;
                    current_hash[target_byte] ^=
                        current_hash[target_byte].rotate_left(shift_amount as u32);
                }
            } else if current_hash[7] % 5 == 0 {
                let repeat = (current_hash[8] % 4) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[25] as usize) + (i as u8) as usize) % 32;
                    let xor_value = current_hash[(i % 16) as usize] ^ 0x66;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];
                    let rotation_amount =
                        ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 2;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount =
                        ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 1;
                    current_hash[target_byte] ^=
                        current_hash[target_byte].rotate_left(shift_amount as u32);
                }
            } else if current_hash[8] % 7 == 0 {
                let repeat = (current_hash[9] % 5) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[30] as usize) + (i as u8) as usize) % 32;
                    let xor_value = current_hash[(i % 16) as usize] ^ 0x77;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];
                    let rotation_amount =
                        ((current_hash[2] as u32) + (current_hash[5] as u32)) % 5 + 1;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] =
                            current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount =
                        ((current_hash[7] as u32) + (current_hash[9] as u32)) % 6 + 2;
                    current_hash[target_byte] ^=
                        current_hash[target_byte].rotate_left(shift_amount as u32);
                }
            }
        }

        current_hash
    }

    #[inline(always)]
    fn calculate_pow_with_sha3(&self, nonce: u64, sha3_hasher: &mut Sha3_256) -> [u8; 32] {
        let current_hash = self.calculate_pow_pre_matrix_with_sha3(nonce, sha3_hasher);
        self.matrix.cryptix_hash(&current_hash)
    }

    pub fn calculate_pow(&self, nonce: u64) -> [u8; 32] {
        let mut sha3_hasher = Sha3_256::new();
        self.calculate_pow_with_sha3(nonce, &mut sha3_hasher)
    }

    pub fn check_pow(&self, nonce: u64) -> (bool, [u8; 32]) {
        let pow = self.calculate_pow(nonce);
        let valid = pow
            .iter()
            .zip(self.target.iter())
            .rev()
            .find(|(a, b)| a != b)
            .map(|(a, b)| a <= b)
            .unwrap_or(true);
        (valid, pow)
    }
}

pub fn compute_share_hash(
    _extra: &[u8],
    timestamp: u64,
    nonce: u64,
    pre_pow_hash: &[u8; 32],
) -> [u8; 32] {
    let state = PowState::new(pre_pow_hash, timestamp, [0xFF; 32]);
    state.calculate_pow(nonce)
}

/// Convert difficulty (f64) to 32-byte LE target.

pub fn difficulty_to_target(difficulty: f64) -> [u8; 32] {
    if !difficulty.is_finite() || difficulty <= 0.0 {
        return [0xFF; 32];
    }

    let difficulty_text = difficulty.to_string();
    let Some((difficulty_num, difficulty_den)) = parse_positive_decimal_rational(&difficulty_text)
    else {
        return [0xFF; 32];
    };

    if difficulty_num == BigUint::from(0u8) {
        return [0xFF; 32];
    }

    let difficulty_one = BigUint::from(0xFFFFu32) << 208usize;
    let target = (difficulty_one * difficulty_den) / difficulty_num;

    if target.bits() > 256 {
        return [0xFF; 32];
    }

    let mut out = [0u8; 32];
    let target_le = target.to_bytes_le();
    let copy_len = target_le.len().min(32);
    out[..copy_len].copy_from_slice(&target_le[..copy_len]);
    out
}

fn parse_positive_decimal_rational(input: &str) -> Option<(BigUint, BigUint)> {
    let mut text = input.trim();
    if text.is_empty() {
        return None;
    }

    if let Some(stripped) = text.strip_prefix('+') {
        text = stripped;
    }
    if text.starts_with('-') {
        return None;
    }

    let (mantissa, exp10) =
        if let Some((value, exp_part)) = text.split_once('e').or_else(|| text.split_once('E')) {
            let exponent = exp_part.trim().parse::<i64>().ok()?;
            (value.trim(), exponent)
        } else {
            (text, 0i64)
        };

    let (whole, frac) = if let Some((left, right)) = mantissa.split_once('.') {
        (left.trim(), right.trim())
    } else {
        (mantissa.trim(), "")
    };

    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    if !(whole.chars().all(|ch| ch.is_ascii_digit()) && frac.chars().all(|ch| ch.is_ascii_digit()))
    {
        return None;
    }

    let merged = format!("{}{}", whole, frac);
    let digits = merged.trim_start_matches('0');
    if digits.is_empty() {
        return Some((BigUint::from(0u8), BigUint::from(1u8)));
    }

    let mut numerator = BigUint::parse_bytes(digits.as_bytes(), 10)?;
    let mut denominator = BigUint::from(1u8);
    let frac_len = frac.len() as i64;
    let scale_shift = exp10 - frac_len;

    if scale_shift >= 0 {
        let power = usize::try_from(scale_shift).ok()?;
        numerator *= ten_pow_biguint(power)?;
    } else {
        let power = usize::try_from(-scale_shift).ok()?;
        denominator = ten_pow_biguint(power)?;
    }

    Some((numerator, denominator))
}

fn ten_pow_biguint(power: usize) -> Option<BigUint> {
    let exponent = u32::try_from(power).ok()?;
    Some(BigUint::from(10u8).pow(exponent))
}

#[inline(always)]
fn compute_ox8_hash_internal(pre_pow_hash: &[u8; 32], timestamp: u64, nonce: u64) -> Hash256 {
    let key = cache_key(pre_pow_hash, timestamp);
    let pow = THREAD_LOCAL_OX8_CONTEXT.with(|context_cell| {
        let mut context = context_cell.borrow_mut();

        let needs_refresh = match context.cached_pow_state.as_ref() {
            Some((cached_key, _)) => *cached_key != key,
            None => true,
        };
        if needs_refresh {
            context.cached_pow_state =
                Some((key, PowState::new(pre_pow_hash, timestamp, [0xFF; 32])));
        }

        let ThreadLocalOx8Context {
            cached_pow_state,
            sha3_hasher,
        } = &mut *context;
        let state = &cached_pow_state
            .as_ref()
            .expect("cached pow state must be initialized")
            .1;
        state.calculate_pow_with_sha3(nonce, sha3_hasher)
    });
    Hash256(pow)
}

#[inline(always)]
fn compute_ox8_pre_matrix_internal(
    pre_pow_hash: &[u8; 32],
    timestamp: u64,
    nonce: u64,
) -> [u8; 32] {
    let key = cache_key(pre_pow_hash, timestamp);
    THREAD_LOCAL_OX8_CONTEXT.with(|context_cell| {
        let mut context = context_cell.borrow_mut();

        let needs_refresh = match context.cached_pow_state.as_ref() {
            Some((cached_key, _)) => *cached_key != key,
            None => true,
        };
        if needs_refresh {
            context.cached_pow_state =
                Some((key, PowState::new(pre_pow_hash, timestamp, [0xFF; 32])));
        }

        let ThreadLocalOx8Context {
            cached_pow_state,
            sha3_hasher,
        } = &mut *context;
        let state = &cached_pow_state
            .as_ref()
            .expect("cached pow state must be initialized")
            .1;
        state.calculate_pow_pre_matrix_with_sha3(nonce, sha3_hasher)
    })
}

#[inline(always)]
pub fn compute_ox8_hash_preparsed(pre_pow_hash: &[u8; 32], timestamp: u64, nonce: u64) -> Hash256 {
    compute_ox8_hash_internal(pre_pow_hash, timestamp, nonce)
}

#[inline(always)]
pub fn compute_ox8_pre_matrix_preparsed(
    pre_pow_hash: &[u8; 32],
    timestamp: u64,
    nonce: u64,
) -> [u8; 32] {
    compute_ox8_pre_matrix_internal(pre_pow_hash, timestamp, nonce)
}

pub fn compute_ox8_hash_with_nonce(header_data: &[u8], nonce: u64) -> Result<Hash256> {
    if header_data.len() < 40 {
        return Err(MinerError::AlgorithmError("Invalid header data length".to_string()).into());
    }

    let pre_pow_hash: [u8; 32] = header_data[0..32]
        .try_into()
        .expect("slice length checked above");
    let timestamp: u64 = u64::from_le_bytes(
        header_data[32..40]
            .try_into()
            .expect("slice length checked above"),
    );
    Ok(compute_ox8_hash_internal(&pre_pow_hash, timestamp, nonce))
}

fn decode_fixed_hex<const N: usize>(
    raw: &str,
    field: &str,
) -> std::result::Result<[u8; N], String> {
    let normalized = raw.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(normalized).map_err(|e| format!("failed to decode {} as hex: {}", field, e))?;
    if bytes.len() != N {
        return Err(format!(
            "invalid {} length: expected {} bytes ({} hex chars), got {} bytes",
            field,
            N,
            N * 2,
            bytes.len()
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_arg(args: &[String], key: &str) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == key {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn print_usage() {
    eprintln!("OX8 standalone CPU integration");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  --pre-pow-hash <64-hex> --timestamp <u64> --nonce <u64>");
    eprintln!("  --header <80-hex> --nonce <u64>");
    eprintln!();
    eprintln!("Output:");
    eprintln!("  mode=<preparsed|header>");
    eprintln!("  backend=<backend description>");
    eprintln!("  pre_pow_hash_hex=<64-hex>");
    eprintln!("  timestamp=<u64>");
    eprintln!("  nonce=<u64>");
    eprintln!("  hash_hex=<64-hex>");
}

fn run_cli(args: &[String]) -> std::result::Result<(), String> {
    let nonce_raw = parse_arg(args, "--nonce").ok_or_else(|| "missing --nonce".to_string())?;
    let nonce = nonce_raw
        .parse::<u64>()
        .map_err(|_| format!("invalid --nonce value '{}'", nonce_raw))?;

    if let Some(header_hex) = parse_arg(args, "--header") {
        if parse_arg(args, "--pre-pow-hash").is_some() || parse_arg(args, "--timestamp").is_some() {
            return Err(
                "use either --header OR --pre-pow-hash/--timestamp mode, not both".to_string(),
            );
        }

        let header = decode_fixed_hex::<40>(&header_hex, "header")?;
        let pre_pow_hash: [u8; 32] = header[..32].try_into().expect("header len checked");
        let timestamp = u64::from_le_bytes(header[32..40].try_into().expect("header len checked"));

        prewarm_ox8_job(&pre_pow_hash);
        let hash = compute_ox8_hash_with_nonce(&header, nonce).map_err(|e| e.to_string())?;

        println!("mode=header");
        println!("backend={}", ox8_backend_description());
        println!("pre_pow_hash_hex={}", hex::encode(pre_pow_hash));
        println!("timestamp={}", timestamp);
        println!("nonce={}", nonce);
        println!("hash_hex={}", hash.to_hex());
        return Ok(());
    }

    let pre_pow_hash_hex = parse_arg(args, "--pre-pow-hash")
        .ok_or_else(|| "missing --pre-pow-hash (or use --header mode)".to_string())?;
    let timestamp_raw = parse_arg(args, "--timestamp")
        .ok_or_else(|| "missing --timestamp (or use --header mode)".to_string())?;
    let timestamp = timestamp_raw
        .parse::<u64>()
        .map_err(|_| format!("invalid --timestamp value '{}'", timestamp_raw))?;
    let pre_pow_hash = decode_fixed_hex::<32>(&pre_pow_hash_hex, "pre_pow_hash")?;

    prewarm_ox8_job(&pre_pow_hash);
    let hash = compute_ox8_hash_preparsed(&pre_pow_hash, timestamp, nonce);

    println!("mode=preparsed");
    println!("backend={}", ox8_backend_description());
    println!("pre_pow_hash_hex={}", hex::encode(pre_pow_hash));
    println!("timestamp={}", timestamp);
    println!("nonce={}", nonce);
    println!("hash_hex={}", hash.to_hex());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return;
    }

    if let Err(error) = run_cli(&args) {
        eprintln!("[ERROR] {}", error);
        eprintln!();
        print_usage();
        std::process::exit(1);
    }
}
