/* eslint-disable no-bitwise */
/**
 * OX8 Standalone Hash JavaScript
 * 
 * API:
 * - ox8Hash({ preMatrixHash, matrixBytes }) -> Uint8Array(32)
 * - ox8HashHex({ preMatrixHashHex, matrixHex }) -> hex string (64 chars)
 * - ox8PowHash({ prePowHash, timestamp, nonce, matrixBytes? }) -> Uint8Array(32)
 * - ox8PowHashHex({ prePowHashHex, timestamp, nonce, matrixHex? }) -> hex string
 *
 * Inputs:
 * - preMatrixHash: 32 bytes (Uint8Array | ArrayBuffer | hex)
 * - matrixBytes: 4096 bytes (64x64) (Uint8Array | ArrayBuffer | hex)
 * - prePowHash: 32 bytes (Uint8Array | ArrayBuffer | hex)
 * - timestamp / nonce: u64-compatible (number, bigint, or hex string)
 */

const U64_MASK = (1n << 64n) - 1n;
const RANK_EPSILON = 1e-9;

const POW_HASH_INITIAL_STATE = [
  1242148031264380989n,
  3008272977830772284n,
  2188519011337848018n,
  1992179434288343456n,
  8876506674959887717n,
  5399642050693751366n,
  1745875063082670864n,
  8605242046444978844n,
  17936695144567157056n,
  3343109343542796272n,
  1123092876221303306n,
  4963925045340115282n,
  17037383077651887893n,
  16629644495023626889n,
  12833675776649114147n,
  3784524041015224902n,
  1082795874807940378n,
  13952716920571277634n,
  13411128033953605860n,
  15060696040649351053n,
  9928834659948351306n,
  5237849264682708699n,
  12825353012139217522n,
  6706187291358897596n,
  196324915476054915n,
];

const HEAVY_HASH_INITIAL_STATE = [
  4239941492252378377n,
  8746723911537738262n,
  8796936657246353646n,
  1272090201925444760n,
  16654558671554924250n,
  8270816933120786537n,
  13907396207649043898n,
  6782861118970774626n,
  9239690602118867528n,
  11582319943599406348n,
  17596056728278508070n,
  15212962468105129023n,
  7812475424661425213n,
  3370482334374859748n,
  5690099369266491460n,
  8596393687355028144n,
  570094237299545110n,
  9119540418498120711n,
  16901969272480492857n,
  13372017233735502424n,
  14372891883993151831n,
  5171152063242093102n,
  10573107899694386186n,
  6096431547456407061n,
  1592359455985097269n,
];

const KECCAK_PI_LANES = [
  10, 7, 11, 17, 18, 3, 5, 16,
  8, 21, 24, 4, 15, 23, 19, 13,
  12, 2, 20, 14, 22, 9, 6, 1,
];

const KECCAK_RHO_PI_ROT = [
  1, 3, 6, 10, 15, 21, 28, 36,
  45, 55, 2, 14, 27, 41, 56, 8,
  25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAK_RNDC_LO = [
  1, 32898, 32906, 2147516416, 32907, 2147483649,
  2147516545, 32777, 138, 136, 2147516425, 2147483658,
  2147516555, 139, 32905, 32771, 32770, 128,
  32778, 2147483658, 2147516545, 32896, 2147483649, 2147516424,
];

const KECCAK_RNDC_HI = [
  0, 0, 2147483648, 2147483648, 0, 0,
  2147483648, 2147483648, 0, 0, 0, 0,
  0, 2147483648, 2147483648, 2147483648, 2147483648, 2147483648,
  0, 2147483648, 2147483648, 2147483648, 0, 2147483648,
];

const SBOX_SOURCE_SELECTORS = [0, 1, 2, 1, 3, 1, 0, 1, 3, 1, 2, 1, 3, 1, 0, 1];
const SBOX_VALUE_SELECTORS = [0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2];
const SBOX_VALUE_MULTIPLIERS = [0x03, 0x05, 0x07, 0x0f, 0x11, 0x13, 0x17, 0x19, 0x1d, 0x1f, 0x23, 0x29, 0x2f, 0x31, 0x37, 0x3f];
const SBOX_VALUE_ADDERS = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

const BLAKE3_IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const BLAKE3_MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const AFTER_COMP_LUT = [
  0x75, 0x7c, 0xeb, 0x87, 0x24, 0xe7, 0x3d, 0x07, 0x48, 0x32, 0xb2, 0xee, 0xef, 0x97, 0xc2, 0x2b,
  0xe9, 0x4b, 0xe2, 0xaf, 0x2f, 0xf3, 0x19, 0xe7, 0x83, 0x94, 0xb9, 0x4b, 0x09, 0x78, 0x95, 0x69,
  0x55, 0xf7, 0xf7, 0x9f, 0x67, 0x01, 0x4a, 0xce, 0xd1, 0x57, 0x64, 0x03, 0xe1, 0x72, 0x8d, 0xcd,
  0x67, 0x41, 0x6a, 0x10, 0xc0, 0x55, 0x42, 0xbd, 0x28, 0x26, 0xee, 0x75, 0x51, 0x2b, 0x7b, 0xe6,
  0xe0, 0x38, 0xd7, 0x1d, 0x48, 0x7d, 0x6c, 0x17, 0x53, 0xfa, 0x7a, 0x89, 0x09, 0x8a, 0x43, 0x7b,
  0x3b, 0xee, 0x9f, 0x09, 0xd9, 0x07, 0xd6, 0x66, 0x23, 0x13, 0x82, 0x5b, 0x4b, 0x6b, 0xc2, 0xaf,
  0xfd, 0xd8, 0x92, 0x0e, 0x40, 0x89, 0x32, 0xee, 0x14, 0x9a, 0xa4, 0xac, 0xec, 0xf9, 0x9d, 0x3a,
  0xbc, 0x51, 0x05, 0x6a, 0x11, 0xa7, 0xac, 0x1b, 0x71, 0x40, 0x0d, 0x05, 0xd0, 0x61, 0x05, 0xe2,
  0x5a, 0x1d, 0xca, 0x4c, 0x56, 0x40, 0x2a, 0x49, 0x67, 0x61, 0x69, 0x21, 0x80, 0x85, 0x59, 0xb8,
  0x2c, 0xd0, 0x20, 0xda, 0x88, 0xac, 0xcc, 0xd1, 0x70, 0x76, 0x98, 0x7f, 0x7c, 0x55, 0xd0, 0xd6,
  0x2b, 0xa5, 0xb7, 0x03, 0x9e, 0x37, 0x9b, 0xb9, 0xf1, 0xe8, 0x1f, 0xe0, 0x42, 0x6b, 0x62, 0x63,
  0xb7, 0xdc, 0x8e, 0xcc, 0x6c, 0xb7, 0x76, 0x27, 0xc1, 0xec, 0x72, 0x17, 0xce, 0x76, 0x65, 0x8c,
  0x9f, 0x16, 0xdb, 0xb2, 0x5f, 0x7f, 0x14, 0x5a, 0x42, 0x89, 0xec, 0x1d, 0xc5, 0xc9, 0xa0, 0x30,
  0xdd, 0x3c, 0xdc, 0x7b, 0x8a, 0x47, 0x3e, 0xb5, 0xea, 0xa9, 0xa9, 0x6a, 0x89, 0x65, 0x4d, 0x3a,
  0xc8, 0xad, 0xbb, 0xad, 0xa0, 0xe5, 0xb8, 0xf6, 0xcd, 0x08, 0xa3, 0xe8, 0xa0, 0x5e, 0x18, 0xa6,
  0x65, 0x27, 0x26, 0x5c, 0x21, 0xa8, 0xf4, 0x3c, 0xca, 0x95, 0x15, 0xfc, 0x9c, 0x1b, 0x9a, 0x0b,
];

function toU64(v) {
  return BigInt.asUintN(64, BigInt(v));
}

function rotl64(v, shift) {
  const s = BigInt(shift & 63);
  if (s === 0n) return toU64(v);
  return toU64((v << s) | (v >> (64n - s)));
}

function add64(a, b) { return toU64(a + b); }
function sub64(a, b) { return toU64(a - b); }
function mul64ByU32(word, m) { return toU64(word * BigInt(m >>> 0)); }

function rotl32(v, shift) {
  const s = shift & 31;
  return ((v << s) | (v >>> (32 - s))) >>> 0;
}

function rotr32(v, shift) {
  const s = shift & 31;
  return ((v >>> s) | (v << (32 - s))) >>> 0;
}

function rotl8(v, shift) {
  const s = shift & 7;
  const b = v & 0xff;
  return (((b << s) | (b >>> (8 - s))) & 0xff) >>> 0;
}

function rotr8(v, shift) {
  const s = shift & 7;
  const b = v & 0xff;
  return (((b >>> s) | (b << (8 - s))) & 0xff) >>> 0;
}

function readU32LE(bytes, offset) {
  return (
    (bytes[offset] & 0xff) |
    ((bytes[offset + 1] & 0xff) << 8) |
    ((bytes[offset + 2] & 0xff) << 16) |
    ((bytes[offset + 3] & 0xff) << 24)
  ) >>> 0;
}

function writeU32LE(bytes, offset, value) {
  const v = value >>> 0;
  bytes[offset + 0] = v & 0xff;
  bytes[offset + 1] = (v >>> 8) & 0xff;
  bytes[offset + 2] = (v >>> 16) & 0xff;
  bytes[offset + 3] = (v >>> 24) & 0xff;
}

function readU64LE(bytes, offset) {
  const lo = BigInt(readU32LE(bytes, offset));
  const hi = BigInt(readU32LE(bytes, offset + 4));
  return toU64((hi << 32n) | lo);
}

function writeU64LE(bytes, offset, word) {
  const w = toU64(word);
  const lo = Number(w & 0xffff_ffffn) >>> 0;
  const hi = Number((w >> 32n) & 0xffff_ffffn) >>> 0;
  writeU32LE(bytes, offset, lo);
  writeU32LE(bytes, offset + 4, hi);
}

function hexToBytes(hex, expectedLength, label = "hex") {
  const raw = String(hex).trim().replace(/^0x/i, "");
  if (raw.length !== expectedLength * 2) {
    throw new Error(`${label} must have ${expectedLength * 2} hex chars, got ${raw.length}`);
  }
  if (!/^[0-9a-fA-F]+$/.test(raw)) {
    throw new Error(`${label} contains non-hex characters`);
  }
  const out = new Uint8Array(expectedLength);
  for (let i = 0; i < expectedLength; i += 1) {
    out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function normalizeBytes(input, expectedLength, label) {
  if (input instanceof Uint8Array) {
    if (input.length !== expectedLength) {
      throw new Error(`${label} must be ${expectedLength} bytes, got ${input.length}`);
    }
    return new Uint8Array(input);
  }

  if (input instanceof ArrayBuffer) {
    const bytes = new Uint8Array(input);
    if (bytes.length !== expectedLength) {
      throw new Error(`${label} must be ${expectedLength} bytes, got ${bytes.length}`);
    }
    return bytes;
  }

  if (typeof input === "string") {
    return hexToBytes(input, expectedLength, label);
  }

  throw new Error(`${label} must be Uint8Array, ArrayBuffer, or hex string`);
}

function parseU64Input(value, label) {
  if (typeof value === "bigint") {
    return toU64(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0) {
      throw new Error(`${label} must be a non-negative number, bigint, or hex string`);
    }
    return toU64(BigInt(Math.trunc(value)));
  }

  if (typeof value === "string") {
    const raw = value.trim();
    const normalized = raw.startsWith("0x") || raw.startsWith("0X") ? raw : `0x${raw}`;
    return toU64(BigInt(normalized));
  }

  throw new Error(`${label} must be a non-negative number, bigint, or hex string`);
}

function keccakF1600(state) {
  for (let round = 0; round < 24; round += 1) {
    const c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
    const c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
    const c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
    const c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
    const c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

    const d0 = c4 ^ rotl64(c1, 1);
    const d1 = c0 ^ rotl64(c2, 1);
    const d2 = c1 ^ rotl64(c3, 1);
    const d3 = c2 ^ rotl64(c4, 1);
    const d4 = c3 ^ rotl64(c0, 1);

    state[0] ^= d0; state[5] ^= d0; state[10] ^= d0; state[15] ^= d0; state[20] ^= d0;
    state[1] ^= d1; state[6] ^= d1; state[11] ^= d1; state[16] ^= d1; state[21] ^= d1;
    state[2] ^= d2; state[7] ^= d2; state[12] ^= d2; state[17] ^= d2; state[22] ^= d2;
    state[3] ^= d3; state[8] ^= d3; state[13] ^= d3; state[18] ^= d3; state[23] ^= d3;
    state[4] ^= d4; state[9] ^= d4; state[14] ^= d4; state[19] ^= d4; state[24] ^= d4;

    let t = state[1];
    for (let i = 0; i < 24; i += 1) {
      const lane = KECCAK_PI_LANES[i];
      const next = state[lane];
      state[lane] = rotl64(t, KECCAK_RHO_PI_ROT[i]);
      t = next;
    }

    for (let row = 0; row < 25; row += 5) {
      const r0 = state[row + 0];
      const r1 = state[row + 1];
      const r2 = state[row + 2];
      const r3 = state[row + 3];
      const r4 = state[row + 4];

      state[row + 0] = toU64(r0 ^ ((~r1 & U64_MASK) & r2));
      state[row + 1] = toU64(r1 ^ ((~r2 & U64_MASK) & r3));
      state[row + 2] = toU64(r2 ^ ((~r3 & U64_MASK) & r4));
      state[row + 3] = toU64(r3 ^ ((~r4 & U64_MASK) & r0));
      state[row + 4] = toU64(r4 ^ ((~r0 & U64_MASK) & r1));
    }

    const rc = (BigInt(KECCAK_RNDC_HI[round] >>> 0) << 32n) | BigInt(KECCAK_RNDC_LO[round] >>> 0);
    state[0] = toU64(state[0] ^ rc);
  }
}

function cryptixHashV2Hash(input) {
  const inputBytes = normalizeBytes(input, 32, "inputHash");
  const st = HEAVY_HASH_INITIAL_STATE.slice();

  st[0] = toU64(st[0] ^ readU64LE(inputBytes, 0));
  st[1] = toU64(st[1] ^ readU64LE(inputBytes, 8));
  st[2] = toU64(st[2] ^ readU64LE(inputBytes, 16));
  st[3] = toU64(st[3] ^ readU64LE(inputBytes, 24));

  keccakF1600(st);

  const out = new Uint8Array(32);
  writeU64LE(out, 0, st[0]);
  writeU64LE(out, 8, st[1]);
  writeU64LE(out, 16, st[2]);
  writeU64LE(out, 24, st[3]);
  return out;
}

function buildPowStateWords(prePowHash, timestamp) {
  const prePowHashBytes = normalizeBytes(prePowHash, 32, "prePowHash");
  const ts = parseU64Input(timestamp, "timestamp");

  const st = POW_HASH_INITIAL_STATE.slice();
  for (let i = 0; i < 4; i += 1) {
    st[i] = toU64(st[i] ^ readU64LE(prePowHashBytes, i * 8));
  }
  st[4] = toU64(st[4] ^ ts);
  return st;
}

function powHashFinalize(powStateWords, nonce) {
  if (!Array.isArray(powStateWords) || powStateWords.length !== 25) {
    throw new Error("powStateWords must be an array of 25 u64 words");
  }

  const nonceU64 = parseU64Input(nonce, "nonce");
  const st = powStateWords.map((word) => toU64(word));

  st[9] = toU64(st[9] ^ nonceU64);
  keccakF1600(st);

  const out = new Uint8Array(32);
  writeU64LE(out, 0, st[0]);
  writeU64LE(out, 8, st[1]);
  writeU64LE(out, 16, st[2]);
  writeU64LE(out, 24, st[3]);
  return out;
}

function sha3_256_32bytes(input) {
  const inputBytes = normalizeBytes(input, 32, "inputHash");
  const st = new Array(25).fill(0n);

  st[0] ^= readU64LE(inputBytes, 0);
  st[1] ^= readU64LE(inputBytes, 8);
  st[2] ^= readU64LE(inputBytes, 16);
  st[3] ^= readU64LE(inputBytes, 24);

  st[4] ^= 0x06n;
  st[16] ^= 0x8000000000000000n;

  keccakF1600(st);

  const out = new Uint8Array(32);
  writeU64LE(out, 0, st[0]);
  writeU64LE(out, 8, st[1]);
  writeU64LE(out, 16, st[2]);
  writeU64LE(out, 24, st[3]);
  return out;
}

function calculatePowPreMatrixFromState(powStateWords, nonce) {
  let currentHash = powHashFinalize(powStateWords, nonce);
  const iterations = (currentHash[0] & 1) + 1;

  for (let i = 0; i < iterations; i += 1) {
    currentHash = sha3_256_32bytes(currentHash);

    if ((currentHash[1] & 3) === 0) {
      const repeat = (currentHash[2] & 3) + 1;
      for (let r = 0; r < repeat; r += 1) {
        const targetByte = (currentHash[1] + i) & 31;
        const xorValue = currentHash[i & 15] ^ 0xa5;
        currentHash[targetByte] = (currentHash[targetByte] ^ xorValue) & 0xff;

        const rotationByte = currentHash[i & 31];
        const rotationAmount = ((currentHash[1] + currentHash[3]) & 3) + 2;
        if ((rotationByte & 1) === 0) {
          currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount);
        } else {
          currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount);
        }

        const shiftAmount = ((currentHash[5] + currentHash[1]) % 3) + 1;
        currentHash[targetByte] = (currentHash[targetByte] ^ rotl8(currentHash[targetByte], shiftAmount)) & 0xff;
      }
    } else if ((currentHash[3] % 3) === 0) {
      const repeat = (currentHash[4] % 5) + 1;
      for (let r = 0; r < repeat; r += 1) {
        const targetByte = (currentHash[6] + i) & 31;
        const xorValue = currentHash[i & 15] ^ 0x55;
        currentHash[targetByte] = (currentHash[targetByte] ^ xorValue) & 0xff;

        const rotationByte = currentHash[i & 31];
        const rotationAmount = ((currentHash[7] + currentHash[2]) % 6) + 1;
        if ((rotationByte & 1) === 0) {
          currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount);
        } else {
          currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount);
        }

        const shiftAmount = ((currentHash[1] + currentHash[3]) % 4) + 1;
        currentHash[targetByte] = (currentHash[targetByte] ^ rotl8(currentHash[targetByte], shiftAmount)) & 0xff;
      }
    } else if ((currentHash[2] % 6) === 0) {
      const repeat = (currentHash[6] & 3) + 1;
      for (let r = 0; r < repeat; r += 1) {
        const targetByte = (currentHash[10] + i) & 31;
        const xorValue = currentHash[i & 15] ^ 0xff;
        currentHash[targetByte] = (currentHash[targetByte] ^ xorValue) & 0xff;

        const rotationByte = currentHash[i & 31];
        const rotationAmount = ((currentHash[7] + currentHash[7]) % 7) + 1;
        if ((rotationByte & 1) === 0) {
          currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount);
        } else {
          currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount);
        }

        const shiftAmount = ((currentHash[3] + currentHash[5]) % 5) + 2;
        currentHash[targetByte] = (currentHash[targetByte] ^ rotl8(currentHash[targetByte], shiftAmount)) & 0xff;
      }
    } else if ((currentHash[7] % 5) === 0) {
      const repeat = (currentHash[8] & 3) + 1;
      for (let r = 0; r < repeat; r += 1) {
        const targetByte = (currentHash[25] + i) & 31;
        const xorValue = currentHash[i & 15] ^ 0x66;
        currentHash[targetByte] = (currentHash[targetByte] ^ xorValue) & 0xff;

        const rotationByte = currentHash[i & 31];
        const rotationAmount = ((currentHash[1] + currentHash[3]) & 3) + 2;
        if ((rotationByte & 1) === 0) {
          currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount);
        } else {
          currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount);
        }

        const shiftAmount = ((currentHash[1] + currentHash[3]) & 3) + 1;
        currentHash[targetByte] = (currentHash[targetByte] ^ rotl8(currentHash[targetByte], shiftAmount)) & 0xff;
      }
    } else if ((currentHash[8] % 7) === 0) {
      const repeat = (currentHash[9] % 5) + 1;
      for (let r = 0; r < repeat; r += 1) {
        const targetByte = (currentHash[30] + i) & 31;
        const xorValue = currentHash[i & 15] ^ 0x77;
        currentHash[targetByte] = (currentHash[targetByte] ^ xorValue) & 0xff;

        const rotationByte = currentHash[i & 31];
        const rotationAmount = ((currentHash[2] + currentHash[5]) % 5) + 1;
        if ((rotationByte & 1) === 0) {
          currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount);
        } else {
          currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount);
        }

        const shiftAmount = ((currentHash[7] + currentHash[9]) % 6) + 2;
        currentHash[targetByte] = (currentHash[targetByte] ^ rotl8(currentHash[targetByte], shiftAmount)) & 0xff;
      }
    }
  }

  return currentHash;
}

function calculatePowPreMatrix({ prePowHash, timestamp, nonce }) {
  const powStateWords = buildPowStateWords(prePowHash, timestamp);
  return calculatePowPreMatrixFromState(powStateWords, nonce);
}

class XoShiRo256PlusPlus {
  constructor(seed32Bytes) {
    const seed = normalizeBytes(seed32Bytes, 32, "prePowHash");
    this.s0 = readU64LE(seed, 0);
    this.s1 = readU64LE(seed, 8);
    this.s2 = readU64LE(seed, 16);
    this.s3 = readU64LE(seed, 24);
  }

  nextU64() {
    const res = add64(this.s0, rotl64(add64(this.s0, this.s3), 23));
    const t = toU64(this.s1 << 17n);

    this.s2 = toU64(this.s2 ^ this.s0);
    this.s3 = toU64(this.s3 ^ this.s1);
    this.s1 = toU64(this.s1 ^ this.s2);
    this.s0 = toU64(this.s0 ^ this.s3);
    this.s2 = toU64(this.s2 ^ t);
    this.s3 = rotl64(this.s3, 45);

    return res;
  }
}

function randMatrixNoRankCheck(rng) {
  const out = new Uint8Array(64 * 64);
  let index = 0;

  for (let row = 0; row < 64; row += 1) {
    let val = 0n;
    for (let col = 0; col < 64; col += 1) {
      const shift = col % 16;
      if (shift === 0) {
        val = rng.nextU64();
      }
      out[index] = Number((val >> BigInt(4 * shift)) & 0x0fn);
      index += 1;
    }
  }

  return out;
}

function computeMatrixRank(matrixBytes) {
  const mat = Array.from({ length: 64 }, (_, row) => {
    const values = new Float64Array(64);
    for (let col = 0; col < 64; col += 1) {
      values[col] = matrixBytes[row * 64 + col];
    }
    return values;
  });

  let rank = 0;
  const rowSelected = new Array(64).fill(false);

  for (let i = 0; i < 64; i += 1) {
    let j = 0;
    while (j < 64) {
      if (!rowSelected[j] && Math.abs(mat[j][i]) > RANK_EPSILON) {
        break;
      }
      j += 1;
    }

    if (j !== 64) {
      rank += 1;
      rowSelected[j] = true;

      for (let p = i + 1; p < 64; p += 1) {
        mat[j][p] /= mat[j][i];
      }

      for (let k = 0; k < 64; k += 1) {
        if (k !== j && Math.abs(mat[k][i]) > RANK_EPSILON) {
          for (let p = i + 1; p < 64; p += 1) {
            mat[k][p] -= mat[j][p] * mat[k][i];
          }
        }
      }
    }
  }

  return rank;
}

function generateOx8Matrix(prePowHash) {
  const seed = normalizeBytes(prePowHash, 32, "prePowHash");
  const rng = new XoShiRo256PlusPlus(seed);

  while (true) {
    const matrix = randMatrixNoRankCheck(rng);
    if (computeMatrixRank(matrix) === 64) {
      return matrix;
    }
  }
}

function blake3Permute(m) {
  const p = new Uint32Array(16);
  for (let i = 0; i < 16; i += 1) {
    p[i] = m[BLAKE3_MSG_PERMUTATION[i]] >>> 0;
  }
  m.set(p);
}

function blake3G(v, a, b, c, d, mx, my) {
  v[a] = (v[a] + v[b] + mx) >>> 0;
  v[d] = rotr32(v[d] ^ v[a], 16);
  v[c] = (v[c] + v[d]) >>> 0;
  v[b] = rotr32(v[b] ^ v[c], 12);
  v[a] = (v[a] + v[b] + my) >>> 0;
  v[d] = rotr32(v[d] ^ v[a], 8);
  v[c] = (v[c] + v[d]) >>> 0;
  v[b] = rotr32(v[b] ^ v[c], 7);
}

function blake3Round(v, m) {
  blake3G(v, 0, 4, 8, 12, m[0], m[1]);
  blake3G(v, 1, 5, 9, 13, m[2], m[3]);
  blake3G(v, 2, 6, 10, 14, m[4], m[5]);
  blake3G(v, 3, 7, 11, 15, m[6], m[7]);
  blake3G(v, 0, 5, 10, 15, m[8], m[9]);
  blake3G(v, 1, 6, 11, 12, m[10], m[11]);
  blake3G(v, 2, 7, 8, 13, m[12], m[13]);
  blake3G(v, 3, 4, 9, 14, m[14], m[15]);
}

function blake3Compress32(input32) {
  const input = normalizeBytes(input32, 32, "blake3Input");

  const m = new Uint32Array(16);
  for (let i = 0; i < 8; i += 1) {
    m[i] = readU32LE(input, i * 4);
  }
  for (let i = 8; i < 16; i += 1) {
    m[i] = 0;
  }

  const v = new Uint32Array(16);
  for (let i = 0; i < 8; i += 1) {
    v[i] = BLAKE3_IV[i] >>> 0;
  }

  v[8] = BLAKE3_IV[0] >>> 0;
  v[9] = BLAKE3_IV[1] >>> 0;
  v[10] = BLAKE3_IV[2] >>> 0;
  v[11] = BLAKE3_IV[3] >>> 0;
  v[12] = 0;
  v[13] = 0;
  v[14] = 32;
  v[15] = 11;

  for (let round = 0; round < 7; round += 1) {
    blake3Round(v, m);
    if (round + 1 < 7) {
      blake3Permute(m);
    }
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i += 1) {
    writeU32LE(out, i * 4, (v[i] ^ v[i + 8]) >>> 0);
  }
  return out;
}

function octonionHash(input32) {
  const input = normalizeBytes(input32, 32, "octonionInput");

  let a0 = BigInt(input[0]);
  let a1 = BigInt(input[1]);
  let a2 = BigInt(input[2]);
  let a3 = BigInt(input[3]);
  let a4 = BigInt(input[4]);
  let a5 = BigInt(input[5]);
  let a6 = BigInt(input[6]);
  let a7 = BigInt(input[7]);

  let b0 = input[8];
  let b1 = input[9];
  let b2 = input[10];
  let b3 = input[11];
  let b4 = input[12];
  let b5 = input[13];
  let b6 = input[14];
  let b7 = input[15];

  for (let i = 8; i < 32; i += 1) {
    let r0 = mul64ByU32(a0, b0);
    r0 = sub64(r0, mul64ByU32(a1, b1));
    r0 = sub64(r0, mul64ByU32(a2, b2));
    r0 = sub64(r0, mul64ByU32(a3, b3));
    r0 = sub64(r0, mul64ByU32(a4, b4));
    r0 = sub64(r0, mul64ByU32(a5, b5));
    r0 = sub64(r0, mul64ByU32(a6, b6));
    r0 = sub64(r0, mul64ByU32(a7, b7));

    let r1 = mul64ByU32(a0, b1);
    r1 = add64(r1, mul64ByU32(a1, b0));
    r1 = add64(r1, mul64ByU32(a2, b3));
    r1 = sub64(r1, mul64ByU32(a3, b2));
    r1 = add64(r1, mul64ByU32(a4, b5));
    r1 = sub64(r1, mul64ByU32(a5, b4));
    r1 = sub64(r1, mul64ByU32(a6, b7));
    r1 = add64(r1, mul64ByU32(a7, b6));

    let r2 = mul64ByU32(a0, b2);
    r2 = sub64(r2, mul64ByU32(a1, b3));
    r2 = add64(r2, mul64ByU32(a2, b0));
    r2 = add64(r2, mul64ByU32(a3, b1));
    r2 = add64(r2, mul64ByU32(a4, b6));
    r2 = sub64(r2, mul64ByU32(a5, b7));
    r2 = add64(r2, mul64ByU32(a6, b4));
    r2 = sub64(r2, mul64ByU32(a7, b5));

    let r3 = mul64ByU32(a0, b3);
    r3 = add64(r3, mul64ByU32(a1, b2));
    r3 = sub64(r3, mul64ByU32(a2, b1));
    r3 = add64(r3, mul64ByU32(a3, b0));
    r3 = add64(r3, mul64ByU32(a4, b7));
    r3 = add64(r3, mul64ByU32(a5, b6));
    r3 = sub64(r3, mul64ByU32(a6, b5));
    r3 = add64(r3, mul64ByU32(a7, b4));

    let r4 = mul64ByU32(a0, b4);
    r4 = sub64(r4, mul64ByU32(a1, b5));
    r4 = sub64(r4, mul64ByU32(a2, b6));
    r4 = sub64(r4, mul64ByU32(a3, b7));
    r4 = add64(r4, mul64ByU32(a4, b0));
    r4 = add64(r4, mul64ByU32(a5, b1));
    r4 = add64(r4, mul64ByU32(a6, b2));
    r4 = add64(r4, mul64ByU32(a7, b3));

    let r5 = mul64ByU32(a0, b5);
    r5 = add64(r5, mul64ByU32(a1, b4));
    r5 = sub64(r5, mul64ByU32(a2, b7));
    r5 = add64(r5, mul64ByU32(a3, b6));
    r5 = sub64(r5, mul64ByU32(a4, b1));
    r5 = add64(r5, mul64ByU32(a5, b0));
    r5 = add64(r5, mul64ByU32(a6, b3));
    r5 = add64(r5, mul64ByU32(a7, b2));

    let r6 = mul64ByU32(a0, b6);
    r6 = add64(r6, mul64ByU32(a1, b7));
    r6 = add64(r6, mul64ByU32(a2, b4));
    r6 = sub64(r6, mul64ByU32(a3, b5));
    r6 = sub64(r6, mul64ByU32(a4, b2));
    r6 = add64(r6, mul64ByU32(a5, b3));
    r6 = add64(r6, mul64ByU32(a6, b0));
    r6 = add64(r6, mul64ByU32(a7, b1));

    let r7 = mul64ByU32(a0, b7);
    r7 = sub64(r7, mul64ByU32(a1, b6));
    r7 = add64(r7, mul64ByU32(a2, b5));
    r7 = add64(r7, mul64ByU32(a3, b4));
    r7 = sub64(r7, mul64ByU32(a4, b3));
    r7 = add64(r7, mul64ByU32(a5, b2));
    r7 = add64(r7, mul64ByU32(a6, b1));
    r7 = add64(r7, mul64ByU32(a7, b0));

    a0 = r0; a1 = r1; a2 = r2; a3 = r3;
    a4 = r4; a5 = r5; a6 = r6; a7 = r7;

    if (i < 31) {
      b0 = b1; b1 = b2; b2 = b3; b3 = b4;
      b4 = b5; b5 = b6; b6 = b7;
      b7 = input[(i + 8) & 31];
    }
  }

  return [a0, a1, a2, a3, a4, a5, a6, a7];
}

function pickRefValue(refType, index, nibbleProduct, productBeforeOct, product, hashBytes) {
  switch (refType) {
    case 0: return nibbleProduct[index];
    case 1: return productBeforeOct[index];
    case 2: return product[index];
    default: return hashBytes[index];
  }
}

function pickArrayByte(selector, index, product, hashBytes, nibbleProduct, productBeforeOct) {
  switch (selector) {
    case 0: return product[index];
    case 1: return hashBytes[index];
    case 2: return nibbleProduct[index];
    default: return productBeforeOct[index];
  }
}

function cryptisRotateLeftBase(segment, product, nibbleProduct, productBeforeOct) {
  switch (segment) {
    case 0: return ((nibbleProduct[3] ^ 0x4f) * 3) & 0xff;
    case 1: return ((product[7] ^ 0xa6) * 2) & 0xff;
    case 2: return ((productBeforeOct[1] ^ 0x9c) * 9) & 0xff;
    case 3: return ((product[6] ^ 0x71) * 4) & 0xff;
    case 4: return ((nibbleProduct[4] ^ 0xb2) * 3) & 0xff;
    case 5: return ((product[0] ^ 0x58) * 6) & 0xff;
    case 6: return ((productBeforeOct[2] ^ 0x37) * 2) & 0xff;
    case 7: return ((product[5] ^ 0x1a) * 5) & 0xff;
    case 8: return ((nibbleProduct[3] ^ 0x93) * 7) & 0xff;
    case 9: return ((product[7] ^ 0x29) * 9) & 0xff;
    case 10: return ((productBeforeOct[1] ^ 0x4e) * 4) & 0xff;
    case 11: return ((nibbleProduct[6] ^ 0xf3) * 5) & 0xff;
    case 12: return ((product[4] ^ 0xb7) * 6) & 0xff;
    case 13: return ((product[0] ^ 0x2d) * 8) & 0xff;
    case 14: return ((productBeforeOct[2] ^ 0x6f) * 3) & 0xff;
    default: return ((nibbleProduct[5] ^ 0xe1) * 7) & 0xff;
  }
}

function cryptisRotateRightBase(segment, product, hashBytes, nibbleProduct, productBeforeOct) {
  switch (segment) {
    case 0: return ((hashBytes[2] ^ 0xd3) * 5) & 0xff;
    case 1: return ((nibbleProduct[5] ^ 0x5b) * 7) & 0xff;
    case 2: return ((product[0] ^ 0x8e) * 3) & 0xff;
    case 3: return ((productBeforeOct[3] ^ 0x2f) * 5) & 0xff;
    case 4: return ((hashBytes[7] ^ 0x6d) * 7) & 0xff;
    case 5: return ((nibbleProduct[1] ^ 0xee) * 9) & 0xff;
    case 6: return ((hashBytes[6] ^ 0x44) * 6) & 0xff;
    case 7: return ((hashBytes[4] ^ 0x7c) * 8) & 0xff;
    case 8: return ((product[2] ^ 0xaf) * 3) & 0xff;
    case 9: return ((nibbleProduct[5] ^ 0xdc) * 2) & 0xff;
    case 10: return ((hashBytes[0] ^ 0x8b) * 3) & 0xff;
    case 11: return ((productBeforeOct[3] ^ 0x62) * 8) & 0xff;
    case 12: return ((product[7] ^ 0x15) * 2) & 0xff;
    case 13: return ((productBeforeOct[1] ^ 0xc8) * 7) & 0xff;
    case 14: return ((nibbleProduct[6] ^ 0x99) * 9) & 0xff;
    default: return ((hashBytes[4] ^ 0x3b) * 5) & 0xff;
  }
}

function computeSboxEntry(sboxIdx, product, hashBytes, nibbleProduct, productBeforeOct, sboxIterations) {
  const segment = sboxIdx >> 4;
  const lane = sboxIdx & 15;

  const p1 = product[(sboxIdx + 1) & 31] & 0xff;
  const h2 = hashBytes[(sboxIdx + 2) & 31] & 0xff;

  const sourceSelector = SBOX_SOURCE_SELECTORS[segment];
  const valueSelector = SBOX_VALUE_SELECTORS[segment];

  const valueByte = pickArrayByte(valueSelector, lane, product, hashBytes, nibbleProduct, productBeforeOct) & 0xff;
  let value = (valueByte * SBOX_VALUE_MULTIPLIERS[segment] + lane * SBOX_VALUE_ADDERS[segment]) & 0xff;

  const rotateLeftShift = (p1 + sboxIdx) & 7;
  const rotateRightShift = (h2 + sboxIdx) & 7;

  const rotateLeftBase = cryptisRotateLeftBase(segment, product, nibbleProduct, productBeforeOct);
  const rotateRightBase = cryptisRotateRightBase(segment, product, hashBytes, nibbleProduct, productBeforeOct);

  const rotationLeft = rotl8(rotateLeftBase, rotateLeftShift);
  const rotationRight = rotr8(rotateRightBase, rotateRightShift);

  const sourceIndex = (sboxIdx + rotationLeft + rotationRight) & 31;
  const sourcePick = pickArrayByte(sourceSelector, sourceIndex, product, hashBytes, nibbleProduct, productBeforeOct) & 0xff;
  value = (sourcePick ^ value) & 0xff;

  const rotateLeftShift2 = (p1 + (sboxIdx << 2)) & 7;
  const rotateRightShift2 = (h2 + (sboxIdx * 6)) & 7;

  const baseMix = (product[(sboxIdx * 3) & 31] ^ hashBytes[(sboxIdx * 7) & 31]) & 0xff;
  const baseValue = ((sboxIdx + baseMix) & 0xff) ^ 0xa5;
  const xorValue = rotl8(baseValue, sboxIdx & 7) ^ 0x55;

  let rotatedValue = (rotl8(value, rotateLeftShift2) | rotr8(value, rotateRightShift2)) & 0xff;
  value = (value ^ rotatedValue ^ xorValue) & 0xff;

  if (sboxIterations === 2) {
    rotatedValue = (rotl8(value, rotateLeftShift2) | rotr8(value, rotateRightShift2)) & 0xff;
    value = (value ^ rotatedValue ^ xorValue) & 0xff;
  }

  return value & 0xff;
}

function ox8Hash({ preMatrixHash, matrixBytes }) {
  const hashBytes = normalizeBytes(preMatrixHash, 32, "preMatrixHash");
  const matrix = normalizeBytes(matrixBytes, 64 * 64, "matrixBytes");

  const product = new Uint8Array(32);
  const nibbleProduct = new Uint8Array(32);
  const productBeforeOct = new Uint8Array(32);

  const nibLookup = Array.from({ length: 16 }, () => new Uint8Array(4));
  for (let block = 0; block < 16; block += 1) {
    const hb0 = hashBytes[block << 1];
    const hb1 = hashBytes[(block << 1) + 1];
    nibLookup[block][0] = hb0 >>> 4;
    nibLookup[block][1] = hb0 & 0x0f;
    nibLookup[block][2] = hb1 >>> 4;
    nibLookup[block][3] = hb1 & 0x0f;
  }

  let rowPtr0 = 0;
  let rowPtr1 = 64;
  let rowPtr2 = 128;
  let rowPtr3 = 192;

  for (let i = 0; i < 32; i += 1) {
    let sum1 = 0;
    let sum2 = 0;
    let sum3 = 0;
    let sum4 = 0;

    for (let block = 0; block < 16; block += 1) {
      const nib = nibLookup[block];
      const base = block * 4;

      sum1 += matrix[rowPtr0 + base + 0] * nib[0];
      sum1 += matrix[rowPtr0 + base + 1] * nib[1];
      sum1 += matrix[rowPtr0 + base + 2] * nib[2];
      sum1 += matrix[rowPtr0 + base + 3] * nib[3];

      sum2 += matrix[rowPtr1 + base + 0] * nib[0];
      sum2 += matrix[rowPtr1 + base + 1] * nib[1];
      sum2 += matrix[rowPtr1 + base + 2] * nib[2];
      sum2 += matrix[rowPtr1 + base + 3] * nib[3];

      sum3 += matrix[rowPtr2 + base + 0] * nib[0];
      sum3 += matrix[rowPtr2 + base + 1] * nib[1];
      sum3 += matrix[rowPtr2 + base + 2] * nib[2];
      sum3 += matrix[rowPtr2 + base + 3] * nib[3];

      sum4 += matrix[rowPtr3 + base + 0] * nib[0];
      sum4 += matrix[rowPtr3 + base + 1] * nib[1];
      sum4 += matrix[rowPtr3 + base + 2] * nib[2];
      sum4 += matrix[rowPtr3 + base + 3] * nib[3];
    }

    sum1 >>>= 0;
    sum2 >>>= 0;
    sum3 >>>= 0;
    sum4 >>>= 0;

    rowPtr0 += 128;
    rowPtr1 += 128;
    rowPtr2 += 64;
    rowPtr3 += 64;

    const aNibble = (
      (sum1 & 0x0f)
      ^ ((sum2 >>> 4) & 0x0f)
      ^ ((sum3 >>> 8) & 0x0f)
      ^ (((sum1 * 0xabcd) >>> 12) & 0x0f)
      ^ (((sum1 * 0x1234) >>> 8) & 0x0f)
      ^ (((sum2 * 0x5678) >>> 16) & 0x0f)
      ^ (((sum3 * 0x9abc) >>> 4) & 0x0f)
      ^ ((rotl32(sum1, 3) & 0x0f) ^ (rotr32(sum3, 5) & 0x0f))
    ) & 0x0f;

    const bNibble = (
      (sum2 & 0x0f)
      ^ ((sum1 >>> 4) & 0x0f)
      ^ ((sum4 >>> 8) & 0x0f)
      ^ (((sum2 * 0xdcba) >>> 14) & 0x0f)
      ^ (((sum2 * 0x8765) >>> 10) & 0x0f)
      ^ (((sum1 * 0x4321) >>> 6) & 0x0f)
      ^ ((rotl32(sum4, 2) ^ rotr32(sum1, 1)) & 0x0f)
    ) & 0x0f;

    const cNibble = (
      (sum3 & 0x0f)
      ^ ((sum2 >>> 4) & 0x0f)
      ^ ((sum2 >>> 8) & 0x0f)
      ^ (((sum3 * 0xf135) >>> 10) & 0x0f)
      ^ (((sum3 * 0x2468) >>> 12) & 0x0f)
      ^ (((sum4 * 0xacef) >>> 8) & 0x0f)
      ^ (((sum2 * 0x1357) >>> 4) & 0x0f)
      ^ ((rotl32(sum3, 5) & 0x0f) ^ (rotr32(sum1, 7) & 0x0f))
    ) & 0x0f;

    const dNibble = (
      (sum1 & 0x0f)
      ^ ((sum4 >>> 4) & 0x0f)
      ^ ((sum1 >>> 8) & 0x0f)
      ^ (((sum4 * 0x57a3) >>> 6) & 0x0f)
      ^ (((sum3 * 0xd4e3) >>> 12) & 0x0f)
      ^ (((sum1 * 0x9f8b) >>> 10) & 0x0f)
      ^ ((rotl32(sum4, 4) ^ ((sum1 + sum2) >>> 0)) & 0x0f)
    ) & 0x0f;

    const hashByte = hashBytes[i] & 0xff;
    nibbleProduct[i] = ((((cNibble & 0x0f) << 4) | (dNibble & 0x0f)) ^ hashByte) & 0xff;
    product[i] = ((((aNibble & 0x0f) << 4) | (bNibble & 0x0f)) ^ hashByte) & 0xff;
  }

  productBeforeOct.set(product);
  const octResult = octonionHash(product);

  for (let i = 0; i < 4; i += 1) {
    const offset = i * 8;
    const mixedWord = toU64(readU64LE(product, offset) ^ octResult[i]);
    writeU64LE(product, offset, mixedWord);
  }

  const updateIndex = (productBeforeOct[2] & 7) + 1;
  const sboxIterations = 1 + (product[updateIndex] & 1);

  const indexBlake = (productBeforeOct[5] & 7) + 1;
  const iterationsBlake = 1 + (product[indexBlake] % 3);

  let output = new Uint8Array(product);
  for (let iter = 0; iter < iterationsBlake; iter += 1) {
    output = blake3Compress32(output);
  }

  let refIdx = 0;
  let productIdx = 0;
  let hashIdx = 0;
  let mixTerm = 0;

  for (let i = 0; i < 32; i += 1) {
    const refVal = pickRefValue(i & 3, refIdx, nibbleProduct, productBeforeOct, product, hashBytes);
    const index = (refVal + product[productIdx] + hashBytes[hashIdx] + mixTerm) & 0xff;
    const sboxByte = computeSboxEntry(index, product, hashBytes, nibbleProduct, productBeforeOct, sboxIterations);
    const afterComp = AFTER_COMP_LUT[product[i] & 0xff];
    output[i] = (output[i] ^ sboxByte ^ afterComp) & 0xff;

    refIdx = (refIdx + 13) & 31;
    productIdx = (productIdx + 31) & 31;
    hashIdx = (hashIdx + 19) & 31;
    mixTerm = (mixTerm + 41) & 0xff;
  }

  return cryptixHashV2Hash(output);
}

function prepareOx8Context({ prePowHash, timestamp, matrixBytes } = {}) {
  const prePowHashBytes = normalizeBytes(prePowHash, 32, "prePowHash");
  const ts = parseU64Input(timestamp, "timestamp");

  const matrix = matrixBytes
    ? normalizeBytes(matrixBytes, 64 * 64, "matrixBytes")
    : generateOx8Matrix(prePowHashBytes);

  const powStateWords = buildPowStateWords(prePowHashBytes, ts);

  return {
    prePowHash: prePowHashBytes,
    timestamp: ts,
    matrixBytes: matrix,
    powStateWords,
  };
}

function ox8PowHashWithContext(context, nonce) {
  if (!context || !Array.isArray(context.powStateWords) || !context.matrixBytes) {
    throw new Error("context must come from prepareOx8Context(...)");
  }

  const preMatrixHash = calculatePowPreMatrixFromState(context.powStateWords, nonce);
  return ox8Hash({
    preMatrixHash,
    matrixBytes: context.matrixBytes,
  });
}

function ox8PowHash({ prePowHash, timestamp, nonce, matrixBytes }) {
  const context = prepareOx8Context({ prePowHash, timestamp, matrixBytes });
  return ox8PowHashWithContext(context, nonce);
}

function ox8HashHex({ preMatrixHashHex, matrixHex }) {
  const out = ox8Hash({
    preMatrixHash: hexToBytes(preMatrixHashHex, 32, "preMatrixHashHex"),
    matrixBytes: hexToBytes(matrixHex, 64 * 64, "matrixHex"),
  });
  return bytesToHex(out);
}

function ox8PowHashHex({ prePowHashHex, timestamp, nonce, matrixHex }) {
  const out = ox8PowHash({
    prePowHash: hexToBytes(prePowHashHex, 32, "prePowHashHex"),
    timestamp,
    nonce,
    matrixBytes: matrixHex ? hexToBytes(matrixHex, 64 * 64, "matrixHex") : undefined,
  });
  return bytesToHex(out);
}

const OX8Standalone = {
  hexToBytes,
  bytesToHex,
  parseU64Input,
  generateOx8Matrix,
  buildPowStateWords,
  powHashFinalize,
  sha3_256_32bytes,
  calculatePowPreMatrix,
  prepareOx8Context,
  ox8Hash,
  ox8HashHex,
  ox8PowHashWithContext,
  ox8PowHash,
  ox8PowHashHex,
};

if (typeof globalThis !== "undefined") {
  globalThis.OX8Standalone = OX8Standalone;
}

export {
  hexToBytes,
  bytesToHex,
  parseU64Input,
  generateOx8Matrix,
  buildPowStateWords,
  powHashFinalize,
  sha3_256_32bytes,
  calculatePowPreMatrix,
  prepareOx8Context,
  ox8Hash,
  ox8HashHex,
  ox8PowHashWithContext,
  ox8PowHash,
  ox8PowHashHex,
};

export default OX8Standalone;
