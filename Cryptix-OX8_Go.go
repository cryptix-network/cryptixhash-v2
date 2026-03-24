package cryptixox8

import (
	"errors"
	"math/bits"
)

var powHashInitialState = [25]uint64{
	1242148031264380989, 3008272977830772284, 2188519011337848018, 1992179434288343456,
	8876506674959887717, 5399642050693751366, 1745875063082670864, 8605242046444978844,
	17936695144567157056, 3343109343542796272, 1123092876221303306, 4963925045340115282,
	17037383077651887893, 16629644495023626889, 12833675776649114147, 3784524041015224902,
	1082795874807940378, 13952716920571277634, 13411128033953605860, 15060696040649351053,
	9928834659948351306, 5237849264682708699, 12825353012139217522, 6706187291358897596,
	196324915476054915,
}

var heavyHashInitialState = [25]uint64{
	4239941492252378377, 8746723911537738262, 8796936657246353646, 1272090201925444760,
	16654558671554924250, 8270816933120786537, 13907396207649043898, 6782861118970774626,
	9239690602118867528, 11582319943599406348, 17596056728278508070, 15212962468105129023,
	7812475424661425213, 3370482334374859748, 5690099369266491460, 8596393687355028144,
	570094237299545110, 9119540418498120711, 16901969272480492857, 13372017233735502424,
	14372891883993151831, 5171152063242093102, 10573107899694386186, 6096431547456407061,
	1592359455985097269,
}

var sboxSourceSelectors = [16]byte{0, 1, 2, 1, 3, 1, 0, 1, 3, 1, 2, 1, 3, 1, 0, 1}
var sboxValueSelectors = [16]byte{0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2}
var sboxValueMultipliers = [16]byte{0x03, 0x05, 0x07, 0x0F, 0x11, 0x13, 0x17, 0x19, 0x1D, 0x1F, 0x23, 0x29, 0x2F, 0x31, 0x37, 0x3F}
var sboxValueAdders = [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA}

var keccakRndc = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakPiLanes = [24]uint32{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}
var keccakRhoPiRot = [24]uint32{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}

var blake3IV = [8]uint32{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}
var blake3MsgPermutation = [16]uint32{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

var afterCompLUT = [256]byte{
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
	0x65, 0x27, 0x26, 0x5C, 0x21, 0xA8, 0xF4, 0x3C, 0xCA, 0x95, 0x15, 0xFC, 0x9C, 0x1B, 0x9A, 0x0B,
}

func rotl8(v byte, s uint32) byte {
	s &= 7
	return (v << s) | (v >> ((8 - s) & 7))
}

func rotr8(v byte, s uint32) byte {
	s &= 7
	return (v >> s) | (v << ((8 - s) & 7))
}

func rotl32(v uint32, s uint32) uint32 {
	s &= 31
	return bits.RotateLeft32(v, int(s))
}

func rotr32(v uint32, s uint32) uint32 {
	s &= 31
	return bits.RotateLeft32(v, -int(s))
}

func rotl64(v uint64, s uint32) uint64 {
	s &= 63
	return bits.RotateLeft64(v, int(s))
}

func load64LE(in []byte, off uint32) uint64 {
	b := off
	return uint64(in[b+0]) |
		uint64(in[b+1])<<8 |
		uint64(in[b+2])<<16 |
		uint64(in[b+3])<<24 |
		uint64(in[b+4])<<32 |
		uint64(in[b+5])<<40 |
		uint64(in[b+6])<<48 |
		uint64(in[b+7])<<56
}

func load32LE(in []byte, off uint32) uint32 {
	b := off
	return uint32(in[b+0]) |
		uint32(in[b+1])<<8 |
		uint32(in[b+2])<<16 |
		uint32(in[b+3])<<24
}

func store64LE(v uint64, out []byte, off uint32) {
	b := off
	out[b+0] = byte(v)
	out[b+1] = byte(v >> 8)
	out[b+2] = byte(v >> 16)
	out[b+3] = byte(v >> 24)
	out[b+4] = byte(v >> 32)
	out[b+5] = byte(v >> 40)
	out[b+6] = byte(v >> 48)
	out[b+7] = byte(v >> 56)
}

func store32LE(v uint32, out []byte, off uint32) {
	b := off
	out[b+0] = byte(v)
	out[b+1] = byte(v >> 8)
	out[b+2] = byte(v >> 16)
	out[b+3] = byte(v >> 24)
}

func mul64ByU8(a uint64, b byte) uint64 {
	return a * uint64(b)
}

func dot4Acc(sum uint32, row4 []byte, nib4 [4]uint32) uint32 {
	return sum +
		uint32(row4[0])*nib4[0] +
		uint32(row4[1])*nib4[1] +
		uint32(row4[2])*nib4[2] +
		uint32(row4[3])*nib4[3]
}

func keccakF1600(st *[25]uint64) {
	for round := uint32(0); round < 24; round++ {
		c0 := st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20]
		c1 := st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21]
		c2 := st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22]
		c3 := st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23]
		c4 := st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24]

		d0 := c4 ^ rotl64(c1, 1)
		d1 := c0 ^ rotl64(c2, 1)
		d2 := c1 ^ rotl64(c3, 1)
		d3 := c2 ^ rotl64(c4, 1)
		d4 := c3 ^ rotl64(c0, 1)

		st[0] ^= d0
		st[5] ^= d0
		st[10] ^= d0
		st[15] ^= d0
		st[20] ^= d0
		st[1] ^= d1
		st[6] ^= d1
		st[11] ^= d1
		st[16] ^= d1
		st[21] ^= d1
		st[2] ^= d2
		st[7] ^= d2
		st[12] ^= d2
		st[17] ^= d2
		st[22] ^= d2
		st[3] ^= d3
		st[8] ^= d3
		st[13] ^= d3
		st[18] ^= d3
		st[23] ^= d3
		st[4] ^= d4
		st[9] ^= d4
		st[14] ^= d4
		st[19] ^= d4
		st[24] ^= d4

		t := st[1]
		for i := uint32(0); i < 24; i++ {
			lane := keccakPiLanes[i]
			next := st[lane]
			st[lane] = rotl64(t, keccakRhoPiRot[i])
			t = next
		}

		for row := uint32(0); row < 25; row += 5 {
			r0 := st[row+0]
			r1 := st[row+1]
			r2 := st[row+2]
			r3 := st[row+3]
			r4 := st[row+4]
			st[row+0] = r0 ^ ((^r1) & r2)
			st[row+1] = r1 ^ ((^r2) & r3)
			st[row+2] = r2 ^ ((^r3) & r4)
			st[row+3] = r3 ^ ((^r4) & r0)
			st[row+4] = r4 ^ ((^r0) & r1)
		}

		st[0] ^= keccakRndc[round]
	}
}

func sha3_256_32bytes(input [32]byte) [32]byte {
	var st [25]uint64
	st[0] ^= load64LE(input[:], 0)
	st[1] ^= load64LE(input[:], 8)
	st[2] ^= load64LE(input[:], 16)
	st[3] ^= load64LE(input[:], 24)
	st[4] ^= 0x06
	st[16] ^= (0x80 << 56)
	keccakF1600(&st)

	var out [32]byte
	store64LE(st[0], out[:], 0)
	store64LE(st[1], out[:], 8)
	store64LE(st[2], out[:], 16)
	store64LE(st[3], out[:], 24)
	return out
}

func octonionHash(inputHash [32]byte) [8]uint64 {
	a0, a1, a2, a3 := uint64(inputHash[0]), uint64(inputHash[1]), uint64(inputHash[2]), uint64(inputHash[3])
	a4, a5, a6, a7 := uint64(inputHash[4]), uint64(inputHash[5]), uint64(inputHash[6]), uint64(inputHash[7])
	b0, b1, b2, b3 := inputHash[8], inputHash[9], inputHash[10], inputHash[11]
	b4, b5, b6, b7 := inputHash[12], inputHash[13], inputHash[14], inputHash[15]

	for i := uint32(8); i < 32; i++ {
		r0 := mul64ByU8(a0, b0) - mul64ByU8(a1, b1) - mul64ByU8(a2, b2) - mul64ByU8(a3, b3) - mul64ByU8(a4, b4) - mul64ByU8(a5, b5) - mul64ByU8(a6, b6) - mul64ByU8(a7, b7)
		r1 := mul64ByU8(a0, b1) + mul64ByU8(a1, b0) + mul64ByU8(a2, b3) - mul64ByU8(a3, b2) + mul64ByU8(a4, b5) - mul64ByU8(a5, b4) - mul64ByU8(a6, b7) + mul64ByU8(a7, b6)
		r2 := mul64ByU8(a0, b2) - mul64ByU8(a1, b3) + mul64ByU8(a2, b0) + mul64ByU8(a3, b1) + mul64ByU8(a4, b6) - mul64ByU8(a5, b7) + mul64ByU8(a6, b4) - mul64ByU8(a7, b5)
		r3 := mul64ByU8(a0, b3) + mul64ByU8(a1, b2) - mul64ByU8(a2, b1) + mul64ByU8(a3, b0) + mul64ByU8(a4, b7) + mul64ByU8(a5, b6) - mul64ByU8(a6, b5) + mul64ByU8(a7, b4)
		r4 := mul64ByU8(a0, b4) - mul64ByU8(a1, b5) - mul64ByU8(a2, b6) - mul64ByU8(a3, b7) + mul64ByU8(a4, b0) + mul64ByU8(a5, b1) + mul64ByU8(a6, b2) + mul64ByU8(a7, b3)
		r5 := mul64ByU8(a0, b5) + mul64ByU8(a1, b4) - mul64ByU8(a2, b7) + mul64ByU8(a3, b6) - mul64ByU8(a4, b1) + mul64ByU8(a5, b0) + mul64ByU8(a6, b3) + mul64ByU8(a7, b2)
		r6 := mul64ByU8(a0, b6) + mul64ByU8(a1, b7) + mul64ByU8(a2, b4) - mul64ByU8(a3, b5) - mul64ByU8(a4, b2) + mul64ByU8(a5, b3) + mul64ByU8(a6, b0) + mul64ByU8(a7, b1)
		r7 := mul64ByU8(a0, b7) - mul64ByU8(a1, b6) + mul64ByU8(a2, b5) + mul64ByU8(a3, b4) - mul64ByU8(a4, b3) + mul64ByU8(a5, b2) + mul64ByU8(a6, b1) + mul64ByU8(a7, b0)

		a0, a1, a2, a3 = r0, r1, r2, r3
		a4, a5, a6, a7 = r4, r5, r6, r7

		if i < 31 {
			b0, b1, b2, b3 = b1, b2, b3, b4
			b4, b5, b6 = b5, b6, b7
			b7 = inputHash[(i+8)&31]
		}
	}

	return [8]uint64{a0, a1, a2, a3, a4, a5, a6, a7}
}

func blake3Permute(m *[16]uint32) {
	var p [16]uint32
	for i := uint32(0); i < 16; i++ {
		p[i] = m[blake3MsgPermutation[i]]
	}
	*m = p
}

func blake3G(v *[16]uint32, a, b, c, d, mx, my uint32) {
	v[a] = v[a] + v[b] + mx
	v[d] = rotr32(v[d]^v[a], 16)
	v[c] = v[c] + v[d]
	v[b] = rotr32(v[b]^v[c], 12)
	v[a] = v[a] + v[b] + my
	v[d] = rotr32(v[d]^v[a], 8)
	v[c] = v[c] + v[d]
	v[b] = rotr32(v[b]^v[c], 7)
}

func blake3Round(v *[16]uint32, m *[16]uint32) {
	blake3G(v, 0, 4, 8, 12, m[0], m[1])
	blake3G(v, 1, 5, 9, 13, m[2], m[3])
	blake3G(v, 2, 6, 10, 14, m[4], m[5])
	blake3G(v, 3, 7, 11, 15, m[6], m[7])
	blake3G(v, 0, 5, 10, 15, m[8], m[9])
	blake3G(v, 1, 6, 11, 12, m[10], m[11])
	blake3G(v, 2, 7, 8, 13, m[12], m[13])
	blake3G(v, 3, 4, 9, 14, m[14], m[15])
}

func blake3Compress32(input [32]byte) [32]byte {
	var m [16]uint32
	var v [16]uint32
	for i := uint32(0); i < 8; i++ {
		m[i] = load32LE(input[:], i*4)
		v[i] = blake3IV[i]
	}

	v[8], v[9], v[10], v[11] = blake3IV[0], blake3IV[1], blake3IV[2], blake3IV[3]
	v[12], v[13], v[14], v[15] = 0, 0, 32, (1 | 2 | 8)

	for round := uint32(0); round < 7; round++ {
		blake3Round(&v, &m)
		if round+1 < 7 {
			blake3Permute(&m)
		}
	}

	var out [32]byte
	for i := uint32(0); i < 8; i++ {
		store32LE(v[i]^v[i+8], out[:], i*4)
	}
	return out
}

func cryptixHashV2Hash(input [32]byte) [32]byte {
	st := heavyHashInitialState
	st[0] ^= load64LE(input[:], 0)
	st[1] ^= load64LE(input[:], 8)
	st[2] ^= load64LE(input[:], 16)
	st[3] ^= load64LE(input[:], 24)
	keccakF1600(&st)

	var out [32]byte
	store64LE(st[0], out[:], 0)
	store64LE(st[1], out[:], 8)
	store64LE(st[2], out[:], 16)
	store64LE(st[3], out[:], 24)
	return out
}

func pickRefValue(refType byte, idx uint32, nibbleProduct, productBeforeOct, product, hashBytes [32]byte) byte {
	switch refType {
	case 0:
		return nibbleProduct[idx]
	case 1:
		return productBeforeOct[idx]
	case 2:
		return product[idx]
	default:
		return hashBytes[idx]
	}
}

func pickArrayByte(selector byte, idx uint32, product, hashBytes, nibbleProduct, productBeforeOct [32]byte) byte {
	switch selector {
	case 0:
		return product[idx]
	case 1:
		return hashBytes[idx]
	case 2:
		return nibbleProduct[idx]
	default:
		return productBeforeOct[idx]
	}
}

func computeSboxEntry(sboxIdx uint32, rotateLeftBases, rotateRightBases [16]byte, product, hashBytes, nibbleProduct, productBeforeOct [32]byte, sboxIterations uint32) byte {
	segment := sboxIdx >> 4
	lane := sboxIdx & 15
	p1 := product[(sboxIdx+1)&31]
	h2 := hashBytes[(sboxIdx+2)&31]

	value := byte(
		pickArrayByte(sboxValueSelectors[segment], lane, product, hashBytes, nibbleProduct, productBeforeOct)*
			sboxValueMultipliers[segment] +
			byte(lane)*sboxValueAdders[segment],
	)

	rotationLeft := rotl8(rotateLeftBases[segment], (uint32(p1)+sboxIdx)&7)
	rotationRight := rotr8(rotateRightBases[segment], (uint32(h2)+sboxIdx)&7)
	sourceIndex := (sboxIdx + uint32(rotationLeft) + uint32(rotationRight)) & 31
	value ^= pickArrayByte(sboxSourceSelectors[segment], sourceIndex, product, hashBytes, nibbleProduct, productBeforeOct)

	rotateLeftShift2 := (uint32(p1) + (sboxIdx << 2)) & 7
	rotateRightShift2 := (uint32(h2) + (sboxIdx * 6)) & 7
	baseValue := byte(sboxIdx+uint32(product[(sboxIdx*3)&31]^hashBytes[(sboxIdx*7)&31])) ^ 0xA5
	xorValue := rotl8(baseValue, sboxIdx&7) ^ 0x55

	rotatedValue := rotl8(value, rotateLeftShift2) | rotr8(value, rotateRightShift2)
	value ^= rotatedValue ^ xorValue
	if sboxIterations == 2 {
		rotatedValue = rotl8(value, rotateLeftShift2) | rotr8(value, rotateRightShift2)
		value ^= rotatedValue ^ xorValue
	}
	return value
}

func cryptixHashMatrix(matrix [64][64]byte, hashBytes [32]byte) [32]byte {
	var product [32]byte
	var nibbleProduct [32]byte

	var matrixFlat [4096]byte
	for r := 0; r < 64; r++ {
		copy(matrixFlat[r*64:(r+1)*64], matrix[r][:])
	}

	rowPtr0 := uint32(0)
	rowPtr1 := uint32(64)
	rowPtr2 := uint32(128)
	rowPtr3 := uint32(192)

	for i := uint32(0); i < 32; i++ {
		sum1, sum2, sum3, sum4 := uint32(0), uint32(0), uint32(0), uint32(0)
		for block := uint32(0); block < 16; block++ {
			hashByteIdx := block << 1
			hb0 := hashBytes[hashByteIdx]
			hb1 := hashBytes[hashByteIdx+1]
			nib := [4]uint32{uint32(hb0 >> 4), uint32(hb0 & 0x0F), uint32(hb1 >> 4), uint32(hb1 & 0x0F)}

			off := block << 2
			sum1 = dot4Acc(sum1, matrixFlat[rowPtr0+off:rowPtr0+off+4], nib)
			sum2 = dot4Acc(sum2, matrixFlat[rowPtr1+off:rowPtr1+off+4], nib)
			sum3 = dot4Acc(sum3, matrixFlat[rowPtr2+off:rowPtr2+off+4], nib)
			sum4 = dot4Acc(sum4, matrixFlat[rowPtr3+off:rowPtr3+off+4], nib)
		}

		rowPtr0 += 128
		rowPtr1 += 128
		rowPtr2 += 64
		rowPtr3 += 64

		aNibble := (sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum3 >> 8) & 0xF) ^ ((sum1*0xABCD)>>12)&0xF ^ ((sum1*0x1234)>>8)&0xF ^ ((sum2*0x5678)>>16)&0xF ^ ((sum3*0x9ABC)>>4)&0xF ^ ((rotl32(sum1, 3) & 0xF) ^ (rotr32(sum3, 5) & 0xF))
		bNibble := (sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum4 >> 8) & 0xF) ^ ((sum2*0xDCBA)>>14)&0xF ^ ((sum2*0x8765)>>10)&0xF ^ ((sum1*0x4321)>>6)&0xF ^ ((rotl32(sum4, 2) ^ rotr32(sum1, 1)) & 0xF)
		cNibble := (sum3 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF) ^ ((sum3*0xF135)>>10)&0xF ^ ((sum3*0x2468)>>12)&0xF ^ ((sum4*0xACEF)>>8)&0xF ^ ((sum2*0x1357)>>4)&0xF ^ ((rotl32(sum3, 5) & 0xF) ^ (rotr32(sum1, 7) & 0xF))
		dNibble := (sum1 & 0xF) ^ ((sum4 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF) ^ ((sum4*0x57A3)>>6)&0xF ^ ((sum3*0xD4E3)>>12)&0xF ^ ((sum1*0x9F8B)>>10)&0xF ^ ((rotl32(sum4, 4) ^ (sum1 + sum2)) & 0xF)

		h := hashBytes[i]
		nibbleProduct[i] = byte((((cNibble & 0xF) << 4) | (dNibble & 0xF)) ^ uint32(h))
		product[i] = byte((((aNibble & 0xF) << 4) | (bNibble & 0xF)) ^ uint32(h))
	}

	productBeforeOct := product
	octResult := octonionHash(product)
	for i := uint32(0); i < 4; i++ {
		off := i * 8
		store64LE(load64LE(product[:], off)^octResult[i], product[:], off)
	}

	rotateLeftBases := [16]byte{
		(nibbleProduct[3] ^ 0x4F) * 3,
		(product[7] ^ 0xA6) * 2,
		(productBeforeOct[1] ^ 0x9C) * 9,
		(product[6] ^ 0x71) * 4,
		(nibbleProduct[4] ^ 0xB2) * 3,
		(product[0] ^ 0x58) * 6,
		(productBeforeOct[2] ^ 0x37) * 2,
		(product[5] ^ 0x1A) * 5,
		(nibbleProduct[3] ^ 0x93) * 7,
		(product[7] ^ 0x29) * 9,
		(productBeforeOct[1] ^ 0x4E) * 4,
		(nibbleProduct[6] ^ 0xF3) * 5,
		(product[4] ^ 0xB7) * 6,
		(product[0] ^ 0x2D) * 8,
		(productBeforeOct[2] ^ 0x6F) * 3,
		(nibbleProduct[5] ^ 0xE1) * 7,
	}
	rotateRightBases := [16]byte{
		(hashBytes[2] ^ 0xD3) * 5,
		(nibbleProduct[5] ^ 0x5B) * 7,
		(product[0] ^ 0x8E) * 3,
		(productBeforeOct[3] ^ 0x2F) * 5,
		(hashBytes[7] ^ 0x6D) * 7,
		(nibbleProduct[1] ^ 0xEE) * 9,
		(hashBytes[6] ^ 0x44) * 6,
		(hashBytes[4] ^ 0x7C) * 8,
		(product[2] ^ 0xAF) * 3,
		(nibbleProduct[5] ^ 0xDC) * 2,
		(hashBytes[0] ^ 0x8B) * 3,
		(productBeforeOct[3] ^ 0x62) * 8,
		(product[7] ^ 0x15) * 2,
		(productBeforeOct[1] ^ 0xC8) * 7,
		(nibbleProduct[6] ^ 0x99) * 9,
		(hashBytes[4] ^ 0x3B) * 5,
	}

	updateIndex := uint32(productBeforeOct[2]&7) + 1
	sboxIterations := uint32(1 + (product[updateIndex] & 1))
	indexBlake := uint32(productBeforeOct[5]&7) + 1
	iterationsBlake := uint32(1 + (product[indexBlake] % 3))

	output := product
	for i := uint32(0); i < iterationsBlake; i++ {
		output = blake3Compress32(output)
	}

	refIdx, productIdx, hashIdx, mixTerm := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := uint32(0); i < 32; i++ {
		refVal := pickRefValue(byte(i&3), refIdx, nibbleProduct, productBeforeOct, product, hashBytes)
		index := (uint32(refVal) + uint32(product[productIdx]) + uint32(hashBytes[hashIdx]) + mixTerm) & 255
		sboxByte := computeSboxEntry(index, rotateLeftBases, rotateRightBases, product, hashBytes, nibbleProduct, productBeforeOct, sboxIterations)
		output[i] ^= sboxByte ^ afterCompLUT[product[i]]

		refIdx = (refIdx + 13) & 31
		productIdx = (productIdx + 31) & 31
		hashIdx = (hashIdx + 19) & 31
		mixTerm = (mixTerm + 41) & 255
	}

	return cryptixHashV2Hash(output)
}

func powHashFinalizeFromHeader(header72 [72]byte, nonce uint64) [32]byte {
	st := powHashInitialState
	for i := uint32(0); i < 9; i++ {
		st[i] ^= load64LE(header72[:], i*8)
	}
	st[9] ^= nonce
	keccakF1600(&st)

	var out [32]byte
	store64LE(st[0], out[:], 0)
	store64LE(st[1], out[:], 8)
	store64LE(st[2], out[:], 16)
	store64LE(st[3], out[:], 24)
	return out
}

func calculatePowPreMatrixFromHeader(header72 [72]byte, nonce uint64) [32]byte {
	currentHash := powHashFinalizeFromHeader(header72, nonce)
	iterations := uint32(currentHash[0]&1) + 1

	for i := uint32(0); i < iterations; i++ {
		currentHash = sha3_256_32bytes(currentHash)

		if (currentHash[1] & 3) == 0 {
			repeat := uint32(currentHash[2]&3) + 1
			for r := uint32(0); r < repeat; r++ {
				targetByte := (uint32(currentHash[1]) + i) & 31
				currentHash[targetByte] ^= currentHash[i&15] ^ 0xA5
				rotationByte := currentHash[i&31]
				rotationAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) & 3) + 2
				if (rotationByte & 1) == 0 {
					currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount)
				} else {
					currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount)
				}
				shiftAmount := ((uint32(currentHash[5]) + uint32(currentHash[1])) % 3) + 1
				currentHash[targetByte] ^= rotl8(currentHash[targetByte], shiftAmount)
			}
		} else if (currentHash[3] % 3) == 0 {
			repeat := uint32(currentHash[4]%5) + 1
			for r := uint32(0); r < repeat; r++ {
				targetByte := (uint32(currentHash[6]) + i) & 31
				currentHash[targetByte] ^= currentHash[i&15] ^ 0x55
				rotationByte := currentHash[i&31]
				rotationAmount := ((uint32(currentHash[7]) + uint32(currentHash[2])) % 6) + 1
				if (rotationByte & 1) == 0 {
					currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount)
				} else {
					currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount)
				}
				shiftAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) % 4) + 1
				currentHash[targetByte] ^= rotl8(currentHash[targetByte], shiftAmount)
			}
		} else if (currentHash[2] % 6) == 0 {
			repeat := uint32(currentHash[6]&3) + 1
			for r := uint32(0); r < repeat; r++ {
				targetByte := (uint32(currentHash[10]) + i) & 31
				currentHash[targetByte] ^= currentHash[i&15] ^ 0xFF
				rotationByte := currentHash[i&31]
				rotationAmount := ((uint32(currentHash[7]) + uint32(currentHash[7])) % 7) + 1
				if (rotationByte & 1) == 0 {
					currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount)
				} else {
					currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount)
				}
				shiftAmount := ((uint32(currentHash[3]) + uint32(currentHash[5])) % 5) + 2
				currentHash[targetByte] ^= rotl8(currentHash[targetByte], shiftAmount)
			}
		} else if (currentHash[7] % 5) == 0 {
			repeat := uint32(currentHash[8]&3) + 1
			for r := uint32(0); r < repeat; r++ {
				targetByte := (uint32(currentHash[25]) + i) & 31
				currentHash[targetByte] ^= currentHash[i&15] ^ 0x66
				rotationByte := currentHash[i&31]
				rotationAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) & 3) + 2
				if (rotationByte & 1) == 0 {
					currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount)
				} else {
					currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount)
				}
				shiftAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) & 3) + 1
				currentHash[targetByte] ^= rotl8(currentHash[targetByte], shiftAmount)
			}
		} else if (currentHash[8] % 7) == 0 {
			repeat := uint32(currentHash[9]%5) + 1
			for r := uint32(0); r < repeat; r++ {
				targetByte := (uint32(currentHash[30]) + i) & 31
				currentHash[targetByte] ^= currentHash[i&15] ^ 0x77
				rotationByte := currentHash[i&31]
				rotationAmount := ((uint32(currentHash[2]) + uint32(currentHash[5])) % 5) + 1
				if (rotationByte & 1) == 0 {
					currentHash[targetByte] = rotl8(currentHash[targetByte], rotationAmount)
				} else {
					currentHash[targetByte] = rotr8(currentHash[targetByte], rotationAmount)
				}
				shiftAmount := ((uint32(currentHash[7]) + uint32(currentHash[9])) % 6) + 2
				currentHash[targetByte] ^= rotl8(currentHash[targetByte], shiftAmount)
			}
		}
	}

	return currentHash
}

// Hash computes the full Cryptix OX8 hash from a 72-byte header, nonce and 64x64 matrix.
func Hash(header72 [72]byte, nonce uint64, matrix [64][64]byte) [32]byte {
	pre := calculatePowPreMatrixFromHeader(header72, nonce)
	return cryptixHashMatrix(matrix, pre)
}

// HashFromSlices is a convenience wrapper for developers wiring dynamic buffers.
func HashFromSlices(header72 []byte, nonce uint64, matrix []byte) ([]byte, error) {
	if len(header72) != 72 {
		return nil, errors.New("header72 must be exactly 72 bytes")
	}
	if len(matrix) != 64*64 {
		return nil, errors.New("matrix must be exactly 4096 bytes (64x64)")
	}

	var h [72]byte
	copy(h[:], header72)

	var m [64][64]byte
	for r := 0; r < 64; r++ {
		copy(m[r][:], matrix[r*64:(r+1)*64])
	}

	out := Hash(h, nonce, m)
	res := make([]byte, 32)
	copy(res, out[:])
	return res, nil
}
