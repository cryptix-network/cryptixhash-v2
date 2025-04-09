package pow

import (
	"math"
	"math/bits"

	"github.com/zeebo/blake3"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/hashes"
)

const eps float64 = 1e-9

type matrix [64][64]uint16

func generateMatrix(hash *externalapi.DomainHash) *matrix {
	var mat matrix
	generator := newxoShiRo256PlusPlus(hash)
	for {
		for i := range mat {
			for j := 0; j < 64; j += 16 {
				val := generator.Uint64()
				for shift := 0; shift < 16; shift++ {
					mat[i][j+shift] = uint16(val >> (4 * shift) & 0x0F)
				}
			}
		}
		if mat.computeRank() == 64 {
			return &mat
		}
	}
}

func (mat *matrix) computeRank() int {
	var B [64][64]float64
	for i := range B {
		for j := range B[0] {
			B[i][j] = float64(mat[i][j])
		}
	}
	var rank int
	var rowSelected [64]bool
	for i := 0; i < 64; i++ {
		var j int
		for j = 0; j < 64; j++ {
			if !rowSelected[j] && math.Abs(B[j][i]) > eps {
				break
			}
		}
		if j != 64 {
			rank++
			rowSelected[j] = true
			for p := i + 1; p < 64; p++ {
				B[j][p] /= B[j][i]
			}
			for k := 0; k < 64; k++ {
				if k != j && math.Abs(B[k][i]) > eps {
					for p := i + 1; p < 64; p++ {
						B[k][p] -= B[j][p] * B[k][i]
					}
				}
			}
		}
	}
	return rank
}

// ***Anti-FPGA Sidedoor***
func chaoticRandom(x uint32) uint32 {
	return (x * 362605) ^ 0xA5A5A5A5
}

func memoryIntensiveMix(seed uint32) uint32 {
	acc := seed
	for i := 0; i < 32; i++ {
		acc = (acc * 16625) ^ uint32(i)
	}
	return acc
}

func recursiveFibonacciModulated(x uint32, depth uint8) uint32 {
	a := uint32(1)
	b := x | 1
	actualDepth := depth
	if depth > 8 {
		actualDepth = 8
	}

	xMod := x
	for i := uint8(0); i < actualDepth; i++ {
		temp := b
		b = b + (a ^ bits.RotateLeft32(xMod, int(b%17)))
		a = temp
		xMod = rotateRight32(xMod, a%13) ^ b
	}

	return xMod
}

func rotateRight32(x uint32, n uint32) uint32 {
	return bits.RotateLeft32(x, -int(n))
}

func antiFPGAHash(input uint32) uint32 {
	x := input
	noise := memoryIntensiveMix(x)
	depth := uint8((noise & 0x0F) + 10)

	primeFactorSum := uint32(bits.OnesCount32(x))
	x ^= primeFactorSum

	x = recursiveFibonacciModulated(x^noise, depth)
	x ^= memoryIntensiveMix(bits.RotateLeft32(x, 9))

	return x
}

func computeAfterCompProduct(preCompProduct [32]byte) [32]byte {
	var afterCompProduct [32]byte

	for i := 0; i < 32; i++ {
		input := uint32(preCompProduct[i]) ^ (uint32(i) << 8)
		normalizedInput := input % 256
		modifiedInput := chaoticRandom(normalizedInput)

		hashed := antiFPGAHash(modifiedInput)
		afterCompProduct[i] = byte(hashed & 0xFF)
	}

	return afterCompProduct
}

// Otionion

// Octonion Multiply
func octonionMultiply(a, b [8]int64) [8]int64 {
	var result [8]int64

	// e0
	result[0] = a[0]*b[0] - a[1]*b[1] - a[2]*b[2] - a[3]*b[3] - a[4]*b[4] - a[5]*b[5] - a[6]*b[6] - a[7]*b[7]

	// e1
	result[1] = a[0]*b[1] + a[1]*b[0] + a[2]*b[3] - a[3]*b[2] + a[4]*b[5] - a[5]*b[4] - a[6]*b[7] + a[7]*b[6]

	// e2
	result[2] = a[0]*b[2] - a[1]*b[3] + a[2]*b[0] + a[3]*b[1] + a[4]*b[6] - a[5]*b[7] + a[6]*b[4] - a[7]*b[5]

	// e3
	result[3] = a[0]*b[3] + a[1]*b[2] - a[2]*b[1] + a[3]*b[0] + a[4]*b[7] + a[5]*b[6] - a[6]*b[5] + a[7]*b[4]

	// e4
	result[4] = a[0]*b[4] - a[1]*b[5] - a[2]*b[6] - a[3]*b[7] + a[4]*b[0] + a[5]*b[1] + a[6]*b[2] + a[7]*b[3]

	// e5
	result[5] = a[0]*b[5] + a[1]*b[4] - a[2]*b[7] + a[3]*b[6] - a[4]*b[1] + a[5]*b[0] + a[6]*b[3] + a[7]*b[2]

	// e6
	result[6] = a[0]*b[6] + a[1]*b[7] + a[2]*b[4] - a[3]*b[5] - a[4]*b[2] + a[5]*b[3] + a[6]*b[0] + a[7]*b[1]

	// e7
	result[7] = a[0]*b[7] - a[1]*b[6] + a[2]*b[5] + a[3]*b[4] - a[4]*b[3] + a[5]*b[2] + a[6]*b[1] + a[7]*b[0]

	return result
}

// RotateLeft
func rotateLeft(val byte, shift uint32) byte {
	return (val << shift) | (val >> (8 - shift))
}

// RotateRight
func rotateRight(val byte, shift uint32) byte {
	return (val >> shift) | (val << (8 - shift))
}

// Octonion Hash
func octonionHash(inputHash [32]byte) [8]int64 {
	var oct [8]int64

	for i := 0; i < 8; i++ {
		oct[i] = int64(inputHash[i])
	}

	for i := 8; i < len(inputHash); i++ {
		var rotation [8]int64
		for j := 0; j < 8; j++ {
			rotation[j] = int64(inputHash[(i+j)%32])
		}
		oct = octonionMultiply(oct, rotation)
	}

	return oct
}

func (mat *matrix) HeavyHash(hash *externalapi.DomainHash) *externalapi.DomainHash {
	hashBytes := hash.ByteArray()

	// Nibbles extraction
	var nibbles [64]uint16
	var product [32]byte
	var nibbleProduct [32]byte

	for i := 0; i < 32; i++ {
		nibbles[2*i] = uint16(hashBytes[i] >> 4)
		nibbles[2*i+1] = uint16(hashBytes[i] & 0x0F)
	}

	// Matrix and vector multiplication
	for i := 0; i < 32; i++ {
		var sum1, sum2, sum3, sum4 uint32
		for j := 0; j < 64; j++ {
			elem := nibbles[j]
			sum1 += uint32(mat[2*i][j]) * uint32(elem)
			sum2 += uint32(mat[2*i+1][j]) * uint32(elem)
			sum3 += uint32(mat[1*i+2][j]) * uint32(elem)
			sum4 += uint32(mat[1*i+3][j]) * uint32(elem)
		}

		// Nibble calculations
		aNibble := (sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum3 >> 8) & 0xF) ^
			((sum1*0xABCD)>>12)&0xF ^
			((sum1*0x1234)>>8)&0xF ^
			((sum2*0x5678)>>16)&0xF ^
			((sum3*0x9ABC)>>4)&0xF ^
			((sum1 << 3) & 0xF) ^ (sum3>>5)&0xF

		bNibble := (sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum4 >> 8) & 0xF) ^
			((sum2*0xDCBA)>>14)&0xF ^
			((sum2*0x8765)>>10)&0xF ^
			((sum1*0x4321)>>6)&0xF ^
			((sum4<<2)^sum1>>1)&0xF

		cNibble := (sum3 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF) ^
			((sum3*0xF135)>>10)&0xF ^
			((sum3*0x2468)>>12)&0xF ^
			((sum4*0xACEF)>>8)&0xF ^
			((sum2*0x1357)>>4)&0xF ^
			((sum3 << 5) & 0xF) ^ (sum1>>7)&0xF

		dNibble := (sum1 & 0xF) ^ ((sum4 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF) ^
			((sum4*0x57A3)>>6)&0xF ^
			((sum3*0xD4E3)>>12)&0xF ^
			((sum1*0x9F8B)>>10)&0xF ^
			((sum4<<4)^sum1+sum2)&0xF

		nibbleProduct[i] = byte((cNibble << 4) | dNibble)
		product[i] = byte((aNibble << 4) | bNibble)
	}

	// XOR with original hash
	for i := 0; i < 32; i++ {
		product[i] ^= hashBytes[i]
		nibbleProduct[i] ^= hashBytes[i]
	}

	// Octonion transformation
	var productBeforeOct [32]byte
	copy(productBeforeOct[:], product[:32])

	octonionResult := octonionHash(product)

	for i := 0; i < 32; i++ {
		octValue := octonionResult[i/8]
		octValueU8 := byte((octValue >> (8 * (i % 8))) & 0xFF)
		product[i] ^= octValueU8
	}

	// S-Box Array
	var sbox [256]byte

	// Generation
	for i := 0; i < 256; i++ {
		var sourceArray []byte
		var rotateLeftVal, rotateRightVal byte

		switch {
		case i < 16:
			sourceArray = product[:]
			rotateLeftVal = byte((nibbleProduct[3] ^ 0x4F) * 3)
			rotateRightVal = byte((hashBytes[2] ^ 0xD3) * 5)
		case i < 32:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((product[7] ^ 0xA6) * 2)
			rotateRightVal = byte((nibbleProduct[5] ^ 0x5B) * 7)
		case i < 48:
			sourceArray = nibbleProduct[:]
			rotateLeftVal = byte((productBeforeOct[1] ^ 0x9C) * 9)
			rotateRightVal = byte((product[0] ^ 0x8E) * 3)
		case i < 64:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((product[6] ^ 0x71) * 4)
			rotateRightVal = byte((productBeforeOct[3] ^ 0x2F) * 5)
		case i < 80:
			sourceArray = productBeforeOct[:]
			rotateLeftVal = byte((nibbleProduct[4] ^ 0xB2) * 3)
			rotateRightVal = byte((hashBytes[7] ^ 0x6D) * 7)
		case i < 96:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((product[0] ^ 0x58) * 6)
			rotateRightVal = byte((nibbleProduct[1] ^ 0xEE) * 9)
		case i < 112:
			sourceArray = product[:]
			rotateLeftVal = byte((productBeforeOct[2] ^ 0x37) * 2)
			rotateRightVal = byte((hashBytes[6] ^ 0x44) * 6)
		case i < 128:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((product[5] ^ 0x1A) * 5)
			rotateRightVal = byte((hashBytes[4] ^ 0x7C) * 8)
		case i < 144:
			sourceArray = productBeforeOct[:]
			rotateLeftVal = byte((nibbleProduct[3] ^ 0x93) * 7)
			rotateRightVal = byte((product[2] ^ 0xAF) * 3)
		case i < 160:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((product[7] ^ 0x29) * 9)
			rotateRightVal = byte((nibbleProduct[5] ^ 0xDC) * 2)
		case i < 176:
			sourceArray = nibbleProduct[:]
			rotateLeftVal = byte((productBeforeOct[1] ^ 0x4E) * 4)
			rotateRightVal = byte((hashBytes[0] ^ 0x8B) * 3)
		case i < 192:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((nibbleProduct[6] ^ 0xF3) * 5)
			rotateRightVal = byte((productBeforeOct[3] ^ 0x62) * 8)
		case i < 208:
			sourceArray = productBeforeOct[:]
			rotateLeftVal = byte((product[4] ^ 0xB7) * 6)
			rotateRightVal = byte((product[7] ^ 0x15) * 2)
		case i < 224:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((product[0] ^ 0x2D) * 8)
			rotateRightVal = byte((productBeforeOct[1] ^ 0xC8) * 7)
		case i < 240:
			sourceArray = product[:]
			rotateLeftVal = byte((productBeforeOct[2] ^ 0x6F) * 3)
			rotateRightVal = byte((nibbleProduct[6] ^ 0x99) * 9)
		default:
			sourceArray = hashBytes[:]
			rotateLeftVal = byte((nibbleProduct[5] ^ 0xE1) * 7)
			rotateRightVal = byte((hashBytes[4] ^ 0x3B) * 5)
		}

		var value byte
		switch {
		case i < 16:
			value = (product[i%32] ^ 0x03 + byte(i) ^ 0xAA) & 0xFF
		case i < 32:
			value = (hashBytes[(i-16)%32] ^ 0x05 + byte(i-16) ^ 0xBB) & 0xFF
		case i < 48:
			value = (productBeforeOct[(i-32)%32] ^ 0x07 + byte(i-32) ^ 0xCC) & 0xFF
		case i < 64:
			value = (nibbleProduct[(i-48)%32] ^ 0x0F + byte(i-48) ^ 0xDD) & 0xFF
		case i < 80:
			value = (product[(i-64)%32] ^ 0x11 + byte(i-64) ^ 0xEE) & 0xFF
		case i < 96:
			value = (hashBytes[(i-80)%32] ^ 0x13 + byte(i-80) ^ 0xFF) & 0xFF
		case i < 112:
			value = (productBeforeOct[(i-96)%32] ^ 0x17 + byte(i-96) ^ 0x11) & 0xFF
		case i < 128:
			value = (nibbleProduct[(i-112)%32] ^ 0x19 + byte(i-112) ^ 0x22) & 0xFF
		case i < 144:
			value = (product[(i-128)%32] ^ 0x1D + byte(i-128) ^ 0x33) & 0xFF
		case i < 160:
			value = (hashBytes[(i-144)%32] ^ 0x1F + byte(i-144) ^ 0x44) & 0xFF
		case i < 176:
			value = (productBeforeOct[(i-160)%32] ^ 0x23 + byte(i-160) ^ 0x55) & 0xFF
		case i < 192:
			value = (nibbleProduct[(i-176)%32] ^ 0x29 + byte(i-176) ^ 0x66) & 0xFF
		case i < 208:
			value = (product[(i-192)%32] ^ 0x2F + byte(i-192) ^ 0x77) & 0xFF
		case i < 224:
			value = (hashBytes[(i-208)%32] ^ 0x31 + byte(i-208) ^ 0x88) & 0xFF
		case i < 240:
			value = (productBeforeOct[(i-224)%32] ^ 0x37 + byte(i-224) ^ 0x99) & 0xFF
		default:
			value = (nibbleProduct[(i-240)%32] ^ 0x3F + byte(i-240) ^ 0xAA) & 0xFF
		}

		rotateLeftShift := (product[(i+1)%32] + byte(i)) % 8
		rotateRightShift := (hashBytes[(i+2)%32] + byte(i)) % 8

		rotationLeft := rotateLeftVal << rotateLeftShift
		rotationRight := rotateRightVal >> rotateRightShift

		index := (i + int(rotationLeft) + int(rotationRight)) % len(sourceArray)
		sbox[i] = sourceArray[index] ^ value
	}

	index := int((productBeforeOct[2] % 8) + 1)
	iterations := 1 + int(product[index]%2)

	// S-Box Update
	for iter := 0; iter < iterations; iter++ {
		tempSbox := sbox

		for i := 0; i < 256; i++ {
			value := tempSbox[i]
			rotateLeftShift := (uint32(product[(i+1)%len(product)]) + uint32(i) + uint32(i*3)) % 8
			rotateRightShift := (uint32(hashBytes[(i+2)%len(hashBytes)]) + uint32(i) + uint32(i*5)) % 8
			rotatedValue := rotateLeft(value, rotateLeftShift) | rotateRight(value, rotateRightShift)

			baseValue := byte(i) + (product[(i*3)%len(product)] ^ hashBytes[(i*7)%len(hashBytes)]) ^ 0xA5
			shiftedValue := rotateLeft(baseValue, uint32(i%8))
			xorValue := shiftedValue ^ 0x55

			value ^= rotatedValue ^ xorValue
			tempSbox[i] = value
		}

		sbox = tempSbox
	}

	// BLAKE3 Hashing Chain
	indexBlake := int((productBeforeOct[5] % 8) + 1)
	iterationsBlake := 1 + int(product[indexBlake]%3)

	var b3HashArray [32]byte
	copy(b3HashArray[:], product[:])
	for i := 0; i < iterationsBlake; i++ {
		hasher := blake3.New()
		hasher.Write(b3HashArray[:])
		sum := hasher.Sum(nil)
		copy(b3HashArray[:], sum[:32])
	}

	// After-Compression Product
	afterCompProduct := computeAfterCompProduct(productBeforeOct)

	// S-Box XOR
	for i := 0; i < 32; i++ {
		var refArray []byte
		switch (i * 31) % 4 {
		case 0:
			refArray = nibbleProduct[:]
		case 1:
			refArray = hashBytes[:]
		case 2:
			refArray = product[:]
		default:
			refArray = productBeforeOct[:]
		}

		byteVal := int(refArray[(i*13)%len(refArray)])
		index := (byteVal + int(product[(i*31)%len(product)]) + int(hashBytes[(i*19)%len(hashBytes)]) + i*41) % 256

		b3HashArray[i] ^= sbox[index]
	}

	// Finales XOR
	for i := 0; i < 32; i++ {
		b3HashArray[i] ^= afterCompProduct[i]
	}

	// Hash again
	writer := hashes.NewHeavyHashWriter()
	writer.InfallibleWrite(b3HashArray[:])
	return writer.Finalize()
}
