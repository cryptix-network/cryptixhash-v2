package pow

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/hashes"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/serialization"
	"github.com/cryptix-network/cryptixd/util/difficulty"

	"math/big"
	"math/bits"

	"golang.org/x/crypto/sha3"
)

// State is an intermediate data structure with pre-computed values to speed up mining.
type State struct {
	mat        matrix
	Timestamp  int64
	Nonce      uint64
	Target     big.Int
	prePowHash externalapi.DomainHash
}

// NewState creates a new state with pre-computed values to speed up mining
// It takes the target from the Bits field
func NewState(header externalapi.MutableBlockHeader) *State {
	target := difficulty.CompactToBig(header.Bits())
	// Zero out the time and nonce.
	timestamp, nonce := header.TimeInMilliseconds(), header.Nonce()
	header.SetTimeInMilliseconds(0)
	header.SetNonce(0)
	prePowHash := consensushashing.HeaderHash(header)
	header.SetTimeInMilliseconds(timestamp)
	header.SetNonce(nonce)

	return &State{
		Target:     *target,
		prePowHash: *prePowHash,
		mat:        *generateMatrix(prePowHash),
		Timestamp:  timestamp,
		Nonce:      nonce,
	}
}

func (state *State) CalculateProofOfWorkValue() *big.Int {
	writer := hashes.NewPoWHashWriter()
	writer.InfallibleWrite(state.prePowHash.ByteSlice())

	err := serialization.WriteElement(writer, state.Timestamp)
	if err != nil {
		panic(err)
	}

	zeroes := [32]byte{}
	writer.InfallibleWrite(zeroes[:])

	err = serialization.WriteElement(writer, state.Nonce)
	if err != nil {
		panic(err)
	}

	initialHash := writer.Finalize()
	hashBytes := initialHash.ByteSlice()
	if len(hashBytes) != 32 {
		panic("expected 32-byte hash")
	}

	iterations := int(hashBytes[0]%2) + 1
	currentHash := make([]byte, 32)
	copy(currentHash, hashBytes)

	sha3Hasher := sha3.New256()

	for i := 0; i < iterations; i++ {
		sha3Hasher.Reset()
		sha3Hasher.Write(currentHash)
		newHash := sha3Hasher.Sum(nil)
		copy(currentHash, newHash)

		cond1 := currentHash[1]%4 == 0
		cond2 := currentHash[3]%3 == 0
		cond3 := currentHash[2]%6 == 0
		cond4 := currentHash[7]%5 == 0
		cond5 := currentHash[8]%7 == 0

		switch {
		case cond1:
			repeat := int(currentHash[2]%4) + 1
			for r := 0; r < repeat; r++ {
				targetByte := ((int(currentHash[1]) + i) % 32)
				xorVal := currentHash[i%16] ^ 0xA5
				currentHash[targetByte] ^= xorVal

				rotationByte := currentHash[i%32]
				rotationAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) % 4) + 2
				if rotationByte%2 == 0 {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], int(rotationAmount))
				} else {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], -int(rotationAmount))
				}

				shiftAmount := ((uint32(currentHash[5]) + uint32(currentHash[1])) % 3) + 1
				currentHash[targetByte] ^= bits.RotateLeft8(currentHash[targetByte], int(shiftAmount))
			}

		case cond2:
			repeat := int(currentHash[4]%5) + 1
			for r := 0; r < repeat; r++ {
				targetByte := ((int(currentHash[6]) + i) % 32)
				xorVal := currentHash[i%16] ^ 0x55
				currentHash[targetByte] ^= xorVal

				rotationByte := currentHash[i%32]
				rotationAmount := ((uint32(currentHash[7]) + uint32(currentHash[2])) % 6) + 1
				if rotationByte%2 == 0 {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], int(rotationAmount))
				} else {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], -int(rotationAmount))
				}

				shiftAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) % 4) + 1
				currentHash[targetByte] ^= bits.RotateLeft8(currentHash[targetByte], int(shiftAmount))
			}

		case cond3:
			repeat := int(currentHash[6]%4) + 1
			for r := 0; r < repeat; r++ {
				targetByte := ((int(currentHash[10]) + i) % 32)
				xorVal := currentHash[i%16] ^ 0xFF
				currentHash[targetByte] ^= xorVal

				rotationByte := currentHash[i%32]
				rotationAmount := ((uint32(currentHash[7]) * 2) % 7) + 1
				if rotationByte%2 == 0 {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], int(rotationAmount))
				} else {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], -int(rotationAmount))
				}

				shiftAmount := ((uint32(currentHash[3]) + uint32(currentHash[5])) % 5) + 2
				currentHash[targetByte] ^= bits.RotateLeft8(currentHash[targetByte], int(shiftAmount))
			}

		case cond4:
			repeat := int(currentHash[8]%4) + 1
			for r := 0; r < repeat; r++ {
				targetByte := ((int(currentHash[25]) + i) % 32)
				xorVal := currentHash[i%16] ^ 0x66
				currentHash[targetByte] ^= xorVal

				rotationByte := currentHash[i%32]
				rotationAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) % 4) + 2
				if rotationByte%2 == 0 {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], int(rotationAmount))
				} else {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], -int(rotationAmount))
				}

				shiftAmount := ((uint32(currentHash[1]) + uint32(currentHash[3])) % 4) + 1
				currentHash[targetByte] ^= bits.RotateLeft8(currentHash[targetByte], int(shiftAmount))
			}

		case cond5:
			repeat := int(currentHash[9]%5) + 1
			for r := 0; r < repeat; r++ {
				targetByte := ((int(currentHash[30]) + i) % 32)
				xorVal := currentHash[i%16] ^ 0x77
				currentHash[targetByte] ^= xorVal

				rotationByte := currentHash[i%32]
				rotationAmount := ((uint32(currentHash[2]) + uint32(currentHash[5])) % 5) + 1
				if rotationByte%2 == 0 {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], int(rotationAmount))
				} else {
					currentHash[targetByte] = bits.RotateLeft8(currentHash[targetByte], -int(rotationAmount))
				}

				shiftAmount := ((uint32(currentHash[7]) + uint32(currentHash[9])) % 6) + 2
				currentHash[targetByte] ^= bits.RotateLeft8(currentHash[targetByte], int(shiftAmount))
			}
		}
	}

	finalDomainHash, err := externalapi.NewDomainHashFromByteSlice(currentHash)
	if err != nil {
		panic(err)
	}

	heavyHash := state.mat.HeavyHash(finalDomainHash)
	return toBig(heavyHash)
}

// IncrementNonce the nonce in State by 1
func (state *State) IncrementNonce() {
	state.Nonce++
}

// CheckProofOfWork check's if the block has a valid PoW according to the provided target
// it does not check if the difficulty itself is valid or less than the maximum for the appropriate network
func (state *State) CheckProofOfWork() bool {
	// The block pow must be less than the claimed target
	powNum := state.CalculateProofOfWorkValue()

	// The block hash must be less or equal than the claimed target.
	return powNum.Cmp(&state.Target) <= 0
}

// CheckProofOfWorkByBits check's if the block has a valid PoW according to its Bits field
// it does not check if the difficulty itself is valid or less than the maximum for the appropriate network
func CheckProofOfWorkByBits(header externalapi.MutableBlockHeader) bool {
	return NewState(header).CheckProofOfWork()
}

// ToBig converts a externalapi.DomainHash into a big.Int treated as a little endian string.
func toBig(hash *externalapi.DomainHash) *big.Int {
	// We treat the Hash as little-endian for PoW purposes, but the big package wants the bytes in big-endian, so reverse them.
	buf := hash.ByteSlice()
	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}

	return new(big.Int).SetBytes(buf)
}

// BlockLevel returns the block level of the given header.
func BlockLevel(header externalapi.BlockHeader, maxBlockLevel int) int {
	// Genesis is defined to be the root of all blocks at all levels, so we define it to be the maximal
	// block level.
	if len(header.DirectParents()) == 0 {
		return maxBlockLevel
	}

	proofOfWorkValue := NewState(header.ToMutable()).CalculateProofOfWorkValue()
	level := maxBlockLevel - proofOfWorkValue.BitLen()
	// If the block has a level lower than genesis make it zero.
	if level < 0 {
		level = 0
	}
	return level
}
