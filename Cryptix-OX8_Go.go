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

// Heavyhash.go here