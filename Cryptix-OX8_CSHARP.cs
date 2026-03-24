using System;

namespace CryptixOx8Standalone
{
    public static class CryptixOx8
    {
        private static readonly ulong[] PowHashInitialState =
        {
            1242148031264380989UL, 3008272977830772284UL, 2188519011337848018UL, 1992179434288343456UL,
            8876506674959887717UL, 5399642050693751366UL, 1745875063082670864UL, 8605242046444978844UL,
            17936695144567157056UL, 3343109343542796272UL, 1123092876221303306UL, 4963925045340115282UL,
            17037383077651887893UL, 16629644495023626889UL, 12833675776649114147UL, 3784524041015224902UL,
            1082795874807940378UL, 13952716920571277634UL, 13411128033953605860UL, 15060696040649351053UL,
            9928834659948351306UL, 5237849264682708699UL, 12825353012139217522UL, 6706187291358897596UL,
            196324915476054915UL
        };

        private static readonly ulong[] HeavyHashInitialState =
        {
            4239941492252378377UL, 8746723911537738262UL, 8796936657246353646UL, 1272090201925444760UL,
            16654558671554924250UL, 8270816933120786537UL, 13907396207649043898UL, 6782861118970774626UL,
            9239690602118867528UL, 11582319943599406348UL, 17596056728278508070UL, 15212962468105129023UL,
            7812475424661425213UL, 3370482334374859748UL, 5690099369266491460UL, 8596393687355028144UL,
            570094237299545110UL, 9119540418498120711UL, 16901969272480492857UL, 13372017233735502424UL,
            14372891883993151831UL, 5171152063242093102UL, 10573107899694386186UL, 6096431547456407061UL,
            1592359455985097269UL
        };

        private static readonly byte[] SboxSourceSelectors = { 0, 1, 2, 1, 3, 1, 0, 1, 3, 1, 2, 1, 3, 1, 0, 1 };
        private static readonly byte[] SboxValueSelectors = { 0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 2 };
        private static readonly byte[] SboxValueMultipliers = { 0x03, 0x05, 0x07, 0x0F, 0x11, 0x13, 0x17, 0x19, 0x1D, 0x1F, 0x23, 0x29, 0x2F, 0x31, 0x37, 0x3F };
        private static readonly byte[] SboxValueAdders = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA };

        private static readonly ulong[] KeccakRndc =
        {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
            0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
            0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
            0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        private static readonly uint[] KeccakPiLanes = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };
        private static readonly uint[] KeccakRhoPiRot = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };

        private static readonly uint[] Blake3IV = { 0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U };
        private static readonly uint[] Blake3MsgPermutation = { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

        private static readonly byte[] AfterCompLut =
        {
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

        private static byte Rotl8(byte v, uint s)
        {
            s &= 7U;
            return (byte)((v << (int)s) | (v >> (int)((8U - s) & 7U)));
        }

        private static byte Rotr8(byte v, uint s)
        {
            s &= 7U;
            return (byte)((v >> (int)s) | (v << (int)((8U - s) & 7U)));
        }

        private static uint Rotl32(uint v, uint s)
        {
            s &= 31U;
            return (v << (int)s) | (v >> (int)((32U - s) & 31U));
        }

        private static uint Rotr32(uint v, uint s)
        {
            s &= 31U;
            return (v >> (int)s) | (v << (int)((32U - s) & 31U));
        }

        private static ulong Rotl64(ulong v, uint s)
        {
            s &= 63U;
            return (v << (int)s) | (v >> (int)((64U - s) & 63U));
        }

        private static ulong Load64Le(byte[] input, int offset)
        {
            unchecked
            {
                return (ulong)input[offset + 0]
                     | ((ulong)input[offset + 1] << 8)
                     | ((ulong)input[offset + 2] << 16)
                     | ((ulong)input[offset + 3] << 24)
                     | ((ulong)input[offset + 4] << 32)
                     | ((ulong)input[offset + 5] << 40)
                     | ((ulong)input[offset + 6] << 48)
                     | ((ulong)input[offset + 7] << 56);
            }
        }

        private static uint Load32Le(byte[] input, int offset)
        {
            unchecked
            {
                return (uint)input[offset + 0]
                     | ((uint)input[offset + 1] << 8)
                     | ((uint)input[offset + 2] << 16)
                     | ((uint)input[offset + 3] << 24);
            }
        }

        private static void Store64Le(ulong value, byte[] output, int offset)
        {
            output[offset + 0] = (byte)value;
            output[offset + 1] = (byte)(value >> 8);
            output[offset + 2] = (byte)(value >> 16);
            output[offset + 3] = (byte)(value >> 24);
            output[offset + 4] = (byte)(value >> 32);
            output[offset + 5] = (byte)(value >> 40);
            output[offset + 6] = (byte)(value >> 48);
            output[offset + 7] = (byte)(value >> 56);
        }

        private static void Store32Le(uint value, byte[] output, int offset)
        {
            output[offset + 0] = (byte)value;
            output[offset + 1] = (byte)(value >> 8);
            output[offset + 2] = (byte)(value >> 16);
            output[offset + 3] = (byte)(value >> 24);
        }

        private static ulong Mul64ByU8(ulong a, byte b)
        {
            unchecked { return a * b; }
        }

        private static uint Dot4Acc(uint sum, byte[] flat, int idx, uint n0, uint n1, uint n2, uint n3)
        {
            unchecked
            {
                return sum
                    + (uint)flat[idx + 0] * n0
                    + (uint)flat[idx + 1] * n1
                    + (uint)flat[idx + 2] * n2
                    + (uint)flat[idx + 3] * n3;
            }
        }

        private static void KeccakF1600(ulong[] st)
        {
            for (uint round = 0; round < 24; round++)
            {
                ulong c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
                ulong c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
                ulong c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
                ulong c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
                ulong c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

                ulong d0 = c4 ^ Rotl64(c1, 1);
                ulong d1 = c0 ^ Rotl64(c2, 1);
                ulong d2 = c1 ^ Rotl64(c3, 1);
                ulong d3 = c2 ^ Rotl64(c4, 1);
                ulong d4 = c3 ^ Rotl64(c0, 1);

                st[0] ^= d0; st[5] ^= d0; st[10] ^= d0; st[15] ^= d0; st[20] ^= d0;
                st[1] ^= d1; st[6] ^= d1; st[11] ^= d1; st[16] ^= d1; st[21] ^= d1;
                st[2] ^= d2; st[7] ^= d2; st[12] ^= d2; st[17] ^= d2; st[22] ^= d2;
                st[3] ^= d3; st[8] ^= d3; st[13] ^= d3; st[18] ^= d3; st[23] ^= d3;
                st[4] ^= d4; st[9] ^= d4; st[14] ^= d4; st[19] ^= d4; st[24] ^= d4;

                ulong t = st[1];
                for (uint i = 0; i < 24; i++)
                {
                    uint lane = KeccakPiLanes[i];
                    ulong next = st[lane];
                    st[lane] = Rotl64(t, KeccakRhoPiRot[i]);
                    t = next;
                }

                for (int row = 0; row < 25; row += 5)
                {
                    ulong r0 = st[row + 0];
                    ulong r1 = st[row + 1];
                    ulong r2 = st[row + 2];
                    ulong r3 = st[row + 3];
                    ulong r4 = st[row + 4];
                    st[row + 0] = r0 ^ ((~r1) & r2);
                    st[row + 1] = r1 ^ ((~r2) & r3);
                    st[row + 2] = r2 ^ ((~r3) & r4);
                    st[row + 3] = r3 ^ ((~r4) & r0);
                    st[row + 4] = r4 ^ ((~r0) & r1);
                }

                st[0] ^= KeccakRndc[round];
            }
        }

        private static byte[] Sha3_256_32bytes(byte[] input)
        {
            ulong[] st = new ulong[25];
            st[0] ^= Load64Le(input, 0);
            st[1] ^= Load64Le(input, 8);
            st[2] ^= Load64Le(input, 16);
            st[3] ^= Load64Le(input, 24);
            st[4] ^= 0x06UL;
            st[16] ^= (0x80UL << 56);
            KeccakF1600(st);

            byte[] output = new byte[32];
            Store64Le(st[0], output, 0);
            Store64Le(st[1], output, 8);
            Store64Le(st[2], output, 16);
            Store64Le(st[3], output, 24);
            return output;
        }

        private static ulong[] OctonionHash(byte[] inputHash)
        {
            ulong a0 = inputHash[0], a1 = inputHash[1], a2 = inputHash[2], a3 = inputHash[3];
            ulong a4 = inputHash[4], a5 = inputHash[5], a6 = inputHash[6], a7 = inputHash[7];
            byte b0 = inputHash[8], b1 = inputHash[9], b2 = inputHash[10], b3 = inputHash[11];
            byte b4 = inputHash[12], b5 = inputHash[13], b6 = inputHash[14], b7 = inputHash[15];

            for (int i = 8; i < 32; i++)
            {
                ulong r0 = Mul64ByU8(a0, b0) - Mul64ByU8(a1, b1) - Mul64ByU8(a2, b2) - Mul64ByU8(a3, b3) - Mul64ByU8(a4, b4) - Mul64ByU8(a5, b5) - Mul64ByU8(a6, b6) - Mul64ByU8(a7, b7);
                ulong r1 = Mul64ByU8(a0, b1) + Mul64ByU8(a1, b0) + Mul64ByU8(a2, b3) - Mul64ByU8(a3, b2) + Mul64ByU8(a4, b5) - Mul64ByU8(a5, b4) - Mul64ByU8(a6, b7) + Mul64ByU8(a7, b6);
                ulong r2 = Mul64ByU8(a0, b2) - Mul64ByU8(a1, b3) + Mul64ByU8(a2, b0) + Mul64ByU8(a3, b1) + Mul64ByU8(a4, b6) - Mul64ByU8(a5, b7) + Mul64ByU8(a6, b4) - Mul64ByU8(a7, b5);
                ulong r3 = Mul64ByU8(a0, b3) + Mul64ByU8(a1, b2) - Mul64ByU8(a2, b1) + Mul64ByU8(a3, b0) + Mul64ByU8(a4, b7) + Mul64ByU8(a5, b6) - Mul64ByU8(a6, b5) + Mul64ByU8(a7, b4);
                ulong r4 = Mul64ByU8(a0, b4) - Mul64ByU8(a1, b5) - Mul64ByU8(a2, b6) - Mul64ByU8(a3, b7) + Mul64ByU8(a4, b0) + Mul64ByU8(a5, b1) + Mul64ByU8(a6, b2) + Mul64ByU8(a7, b3);
                ulong r5 = Mul64ByU8(a0, b5) + Mul64ByU8(a1, b4) - Mul64ByU8(a2, b7) + Mul64ByU8(a3, b6) - Mul64ByU8(a4, b1) + Mul64ByU8(a5, b0) + Mul64ByU8(a6, b3) + Mul64ByU8(a7, b2);
                ulong r6 = Mul64ByU8(a0, b6) + Mul64ByU8(a1, b7) + Mul64ByU8(a2, b4) - Mul64ByU8(a3, b5) - Mul64ByU8(a4, b2) + Mul64ByU8(a5, b3) + Mul64ByU8(a6, b0) + Mul64ByU8(a7, b1);
                ulong r7 = Mul64ByU8(a0, b7) - Mul64ByU8(a1, b6) + Mul64ByU8(a2, b5) + Mul64ByU8(a3, b4) - Mul64ByU8(a4, b3) + Mul64ByU8(a5, b2) + Mul64ByU8(a6, b1) + Mul64ByU8(a7, b0);

                a0 = r0; a1 = r1; a2 = r2; a3 = r3; a4 = r4; a5 = r5; a6 = r6; a7 = r7;

                if (i < 31)
                {
                    b0 = b1; b1 = b2; b2 = b3; b3 = b4;
                    b4 = b5; b5 = b6; b6 = b7;
                    b7 = inputHash[(i + 8) & 31];
                }
            }

            return new[] { a0, a1, a2, a3, a4, a5, a6, a7 };
        }

        private static void Blake3Permute(uint[] m)
        {
            uint[] p = new uint[16];
            for (int i = 0; i < 16; i++) p[i] = m[Blake3MsgPermutation[i]];
            Array.Copy(p, m, 16);
        }

        private static void Blake3G(uint[] v, int a, int b, int c, int d, uint mx, uint my)
        {
            unchecked
            {
                v[a] = v[a] + v[b] + mx;
                v[d] = Rotr32(v[d] ^ v[a], 16);
                v[c] = v[c] + v[d];
                v[b] = Rotr32(v[b] ^ v[c], 12);
                v[a] = v[a] + v[b] + my;
                v[d] = Rotr32(v[d] ^ v[a], 8);
                v[c] = v[c] + v[d];
                v[b] = Rotr32(v[b] ^ v[c], 7);
            }
        }

        private static void Blake3Round(uint[] v, uint[] m)
        {
            Blake3G(v, 0, 4, 8, 12, m[0], m[1]);
            Blake3G(v, 1, 5, 9, 13, m[2], m[3]);
            Blake3G(v, 2, 6, 10, 14, m[4], m[5]);
            Blake3G(v, 3, 7, 11, 15, m[6], m[7]);
            Blake3G(v, 0, 5, 10, 15, m[8], m[9]);
            Blake3G(v, 1, 6, 11, 12, m[10], m[11]);
            Blake3G(v, 2, 7, 8, 13, m[12], m[13]);
            Blake3G(v, 3, 4, 9, 14, m[14], m[15]);
        }

        private static byte[] Blake3Compress32(byte[] input)
        {
            uint[] m = new uint[16];
            uint[] v = new uint[16];
            for (int i = 0; i < 8; i++)
            {
                m[i] = Load32Le(input, i * 4);
                v[i] = Blake3IV[i];
            }

            v[8] = Blake3IV[0]; v[9] = Blake3IV[1]; v[10] = Blake3IV[2]; v[11] = Blake3IV[3];
            v[12] = 0; v[13] = 0; v[14] = 32; v[15] = 1 | 2 | 8;

            for (int round = 0; round < 7; round++)
            {
                Blake3Round(v, m);
                if (round + 1 < 7) Blake3Permute(m);
            }

            byte[] output = new byte[32];
            for (int i = 0; i < 8; i++) Store32Le(v[i] ^ v[i + 8], output, i * 4);
            return output;
        }

        private static byte[] CryptixHashV2Hash(byte[] input)
        {
            ulong[] st = new ulong[25];
            Array.Copy(HeavyHashInitialState, st, 25);
            st[0] ^= Load64Le(input, 0);
            st[1] ^= Load64Le(input, 8);
            st[2] ^= Load64Le(input, 16);
            st[3] ^= Load64Le(input, 24);
            KeccakF1600(st);

            byte[] output = new byte[32];
            Store64Le(st[0], output, 0);
            Store64Le(st[1], output, 8);
            Store64Le(st[2], output, 16);
            Store64Le(st[3], output, 24);
            return output;
        }

        private static byte PickRefValue(byte refType, uint idx, byte[] nibbleProduct, byte[] productBeforeOct, byte[] product, byte[] hashBytes)
        {
            return refType switch
            {
                0 => nibbleProduct[idx],
                1 => productBeforeOct[idx],
                2 => product[idx],
                _ => hashBytes[idx],
            };
        }

        private static byte PickArrayByte(byte selector, uint idx, byte[] product, byte[] hashBytes, byte[] nibbleProduct, byte[] productBeforeOct)
        {
            return selector switch
            {
                0 => product[idx],
                1 => hashBytes[idx],
                2 => nibbleProduct[idx],
                _ => productBeforeOct[idx],
            };
        }

        private static byte ComputeSboxEntry(uint sboxIdx, byte[] rotateLeftBases, byte[] rotateRightBases, byte[] product, byte[] hashBytes, byte[] nibbleProduct, byte[] productBeforeOct, uint sboxIterations)
        {
            uint segment = sboxIdx >> 4;
            uint lane = sboxIdx & 15;
            byte p1 = product[(sboxIdx + 1) & 31];
            byte h2 = hashBytes[(sboxIdx + 2) & 31];

            byte value = unchecked((byte)(
                PickArrayByte(SboxValueSelectors[segment], lane, product, hashBytes, nibbleProduct, productBeforeOct) * SboxValueMultipliers[segment] +
                (byte)lane * SboxValueAdders[segment]));

            byte rotationLeft = Rotl8(rotateLeftBases[segment], (uint)(p1 + sboxIdx) & 7);
            byte rotationRight = Rotr8(rotateRightBases[segment], (uint)(h2 + sboxIdx) & 7);
            uint sourceIndex = (sboxIdx + rotationLeft + rotationRight) & 31;
            value ^= PickArrayByte(SboxSourceSelectors[segment], sourceIndex, product, hashBytes, nibbleProduct, productBeforeOct);

            uint rotateLeftShift2 = (uint)(p1 + (sboxIdx << 2)) & 7;
            uint rotateRightShift2 = (uint)(h2 + (sboxIdx * 6)) & 7;
            byte baseValue = (byte)(((byte)(sboxIdx + (product[(sboxIdx * 3) & 31] ^ hashBytes[(sboxIdx * 7) & 31])) ^ 0xA5));
            byte xorValue = (byte)(Rotl8(baseValue, sboxIdx & 7) ^ 0x55);

            byte rotatedValue = (byte)(Rotl8(value, rotateLeftShift2) | Rotr8(value, rotateRightShift2));
            value ^= (byte)(rotatedValue ^ xorValue);
            if (sboxIterations == 2)
            {
                rotatedValue = (byte)(Rotl8(value, rotateLeftShift2) | Rotr8(value, rotateRightShift2));
                value ^= (byte)(rotatedValue ^ xorValue);
            }

            return value;
        }

        private static byte[] CryptixHashMatrix(byte[] matrixFlat, byte[] hashBytes)
        {
            byte[] product = new byte[32];
            byte[] nibbleProduct = new byte[32];

            uint rowPtr0 = 0, rowPtr1 = 64, rowPtr2 = 128, rowPtr3 = 192;

            for (uint i = 0; i < 32; i++)
            {
                uint sum1 = 0, sum2 = 0, sum3 = 0, sum4 = 0;

                for (uint block = 0; block < 16; block++)
                {
                    uint hidx = block << 1;
                    byte hb0 = hashBytes[hidx];
                    byte hb1 = hashBytes[hidx + 1];
                    uint n0 = (uint)(hb0 >> 4);
                    uint n1 = (uint)(hb0 & 0x0F);
                    uint n2 = (uint)(hb1 >> 4);
                    uint n3 = (uint)(hb1 & 0x0F);

                    uint off = block << 2;
                    sum1 = Dot4Acc(sum1, matrixFlat, (int)(rowPtr0 + off), n0, n1, n2, n3);
                    sum2 = Dot4Acc(sum2, matrixFlat, (int)(rowPtr1 + off), n0, n1, n2, n3);
                    sum3 = Dot4Acc(sum3, matrixFlat, (int)(rowPtr2 + off), n0, n1, n2, n3);
                    sum4 = Dot4Acc(sum4, matrixFlat, (int)(rowPtr3 + off), n0, n1, n2, n3);
                }

                rowPtr0 += 128;
                rowPtr1 += 128;
                rowPtr2 += 64;
                rowPtr3 += 64;

                uint aNibble = unchecked((sum1 & 0xFU)
                    ^ ((sum2 >> 4) & 0xFU)
                    ^ ((sum3 >> 8) & 0xFU)
                    ^ ((sum1 * 0xABCDU >> 12) & 0xFU)
                    ^ ((sum1 * 0x1234U >> 8) & 0xFU)
                    ^ ((sum2 * 0x5678U >> 16) & 0xFU)
                    ^ ((sum3 * 0x9ABCU >> 4) & 0xFU)
                    ^ ((Rotl32(sum1, 3) & 0xFU) ^ (Rotr32(sum3, 5) & 0xFU)));

                uint bNibble = unchecked((sum2 & 0xFU)
                    ^ ((sum1 >> 4) & 0xFU)
                    ^ ((sum4 >> 8) & 0xFU)
                    ^ ((sum2 * 0xDCBAU >> 14) & 0xFU)
                    ^ ((sum2 * 0x8765U >> 10) & 0xFU)
                    ^ ((sum1 * 0x4321U >> 6) & 0xFU)
                    ^ ((Rotl32(sum4, 2) ^ Rotr32(sum1, 1)) & 0xFU));

                uint cNibble = unchecked((sum3 & 0xFU)
                    ^ ((sum2 >> 4) & 0xFU)
                    ^ ((sum2 >> 8) & 0xFU)
                    ^ ((sum3 * 0xF135U >> 10) & 0xFU)
                    ^ ((sum3 * 0x2468U >> 12) & 0xFU)
                    ^ ((sum4 * 0xACEFU >> 8) & 0xFU)
                    ^ ((sum2 * 0x1357U >> 4) & 0xFU)
                    ^ ((Rotl32(sum3, 5) & 0xFU) ^ (Rotr32(sum1, 7) & 0xFU)));

                uint dNibble = unchecked((sum1 & 0xFU)
                    ^ ((sum4 >> 4) & 0xFU)
                    ^ ((sum1 >> 8) & 0xFU)
                    ^ ((sum4 * 0x57A3U >> 6) & 0xFU)
                    ^ ((sum3 * 0xD4E3U >> 12) & 0xFU)
                    ^ ((sum1 * 0x9F8BU >> 10) & 0xFU)
                    ^ ((Rotl32(sum4, 4) ^ (sum1 + sum2)) & 0xFU));

                byte h = hashBytes[i];
                nibbleProduct[i] = (byte)((((cNibble & 0xFU) << 4) | (dNibble & 0xFU)) ^ h);
                product[i] = (byte)((((aNibble & 0xFU) << 4) | (bNibble & 0xFU)) ^ h);
            }

            byte[] productBeforeOct = (byte[])product.Clone();
            ulong[] octResult = OctonionHash(product);
            for (int i = 0; i < 4; i++)
            {
                int off = i * 8;
                Store64Le(Load64Le(product, off) ^ octResult[i], product, off);
            }

            byte[] rotateLeftBases =
            {
                (byte)((nibbleProduct[3] ^ 0x4F) * 3), (byte)((product[7] ^ 0xA6) * 2),
                (byte)((productBeforeOct[1] ^ 0x9C) * 9), (byte)((product[6] ^ 0x71) * 4),
                (byte)((nibbleProduct[4] ^ 0xB2) * 3), (byte)((product[0] ^ 0x58) * 6),
                (byte)((productBeforeOct[2] ^ 0x37) * 2), (byte)((product[5] ^ 0x1A) * 5),
                (byte)((nibbleProduct[3] ^ 0x93) * 7), (byte)((product[7] ^ 0x29) * 9),
                (byte)((productBeforeOct[1] ^ 0x4E) * 4), (byte)((nibbleProduct[6] ^ 0xF3) * 5),
                (byte)((product[4] ^ 0xB7) * 6), (byte)((product[0] ^ 0x2D) * 8),
                (byte)((productBeforeOct[2] ^ 0x6F) * 3), (byte)((nibbleProduct[5] ^ 0xE1) * 7)
            };

            byte[] rotateRightBases =
            {
                (byte)((hashBytes[2] ^ 0xD3) * 5), (byte)((nibbleProduct[5] ^ 0x5B) * 7),
                (byte)((product[0] ^ 0x8E) * 3), (byte)((productBeforeOct[3] ^ 0x2F) * 5),
                (byte)((hashBytes[7] ^ 0x6D) * 7), (byte)((nibbleProduct[1] ^ 0xEE) * 9),
                (byte)((hashBytes[6] ^ 0x44) * 6), (byte)((hashBytes[4] ^ 0x7C) * 8),
                (byte)((product[2] ^ 0xAF) * 3), (byte)((nibbleProduct[5] ^ 0xDC) * 2),
                (byte)((hashBytes[0] ^ 0x8B) * 3), (byte)((productBeforeOct[3] ^ 0x62) * 8),
                (byte)((product[7] ^ 0x15) * 2), (byte)((productBeforeOct[1] ^ 0xC8) * 7),
                (byte)((nibbleProduct[6] ^ 0x99) * 9), (byte)((hashBytes[4] ^ 0x3B) * 5)
            };

            uint updateIndex = (uint)(productBeforeOct[2] & 7) + 1;
            uint sboxIterations = 1U + (uint)(product[updateIndex] & 1);
            uint indexBlake = (uint)(productBeforeOct[5] & 7) + 1;
            uint iterationsBlake = 1U + (uint)(product[indexBlake] % 3);

            byte[] output = (byte[])product.Clone();
            for (uint i = 0; i < iterationsBlake; i++) output = Blake3Compress32(output);

            uint refIdx = 0, productIdx = 0, hashIdx = 0, mixTerm = 0;
            for (uint i = 0; i < 32; i++)
            {
                byte refVal = PickRefValue((byte)(i & 3), refIdx, nibbleProduct, productBeforeOct, product, hashBytes);
                uint index = (uint)(refVal + product[productIdx] + hashBytes[hashIdx]) + mixTerm;
                index &= 255;
                byte sboxByte = ComputeSboxEntry(index, rotateLeftBases, rotateRightBases, product, hashBytes, nibbleProduct, productBeforeOct, sboxIterations);
                output[i] ^= (byte)(sboxByte ^ AfterCompLut[product[i]]);

                refIdx = (refIdx + 13) & 31;
                productIdx = (productIdx + 31) & 31;
                hashIdx = (hashIdx + 19) & 31;
                mixTerm = (mixTerm + 41) & 255;
            }

            return CryptixHashV2Hash(output);
        }

        private static byte[] PowHashFinalizeFromHeader(byte[] header72, ulong nonce)
        {
            ulong[] st = new ulong[25];
            Array.Copy(PowHashInitialState, st, 25);
            for (int i = 0; i < 9; i++) st[i] ^= Load64Le(header72, i * 8);
            st[9] ^= nonce;
            KeccakF1600(st);

            byte[] output = new byte[32];
            Store64Le(st[0], output, 0);
            Store64Le(st[1], output, 8);
            Store64Le(st[2], output, 16);
            Store64Le(st[3], output, 24);
            return output;
        }

        private static byte[] CalculatePowPreMatrixFromHeader(byte[] header72, ulong nonce)
        {
            byte[] currentHash = PowHashFinalizeFromHeader(header72, nonce);
            uint iterations = (uint)(currentHash[0] & 1) + 1;

            for (uint i = 0; i < iterations; i++)
            {
                currentHash = Sha3_256_32bytes(currentHash);

                if ((currentHash[1] & 3) == 0)
                {
                    uint repeat = (uint)(currentHash[2] & 3) + 1;
                    for (uint r = 0; r < repeat; r++)
                    {
                        uint targetByte = ((uint)currentHash[1] + i) & 31;
                        currentHash[targetByte] ^= (byte)(currentHash[i & 15] ^ 0xA5);

                        byte rotationByte = currentHash[i & 31];
                        uint rotationAmount = (((uint)currentHash[1] + currentHash[3]) & 3) + 2;
                        currentHash[targetByte] = (rotationByte & 1) == 0
                            ? Rotl8(currentHash[targetByte], rotationAmount)
                            : Rotr8(currentHash[targetByte], rotationAmount);

                        uint shiftAmount = (((uint)currentHash[5] + currentHash[1]) % 3) + 1;
                        currentHash[targetByte] ^= Rotl8(currentHash[targetByte], shiftAmount);
                    }
                }
                else if ((currentHash[3] % 3) == 0)
                {
                    uint repeat = (uint)(currentHash[4] % 5) + 1;
                    for (uint r = 0; r < repeat; r++)
                    {
                        uint targetByte = ((uint)currentHash[6] + i) & 31;
                        currentHash[targetByte] ^= (byte)(currentHash[i & 15] ^ 0x55);

                        byte rotationByte = currentHash[i & 31];
                        uint rotationAmount = (((uint)currentHash[7] + currentHash[2]) % 6) + 1;
                        currentHash[targetByte] = (rotationByte & 1) == 0
                            ? Rotl8(currentHash[targetByte], rotationAmount)
                            : Rotr8(currentHash[targetByte], rotationAmount);

                        uint shiftAmount = (((uint)currentHash[1] + currentHash[3]) % 4) + 1;
                        currentHash[targetByte] ^= Rotl8(currentHash[targetByte], shiftAmount);
                    }
                }
                else if ((currentHash[2] % 6) == 0)
                {
                    uint repeat = (uint)(currentHash[6] & 3) + 1;
                    for (uint r = 0; r < repeat; r++)
                    {
                        uint targetByte = ((uint)currentHash[10] + i) & 31;
                        currentHash[targetByte] ^= (byte)(currentHash[i & 15] ^ 0xFF);

                        byte rotationByte = currentHash[i & 31];
                        uint rotationAmount = (((uint)currentHash[7] + currentHash[7]) % 7) + 1;
                        currentHash[targetByte] = (rotationByte & 1) == 0
                            ? Rotl8(currentHash[targetByte], rotationAmount)
                            : Rotr8(currentHash[targetByte], rotationAmount);

                        uint shiftAmount = (((uint)currentHash[3] + currentHash[5]) % 5) + 2;
                        currentHash[targetByte] ^= Rotl8(currentHash[targetByte], shiftAmount);
                    }
                }
                else if ((currentHash[7] % 5) == 0)
                {
                    uint repeat = (uint)(currentHash[8] & 3) + 1;
                    for (uint r = 0; r < repeat; r++)
                    {
                        uint targetByte = ((uint)currentHash[25] + i) & 31;
                        currentHash[targetByte] ^= (byte)(currentHash[i & 15] ^ 0x66);

                        byte rotationByte = currentHash[i & 31];
                        uint rotationAmount = (((uint)currentHash[1] + currentHash[3]) & 3) + 2;
                        currentHash[targetByte] = (rotationByte & 1) == 0
                            ? Rotl8(currentHash[targetByte], rotationAmount)
                            : Rotr8(currentHash[targetByte], rotationAmount);

                        uint shiftAmount = (((uint)currentHash[1] + currentHash[3]) & 3) + 1;
                        currentHash[targetByte] ^= Rotl8(currentHash[targetByte], shiftAmount);
                    }
                }
                else if ((currentHash[8] % 7) == 0)
                {
                    uint repeat = (uint)(currentHash[9] % 5) + 1;
                    for (uint r = 0; r < repeat; r++)
                    {
                        uint targetByte = ((uint)currentHash[30] + i) & 31;
                        currentHash[targetByte] ^= (byte)(currentHash[i & 15] ^ 0x77);

                        byte rotationByte = currentHash[i & 31];
                        uint rotationAmount = (((uint)currentHash[2] + currentHash[5]) % 5) + 1;
                        currentHash[targetByte] = (rotationByte & 1) == 0
                            ? Rotl8(currentHash[targetByte], rotationAmount)
                            : Rotr8(currentHash[targetByte], rotationAmount);

                        uint shiftAmount = (((uint)currentHash[7] + currentHash[9]) % 6) + 2;
                        currentHash[targetByte] ^= Rotl8(currentHash[targetByte], shiftAmount);
                    }
                }
            }

            return currentHash;
        }

        public static byte[] Hash(byte[] header72, ulong nonce, byte[] matrix4096)
        {
            if (header72 == null || header72.Length != 72) throw new ArgumentException("header72 must be exactly 72 bytes", nameof(header72));
            if (matrix4096 == null || matrix4096.Length != 64 * 64) throw new ArgumentException("matrix must be exactly 4096 bytes (64x64)", nameof(matrix4096));

            byte[] pre = CalculatePowPreMatrixFromHeader(header72, nonce);
            return CryptixHashMatrix(matrix4096, pre);
        }

        public static byte[] Hash(byte[] header72, ulong nonce, byte[,] matrix)
        {
            if (matrix == null || matrix.GetLength(0) != 64 || matrix.GetLength(1) != 64)
                throw new ArgumentException("matrix must be [64,64]", nameof(matrix));

            byte[] flat = new byte[4096];
            int idx = 0;
            for (int r = 0; r < 64; r++)
            for (int c = 0; c < 64; c++)
                flat[idx++] = matrix[r, c];

            return Hash(header72, nonce, flat);
        }
    }
}
