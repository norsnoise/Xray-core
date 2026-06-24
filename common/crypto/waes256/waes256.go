// SPDX-License-Identifier: GPL-2.0-only
// Pure-Go port of the WAES-256 reference cipher (reference/waes256.py|c).
// WAES-256: AES's 4x4 state with every cell promoted to 16 bits -> 256-bit
// block and 256-bit key, 14 rounds, AES key schedule. EXPERIMENTAL, study only.
package waes256

import (
	"crypto/cipher"
	"errors"
)

const (
	w         = 16      // cell width in bits
	mask      = 0xFFFF  // (1<<w)-1
	poly      = 0x1100B // x^16+x^12+x^3+x+1 (primitive, generator 2)
	order     = 0xFFFF  // (1<<w)-1
	nCells    = 4       // state is nCells x nCells
	BlockSize = 32      // bytes (256 bits)
	KeySize   = 32      // bytes (256 bits)
	rounds    = 14      // NR
	nk        = 4       // key length in 4-cell words (= Nb)
	affineC   = 0x6308
)

var affineTaps = [...]uint{0, 1, 2, 3, 4}

var (
	expTab [2 * order]uint16
	logTab [1 << w]uint16
	sbox   [1 << w]uint16
	invBox [1 << w]uint16
	rcon   [rounds + 1]uint16
)

// gfMulRaw multiplies in GF(2^16) the slow way; only used to build the tables.
func gfMulRaw(a, b int) int {
	r := 0
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		a <<= 1
		if a&(1<<w) != 0 {
			a ^= poly
		}
		b >>= 1
	}
	return r
}

func gfMul(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	return int(expTab[int(logTab[a])+int(logTab[b])])
}

func rotr(v uint16, n uint) uint16 {
	if n == 0 {
		return v
	}
	return ((v >> n) | (v << (w - n))) & mask
}

func init() {
	// log/exp tables on generator 2
	x := 1
	for i := 0; i < order; i++ {
		expTab[i] = uint16(x)
		logTab[x] = uint16(i)
		x = gfMulRaw(x, 2)
	}
	for i := order; i < 2*order; i++ {
		expTab[i] = expTab[i-order]
	}
	// 16-bit S-box: S(a) = affineC ^ XOR_t rotr(inv(a), t)
	for a := 0; a < (1 << w); a++ {
		var q int
		if a != 0 {
			q = int(expTab[order-int(logTab[a])]) // gf_inv(a)
		}
		s := uint16(affineC)
		for _, t := range affineTaps {
			s ^= rotr(uint16(q), t)
		}
		sbox[a] = s
		invBox[s] = uint16(a)
	}
	// Rcon[r] = x^(r-1) for r = 1..NR
	rc := 1
	for r := 1; r <= rounds; r++ {
		rcon[r] = uint16(rc)
		rc = gfMul(rc, 2)
	}
}

type state [nCells][nCells]uint16

func bytesToState(b []byte) state {
	var wd [16]uint16
	for k := 0; k < 16; k++ {
		wd[k] = uint16(b[2*k])<<8 | uint16(b[2*k+1])
	}
	var s state
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			s[r][c] = wd[c*nCells+r] // column-major
		}
	}
	return s
}

func stateToBytes(s state, dst []byte) {
	i := 0
	for c := 0; c < nCells; c++ {
		for r := 0; r < nCells; r++ {
			dst[i] = byte(s[r][c] >> 8)
			dst[i+1] = byte(s[r][c])
			i += 2
		}
	}
}

func subWords(s state, box *[1 << w]uint16) state {
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			s[r][c] = box[s[r][c]]
		}
	}
	return s
}

func shiftRows(s state) state {
	var o state
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			o[r][c] = s[r][(c+r)%nCells] // rotate row r left by r
		}
	}
	return o
}

func invShiftRows(s state) state {
	var o state
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			o[r][(c+r)%nCells] = s[r][c] // rotate row r right by r
		}
	}
	return o
}

var (
	mdsM    = [nCells][nCells]int{{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}}
	invMdsM = [nCells][nCells]int{{0x0E, 0x0B, 0x0D, 0x09}, {0x09, 0x0E, 0x0B, 0x0D}, {0x0D, 0x09, 0x0E, 0x0B}, {0x0B, 0x0D, 0x09, 0x0E}}
)

func mixColumns(s state, m *[nCells][nCells]int) state {
	var o state
	for c := 0; c < nCells; c++ {
		for r := 0; r < nCells; r++ {
			acc := 0
			for k := 0; k < nCells; k++ {
				acc ^= gfMul(m[r][k], int(s[k][c]))
			}
			o[r][c] = uint16(acc)
		}
	}
	return o
}

func addRoundKey(s, rk state) state {
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			s[r][c] ^= rk[r][c]
		}
	}
	return s
}

// Cipher implements crypto/cipher.Block with a 32-byte block.
type Cipher struct {
	rks [rounds + 1]state
}

// NewCipher returns a WAES-256 block cipher. key must be 32 bytes.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, errors.New("waes256: key must be 32 bytes")
	}
	c := &Cipher{}
	var words [nCells * (rounds + 1)][4]uint16 // 60 words
	var cells [16]uint16
	for k := 0; k < 16; k++ {
		cells[k] = uint16(key[2*k])<<8 | uint16(key[2*k+1])
	}
	for i := 0; i < nk; i++ {
		copy(words[i][:], cells[4*i:4*i+4])
	}
	for i := nk; i < len(words); i++ {
		var temp [4]uint16 = words[i-1]
		if i%nk == 0 {
			temp = [4]uint16{temp[1], temp[2], temp[3], temp[0]} // RotWord
			for j := 0; j < 4; j++ {
				temp[j] = sbox[temp[j]] // SubWord
			}
			temp[0] ^= rcon[i/nk] // Rcon
		}
		for j := 0; j < 4; j++ {
			words[i][j] = words[i-nk][j] ^ temp[j]
		}
	}
	for r := 0; r <= rounds; r++ {
		for row := 0; row < nCells; row++ {
			for col := 0; col < nCells; col++ {
				c.rks[r][row][col] = words[4*r+col][row]
			}
		}
	}
	return c, nil
}

func (c *Cipher) BlockSize() int { return BlockSize }

func (c *Cipher) Encrypt(dst, src []byte) {
	s := addRoundKey(bytesToState(src), c.rks[0])
	for r := 1; r < rounds; r++ {
		s = addRoundKey(mixColumns(shiftRows(subWords(s, &sbox)), &mdsM), c.rks[r])
	}
	s = shiftRows(subWords(s, &sbox)) // final round: no MixColumns
	s = addRoundKey(s, c.rks[rounds])
	stateToBytes(s, dst)
}

func (c *Cipher) Decrypt(dst, src []byte) {
	s := addRoundKey(bytesToState(src), c.rks[rounds])
	s = subWords(invShiftRows(s), &invBox)
	for r := rounds - 1; r > 0; r-- {
		s = mixColumns(addRoundKey(s, c.rks[r]), &invMdsM)
		s = subWords(invShiftRows(s), &invBox)
	}
	s = addRoundKey(s, c.rks[0])
	stateToBytes(s, dst)
}

var _ cipher.Block = (*Cipher)(nil)
