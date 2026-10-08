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

// The state is 16 cells in column-major order, s[col*nCells+row], which is
// also the order the cells are serialized in, two bytes each, big-endian.
type state [nCells * nCells]uint16

func loadState(b []byte) (s state) {
	for k := range s {
		s[k] = uint16(b[2*k])<<8 | uint16(b[2*k+1])
	}
	return
}

func storeState(s *state, dst []byte) {
	for k, v := range s {
		dst[2*k] = byte(v >> 8)
		dst[2*k+1] = byte(v)
	}
}

// xtime multiplies by x (i.e. 2) in GF(2^16) without tables or branches.
func xtime(a uint16) uint16 {
	return a<<1 ^ (poly & mask & -(a >> (w - 1)))
}

// subShift applies SubWords then ShiftRows (row r rotated left by r).
func subShift(s *state, box *[1 << w]uint16) (o state) {
	for c := 0; c < nCells; c++ {
		for r := 0; r < nCells; r++ {
			o[c*nCells+r] = box[s[((c+r)%nCells)*nCells+r]]
		}
	}
	return
}

// invShiftSub applies InvShiftRows (row r rotated right by r) then InvSubWords.
func invShiftSub(s *state, box *[1 << w]uint16) (o state) {
	for c := 0; c < nCells; c++ {
		for r := 0; r < nCells; r++ {
			o[((c+r)%nCells)*nCells+r] = box[s[c*nCells+r]]
		}
	}
	return
}

// mixColumns multiplies each column by the circulant (2 3 1 1).
func mixColumns(s *state) {
	for c := 0; c < nCells*nCells; c += nCells {
		a0, a1, a2, a3 := s[c], s[c+1], s[c+2], s[c+3]
		t := a0 ^ a1 ^ a2 ^ a3
		s[c] = a0 ^ t ^ xtime(a0^a1)
		s[c+1] = a1 ^ t ^ xtime(a1^a2)
		s[c+2] = a2 ^ t ^ xtime(a2^a3)
		s[c+3] = a3 ^ t ^ xtime(a3^a0)
	}
}

// invMixColumns multiplies each column by the circulant (0E 0B 0D 09), which
// factors as (2 3 1 1) * (5 0 4 0). The identity holds over GF(2)[x] with no
// reduction, so it holds in this field as it does in AES's.
func invMixColumns(s *state) {
	for c := 0; c < nCells*nCells; c += nCells {
		u := xtime(xtime(s[c] ^ s[c+2]))
		v := xtime(xtime(s[c+1] ^ s[c+3]))
		s[c] ^= u
		s[c+1] ^= v
		s[c+2] ^= u
		s[c+3] ^= v
	}
	mixColumns(s)
}

func addRoundKey(s, rk *state) {
	for k := range s {
		s[k] ^= rk[k]
	}
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
		for col := 0; col < nCells; col++ {
			copy(c.rks[r][col*nCells:], words[4*r+col][:])
		}
	}
	return c, nil
}

func (c *Cipher) BlockSize() int { return BlockSize }

func (c *Cipher) Encrypt(dst, src []byte) {
	s := loadState(src)
	addRoundKey(&s, &c.rks[0])
	for r := 1; r < rounds; r++ {
		s = subShift(&s, &sbox)
		mixColumns(&s)
		addRoundKey(&s, &c.rks[r])
	}
	s = subShift(&s, &sbox) // final round: no MixColumns
	addRoundKey(&s, &c.rks[rounds])
	storeState(&s, dst)
}

func (c *Cipher) Decrypt(dst, src []byte) {
	s := loadState(src)
	addRoundKey(&s, &c.rks[rounds])
	s = invShiftSub(&s, &invBox)
	for r := rounds - 1; r > 0; r-- {
		addRoundKey(&s, &c.rks[r])
		invMixColumns(&s)
		s = invShiftSub(&s, &invBox)
	}
	addRoundKey(&s, &c.rks[0])
	storeState(&s, dst)
}

var _ cipher.Block = (*Cipher)(nil)
