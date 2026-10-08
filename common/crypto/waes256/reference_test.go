package waes256

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// The straightforward 4x4-state implementation the optimized cipher replaced.
// It mirrors the reference cipher step by step and is kept as an oracle.

type refState [nCells][nCells]uint16

func refBytesToState(b []byte) refState {
	var wd [16]uint16
	for k := 0; k < 16; k++ {
		wd[k] = uint16(b[2*k])<<8 | uint16(b[2*k+1])
	}
	var s refState
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			s[r][c] = wd[c*nCells+r] // column-major
		}
	}
	return s
}

func refStateToBytes(s refState, dst []byte) {
	i := 0
	for c := 0; c < nCells; c++ {
		for r := 0; r < nCells; r++ {
			dst[i] = byte(s[r][c] >> 8)
			dst[i+1] = byte(s[r][c])
			i += 2
		}
	}
}

func refSubWords(s refState, box *[1 << w]uint16) refState {
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			s[r][c] = box[s[r][c]]
		}
	}
	return s
}

func refShiftRows(s refState) refState {
	var o refState
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			o[r][c] = s[r][(c+r)%nCells] // rotate row r left by r
		}
	}
	return o
}

func refInvShiftRows(s refState) refState {
	var o refState
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			o[r][(c+r)%nCells] = s[r][c] // rotate row r right by r
		}
	}
	return o
}

var (
	refMdsM    = [nCells][nCells]int{{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}}
	refInvMdsM = [nCells][nCells]int{{0x0E, 0x0B, 0x0D, 0x09}, {0x09, 0x0E, 0x0B, 0x0D}, {0x0D, 0x09, 0x0E, 0x0B}, {0x0B, 0x0D, 0x09, 0x0E}}
)

func refMixColumns(s refState, m *[nCells][nCells]int) refState {
	var o refState
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

func refAddRoundKey(s, rk refState) refState {
	for r := 0; r < nCells; r++ {
		for c := 0; c < nCells; c++ {
			s[r][c] ^= rk[r][c]
		}
	}
	return s
}

func refRoundKeys(c *Cipher) (rks [rounds + 1]refState) {
	for i := range c.rks {
		for r := 0; r < nCells; r++ {
			for col := 0; col < nCells; col++ {
				rks[i][r][col] = c.rks[i][col*nCells+r]
			}
		}
	}
	return
}

func refEncrypt(c *Cipher, dst, src []byte) {
	rks := refRoundKeys(c)
	s := refAddRoundKey(refBytesToState(src), rks[0])
	for r := 1; r < rounds; r++ {
		s = refAddRoundKey(refMixColumns(refShiftRows(refSubWords(s, &sbox)), &refMdsM), rks[r])
	}
	s = refShiftRows(refSubWords(s, &sbox)) // final round: no MixColumns
	s = refAddRoundKey(s, rks[rounds])
	refStateToBytes(s, dst)
}

func refDecrypt(c *Cipher, dst, src []byte) {
	rks := refRoundKeys(c)
	s := refAddRoundKey(refBytesToState(src), rks[rounds])
	s = refSubWords(refInvShiftRows(s), &invBox)
	for r := rounds - 1; r > 0; r-- {
		s = refMixColumns(refAddRoundKey(s, rks[r]), &refInvMdsM)
		s = refSubWords(refInvShiftRows(s), &invBox)
	}
	s = refAddRoundKey(s, rks[0])
	refStateToBytes(s, dst)
}

// TestMatchesReference checks the optimized cipher against the oracle on
// random keys and blocks, in both directions.
func TestMatchesReference(t *testing.T) {
	key := make([]byte, KeySize)
	in := make([]byte, BlockSize)
	want := make([]byte, BlockSize)
	got := make([]byte, BlockSize)
	for i := 0; i < 200; i++ {
		rand.Read(key)
		c, _ := NewCipher(key)
		for j := 0; j < 20; j++ {
			rand.Read(in)
			refEncrypt(c, want, in)
			c.Encrypt(got, in)
			if !bytes.Equal(got, want) {
				t.Fatalf("Encrypt mismatch\n key %x\n in  %x\n got  %x\n want %x", key, in, got, want)
			}
			refDecrypt(c, want, in)
			c.Decrypt(got, in)
			if !bytes.Equal(got, want) {
				t.Fatalf("Decrypt mismatch\n key %x\n in  %x\n got  %x\n want %x", key, in, got, want)
			}
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	c, _ := NewCipher(make([]byte, KeySize))
	buf := make([]byte, BlockSize)
	b.SetBytes(BlockSize)
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkReferenceEncrypt(b *testing.B) {
	c, _ := NewCipher(make([]byte, KeySize))
	buf := make([]byte, BlockSize)
	b.SetBytes(BlockSize)
	for i := 0; i < b.N; i++ {
		refEncrypt(c, buf, buf)
	}
}

func BenchmarkCascadeSeal16K(b *testing.B) {
	a, _ := NewCascadeAEAD(make([]byte, KeySize))
	pt := make([]byte, 16384)
	nonce := make([]byte, nonceSize)
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		a.Seal(nil, nonce, pt, nil)
	}
}
