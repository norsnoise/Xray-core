// SPDX-License-Identifier: GPL-2.0-only
package waes256

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

// AEAD over WAES-256: CTR for confidentiality + HMAC-SHA256 (encrypt-then-MAC)
// for integrity. GCM is unavailable because it requires a 128-bit block and
// WAES-256's block is 256-bit. 12-byte nonce, 16-byte tag.
const (
	nonceSize = 12
	tagSize   = 16
)

type waesAEAD struct {
	block  *Cipher
	macKey []byte
}

// NewAEAD builds a cipher.AEAD from a 32-byte WAES-256 key.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Separate MAC key so the HMAC and the CTR keystream never share key material.
	mk := sha256.Sum256(append([]byte("WAES256-AEAD-MAC\x01"), key...))
	return &waesAEAD{block: block, macKey: mk[:]}, nil
}

func (a *waesAEAD) NonceSize() int { return nonceSize }
func (a *waesAEAD) Overhead() int  { return tagSize }

// iv expands a 12-byte nonce into a 32-byte CTR counter block (nonce||zeros).
func (a *waesAEAD) iv(nonce []byte) []byte {
	iv := make([]byte, BlockSize)
	copy(iv, nonce)
	return iv
}

func (a *waesAEAD) tag(nonce, additionalData, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, a.macKey)
	h.Write(nonce)
	h.Write(additionalData)
	h.Write(ciphertext)
	// bind lengths to stop AD/ciphertext boundary ambiguity
	var lens [16]byte
	putUint64(lens[0:8], uint64(len(additionalData)))
	putUint64(lens[8:16], uint64(len(ciphertext)))
	h.Write(lens[:])
	return h.Sum(nil)[:tagSize]
}

func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

func (a *waesAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != nonceSize {
		panic("waes256: incorrect nonce length")
	}
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(a.block, a.iv(nonce)).XORKeyStream(ct, plaintext)
	tag := a.tag(nonce, additionalData, ct)
	ret := append(dst, ct...)
	return append(ret, tag...)
}

func (a *waesAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, errors.New("waes256: incorrect nonce length")
	}
	if len(ciphertext) < tagSize {
		return nil, errors.New("waes256: ciphertext too short")
	}
	ct := ciphertext[:len(ciphertext)-tagSize]
	tag := ciphertext[len(ciphertext)-tagSize:]
	want := a.tag(nonce, additionalData, ct)
	if subtle.ConstantTimeCompare(tag, want) != 1 {
		return nil, errors.New("waes256: message authentication failed")
	}
	pt := make([]byte, len(ct))
	cipher.NewCTR(a.block, a.iv(nonce)).XORKeyStream(pt, ct)
	return append(dst, pt...), nil
}

var _ cipher.AEAD = (*waesAEAD)(nil)
