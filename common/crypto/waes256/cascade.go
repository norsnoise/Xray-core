// SPDX-License-Identifier: GPL-2.0-only
package waes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
)

// cascadeAEAD layers two ciphers: the plaintext is first encrypted with
// AES-256-CTR (inner), then sealed with the WAES-256 AEAD (outer), so the bytes
// produced are WAES256(AES256-CTR(plaintext)). The inner AES-256 layer provides
// confidentiality; authentication is provided once by the outer WAES-256 AEAD
// over the AES-256 ciphertext (encrypt-then-MAC). Total overhead stays 16 bytes
// (one outer tag) and the nonce size stays 12, so it is a drop-in for a plain
// AES-256-GCM / WAES-256 AEAD.
type cascadeAEAD struct {
	aesBlock cipher.Block // AES-256 (inner)
	outer    cipher.AEAD  // WAES-256 CTR+HMAC (outer)
}

func (c *cascadeAEAD) NonceSize() int { return c.outer.NonceSize() }
func (c *cascadeAEAD) Overhead() int  { return c.outer.Overhead() }

// ctrIV expands the 12-byte AEAD nonce into a 16-byte AES-CTR IV (nonce||zeros).
func ctrIV(nonce []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	copy(iv, nonce)
	return iv
}

func (c *cascadeAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	mid := make([]byte, len(plaintext))
	cipher.NewCTR(c.aesBlock, ctrIV(nonce)).XORKeyStream(mid, plaintext)
	return c.outer.Seal(dst, nonce, mid, additionalData)
}

func (c *cascadeAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	mid, err := c.outer.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(c.aesBlock, ctrIV(nonce)).XORKeyStream(mid, mid)
	return append(dst, mid...), nil
}

// NewCascadeAEAD builds the AES-256-CTR + WAES-256 cascade from a 32-byte key.
// Two independent subkeys are derived so the layers never share key material.
func NewCascadeAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("waes256: cascade key must be 32 bytes")
	}
	aesKey := sha256.Sum256(append([]byte("waes256-cascade-aes\x01"), key...))
	waesKey := sha256.Sum256(append([]byte("waes256-cascade-waes\x01"), key...))
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}
	outer, err := NewAEAD(waesKey[:])
	if err != nil {
		return nil, err
	}
	return &cascadeAEAD{aesBlock: block, outer: outer}, nil
}

var _ cipher.AEAD = (*cascadeAEAD)(nil)
