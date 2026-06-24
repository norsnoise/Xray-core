package waes256

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Reference vector from waes256.py / waes256.c: E(0^256, 0^256).
const refVector = "43e012f37fcfa47852c843208a39e873f99d617ec43660f217aefed7dad9ed53"

func TestReferenceVector(t *testing.T) {
	c, err := NewCipher(make([]byte, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, BlockSize)
	c.Encrypt(dst, make([]byte, BlockSize))
	got := hex.EncodeToString(dst)
	if got != refVector {
		t.Fatalf("E(0,0)\n got  %s\n want %s", got, refVector)
	}
}

func TestBlockRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	pt := make([]byte, BlockSize)
	for i := range key {
		key[i] = byte(i * 7)
	}
	for i := range pt {
		pt[i] = byte(255 - i*3)
	}
	c, _ := NewCipher(key)
	ct := make([]byte, BlockSize)
	c.Encrypt(ct, pt)
	if bytes.Equal(ct, pt) {
		t.Fatal("ciphertext equals plaintext")
	}
	back := make([]byte, BlockSize)
	c.Decrypt(back, ct)
	if !bytes.Equal(back, pt) {
		t.Fatalf("decrypt mismatch\n got  %x\n want %x", back, pt)
	}
}

func TestSboxBijective(t *testing.T) {
	var seen [1 << 16]bool
	for a := 0; a < (1 << 16); a++ {
		if seen[sbox[a]] {
			t.Fatalf("S-box collision at %d", a)
		}
		seen[sbox[a]] = true
		if invBox[sbox[a]] != uint16(a) {
			t.Fatalf("inverse S-box mismatch at %d", a)
		}
	}
	// no fixed / anti-fixed points (claimed property of c=0x6308)
	for a := 0; a < (1 << 16); a++ {
		if sbox[a] == uint16(a) {
			t.Fatalf("fixed point at %d", a)
		}
		if sbox[a] == uint16(a)^mask {
			t.Fatalf("anti-fixed point at %d", a)
		}
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	a, err := NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, a.NonceSize())
	copy(nonce, []byte("noncebytes!!"))
	ad := []byte("associated-data")
	for _, ptLen := range []int{0, 1, 15, 16, 31, 32, 33, 100, 1000} {
		pt := make([]byte, ptLen)
		for i := range pt {
			pt[i] = byte(i)
		}
		sealed := a.Seal(nil, nonce, pt, ad)
		if len(sealed) != ptLen+a.Overhead() {
			t.Fatalf("len %d: sealed len %d, want %d", ptLen, len(sealed), ptLen+a.Overhead())
		}
		opened, err := a.Open(nil, nonce, sealed, ad)
		if err != nil {
			t.Fatalf("len %d: open: %v", ptLen, err)
		}
		if !bytes.Equal(opened, pt) {
			t.Fatalf("len %d: opened mismatch", ptLen)
		}
	}
}

func TestAEADTamperRejected(t *testing.T) {
	a, _ := NewAEAD(make([]byte, KeySize))
	nonce := make([]byte, a.NonceSize())
	ad := []byte("ad")
	pt := []byte("the quick brown fox jumps over the lazy dog")
	sealed := a.Seal(nil, nonce, pt, ad)

	// flip a ciphertext bit
	bad := append([]byte(nil), sealed...)
	bad[0] ^= 0x01
	if _, err := a.Open(nil, nonce, bad, ad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	// flip a tag bit
	bad = append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 0x80
	if _, err := a.Open(nil, nonce, bad, ad); err == nil {
		t.Fatal("tampered tag accepted")
	}
	// wrong AD
	if _, err := a.Open(nil, nonce, sealed, []byte("AD")); err == nil {
		t.Fatal("wrong associated data accepted")
	}
	// wrong nonce
	badNonce := make([]byte, a.NonceSize())
	badNonce[0] = 1
	if _, err := a.Open(nil, badNonce, sealed, ad); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}
