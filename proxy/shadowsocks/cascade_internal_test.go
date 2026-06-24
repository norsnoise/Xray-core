package shadowsocks

import (
	"bytes"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
)

func TestCascadeAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	a := createAes256ThenWaes256(key)
	t.Logf("NonceSize=%d Overhead=%d", a.NonceSize(), a.Overhead())

	gen := crypto.GenerateAEADNonceWithSize(a.NonceSize())
	for _, n := range []int{0, 1, 2, 34, 200} {
		pt := make([]byte, n)
		for i := range pt {
			pt[i] = byte(i)
		}
		nonce := gen()
		sealed := a.Seal(nil, nonce, pt, nil)
		// re-derive the SAME nonce for open by using a fresh generator in lockstep
		opened, err := a.Open(nil, nonce, sealed, nil)
		if err != nil {
			t.Fatalf("n=%d open: %v", n, err)
		}
		if !bytes.Equal(opened, pt) {
			t.Fatalf("n=%d mismatch", n)
		}
	}
}

// TestCascadeInPlace exercises the aliasing pattern the chunk size parser uses:
// Seal(b[:0], b[:2]) and Open(b[:0], b) where dst and the data share storage.
func TestCascadeInPlace(t *testing.T) {
	a := createAes256ThenWaes256(make([]byte, 32))
	gen := crypto.GenerateAEADNonceWithSize(a.NonceSize())
	nonce := gen()

	buf := make([]byte, 2, 2+a.Overhead())
	buf[0], buf[1] = 0xAB, 0xCD
	sealed := a.Seal(buf[:0], nonce, buf[:2], nil)
	opened, err := a.Open(sealed[:0], nonce, sealed, nil)
	if err != nil {
		t.Fatalf("in-place open: %v", err)
	}
	if len(opened) != 2 || opened[0] != 0xAB || opened[1] != 0xCD {
		t.Fatalf("in-place mismatch: %x", opened)
	}
}

// TestCascadeStream runs data through the real Shadowsocks AEAD stream path.
func TestCascadeStream(t *testing.T) {
	cipherImpl := &AEADCipher{KeyBytes: 32, IVBytes: 32, AEADAuthCreator: createAes256ThenWaes256}
	key := make([]byte, 32)
	iv := make([]byte, 32)
	for i := range iv {
		iv[i] = byte(i)
	}
	payload := []byte("cascade stream payload: aes-256 then waes-256")

	pr, pw := io.Pipe()
	w, err := cipherImpl.NewEncryptionWriter(key, iv, pw)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := buf.New()
		b.Write(payload)
		w.WriteMultiBuffer(buf.MultiBuffer{b})
		w.WriteMultiBuffer(buf.MultiBuffer{}) // flush/EOF marker
		pw.Close()
	}()

	r, err := cipherImpl.NewDecryptionReader(key, iv, pr)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := r.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if got := mb[0].Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("stream mismatch:\n got  %q\n want %q", got, payload)
	}
}
