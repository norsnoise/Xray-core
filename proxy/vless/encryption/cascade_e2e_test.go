package encryption

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// TestRecordRoundTripCascade drives the VLESS-Encryption record layer
// (CommonConn.Write/Read) end to end. NewAEAD now builds the AES-256-CTR +
// WAES-256 cascade, so this proves VLESS data records encrypt and decrypt with
// aes256+waes256, including the multi-record chunking and per-record nonce.
func TestRecordRoundTripCascade(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	ctx := []byte("vless-record-context")

	w := NewCommonConn(c1, true)
	r := NewCommonConn(c2, true)
	// Same context + key on both ends => identical derived cascade keys.
	w.AEAD = NewAEAD(ctx, key, true)
	r.PeerAEAD = NewAEAD(ctx, key, true)

	// Larger than 8192 to exercise multi-record framing and nonce stepping.
	payload := bytes.Repeat([]byte("VLESS aes256+waes256 cascade record! "), 600)

	writeErr := make(chan error, 1)
	go func() {
		_, err := w.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("decrypted payload does not match plaintext")
	}
}

// TestRecordWireIsEncrypted confirms the plaintext is not present in the bytes
// emitted on the wire by the record layer.
func TestRecordWireIsEncrypted(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ctx := []byte("vless-record-context")

	var wire bytes.Buffer
	w := NewCommonConn(nopConn{&wire}, true)
	w.AEAD = NewAEAD(ctx, key, true)

	payload := []byte("the quick brown fox jumps over the lazy dog")
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire.Bytes(), payload) {
		t.Fatal("plaintext appears on the wire")
	}
	// First 3 bytes must mimic a TLS 1.3 application-data record header.
	if b := wire.Bytes(); len(b) < 3 || b[0] != 0x17 || b[1] != 0x03 || b[2] != 0x03 {
		t.Fatalf("record header not TLS-like: % x", wire.Bytes()[:min(3, len(wire.Bytes()))])
	}
}

// nopConn adapts an io.Writer to net.Conn (only Write is exercised).
type nopConn struct{ io.Writer }

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
