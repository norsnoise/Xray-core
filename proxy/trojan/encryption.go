package trojan

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/crypto/waes256"
	"github.com/xtls/xray-core/common/errors"
	"lukechampine.com/blake3"
)

// Experimental opt-in inner encryption for Trojan: when an account sets
// Encryption = "waes-256", the whole post-TLS stream is wrapped in the
// AES-256-CTR + WAES-256 cascade. A random 32-byte salt is sent first (by the
// client); both directions key off it with distinct labels. Records are
// length-prefixed AEAD frames with a per-direction incrementing nonce.
//
// Not wire-compatible with stock Trojan; run this build on both ends. Does not
// combine with Trojan fallbacks. Study only.

const (
	waesSaltLen  = 32
	waesMaxChunk = 16384
	waesTagLen   = 16
	waesNonceLen = 12
)

func waesCascade(password string, salt []byte, dir string) cipher.AEAD {
	k := make([]byte, 32)
	material := append(append([]byte{}, salt...), []byte(password)...)
	blake3.DeriveKey(k, "trojan-waes256-"+dir, material)
	aead, _ := waes256.NewCascadeAEAD(k)
	return aead
}

// seqAEAD pairs an AEAD with a monotonically increasing 96-bit nonce.
type seqAEAD struct {
	aead  cipher.AEAD
	count uint64
}

func (s *seqAEAD) nonce() []byte {
	var n [waesNonceLen]byte
	binary.BigEndian.PutUint64(n[4:], s.count)
	s.count++
	return n[:]
}

func (s *seqAEAD) seal(plaintext []byte) []byte {
	return s.aead.Seal(nil, s.nonce(), plaintext, nil)
}

func (s *seqAEAD) open(ciphertext []byte) ([]byte, error) {
	return s.aead.Open(nil, s.nonce(), ciphertext, nil)
}

// cryptoConn wraps a net.Conn with the Trojan WAES-256 cascade record layer.
type cryptoConn struct {
	net.Conn

	isClient   bool
	password   string   // client side
	candidates []string // server side: encryption-enabled passwords to try

	wOnce sync.Once
	wErr  error
	w     *seqAEAD

	rOnce sync.Once
	rErr  error
	r     *seqAEAD

	readBuf []byte // leftover decrypted plaintext
}

// NewClientCryptoConn wraps conn for a Trojan client using the account password.
func NewClientCryptoConn(conn net.Conn, password string) net.Conn {
	return &cryptoConn{Conn: conn, isClient: true, password: password}
}

// NewServerCryptoConn wraps conn for a Trojan server. The first matching
// password among candidates identifies the session key.
func NewServerCryptoConn(conn net.Conn, candidates []string) net.Conn {
	return &cryptoConn{Conn: conn, candidates: candidates}
}

func (c *cryptoConn) initClient() {
	c.wOnce.Do(func() {
		salt := make([]byte, waesSaltLen)
		if _, err := rand.Read(salt); err != nil {
			c.wErr = err
			return
		}
		if _, err := c.Conn.Write(salt); err != nil {
			c.wErr = err
			return
		}
		c.w = &seqAEAD{aead: waesCascade(c.password, salt, "c2s")}
		c.r = &seqAEAD{aead: waesCascade(c.password, salt, "s2c")}
	})
}

func readFrame(conn net.Conn) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint16(h[:]))
	if l < waesTagLen {
		return nil, errors.New("trojan/waes256: short frame")
	}
	body := make([]byte, l)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func (c *cryptoConn) initServer() {
	c.rOnce.Do(func() {
		salt := make([]byte, waesSaltLen)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			c.rErr = err
			return
		}
		body, err := readFrame(c.Conn)
		if err != nil {
			c.rErr = err
			return
		}
		for _, pw := range c.candidates {
			r := &seqAEAD{aead: waesCascade(pw, salt, "c2s")}
			pt, err := r.open(body)
			if err == nil {
				c.password = pw
				c.r = r
				c.w = &seqAEAD{aead: waesCascade(pw, salt, "s2c")}
				c.readBuf = pt
				return
			}
		}
		c.rErr = errors.New("trojan/waes256: no candidate password matched")
	})
}

func (c *cryptoConn) ensureWrite() error {
	if c.isClient {
		c.initClient()
		return c.wErr
	}
	c.initServer() // server derives the write key while reading the salt+first frame
	return c.rErr
}

func (c *cryptoConn) ensureRead() error {
	if c.isClient {
		c.initClient() // client derives the read key when it sends the salt
		return c.wErr
	}
	c.initServer()
	return c.rErr
}

func (c *cryptoConn) Write(b []byte) (int, error) {
	if err := c.ensureWrite(); err != nil {
		return 0, err
	}
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > waesMaxChunk {
			chunk = chunk[:waesMaxChunk]
		}
		ct := c.w.seal(chunk)
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(ct)))
		if _, err := c.Conn.Write(append(h[:], ct...)); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *cryptoConn) Read(b []byte) (int, error) {
	if err := c.ensureRead(); err != nil {
		return 0, err
	}
	if len(c.readBuf) == 0 {
		body, err := readFrame(c.Conn)
		if err != nil {
			return 0, err
		}
		pt, err := c.r.open(body)
		if err != nil {
			return 0, err
		}
		c.readBuf = pt
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}
