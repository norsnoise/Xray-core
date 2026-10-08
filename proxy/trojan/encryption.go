package trojan

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/crypto/waes256"
	"github.com/xtls/xray-core/common/errors"
	"lukechampine.com/blake3"
)

// Experimental opt-in inner encryption for Trojan: when an account sets
// Encryption = "waes-256", the whole post-TLS stream is wrapped in the
// AES-256-CTR + WAES-256 cascade. The client sends a random 32-byte salt first
// and keys the upload (c2s) off it. The server answers with its own random
// 32-byte salt and keys the download (s2c) off both salts, so a replayed client
// stream never makes the server reuse a download key/nonce. The client's first
// record carries only its clock, which the server requires to be within
// waesMaxClockSkew; the server also remembers authenticated client salts for
// as long as such a record can be accepted and rejects repeats, so a captured
// request cannot be replayed to re-run it, however old it is. Records are
// length-prefixed AEAD frames with a per-direction incrementing nonce.
//
// Not wire-compatible with stock Trojan; run this build on both ends. Does not
// combine with Trojan fallbacks. Study only.

const (
	waesSaltLen  = 32
	waesMaxChunk = 16384
	waesTagLen   = 16
	waesNonceLen = 12

	waesTimeLen = 8

	// waesMaxClockSkew is how far, in seconds, the client's clock may be from
	// the server's.
	waesMaxClockSkew = 90
	// waesReplayWindow is how long, in seconds, a client salt is remembered;
	// the filter keeps each salt for between one and two windows. A salt can
	// pass the clock check for at most 2*waesMaxClockSkew seconds, so it is
	// remembered for the whole time a replay of it could pass.
	waesReplayWindow = 2 * waesMaxClockSkew
)

// waesNow is the clock used for the first-record timestamp; tests replace it.
var waesNow = time.Now

// NewSaltFilter returns the server-wide filter of seen client salts.
func NewSaltFilter() *antireplay.ReplayFilter[[waesSaltLen]byte] {
	return antireplay.NewMapFilter[[waesSaltLen]byte](waesReplayWindow)
}

// waesCascade derives a direction key from the password and the salts. Salts
// are fixed-length, so their concatenation with the password is unambiguous.
func waesCascade(password string, dir string, salts ...[]byte) cipher.AEAD {
	k := make([]byte, 32)
	var material []byte
	for _, s := range salts {
		material = append(material, s...)
	}
	material = append(material, password...)
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
	password   string                                      // client side
	candidates []string                                    // server side: encryption-enabled passwords to try
	salts      *antireplay.ReplayFilter[[waesSaltLen]byte] // server side

	clientSalt []byte
	wPrefix    []byte // server side: its salt, sent ahead of the first frame

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
// password among candidates identifies the session key; salts rejects client
// salts already seen.
func NewServerCryptoConn(conn net.Conn, candidates []string, salts *antireplay.ReplayFilter[[waesSaltLen]byte]) net.Conn {
	return &cryptoConn{Conn: conn, candidates: candidates, salts: salts}
}

func (c *cryptoConn) initClient() {
	c.wOnce.Do(func() {
		salt := make([]byte, waesSaltLen)
		if _, err := rand.Read(salt); err != nil {
			c.wErr = err
			return
		}
		c.clientSalt = salt
		c.w = &seqAEAD{aead: waesCascade(c.password, "c2s", salt)}
		var ts [waesTimeLen]byte
		binary.BigEndian.PutUint64(ts[:], uint64(waesNow().Unix()))
		ct := c.w.seal(ts[:])
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(ct)))
		if _, err := c.Conn.Write(append(append(salt, h[:]...), ct...)); err != nil {
			c.wErr = err
			return
		}
	})
}

// initClientRead reads the server's salt and derives the download key.
func (c *cryptoConn) initClientRead() {
	c.rOnce.Do(func() {
		serverSalt := make([]byte, waesSaltLen)
		if _, err := io.ReadFull(c.Conn, serverSalt); err != nil {
			c.rErr = err
			return
		}
		c.r = &seqAEAD{aead: waesCascade(c.password, "s2c", c.clientSalt, serverSalt)}
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
			r := &seqAEAD{aead: waesCascade(pw, "c2s", salt)}
			pt, err := r.open(body)
			if err == nil {
				if len(pt) != waesTimeLen {
					c.rErr = errors.New("trojan/waes256: bad first record")
					return
				}
				skew := waesNow().Unix() - int64(binary.BigEndian.Uint64(pt))
				if skew < -waesMaxClockSkew || skew > waesMaxClockSkew {
					c.rErr = errors.New("trojan/waes256: client clock off by ", skew, "s (stale or replayed)")
					return
				}
				// Record the salt only once it authenticates, so junk
				// connections cannot fill the filter.
				if !c.salts.Check([waesSaltLen]byte(salt)) {
					c.rErr = errors.New("trojan/waes256: replayed client salt")
					return
				}
				serverSalt := make([]byte, waesSaltLen)
				if _, err := rand.Read(serverSalt); err != nil {
					c.rErr = err
					return
				}
				c.password = pw
				c.r = r
				c.w = &seqAEAD{aead: waesCascade(pw, "s2c", salt, serverSalt)}
				c.wPrefix = serverSalt
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
		c.initClient() // the server's salt only follows the client's salt
		if c.wErr != nil {
			return c.wErr
		}
		c.initClientRead()
		return c.rErr
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
		frame := append(append(c.wPrefix, h[:]...), ct...)
		c.wPrefix = nil
		if _, err := c.Conn.Write(frame); err != nil {
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
