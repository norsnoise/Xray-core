package trojan

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// TestAccountProtoRoundTrip verifies the hand-edited descriptor: the new
// Encryption field must survive protobuf marshal/unmarshal.
func TestAccountProtoRoundTrip(t *testing.T) {
	a := &Account{Password: "pw", Encryption: "waes-256"}
	b, err := proto.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var got Account
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Password != "pw" || got.Encryption != "waes-256" {
		t.Fatalf("round-trip lost fields: %q / %q", got.Password, got.Encryption)
	}
}

// TestCryptoConnRoundTrip drives the client/server wrapper over a pipe.
func TestCryptoConnRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	client := NewClientCryptoConn(c1, "secret-password")
	server := NewServerCryptoConn(c2, []string{"wrong-one", "secret-password"}, NewSaltFilter())

	req := []byte("trojan request body over waes256 cascade, longer than one record " +
		string(bytes.Repeat([]byte("X"), 20000)))
	resp := []byte("server response body")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// server reads the request, then replies
		got := make([]byte, len(req))
		readFull(t, server, got)
		if !bytes.Equal(got, req) {
			t.Errorf("server got wrong request")
		}
		if _, err := server.Write(resp); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()

	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(resp))
	readFull(t, client, got)
	if !bytes.Equal(got, resp) {
		t.Fatalf("client got wrong response: %q", got)
	}
	wg.Wait()
}

func readFull(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	off := 0
	for off < len(b) {
		n, err := c.Read(b[off:])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		off += n
	}
}

func TestAccountAsAccountEncryption(t *testing.T) {
	a := &Account{Password: "pw", Encryption: "waes-256"}
	acc, err := a.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if acc.(*MemoryAccount).Encryption != "waes-256" {
		t.Fatalf("MemoryAccount.Encryption = %q", acc.(*MemoryAccount).Encryption)
	}
}

// TestCryptoConnReplayFreshDownloadKey replays one captured client stream to
// two server sessions that do not share a salt filter (e.g. across a restart,
// or after the filter window): each must answer under its own salt, so
// identical replies must not produce identical (or XOR-related) ciphertext.
func TestCryptoConnReplayFreshDownloadKey(t *testing.T) {
	// capture the client's wire bytes
	var wire bytes.Buffer
	rec := &recordConn{w: &wire}
	client := NewClientCryptoConn(rec, "secret-password")
	if _, err := client.Write([]byte("trojan request")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	resp := []byte("identical server response")
	replyWire := func() []byte {
		c1, c2 := net.Pipe()
		defer c1.Close()
		server := NewServerCryptoConn(c2, []string{"secret-password"}, NewSaltFilter())
		go func() {
			c1.Write(wire.Bytes())
		}()
		got := make([]byte, len("trojan request"))
		readFull(t, server, got)
		out := make(chan []byte, 1)
		go func() {
			b := make([]byte, waesSaltLen+2+len(resp)+waesTagLen)
			io.ReadFull(c1, b)
			out <- b
		}()
		if _, err := server.Write(resp); err != nil {
			t.Fatalf("server write: %v", err)
		}
		return <-out
	}

	r1, r2 := replyWire(), replyWire()
	if bytes.Equal(r1[:waesSaltLen], r2[:waesSaltLen]) {
		t.Fatal("server reused its salt")
	}
	if bytes.Equal(r1[waesSaltLen:], r2[waesSaltLen:]) {
		t.Fatal("replayed session reused the download key/nonce")
	}
}

// TestCryptoConnReplayRejected replays one captured client stream to a server
// that already accepted it: the shared salt filter must reject the replay.
func TestCryptoConnReplayRejected(t *testing.T) {
	var wire bytes.Buffer
	client := NewClientCryptoConn(&recordConn{w: &wire}, "secret-password")
	if _, err := client.Write([]byte("trojan request")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	salts := NewSaltFilter()
	session := func() error {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		server := NewServerCryptoConn(c2, []string{"secret-password"}, salts)
		go c1.Write(wire.Bytes())
		_, err := server.Read(make([]byte, 64))
		return err
	}

	if err := session(); err != nil {
		t.Fatalf("first session rejected: %v", err)
	}
	if err := session(); err == nil {
		t.Fatal("replayed session accepted")
	}
}

// TestCryptoConnBadFrameNotRecorded checks that a salt whose first frame fails
// authentication is not remembered, so junk cannot poison the filter.
func TestCryptoConnBadFrameNotRecorded(t *testing.T) {
	var wire bytes.Buffer
	client := NewClientCryptoConn(&recordConn{w: &wire}, "secret-password")
	if _, err := client.Write([]byte("trojan request")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	good := wire.Bytes()
	bad := append([]byte{}, good...)
	bad[waesSaltLen+2+waesTimeLen+waesTagLen-1] ^= 1 // corrupt the first record's tag

	salts := NewSaltFilter()
	session := func(b []byte) error {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		server := NewServerCryptoConn(c2, []string{"secret-password"}, salts)
		go c1.Write(b)
		_, err := server.Read(make([]byte, 64))
		return err
	}

	if err := session(bad); err == nil {
		t.Fatal("corrupted frame accepted")
	}
	if err := session(good); err != nil {
		t.Fatalf("genuine session rejected after a bad frame with its salt: %v", err)
	}
}

// TestCryptoConnClockSkew checks the first-record timestamp: a client clock
// within waesMaxClockSkew is accepted, one beyond it (or an old capture) is not.
func TestCryptoConnClockSkew(t *testing.T) {
	defer func() { waesNow = time.Now }()
	base := time.Now()

	for _, tc := range []struct {
		name   string
		offset time.Duration // client clock minus server clock
		ok     bool
	}{
		{"in sync", 0, true},
		{"client ahead within skew", (waesMaxClockSkew - 5) * time.Second, true},
		{"client behind within skew", -(waesMaxClockSkew - 5) * time.Second, true},
		{"client ahead beyond skew", (waesMaxClockSkew + 5) * time.Second, false},
		{"old capture", -10 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wire bytes.Buffer
			waesNow = func() time.Time { return base.Add(tc.offset) }
			client := NewClientCryptoConn(&recordConn{w: &wire}, "secret-password")
			if _, err := client.Write([]byte("trojan request")); err != nil {
				t.Fatalf("client write: %v", err)
			}

			waesNow = func() time.Time { return base }
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			server := NewServerCryptoConn(c2, []string{"secret-password"}, NewSaltFilter())
			go c1.Write(wire.Bytes())
			_, err := server.Read(make([]byte, 64))
			if tc.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// recordConn is a write-only net.Conn that records what is written to it.
type recordConn struct {
	net.Conn
	w io.Writer
}

func (r *recordConn) Write(b []byte) (int, error) { return r.w.Write(b) }
