package trojan

import (
	"bytes"
	"net"
	"sync"
	"testing"

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
	server := NewServerCryptoConn(c2, []string{"wrong-one", "secret-password"})

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
