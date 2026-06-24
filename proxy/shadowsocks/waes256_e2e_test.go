package shadowsocks_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/shadowsocks"
)

// TestTCPRequestWAES256 runs a full Shadowsocks TCP request through the real
// encrypt (WriteTCPRequest) and decrypt (ReadTCPSession) data path using the
// WAES-256 AEAD cipher method, proving proxied data is encrypted with WAES-256.
func TestTCPRequestWAES256(t *testing.T) {
	request := &protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("example.com"),
		Port:    1234,
		User: &protocol.MemoryUser{
			Email: "love@example.com",
			Account: toAccount(&Account{
				Password:   "waes-256-password",
				CipherType: CipherType_WAES_256_GCM,
			}),
		},
	}
	payload := []byte("the quick brown fox jumps over the lazy dog")

	cache := buf.New()
	defer cache.Release()

	data := buf.New()
	common.Must2(data.Write(payload))

	writer, err := WriteTCPRequest(request, cache)
	common.Must(err)
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

	// The wire bytes must not contain the cleartext payload.
	if got := cache.Bytes(); contains(got, payload) {
		t.Fatal("payload appears in cleartext on the wire")
	}

	validator := new(Validator)
	validator.Add(request.User)
	decodedRequest, reader, err := ReadTCPSession(validator, cache)
	common.Must(err)
	if !equalRequestHeader(decodedRequest, request) {
		t.Error("different request after WAES-256 round-trip")
	}

	decodedData, err := reader.ReadMultiBuffer()
	common.Must(err)
	if r := cmp.Diff(decodedData[0].Bytes(), payload); r != "" {
		t.Error("data mismatch after WAES-256 decrypt: ", r)
	}
}

// TestUDPRequestWAES256 runs a full Shadowsocks UDP packet through EncodeUDPPacket
// and DecodeUDPPacket with the WAES-256 cascade method (AES-256-CTR then WAES-256),
// proving UDP payloads are encrypted with the cascade too.
func TestUDPRequestWAES256(t *testing.T) {
	request := protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandUDP,
		Address: net.DomainAddress("example.com"),
		Port:    1234,
		User: &protocol.MemoryUser{
			Email: "love@example.com",
			Account: toAccount(&Account{
				Password:   "waes-256-password",
				CipherType: CipherType_WAES_256_GCM,
			}),
		},
	}

	data := buf.New()
	defer data.Release()
	common.Must2(data.WriteString("udp string for aes-256 then waes-256"))
	payload := append([]byte(nil), data.Bytes()...)

	encoded, err := EncodeUDPPacket(&request, data.Bytes())
	common.Must(err)
	defer encoded.Release()

	// The encoded packet must not contain the cleartext payload.
	if contains(encoded.Bytes(), payload) {
		t.Fatal("UDP payload appears in cleartext on the wire")
	}

	validator := new(Validator)
	validator.Add(request.User)
	decodedRequest, decodedData, err := DecodeUDPPacket(validator, encoded)
	common.Must(err)
	defer decodedData.Release()

	if !equalRequestHeader(decodedRequest, &request) {
		t.Error("different request after WAES-256 UDP round-trip")
	}
	if r := cmp.Diff(decodedData.Bytes(), payload); r != "" {
		t.Error("UDP data mismatch after WAES-256 decrypt: ", r)
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
