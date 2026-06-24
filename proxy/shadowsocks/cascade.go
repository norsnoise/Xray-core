package shadowsocks

import (
	"crypto/cipher"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto/waes256"
)

// createAes256ThenWaes256 builds the AES-256-CTR + WAES-256 cascade, i.e. the
// data is encrypted with AES-256-CTR first, then sealed with WAES-256 ->
// WAES-256(AES-256-CTR(data)). See common/crypto/waes256.NewCascadeAEAD.
// Total AEAD overhead stays 16 bytes, so the Shadowsocks framing is unchanged.
func createAes256ThenWaes256(key []byte) cipher.AEAD {
	aead, err := waes256.NewCascadeAEAD(key)
	common.Must(err)
	return aead
}
