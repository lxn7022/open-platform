package crypt

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMd5String(t *testing.T) {
	assert.Equal(t, "84e3672326017c219590eb44c9dd39f0", Md5String("test crypt", false))
	assert.Equal(t, "84E3672326017C219590EB44C9DD39F0", Md5String("test crypt", true))
}

func TestSha1String(t *testing.T) {
	assert.Equal(t, "03bb057a608f6a4572b8dd5ea18285b06c9c598d", Sha1String("test crypt", false))
	assert.Equal(t, "03BB057A608F6A4572B8DD5EA18285B06C9C598D", Sha1String("test crypt", true))
}

func TestSha256String(t *testing.T) {
	assert.Equal(t, "6e3c9b9746f646545b1d9939c201c62ad4a83052edf12eead44c1089410b2c8c", Sha256String("test crypt", false))
	assert.Equal(t, "6E3C9B9746F646545B1D9939C201C62AD4A83052EDF12EEAD44C1089410B2C8C", Sha256String("test crypt", true))
}

func TestSha512String(t *testing.T) {
	assert.Equal(t, `544ae7e88b0e953f678b9723777ad42a5e6f9955fe034a6e0d2d43d3922c5d794c252d96282f01d0`+
		`f28593b3bbd160f808b641aef6ed073eff1060d81982e443`, Sha512String("test crypt", false))
	assert.Equal(t, `544AE7E88B0E953F678B9723777AD42A5E6F9955FE034A6E0D2D43D3922C5D794C252D96282F01D0`+
		`F28593B3BBD160F808B641AEF6ED073EFF1060D81982E443`, Sha512String("test crypt", true))
}

func TestHmacMD5(t *testing.T) {
	result, err := HmacMD5("test crypt", "key")
	assert.Equal(t, "ff3a083d820dbd59adcbacfd544b1436", hex.EncodeToString(result))
	assert.NoError(t, err)
}

func TestHmacMD5Base64(t *testing.T) {
	result, err := HmacMD5Base64("test crypt", "key")
	assert.Equal(t, "ff3a083d820dbd59adcbacfd544b1436", hex.EncodeToString(b64Decode(result)))
	assert.NoError(t, err)
}

func TestHmacSha1(t *testing.T) {
	result, err := HmacSha1("test crypt", "key")
	assert.Equal(t, "1e3aca7f6805c5ae9d916816a4173c198a9a138a", hex.EncodeToString(result))
	assert.NoError(t, err)
}

func TestHmacSha1Base64(t *testing.T) {
	result, err := HmacSha1Base64("test crypt", "key")
	assert.Equal(t, "1e3aca7f6805c5ae9d916816a4173c198a9a138a", hex.EncodeToString(b64Decode(result)))
	assert.NoError(t, err)
}

func TestHmacSha256(t *testing.T) {
	result, err := HmacSha256("test crypt", "key")
	assert.Equal(t, "db98ace40ce593ee24f0859d6adcf870789a1c5d58fc9d087c64110d0950bc1e", hex.EncodeToString(result))
	assert.NoError(t, err)
}
func TestHmacSha512(t *testing.T) {
	result, err := HmacSha512("test crypt", "key")
	assert.Equal(t, "f2e1c5b76ab66fc2183f2d4f68508fb56bbd952f25c7c82d83f362897950484da40c90043a4914d7edb4c5e6861904695dd96756dbbacd081ac99f20f3d8e865", hex.EncodeToString(result))
	assert.NoError(t, err)
}
