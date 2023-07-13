package crypt

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func b64Decode(s string) []byte {
	bytes, _ := base64.StdEncoding.DecodeString(s)
	return bytes
}
func b64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func TestAESCBC_128(t *testing.T) {
	plain := "test crypt"
	key, iv := "E15E2A40282E42E0", "3B3B16BFE6A8A7CF"
	expect := "PP89uNAvdf3KvSVkwe5Usw=="

	result, err := AESEncryptCBC([]byte(key), []byte(iv), []byte(plain))
	assert.Equal(t, expect, b64Encode(result), "should equal")
	assert.NoError(t, err)

	result2, err := AESDecryptCBC([]byte(key), []byte(iv), result)
	assert.Equal(t, plain, string(result2), "should equal")
	assert.NoError(t, err)
}

func TestAESCBC_256(t *testing.T) {
	plain := "test crypt"
	key, iv := "E15E2A40282E42E01163B2643C208505", "3B3B16BFE6A8A7CF"
	expect := "NI5P7cbJMFHUv3X0TB4QeQ=="

	result, err := AESEncryptCBC([]byte(key), []byte(iv), []byte(plain))
	assert.Equal(t, expect, b64Encode(result), "should equal")
	assert.NoError(t, err)

	result2, err := AESDecryptCBC([]byte(key), []byte(iv), result)
	assert.Equal(t, plain, string(result2), "should equal")
	assert.NoError(t, err)
}

func TestAESECB(t *testing.T) {
	plain := "test crypt"
	key := "E15E2A40282E42E01163B2643C208505"
	expect := "vzvqC5+V5G5/tuNunf6RAA=="

	result, err := AESEncryptECB([]byte(key), []byte(plain))
	assert.Equal(t, expect, b64Encode(result), "should equal")
	assert.NoError(t, err)

	result2, err := AESDecryptECB([]byte(key), result)
	assert.Equal(t, plain, string(result2), "should equal")
	assert.NoError(t, err)
}
