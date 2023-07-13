package crypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

// Md5String 计算字符串进行MD5值，并且可以选择返回大、小写
func Md5String(s string, upper bool) string {
	return Md5Bytes([]byte(s), upper)
}

// Md5Bytes 对字符数组进行MD5加密，并且可以选择返回大、小写
func Md5Bytes(b []byte, upper bool) string {
	return HashBytes(md5.New, b, upper)
}

// Sha1String 对字符串进行sha1加密，并且可以选择返回大、小写
func Sha1String(s string, upper bool) string {
	return Sha1Bytes([]byte(s), upper)
}

// Sha1Bytes 对字符数组进行sha1加密，并且可以选择返回大、小写
func Sha1Bytes(b []byte, upper bool) string {
	return HashBytes(sha1.New, b, upper)
}

// Sha256String 对字符串进行sha256加密，并且可以选择返回大、小写
func Sha256String(s string, upper bool) string {
	return Sha256Bytes([]byte(s), upper)
}

// Sha256Bytes 对字符数组进行sha256加密，并且可以选择返回大、小写
func Sha256Bytes(b []byte, upper bool) string {
	return HashBytes(sha256.New, b, upper)
}

// Sha512String 对字符串进行sha512加密，并且可以选择返回大、小写
func Sha512String(s string, upper bool) string {
	return Sha512Bytes([]byte(s), upper)
}

// Sha512Bytes 对字符数组进行sha512加密，并且可以选择返回大、小写
func Sha512Bytes(b []byte, upper bool) string {
	return HashBytes(sha512.New, b, upper)
}

// HmacMD5 Hmac-md5编码
func HmacMD5(source, key string) (result []byte, err error) {
	return HmacHash(md5.New, source, key)
}

// HmacMD5Base64 Hmac-md5编码 返回Base64
func HmacMD5Base64(source, key string) (result string, err error) {
	bytes, err := HmacMD5(source, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// HmacSha1 Hmac-SHA1编码
func HmacSha1(source, key string) (result []byte, err error) {
	return HmacHash(sha1.New, source, key)
}

// HmacSha1Base64 Hmac-SHA1编码 返回Base64
func HmacSha1Base64(source, key string) (result string, err error) {
	bytes, err := HmacSha1(source, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// HmacSha256 Hmac-SHA256编码
func HmacSha256(source, key string) (result []byte, err error) {
	return HmacHash(sha256.New, source, key)
}

// HmacSha512 Hmac-SHA512编码
func HmacSha512(source, key string) (result []byte, err error) {
	return HmacHash(sha512.New, source, key)
}

// HmacHash Hmac-xxx编码
func HmacHash(h func() hash.Hash, source, key string) (result []byte, err error) {
	mac := hmac.New(h, []byte(key))
	if _, err = mac.Write([]byte(source)); err != nil {
		return
	}
	return mac.Sum(nil), nil
}

// HashBytes 对字符数组进行哈希，并且可以选择返回大、小写
func HashBytes(h func() hash.Hash, b []byte, upper bool) string {
	m := h()
	m.Write(b)
	result := m.Sum(nil)
	if upper {
		return fmt.Sprintf("%X", result)
	}
	return fmt.Sprintf("%x", result)
}
