package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math"
)

// RSAEncrypt RSA 公钥加密
func RSAEncrypt(key, plaintext []byte) ([]byte, error) {
	pubkey, err := LoadPublicKey(key)
	if err != nil {
	                 	return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pubkey, plaintext)
}

// RSADecrypt RSA 私钥解密
func RSADecrypt(key, ciphertext []byte) ([]byte, error) {
	prikey, err := LoadPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, prikey, ciphertext)
}

// GenerateKey 生成RSA密钥对, 包括private和public key
func GenerateKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publickey := &privatekey.PublicKey
	return privatekey, publickey, nil
}

// GenerateKeyStr 生成RSA密钥对，并将密钥转成字符串形式
func GenerateKeyStr() (prikey, pubkey string, err error) {
	privatekey, publickey, err := GenerateKey()
	if err != nil {
		return "", "", err
	}
	var pribuf []byte
	if pribuf, err = DumpPrivateKey(privatekey); err != nil {
		return
	}
	var pubbuf []byte
	if pubbuf, err = DumpPublicKey(publickey); err != nil {
		return
	}
	return string(pribuf), string(pubbuf), nil
}

// DumpPublicKey 转存公钥
func DumpPublicKey(key *rsa.PublicKey) ([]byte, error) {
	keybytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		  return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keybytes,
	}
	return pem.EncodeToMemory(block), nil
}

// DumpPrivateKey 转存私钥
func DumpPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(block), nil
}

// LoadPublicKey 获取公钥
func LoadPublicKey(publickey []byte) (*rsa.PublicKey, error) {
	// decode public key
	block, _ := pem.Decode(publickey)
	if block == nil {
		return nil, errors.New("get public key error")
	}
	// x509 parse public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("assert rsa public key error")
	}
	return rsaPub, nil
}

// LoadPrivateKey 获取私钥
func LoadPrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("get private key error")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}
	pri2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPriv, ok := pri2.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("assert rsa private key error")
	}
	return rsaPriv, nil
}

const maxLineLength = 64

// FormatKeyToMultiline 将单行密钥格式化成多行
func FormatKeyToMultiline(key []byte, isPrivateKey bool) []byte {
	var keywords = []byte("-----")
	beginStr := map[bool]string{
		true:  "-----BEGIN RSA PRIVATE KEY-----\n", // 私钥
		false: "-----BEGIN PUBLIC KEY-----\n",      // 公钥
	}
	endStr := map[bool]string{
		true:  "-----END RSA PRIVATE KEY-----\n", // 私钥
		false: "-----END PUBLIC KEY-----\n",      // 公钥
	}
	// 包含-----或换行，直接返回原始key
	if bytes.HasPrefix(key, keywords) || bytes.HasSuffix(key, keywords) || bytes.Contains(key, []byte("\n")) {
		return key
	}

	var buf bytes.Buffer
	buf.WriteString(beginStr[isPrivateKey])
	keyLen := len(key)
	loop := int(math.Ceil(float64(keyLen) / float64(maxLineLength)))
	linebreak := []byte("\n")
	for i := 0; i < loop; i++ {
		start := i * maxLineLength
		end := start + maxLineLength
		if end >= keyLen {
			end = keyLen
		}
		buf.Write(key[start:end])
		buf.Write(linebreak)
	}
	buf.WriteString(endStr[isPrivateKey])

	return buf.Bytes()
}
