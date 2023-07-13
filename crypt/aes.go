package crypt

import (
	"bytes"
	"errors"

	"crypto/aes"
	"crypto/cipher"
)

// PKCS7Padding 填充
func PKCS7Padding(orig []byte, blockSize int) []byte {
	padding := blockSize - len(orig)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(orig, padtext...)
}

// PKCS7UnPadding 解填充
func PKCS7UnPadding(orig []byte) ([]byte, error) {
	length := len(orig)
	if length == 0 {
		return nil, nil
	}
	unpadding := int(orig[length-1])
	size := length - unpadding
	if size < 0 {
		return nil, errors.New("unpadding length invalid")
	}
	return orig[:size], nil
}

// AESEncryptCBC AES CBC模式加密
func AESEncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data := PKCS7Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, data)
	return ciphertext, nil
}

// AESDecryptCBC AES CBC模式解密
func AESDecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return PKCS7UnPadding(plaintext)
}

// AESEncryptECB AES ECB模式加密
func AESEncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	data := PKCS7Padding(plaintext, blockSize)
	ciphertext := make([]byte, len(data))
	// 分组分块加密
	for bs, be := 0, blockSize; bs <= len(plaintext); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(ciphertext[bs:be], data[bs:be])
	}
	return ciphertext, nil
}

// AESDecryptECB AES ECB模式加密
func AESDecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	for bs, be := 0, block.BlockSize(); bs < len(ciphertext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
	}
	return PKCS7UnPadding(plaintext)
}
