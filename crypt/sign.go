// Package crypt 本模块主要用于用户身份鉴别，使用 RSAWithSHA256算法，用私钥签名，用公钥验签。
package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
)

// 常量定义
const (
	// 签名方式
	SignMD5           = "MD5"
	SignHmacMD5       = "HMAC-MD5"
	SignHmacSha1      = "HMAC-SHA1"
	SignSHA1WithRSA   = "SHA1WithRSA"
	SignSHA256WithRSA = "SHA256WithRSA"
)

// SignParams 签名参数
type SignParams struct {
	SignType   string
	PrivateKey string
	Secret     string
	Md5Upper   bool
	SafeBase64 bool
}

// CalcSign 计算签名
func CalcSign(data string, params *SignParams) (sign string, err error) {
	switch params.SignType {
	case SignMD5:
		sign = Md5String(data, params.Md5Upper)
	case SignHmacMD5:
		sign, err = HmacMD5Base64(data, params.Secret)
	case SignHmacSha1:
		sign, err = HmacSha1Base64(data, params.Secret)
	case SignSHA1WithRSA:
		sign, err = SignSha1WithRsa(params.PrivateKey, data)
	case SignSHA256WithRSA:
		sign, err = SignSha256WithRsa(params.PrivateKey, data)
	default:
		err = fmt.Errorf("unsupport sign type: %v", params.SignType)
	}

	if err != nil {
		return "", err
	}

	if params.SafeBase64 {
		sign = tryToURLSafeBase64(sign)
	}
	return sign, nil
}

// tryToURLSafeBase64 尝试将base64转url safe base64，如果非base64，原样返回
func tryToURLSafeBase64(data string) string {
	if v, err := base64.StdEncoding.DecodeString(data); err == nil {
		data = base64.RawURLEncoding.EncodeToString(v)
	}
	return data
}

// SignPKCS1v15 使用RSA PKCS1v15算法签名
func SignPKCS1v15(key, src []byte, hash crypto.Hash) (string, error) {
	prikey, err := LoadPrivateKey(key)
	if err != nil {
		return "", err
	}
	var h = hash.New()
	h.Write(src)
	hashed := h.Sum(nil)

	signByte, err := rsa.SignPKCS1v15(rand.Reader, prikey, hash, hashed)
	return base64.StdEncoding.EncodeToString(signByte), err
}

// VerifyPKCS1v15 使用RSA PKCS1v15验证签名
func VerifyPKCS1v15(key, src, sig []byte, hash crypto.Hash) error {
	signBuf, err := base64.StdEncoding.DecodeString(string(sig))
	if err != nil {
		return err
	}
	pubkey, err := LoadPublicKey(key)
	if err != nil {
		return err
	}
	var h = hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pubkey, hash, hashed, signBuf)
}

// SignSha1WithRsa 使用RSAWithSHA1算法签名
func SignSha1WithRsa(privateKey, data string) (string, error) {
	return SignPKCS1v15([]byte(privateKey), []byte(data), crypto.SHA1)
}

// VerifySignSha1WithRsa 使用RSAWithSHA1验证签名
func VerifySignSha1WithRsa(publicKey, source, targetSign string) error {
	return VerifyPKCS1v15([]byte(publicKey), []byte(source), []byte(targetSign), crypto.SHA1)
}

// SignSha256WithRsa 使用RSAWithSHA256算法签名
func SignSha256WithRsa(privateKey, data string) (string, error) {
	return SignPKCS1v15([]byte(privateKey), []byte(data), crypto.SHA256)
}

// VerifySignSha256WithRsa 使用RSAWithSHA256验证签名
func VerifySignSha256WithRsa(publicKey, source, targetSign string) error {
	return VerifyPKCS1v15([]byte(publicKey), []byte(source), []byte(targetSign), crypto.SHA256)
}
