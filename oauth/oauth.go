// Package oauth 本文件实现了商户的鉴权
// 这里的实现有以下特点：
// 1）参考了微信小程序后台的鉴权方式，沿用了AccessToke与RefreshToken的体系
// 2）每个商户都有自己的公私钥对，商户在获取AccessToke的时候需要用私钥签名，以验证商户身份
// 3）这里oauth体系是面向商户的，而不是面向终端用户的。
package oauth

import (
	"fmt"
	"saas/crypt"
)

// MerchantInfo 将多个参数打包成一个结构体，方便参数传递
type MerchantInfo struct {
	MerchantID string
	AppID      string
}

// OAuth 主结构体，封装商户数据与Token数据
type OAuth struct {
	merchantDB MerchantDB
	tokenDB    TokenDB
}

// NewOAuth 生成OAuth结构体
func NewOAuth(mdb MerchantDB, tdb TokenDB) *OAuth {
	return &OAuth{mdb, tdb}
}

// MerchantDB 返回OAuth中的merchantDB实例
func (o *OAuth) MerchantDB() MerchantDB {
	return o.merchantDB
}

// TokenDB 返回OAuth中的tokenDB实例
func (o *OAuth) TokenDB() TokenDB {
	return o.tokenDB
}

// GetAccessToken 商户获取某个App对应的accesstoken
func (o *OAuth) GetAccessToken(mInfo *MerchantInfo, targetSign string) (string, error) {
	merchant, err := o.merchantDB.Read(mInfo.MerchantID)
	if err != nil {
		return "", err
	}
	if err = VerifyMerchantInfo(merchant.GetKey(), mInfo, targetSign); err != nil {
		return "", err
	}
	if !merchant.HasApp(mInfo.AppID) {
		return "", fmt.Errorf("merchant(%s) do not have app(%s)", mInfo.MerchantID, mInfo.AppID)
	}
	app := merchant.GetApp(mInfo.AppID)
	token, err := o.tokenDB.CreateToken(app.AppID, app.AppSecret)
	return token.AccessToken, err
}

// RefreshToken 商户对某个App对应的accesstoken进行续期操作
func (o *OAuth) RefreshToken(mInfo *MerchantInfo, accessToken string) (string, error) {
	merchant, err := o.merchantDB.Read(mInfo.MerchantID)
	if err != nil {
		return "", err
	}
	if !merchant.HasApp(mInfo.AppID) {
		return "", fmt.Errorf("merchant(%s) do not have app(%s)", mInfo.MerchantID, mInfo.AppID)
	}
	return o.tokenDB.RefreshToken(accessToken)
}

// VerifyToken 验证商户的某个App对应的accesstoken是否有效
func (o *OAuth) VerifyToken(mInfo *MerchantInfo, accessToken string) error {
	merchant, err := o.merchantDB.Read(mInfo.MerchantID)
	if err != nil {
		return err
	}
	if !merchant.HasApp(mInfo.AppID) {
		return fmt.Errorf("merchant(%s) do not have app(%s)", mInfo.MerchantID, mInfo.AppID)
	}
	return o.tokenDB.VerifyToken(accessToken)
}

// RevokeToken 将商户的某个App对应的accesstoken设置为无效
func (o *OAuth) RevokeToken(mInfo *MerchantInfo, accessToken string) error {
	merchant, err := o.merchantDB.Read(mInfo.MerchantID)
	if err != nil {
		return err
	}
	if !merchant.HasApp(mInfo.AppID) {
		return fmt.Errorf("merchant(%s) do not have app(%s)", mInfo.MerchantID, mInfo.AppID)
	}
	return o.tokenDB.DeleteToken(accessToken)
}

// SignMerchantInfo 对商户的请求信息进行签名。采用非对称加密算法。
func SignMerchantInfo(privateKey string, info *MerchantInfo) (string, error) {
	plaintext := fmt.Sprintf("%s:%s", info.MerchantID, info.AppID)
	return crypt.SignSha256WithRsa(privateKey, plaintext)
}

// VerifyMerchantInfo 对商户的请求信息进行验签。采用非对称加密算法。
func VerifyMerchantInfo(publicKey string, minfo *MerchantInfo, targetSign string) error {
	plaintext := fmt.Sprintf("%s:%s", minfo.MerchantID, minfo.AppID)
	return crypt.VerifySignSha256WithRsa(publicKey, plaintext, targetSign)
}
