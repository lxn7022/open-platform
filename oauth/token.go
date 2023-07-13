package oauth

import (
	"encoding/json"
	"time"
)

// Token 定义Token的所有属性
type Token struct {
	AppID            string        `json:"appid"`
	AppSecret        string        `json:"app_secret"`
	Scope            string        `json:"scope"`
	AccessToken      string        `json:"access"`
	AccessCreateAt   time.Time     `json:"access_create_at"`
	AccessExpiresIn  time.Duration `json:"access_expires_in"`
	RefreshToken     string        `json:"refresh"`
	RefreshCreateAt  time.Time     `json:"refresh_create_at"`
	RefreshExpiresIn time.Duration `json:"refresh_expires_in"`
}

// NewToken 创建Token实例
func NewToken() *Token {
	return &Token{}
}

// GetAccessToken 获取AccessToken
func (t *Token) GetAccessToken() string {
	return t.AccessToken
}

// SetAccessToken 设置AccessToken
func (t *Token) SetAccessToken(accessToken string) {
	t.AccessToken = accessToken
}

// GetAccessCreateAt 获取AccessToken的创建时间
func (t *Token) GetAccessCreateAt() time.Time {
	return t.AccessCreateAt
}

// SetAccessCreateAt 设置AccessToken的创建时间
func (t *Token) SetAccessCreateAt(createAt time.Time) {
	t.AccessCreateAt = createAt
}

// GetAccessExpiresIn 获取AccessToken的截止时间，单位是秒
func (t *Token) GetAccessExpiresIn() time.Duration {
	return t.AccessExpiresIn
}

// SetAccessExpiresIn 设置AccessToken的截止时间，单位是秒
func (t *Token) SetAccessExpiresIn(exp time.Duration) {
	t.AccessExpiresIn = exp
}

// GetRefreshToken 获取RefreshToken
func (t *Token) GetRefreshToken() string {
	return t.RefreshToken
}

// SetRefreshToken 设置RefreshToken
func (t *Token) SetRefreshToken(refresh string) {
	t.RefreshToken = refresh
}

// GetRefreshCreateAt 获取RefreshToken的创建时间
func (t *Token) GetRefreshCreateAt() time.Time {
	return t.RefreshCreateAt
}

// SetRefreshCreateAt 设置RefreshToken的创建时间
func (t *Token) SetRefreshCreateAt(createAt time.Time) {
	t.RefreshCreateAt = createAt
}

// GetRefreshExpiresIn 获取RefreshToken的截止时间，单位是秒
func (t *Token) GetRefreshExpiresIn() time.Duration {
	return t.RefreshExpiresIn
}

// SetRefreshExpiresIn 设置RefreshToken的截止时间，单位是秒
func (t *Token) SetRefreshExpiresIn(exp time.Duration) {
	t.RefreshExpiresIn = exp
}

// Prettify 格式化输出,便于调试
func (t *Token) Prettify() string {
	str, _ := json.MarshalIndent(t, "", "    ")
	return string(str)
}
