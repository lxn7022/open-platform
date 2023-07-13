package oauth

import (
	"encoding/json"
	"fmt"
)

// Application 定义App
type Application struct {
	AppID     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
	Scope     string `json:"scope"`
	AppName   string `json:"app_name"`
}

// String 格式化输出
func (a *Application) String() string {
	return fmt.Sprintf("AppID:%s, AppSecret:%s,Scope:%s,AppName:%s", a.AppID, a.AppSecret, a.Scope, a.AppName)
}

// Merchant 定义商户
type Merchant struct {
	MerchantID string                  `json:"merchant_id"`
	PublicKey  string                  `json:"publickey"` //只存储商户公钥
	Apps       map[string]*Application `json:"applications"`
}

// NewMerchant 创建NewMerchant实例
func NewMerchant(merchantID, pubKey string) *Merchant {
	return &Merchant{
		MerchantID: merchantID,
		PublicKey:  pubKey,
		Apps:       map[string]*Application{},
	}
}

// SetKey 修改商户公钥
func (m *Merchant) SetKey(pubKey string) {
	m.PublicKey = pubKey
}

// GetKey 获取商户公钥
func (m *Merchant) GetKey() string {
	return m.PublicKey
}

// AddApp 给商户新增一个App
func (m *Merchant) AddApp(app *Application) bool {
	if _, ok := m.Apps[app.AppID]; !ok {
		m.Apps[app.AppID] = app
		return true
	}
	return false
}

// DelApp 从商户删除一个App
func (m *Merchant) DelApp(app *Application) bool {
	if _, ok := m.Apps[app.AppID]; ok {
		delete(m.Apps, app.AppID)
		return true
	}
	return false
}

// GetApp 根据AppID获取一个App
func (m *Merchant) GetApp(appID string) *Application {
	return m.Apps[appID]
}

// HasApp 判断商户是否包含一个App
func (m *Merchant) HasApp(appID string) bool {
	_, ok := m.Apps[appID]
	return ok
}

// String 用于格式化输出
func (m *Merchant) String() string {
	return fmt.Sprintf("(MerchantID:%v,PublicKey:%v,Apps:%+v)", m.MerchantID, m.PublicKey, m.Apps)
}

// Prettify 格式化输出,便于调试
func (m *Merchant) Prettify() string {
	str, _ := json.MarshalIndent(m, "", "    ")
	return string(str)
}
