package mtenant

import (
	"encoding/json"
	"saas/oauth"
	"saas/rbac"
	"time"
)

// Tenant 定义一个租户
type Tenant struct {
	TenantID string `json:"tenant_id"`
	//unique名字，可以作为DB表的唯一索引
	TenantName string `json:"tenant_name"`
	//外显名字
	DisplayName string `json:"display_name"`
	//创建时间
	CreatedAt time.Time `json:"created_at"`
	//修改时间
	UpdatedAt time.Time `json:"update_at"`
	//采用OAuth机制进行身份鉴别
	oAuth *oauth.OAuth
	//采用RBAC模型进行权限控制
	rbacMatrix *rbac.RBACMatrix
}

// NewTenant 初始化Tenant实例
func NewTenant(tenantID string, tenantName string, displayName string,
	mdb oauth.MerchantDB, tdb oauth.TokenDB) *Tenant {
	return &Tenant{
		TenantID:    tenantID,
		TenantName:    tenantName,
		DisplayName:     displayName,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		oAuth:       oauth.NewOAuth(mdb, tdb),
		rbacMatrix:  rbac.NewRBACMatrix(),
	}
}

// Prettify 格式化输出,便于调试
func (t *Tenant) Prettify() string {
	str, _ := json.MarshalIndent(t, "", "    ")
	return string(str)
}

// ---------------------------------------------------
// 以下是商户相关操作

// AddMerchant 新增商户
func (t *Tenant) AddMerchant(merchant *oauth.Merchant) error {
	if err := t.oAuth.MerchantDB().Create(merchant); err != nil {
		return err
	}
	// 这里把merchant当做RBAC中的User
	merchantUser := &rbac.User{UserID: merchant.MerchantID}
	t.rbacMatrix.AddUser(merchantUser)
	return nil
}

// DelMerchant 删除商户
func (t *Tenant) DelMerchant(merchant *oauth.Merchant) error {
	if err := t.oAuth.MerchantDB().Delete(merchant.MerchantID); err != nil {
		return err
	}
	// 这里把merchant当做RBAC中的User
	merchantUser := &rbac.User{UserID: merchant.MerchantID}
	t.rbacMatrix.DelUser(merchantUser)
	return nil
}

// HasMerchant 判断商户是否存在
func (t *Tenant) HasMerchant(merchant *oauth.Merchant) bool {
	merchantUser := &rbac.User{UserID: merchant.MerchantID}
	return t.rbacMatrix.HasUser(merchantUser)
}

// ---------------------------------------------------
// 以下是基于OAuth的身份鉴别

// GetAccessToken 商户获取某个App对应的accesstoken
func (t *Tenant) GetAccessToken(merchantID, appID, targetSign string) (string, error) {
	return t.oAuth.GetAccessToken(&oauth.MerchantInfo{MerchantID: merchantID, AppID: appID}, targetSign)
}

// RefreshToken 商户对某个App对应的accesstoken进行续期操作
func (t *Tenant) RefreshToken(merchantID, appID, accessToken string) (string, error) {
	return t.oAuth.RefreshToken(&oauth.MerchantInfo{MerchantID: merchantID, AppID: appID}, accessToken)
}

// VerifyToken 验证商户的某个App对应的accesstoken是否有效
func (t *Tenant) VerifyToken(merchantID, appID, accessToken string) error {
	return t.oAuth.VerifyToken(&oauth.MerchantInfo{MerchantID: merchantID, AppID: appID}, accessToken)
}

// RevokeToken 将商户的某个App对应的accesstoken设置为无效
func (t *Tenant) RevokeToken(merchantID, appID, accessToken string) error {
	return t.oAuth.RevokeToken(&oauth.MerchantInfo{MerchantID: merchantID, AppID: appID}, accessToken)
}

// ---------------------------------------------------
// 以下是基于RBAC的权限控制

// Permit 给merchantID指向的商户授予角色和权限
func (t *Tenant) Permit(merchantID string, role *rbac.Role, perm *rbac.Permission) error {
	merchantUser := &rbac.User{UserID: merchantID}
	r := t.rbacMatrix.GetRBAC(merchantUser)
	return r.Permit(role, perm)
}

// Revoke 从merchantID指向的商户收回角色和权限
func (t *Tenant) Revoke(merchantID string, role *rbac.Role, perm *rbac.Permission) error {
	merchantUser := &rbac.User{UserID: merchantID}
	r := t.rbacMatrix.GetRBAC(merchantUser)
	return r.Revoke(role, perm)
}

// IsGranted 判断merchantID指向的商户是否拥有角色和权限,不考虑继承关系
func (t *Tenant) IsGranted(merchantID string, role *rbac.Role, perm *rbac.Permission) bool {
	merchantUser := &rbac.User{UserID: merchantID}
	r := t.rbacMatrix.GetRBAC(merchantUser)
	return r.IsGranted(role, perm)
}

// IsGrantInherited 判断merchantID指向的商户是否拥有角色和权限,考虑继承关系
func (t *Tenant) IsGrantInherited(merchantID string, role *rbac.Role, perm *rbac.Permission) bool {
	merchantUser := &rbac.User{UserID: merchantID}
	r := t.rbacMatrix.GetRBAC(merchantUser)
	return r.IsGrantInherited(role, perm)
}

// ---------------------------------------------------
// 进一步操作直接调用底层OAuth和RBACMatrix的相关操作来实现

// OAuth 返回底层OAuth实例
func (t *Tenant) OAuth() *oauth.OAuth {
	return t.oAuth
}

// RBACMatrix 返回底层RBACMatrix实例
func (t *Tenant) RBACMatrix() *rbac.RBACMatrix {
	return t.rbacMatrix
}
