package mtenant

import (
	"encoding/json"
	"fmt"
	"time"
)

// TenantInfo 存入数据库的租户信息
type TenantInfo struct {
	TenantID string `json:"tenant_id"`
	//unique名字，可以作为DB表的唯一索引
	TenantName string `json:"tenant_name"`
	//外显名字
	DisplayName string `json:"display_name"`
	//创建时间
	CreatedAt time.Time `json:"created_at"`
	//修改时间
	UpdatedAt time.Time `json:"update_at"`
	//访问OAuth数据库需要的信息
	OAuthDBInfo string `json:"oauth_dbinfo"`
	//访问RBAC数据库需要的信息
	RBACDBInfo string `json:"rbac_dbinfo"`
}

// GetTenantID 获取TenantInfo的属性TenantID
func (t *TenantInfo) GetTenantID() string {
	return t.TenantID
}

// SetTenantID 设置TenantInfo的属性TenantID
func (t *TenantInfo) SetTenantID(tenantID string) {
	t.TenantID = tenantID
}

// GetTenantName 获取TenantInfo的属性TenantName
func (t *TenantInfo) GetTenantName() string {
	return t.TenantName
}

// SetTenantName 设置TenantInfo的属性TenantName
func (t *TenantInfo) SetTenantName(tenantName string) {
	t.TenantName = tenantName
}

// GetDisplayName 获取TenantInfo的属性DisplayName
func (t *TenantInfo) GetDisplayName() string {
	return t.DisplayName
}

// SetDisplayName 设置TenantInfo的属性DisplayName
func (t *TenantInfo) SetDisplayName(displayName string) {
	t.DisplayName = displayName
}

// GetCreatTime 获取TenantInfo的属性CreatedAt
func (t *TenantInfo) GetCreatTime() time.Time {
	return t.CreatedAt
}

// SetCreatTime 设置TenantInfo的属性CreatedAt为当前时间
func (t *TenantInfo) SetCreatTime() {
	t.CreatedAt = time.Now()
}

// GetUpdateTime 获取TenantInfo的属性UpdatedAt
func (t *TenantInfo) GetUpdateTime() time.Time {
	return t.UpdatedAt
}

// SetUpdateTime 设置TenantInfo的属性UpdatedAt为当前时间
func (t *TenantInfo) SetUpdateTime() {
	t.UpdatedAt = time.Now()
}

// GetOAuthDBInfo 获取TenantInfo的属性OAuthDBInfo
func (t *TenantInfo) GetOAuthDBInfo() string {
	return t.OAuthDBInfo
}

// SetOAuthDBInfo 设置TenantInfo的属性OAuthDBInfo
func (t *TenantInfo) SetOAuthDBInfo(oAuthDBInfo string) {
	t.OAuthDBInfo = oAuthDBInfo
}

// GetRBACDBInfo 获取TenantInfo的属性OAuthDBInfo
func (t *TenantInfo) GetRBACDBInfo() string {
	return t.RBACDBInfo
}

// SetRBACDBInfo 设置TenantInfo的属性RBACDBInfo
func (t *TenantInfo) SetRBACDBInfo(rbacDBInfo string) {
	t.RBACDBInfo = rbacDBInfo
}

// Prettify 格式化输出,便于调试
func (t *TenantInfo) Prettify() string {
	str, _ := json.MarshalIndent(t, "", "    ")
	return string(str)
}

// TenantDB 租户信息的数据库访问接口
type TenantDB interface {
	Read(tenantID string) (*TenantInfo, error)
	Delete(tenantID string) error
	Create(tenant *TenantInfo) error
	Update(tenant *TenantInfo) error
}

// BackendTenantDB 实现BackendTenantDB接口的后端数据库，仅示意
type BackendTenantDB struct {
	tenantStore map[string]*TenantInfo // key:tenantID, value:*TenantInfo
}

// NewBackendTenantDB 生成BackendTenantDB实例
func NewBackendTenantDB() *BackendTenantDB {
	return &BackendTenantDB{map[string]*TenantInfo{}}
}

// Read 通过tenantID从数据库获取TenantInfo
func (b *BackendTenantDB) Read(tenantID string) (*TenantInfo, error) {
	m, ok := b.tenantStore[tenantID]
	if !ok {
		return nil, fmt.Errorf("this tenant not exist:%s", tenantID)
	}
	return m, nil
}

// Delete 通过tenantID从数据库删除TenantInfo
func (b *BackendTenantDB) Delete(tenantID string) error {
	if _, ok := b.tenantStore[tenantID]; !ok {
		return fmt.Errorf("this tenant not exist:%s", tenantID)
	}
	delete(b.tenantStore, tenantID)
	return nil
}

// Create 将TenantInfo实例增加到DB
func (b *BackendTenantDB) Create(tenantInfo *TenantInfo) error {
	if _, ok := b.tenantStore[tenantInfo.TenantID]; ok {
		return fmt.Errorf("this tenant already exist:%s", tenantInfo.TenantID)
	}
	b.tenantStore[tenantInfo.TenantID] = tenantInfo
	return nil
}

// Update 将TenantInfo实例更新到DB
func (b *BackendTenantDB) Update(tenantInfo *TenantInfo) error {
	if _, ok := b.tenantStore[tenantInfo.TenantID]; !ok {
		return fmt.Errorf("this tenant not exist:%s", tenantInfo.TenantID)
	}
	b.tenantStore[tenantInfo.TenantID] = tenantInfo
	return nil
}
