// Package mtenant 本文件实现了多租户管理
// 对于多租户的实现，通常的实现都是数据存储型多租户，本实现则主要是接入型多租户。
package mtenant

import "saas/oauth"

// MTenant 定义多租户
type MTenant struct {
	multiTenantDB TenantDB
}

// NewMTenant 生成MTenant实例
func NewMTenant(tnDB TenantDB) *MTenant {
	return &MTenant{tnDB}
}

// GetTenant 返回tenantID对应的Tenant实例，后续的操作都通过Tenant实例来进行
func (m *MTenant) GetTenant(tenantID string) (*Tenant, error) {
	tnInfo, err := m.multiTenantDB.Read(tenantID)
	if err != nil {
		return nil, err
	}
	tenant := NewTenant(tnInfo.TenantID, tnInfo.TenantName, tnInfo.DisplayName,
		oauth.NewBackendMerchantDB(), // 生产的环境中，应根据tnInfo.OAuthDBInfo生成对应的数据库实例
		oauth.NewBackendTokenDB())    // 生产的环境中，应根据tnInfo.OAuthDBInfo生成对应的数据库实例
	return tenant, nil
}
