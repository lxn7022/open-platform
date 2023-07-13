// Package rbac 本文件定义了RBAC模型
// RBAC关联的操作，主要可以分为两类
// 一类是角色相关操作：给用户添加删除角色的操作，比如AddRole、GetRole、DelRole等，返回角色列表Roles、RolesInherited等
// 一类是权限相关操作：给角色授予或者回收权限的操作，比如Permit或Revoke等，判断是否具有某项权限IsPermExist
// 不论是角色相关操作还是权限相关操作，都考虑了继承关系，方法名里带有Inherited字样时，都考虑了继承关系

package rbac

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/thoas/go-funk"
)

// RBAC 定义实现RBAC模型的结构体
type RBAC struct {
	user  User
	roles sync.Map // key: role.ID, value: role
}

// NewRBAC 生成一个新的RBAC实例
func NewRBAC(u User) *RBAC {
	return &RBAC{user: u}
}

// Clone 复制一个RBAC实例
func (rbac *RBAC) Clone(user User) *RBAC {
	r := &RBAC{user: user}
	rbac.roles.Range(func(k, v interface{}) bool {
		r.roles.Store(k, v)
		return true
	})
	return r
}

// AddRole 给用户新增一个角色
func (rbac *RBAC) AddRole(role *Role) error {
	if rbac.IsRoleExist(role) {
		return fmt.Errorf("role %v is already registered", role.ID)
	}
	rbac.roles.Store(role.ID, role)
	return nil
}

// GetRole 根据roleID返回Role实例, 不存在则返回nil
func (rbac *RBAC) GetRole(role *Role) *Role {
	value, ok := rbac.roles.Load(role.ID)
	if !ok {
		return nil
	}
	v, ok := value.(*Role)
	if !ok {
		return nil
	}
	return v
}

// DelRole 删除role指定的角色
func (rbac *RBAC) DelRole(role *Role) error {
	if delRole := rbac.GetRole(role); delRole == nil {
		return fmt.Errorf("role %v is  not registered", role.ID)
	}
	rbac.roles.Delete(role.ID)
	return nil
}

// Roles 返回Role列表，不包括继承的角色
func (rbac *RBAC) Roles() (roles []*Role) {
	rbac.roles.Range(func(k, v interface{}) bool {
		roles = append(roles, v.(*Role))
		return true
	})
	return roles
}

// RolesInherited 返回Role列表，包括继承的角色
func (rbac *RBAC) RolesInherited() (roles []*Role) {
	rbac.roles.Range(func(k, v interface{}) bool {
		roles = append(roles, v.(*Role))
		roles = append(roles, v.(*Role).ParentsDeep()...)
		return true
	})

	// 去重
	return funk.UniqBy(roles, func(p *Role) uint32 {
		return p.ID
	}).([]*Role)
}

// IsRoleExist 检查用户是否已经拥有了一个Role
func (rbac *RBAC) IsRoleExist(role *Role) bool {
	_, ok := rbac.roles.Load(role.ID)
	return ok
}

// IsRoleExistInherited 检查用户是否已经拥有了一个Role，考虑继承的角色
func (rbac *RBAC) IsRoleExistInherited(role *Role) bool {
	if rbac.IsRoleExist(role) {
		return true
	}
	var found bool
	rbac.roles.Range(func(k, v interface{}) bool {
		found = v.(*Role).HasAncestor(role)
		return !found
	})
	return found
}

// Perms 返回用户的Permission权限项, 去除重复项，不包括继承的权限
func (rbac *RBAC) Perms() []*Permission {
	perms := []*Permission{}
	rbac.roles.Range(func(k, v interface{}) bool {
		perms = append(perms, v.(*Role).Permissions()...)
		return true
	})
	// 去重
	return funk.UniqBy(perms, func(p *Permission) uint32 {
		return p.ID
	}).([]*Permission)
}

// PermsInherited 返回用户的Permission权限项, 去除重复项，包括继承的权限
func (rbac *RBAC) PermsInherited() []*Permission {
	perms := []*Permission{}
	rbac.roles.Range(func(k, v interface{}) bool {
		perms = append(perms, v.(*Role).PermissionsDeep()...)
		return true
	})
	// 去重
	return funk.UniqBy(perms, func(p *Permission) uint32 {
		return p.ID
	}).([]*Permission)
}

// IsPermExist 检查用户是否具有某项权限, 不考虑继承的权限
func (rbac *RBAC) IsPermExist(perm *Permission) bool {
	exist := false
	rbac.roles.Range(func(k, v interface{}) bool {
		role := v.(*Role)
		exist = role.IsGranted(perm)
		return !exist
	})
	return exist
}

// IsPermExistInherited 检查用户是否具有某项权限，考虑继承的权限
func (rbac *RBAC) IsPermExistInherited(perm *Permission) bool {
	exist := false
	rbac.roles.Range(func(k, v interface{}) bool {
		role := v.(*Role)
		exist = role.IsGrantInherited(perm)
		return !exist
	})
	return exist
}

// Permit 给用户授权Role以及对应的Permission
func (rbac *RBAC) Permit(role *Role, perm *Permission) error {
	if role == nil {
		return fmt.Errorf("role can not be nil")
	}
	if perm == nil {
		return fmt.Errorf("permission can not be nil")
	}
	if r := rbac.GetRole(role); r != nil {
		// 找到角色, 就地添加权限
		if r.IsGranted(perm) {
			return fmt.Errorf("permission already exist: %v", perm)
		}
		r.Grant(perm)
		return nil
	}
	//没找到角色，生成新role后在添加
	role.Grant(perm)
	return rbac.AddRole(role)

}

// Revoke 回收Role或Permission。如果perm为空，则回收role
func (rbac *RBAC) Revoke(role *Role, perm *Permission) error {
	if role == nil {
		return fmt.Errorf("role can not be nil")
	}
	if perm == nil {
		//perm为空，则回收role
		return rbac.DelRole(role)
	}

	if r := rbac.GetRole(role); r != nil {
		// 找到角色, 移除权限
		r.Revoke(perm)
	}
	return nil
}

// IsGranted 检查是否具有某个Role对应的Permission,不考虑角色继承
func (rbac *RBAC) IsGranted(role *Role, perm *Permission) bool {
	if role == nil || perm == nil {
		return false
	}

	if r := rbac.GetRole(role); r != nil {
		return r.IsGranted(perm)
	}
	return false
}

// IsGrantInherited 检查是否具有某个Role对应的Permission,考虑角色继承
func (rbac *RBAC) IsGrantInherited(role *Role, perm *Permission) bool {
	if role == nil || perm == nil {
		return false
	}
	if r := rbac.GetRole(role); r != nil {
		// 找到角色
		return r.IsGrantInherited(perm)
	}
	return false // 没找到角色
}

// AnyGranted 检查多个Role中是否有一个具有Permission，不考虑角色继承
func (rbac *RBAC) AnyGranted(roles []*Role, perm *Permission) (res bool) {
	for _, r := range roles {
		if rbac.IsGranted(r, perm) {
			return true
		}
	}
	return false
}

// AnyGrantInherited 检查多个Role中是否有一个具有Permission，考虑角色继承
func (rbac *RBAC) AnyGrantInherited(roles []*Role, perm *Permission) (res bool) {
	for _, r := range roles {
		if rbac.IsGrantInherited(r, perm) {
			return true
		}
	}
	return false
}

// AllGranted 检查多个Role中是否每一个都具有Permission，不考虑角色继承
func (rbac *RBAC) AllGranted(roles []*Role, perm *Permission) (res bool) {
	for _, r := range roles {
		if !rbac.IsGranted(r, perm) {
			return false
		}
	}
	return true
}

// AllGrantInherited 检查多个Role中是否每一个都具有Permission，考虑角色继承
func (rbac *RBAC) AllGrantInherited(roles []*Role, perm *Permission) (res bool) {
	for _, r := range roles {
		if !rbac.IsGrantInherited(r, perm) {
			return false
		}
	}
	return true
}

// Prettify 格式化输出RBAC信息
func (rbac *RBAC) Prettify() string {

	strUser := fmt.Sprintf("User:%+v,", rbac.user)

	strPerms := strings.Join(funk.Map(rbac.Perms(), func(perm *Permission) string {
		return fmt.Sprintf("%+v", perm)
	}).([]string), ",")

	strPermsInherited := strings.Join(funk.Map(rbac.PermsInherited(), func(perm *Permission) string {
		return fmt.Sprintf("%+v", perm)
	}).([]string), ",")

	strRoles := strings.Join(funk.Map(rbac.Roles(), func(role *Role) string {
		return fmt.Sprintf("%+v", role)
	}).([]string), ",")

	strRolesInherited := strings.Join(funk.Map(rbac.RolesInherited(), func(role *Role) string {
		return fmt.Sprintf("%+v", role)
	}).([]string), ",")

	var buffer bytes.Buffer
	buffer.WriteString("\nRBAC:\n\t" + strUser + "\n")
	buffer.WriteString("\tPerms:" + strPerms + "\n")
	buffer.WriteString("\tPermsDeep:" + strPermsInherited + "\n")
	buffer.WriteString("\tParents:" + strRoles + "\n")
	buffer.WriteString("\tParentsDeep:" + strRolesInherited + "\n")
	return buffer.String()
}

// ----------------------------------------------------------------------
// ----------------------------------------------------------------------

// RBACMatrix 定义用户与其角色的关系
type RBACMatrix struct {
	rbacMatrix sync.Map // key: user.ID, value: *RBAC
}

// NewRBACMatrix 生成一个新的RBACMatix实例
func NewRBACMatrix() *RBACMatrix {
	r := &RBACMatrix{}
	return r
}

// HasUser 判断用户是否存在
func (matrix *RBACMatrix) HasUser(user *User) bool {
	if _, ok := matrix.rbacMatrix.Load(user.UserID); ok {
		return true
	}
	return false
}

// AddUser 新增一个用户
func (matrix *RBACMatrix) AddUser(user *User) bool {
	if matrix.HasUser(user) {
		// 用户已经存在
		return false
	}
	// 不存在则新建一个RBAC实例
	rbac := NewRBAC(*user)
	matrix.rbacMatrix.Store(user.UserID, rbac)
	return true
}

// DelUser 删除一个用户
func (matrix *RBACMatrix) DelUser(user *User) bool {
	if !matrix.HasUser(user) {
		// 用户不存在
		return false
	}
	matrix.rbacMatrix.Delete(user.UserID)
	return true
}

// GetRBAC 获取用户对应的RBAC
func (matrix *RBACMatrix) GetRBAC(user *User) *RBAC {
	if matrix.HasUser(user) {
		value, _ := matrix.rbacMatrix.Load(user.UserID)
		rbac := value.(*RBAC)
		return rbac
	}
	return nil
}
