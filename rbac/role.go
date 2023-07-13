// 本文件定义了RBAC模型中Role模块的实现。
// Role：定义了权限控制的角色，例如git系统预定义了多种角色，比如Master，Owner，Guest，Developer，Reporter等
// Permission：是一个Object和Action之间的矩阵，定义了可以对一个对象执行什么操。
// Role与Permission之间的关系：一个Role可以有多个Permission
// Role层次结构：Role与Role可以继承，从而形成一个层次结构
// RBAC规范：https://profsandhu.com/journals/tissec/ANSI+INCITS+359-2004.pdf

package rbac

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/thoas/go-funk"
)

// Role 表示角色，一个角色可以有多个permission
type Role struct {
	ID   uint32 `json:"id"`   // 角色ID
	Name string `json:"name"` // 角色名称
	Desc string `json:"desc"` // 角色的描述

	Perms       sync.Map `json:"permissions"`  // 角色具有的权限项，key: permissionID, value=*Permission
	ParentNodes sync.Map `json:"parent_nodes"` // 角色的父节点，key: RoleID, value：*Role
}

// Grant 给Role授权
func (r *Role) Grant(p *Permission) {
	if !r.IsGranted(p) {
		r.Perms.Store(p.ID, p)
	}
}

// Revoke 撤销Role授权
func (r *Role) Revoke(p *Permission) {
	r.Perms.Delete(p.ID)
}

// IsGranted 检查Role是否获得授权
func (r *Role) IsGranted(p *Permission) bool {
	_, ok := r.Perms.Load(p.ID)
	return ok
}

// IsGrantInherited 检查Role是否从祖先处获得授权
func (r *Role) IsGrantInherited(p *Permission) (found bool) {
	// 在本节点找到授权
	if ok := r.IsGranted(p); ok {
		return ok
	}
	// 在祖先节点找到授权
	found = false
	r.ParentNodes.Range(func(key, value interface{}) bool {
		found = value.(*Role).IsGrantInherited(p)
		return !found
	})

	return found
}

// HasAncestor 检查Role的祖先节点是否具有parentRole
func (r *Role) HasAncestor(parentRole *Role) bool {
	if _, ok := r.ParentNodes.Load(parentRole.ID); ok {
		return true
	}
	var found bool
	r.ParentNodes.Range(func(key, value interface{}) bool {
		found = value.(*Role).HasAncestor(parentRole)
		return !found
	})
	return found
}

// AddParent 增加父角色
func (r *Role) AddParent(parentRole *Role) error {
	// 已经存在
	if _, ok := r.ParentNodes.Load(parentRole.ID); ok {
		return fmt.Errorf("parent role with ID %v is already defined for role %v", parentRole.ID, r.ID)
	}
	// 避免循环引用
	if parentRole.HasAncestor(r) {
		return fmt.Errorf("circular reference is found for parentrole:%v while adding to role:%v", parentRole.ID, r.ID)
	}
	r.ParentNodes.Store(parentRole.ID, parentRole)
	return nil
}

// DelParent 删除父角色
func (r *Role) DelParent(parentRole *Role) error {
	if _, ok := r.ParentNodes.Load(parentRole.ID); !ok {
		return fmt.Errorf("parent role with ID %v is not defined for role %v", parentRole.ID, r.ID)
	}
	r.ParentNodes.Delete(parentRole.ID)
	return nil
}

// Parents 返回Role的父节点的Role列表
func (r *Role) Parents() []*Role {
	res := []*Role{}
	r.ParentNodes.Range(func(_, v interface{}) bool {
		res = append(res, v.(*Role))
		return true
	})
	return res
}

// ParentsDeep 递归获取所有Role, 如果Role的ID相同则去重
func (r *Role) ParentsDeep() []*Role {
	res := []*Role{}
	r.ParentNodes.Range(func(_, v interface{}) bool {
		vrole := v.(*Role)
		res = append(res, vrole)
		res = append(res, vrole.ParentsDeep()...)
		return true
	})
	return funk.UniqBy(res, func(r *Role) uint32 {
		return r.ID
	}).([]*Role)
}

// ParentIDs 返回Role的父节点的ID列表
func (r *Role) ParentIDs() []uint32 {
	res := []uint32{}
	for _, r := range r.Parents() {
		res = append(res, r.ID)
	}
	return res
}

// ParentIDsDeep 递归获取所有Role的ID, 如果Role的ID相同则去重
func (r *Role) ParentIDsDeep() []uint32 {
	roles := r.ParentsDeep()
	res := []uint32{}
	for _, v := range roles {
		res = append(res, v.ID)
	}
	return res
}

// Permissions 返回Role的所有Permission
func (r *Role) Permissions() []*Permission {
	res := []*Permission{}
	r.Perms.Range(func(_, v interface{}) bool {
		res = append(res, v.(*Permission))
		return true
	})
	return res
}

// PermissionsDeep 递归获取Role的所有Permission，如果Permission的ID相同则去重
func (r *Role) PermissionsDeep() []*Permission {
	res := []*Permission{}
	res = append(res, r.Permissions()...)

	r.ParentNodes.Range(func(_, v interface{}) bool {
		vrole := v.(*Role)
		res = append(res, vrole.Permissions()...)
		return true
	})
	// 去重
	return funk.UniqBy(res, func(p *Permission) uint32 {
		return p.ID
	}).([]*Permission)
}

// String 格式化输出
func (r *Role) String() string {
	return fmt.Sprintf("(roleID:%v,roleName:%v)", r.ID, r.Name)
}

// PrettifyRole 格式化输出Role信息
func (r *Role) PrettifyRole() string {
	strRole := fmt.Sprintf("Role:%+v,", r)

	strPerms := strings.Join(funk.Map(r.Permissions(), func(perm *Permission) string {
		return fmt.Sprintf("%+v", perm)
	}).([]string), ",")

	strPermsDeep := strings.Join(funk.Map(r.PermissionsDeep(), func(perm *Permission) string {
		return fmt.Sprintf("%+v", perm)
	}).([]string), ",")

	strParents := strings.Join(funk.Map(r.Parents(), func(role *Role) string {
		return fmt.Sprintf("%+v", role)
	}).([]string), ",")

	strParentsDeep := strings.Join(funk.Map(r.ParentsDeep(), func(role *Role) string {
		return fmt.Sprintf("%+v", role)
	}).([]string), ",")

	var buffer bytes.Buffer
	buffer.WriteString("\nRole:\n\t" + strRole + "\n")
	buffer.WriteString("\tPerms:" + strPerms + "\n")
	buffer.WriteString("\tPermsDeep:" + strPermsDeep + "\n")
	buffer.WriteString("\tParents:" + strParents + "\n")
	buffer.WriteString("\tParentsDeep:" + strParentsDeep + "\n")
	return buffer.String()

}
