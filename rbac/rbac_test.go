package rbac

import (
	"fmt"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/thoas/go-funk"
)

func TestRBAC(t *testing.T) {

	opRead := &Operation{ID: 1, Name: Read}
	opUpdate := &Operation{ID: 2, Name: Update}
	opDelete := &Operation{ID: 3, Name: Delete}
	opCreate := &Operation{ID: 4, Name: Create}

	objDianshijv := &Object{ID: 1, Name: "电视剧频道"}
	objMovie := &Object{ID: 2, Name: "电影频道"}
	objZongyi := &Object{ID: 3, Name: "综艺频道"}

	permDianshijv := NewPermission(1, "电视剧-频道权限控制")

	permDianshijv.AddPermission(objDianshijv, opRead)
	permDianshijv.AddPermission(objDianshijv, opUpdate)
	permDianshijv.AddPermission(objDianshijv, opDelete)
	permDianshijv.AddPermission(objDianshijv, opCreate)

	permMovie := NewPermission(2, "电影-频道权限控制")
	permMovie.AddPermission(objMovie, opRead)

	permZongyi := NewPermission(3, "综艺-频道权限控制")
	permZongyi.AddPermission(objZongyi, opRead)

	Convey("Role相关方法", t, func() {
		rbac := NewRBAC(User{"10001", "Alice", ""})
		roleHigh := &Role{ID: 1, Name: "高级编辑"}
		roleMid := &Role{ID: 2, Name: "中级编辑"}
		roleLow := &Role{ID: 3, Name: "初级编辑"}

		roleHigh.Grant(permDianshijv)
		roleMid.Grant(permZongyi)
		roleLow.Grant(permMovie)
		//建立继承关系roleLow->roleMid->roleHigh
		roleLow.AddParent(roleMid)
		roleMid.AddParent(roleHigh)

		err := rbac.AddRole(roleLow)
		So(err, ShouldBeNil)
		err = rbac.AddRole(roleLow)
		So(err, ShouldBeError)
		rbac.AddRole(roleMid)
		rbac.AddRole(roleHigh)

		res := rbac.IsRoleExist(roleHigh)
		So(res, ShouldBeTrue)
		err = rbac.DelRole(roleHigh)
		So(err, ShouldBeNil)
		res = rbac.IsRoleExist(roleHigh)
		So(res, ShouldBeFalse)
		res = rbac.IsRoleExistInherited(roleHigh)
		So(res, ShouldBeTrue)

		role := rbac.GetRole(roleLow)
		t.Logf("role[%v]:%v", 3, role.PrettifyRole())

	})

	Convey("Permission相关方法", t, func() {

		rbac := NewRBAC(User{"10002", "Bob", ""})

		roleHigh := &Role{ID: 1, Name: "高级编辑"}
		roleMid := &Role{ID: 2, Name: "中级编辑"}
		roleLow := &Role{ID: 3, Name: "初级编辑"}

		roleHigh.Grant(permDianshijv)
		roleMid.Grant(permZongyi)
		roleLow.Grant(permMovie)
		//建立继承关系roleLow->roleMid->roleHigh
		roleLow.AddParent(roleMid)
		roleMid.AddParent(roleHigh)

		err := rbac.AddRole(roleLow)
		So(err, ShouldBeNil)
		err = rbac.AddRole(roleMid)
		So(err, ShouldBeNil)
		res := rbac.IsPermExist(permDianshijv)
		So(res, ShouldBeFalse) //节点自身没有权限
		res = rbac.IsPermExistInherited(permDianshijv)
		So(res, ShouldBeTrue) //继承的节点有权限

		strPerms := strings.Join(funk.Map(rbac.Perms(), func(perm *Permission) string {
			return fmt.Sprintf("(permID:%v,permName:%v)", perm.ID, perm.Name)
		}).([]string), ",")
		t.Log("\n\tstrPerms:", strPerms)
		strPermsInherited := strings.Join(funk.Map(rbac.PermsInherited(), func(perm *Permission) string {
			return fmt.Sprintf("(permID:%v,permName:%v)", perm.ID, perm.Name)
		}).([]string), ",")
		t.Log("\n\tstrPermsInherited:", strPermsInherited)

	})

	Convey("对用户授权与取消授权：(Permit,Revoke)", t, func() {
		rbac := NewRBAC(User{"10003", "Tom", ""})

		roleHigh := &Role{ID: 1, Name: "高级编辑"}
		roleMid := &Role{ID: 2, Name: "中级编辑"}
		roleLow := &Role{ID: 3, Name: "初级编辑"}

		roleHigh.Grant(permDianshijv)
		roleMid.Grant(permZongyi)
		roleLow.Grant(permMovie)
		//建立继承关系roleLow->roleMid->roleHigh
		roleLow.AddParent(roleMid)
		roleMid.AddParent(roleHigh)

		err := rbac.AddRole(roleLow)
		So(err, ShouldBeNil)
		err = rbac.Permit(roleLow, permMovie) //permMovie已经存在
		So(err, ShouldBeError)
		err = rbac.Permit(roleLow, permDianshijv) //permDianshijv不存在
		So(err, ShouldBeNil)
		err = rbac.Permit(roleMid, permDianshijv)
		So(err, ShouldBeNil)
		err = rbac.Revoke(roleLow, permDianshijv)
		So(err, ShouldBeNil)
		err = rbac.Revoke(roleMid, nil)
		So(err, ShouldBeNil)

	})

	Convey("检查用户是否有授权：Granted相关", t, func() {
		rbac := NewRBAC(User{"10004", "Jim", ""})

		roleHigh := &Role{ID: 1, Name: "高级编辑"}
		roleMid := &Role{ID: 2, Name: "中级编辑"}
		roleLow := &Role{ID: 3, Name: "初级编辑"}

		roleHigh.Grant(permDianshijv)
		roleMid.Grant(permZongyi)
		roleLow.Grant(permMovie)
		//建立继承关系roleLow->roleMid->roleHigh
		roleLow.AddParent(roleMid)
		roleMid.AddParent(roleHigh)

		err := rbac.AddRole(roleLow)
		So(err, ShouldBeNil)

		res := rbac.IsGranted(roleLow, permMovie)
		So(res, ShouldBeTrue) //节点自身有权限
		res = rbac.IsGranted(roleLow, permZongyi)
		So(res, ShouldBeFalse) //节点自身没有权限
		res = rbac.IsGrantInherited(roleLow, permZongyi)
		So(res, ShouldBeTrue) //节点自身没有权限，继承的节点有权限

		roles := []*Role{roleLow, roleHigh}
		res = rbac.AnyGranted(roles, permDianshijv)
		So(res, ShouldBeFalse)
		res = rbac.AnyGrantInherited(roles, permDianshijv)
		So(res, ShouldBeTrue)

	})

	Convey("检查用户是否有授权：AllGranted与AllGrantInherited", t, func() {
		rbac := NewRBAC(User{"10004", "Jim", ""})

		roleHigh := &Role{ID: 1, Name: "高级编辑"}
		roleMid := &Role{ID: 2, Name: "中级编辑"}
		roleLow := &Role{ID: 3, Name: "初级编辑"}

		roleHigh.Grant(permDianshijv)
		roleMid.Grant(permZongyi)
		roleLow.Grant(permMovie)
		//建立继承关系roleLow->roleMid->roleHigh
		roleLow.AddParent(roleMid)
		roleMid.AddParent(roleHigh)

		err := rbac.AddRole(roleLow)
		So(err, ShouldBeNil)
		err = rbac.AddRole(roleMid)
		So(err, ShouldBeNil)

		roles := []*Role{roleLow, roleMid}
		res := rbac.AllGranted(roles, permZongyi)
		So(res, ShouldBeFalse)
		res = rbac.AnyGrantInherited(roles, permZongyi)
		So(res, ShouldBeTrue)

		t.Log(rbac.Prettify())

	})
}

func TestRBACMatrix(t *testing.T) {
	Convey("测试RBACMatrix的功能", t, func() {
		opRead := &Operation{ID: 1, Name: Read}
		opUpdate := &Operation{ID: 2, Name: Update}
		opDelete := &Operation{ID: 3, Name: Delete}
		opCreate := &Operation{ID: 4, Name: Create}

		objDianshijv := &Object{ID: 1, Name: "电视剧频道"}
		objMovie := &Object{ID: 2, Name: "电影频道"}
		objZongyi := &Object{ID: 3, Name: "综艺频道"}

		permDianshijv := NewPermission(1, "电视剧-频道权限控制")
		permDianshijv.AddPermission(objDianshijv, opRead)
		permDianshijv.AddPermission(objDianshijv, opUpdate)
		permDianshijv.AddPermission(objDianshijv, opDelete)
		permDianshijv.AddPermission(objDianshijv, opCreate)

		permMovie := NewPermission(2, "电影-频道权限控制")
		permMovie.AddPermission(objMovie, opRead)

		permZongyi := NewPermission(3, "综艺-频道权限控制")
		permZongyi.AddPermission(objZongyi, opRead)

		roleHigh := &Role{ID: 1, Name: "高级编辑"}
		roleMid := &Role{ID: 2, Name: "中级编辑"}
		roleLow := &Role{ID: 3, Name: "初级编辑"}

		roleHigh.Grant(permDianshijv)
		roleMid.Grant(permZongyi)
		roleLow.Grant(permMovie)

		alice := &User{"10001", "Alice", ""}
		bob := &User{"10002", "Bob", ""}
		tom := &User{"10003", "Tom", ""}

		var ok bool
		matrix := NewRBACMatrix()
		_ = matrix.AddUser(alice)
		_ = matrix.AddUser(bob)
		ok = matrix.AddUser(tom)
		So(ok, ShouldBeTrue)
		ok = matrix.AddUser(tom)
		So(ok, ShouldBeFalse)
		ok = matrix.DelUser(tom)
		So(ok, ShouldBeTrue)
		ok = matrix.HasUser(tom)
		So(ok, ShouldBeFalse)

	})
}
