package rbac

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	// . "github.com/agiledragon/gomonkey"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/thoas/go-funk"
)

// Only for normal logging purpose, 4 space indent
func PrettifyJson(i interface{}, indent bool) string {
	var str []byte
	if indent {
		str, _ = json.MarshalIndent(i, "", "    ")
	} else {
		str, _ = json.Marshal(i)
	}

	return string(str)
}

func TestRole(t *testing.T) {

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

	Convey("TestRole 验证授权操作", t, func() {

		Convey("IsGranted与IsGrantedDeep", func() {
			roleHigh := &Role{ID: 1, Name: "高级编辑"}
			roleMid := &Role{ID: 2, Name: "中级编辑"}
			roleLow := &Role{ID: 3, Name: "初级编辑"}
			// 高级编辑
			roleHigh.Grant(permDianshijv)
			roleHigh.Grant(permMovie)
			roleHigh.Grant(permZongyi)
			// 中级编辑
			roleMid.Grant(permDianshijv)
			roleMid.Grant(permZongyi)
			// 初级编辑
			roleLow.Grant(permMovie)

			// 级联关系 roleLow->(roleMid,roleHigh), roleMid->roleHigh
			roleLow.AddParent(roleHigh)
			roleMid.AddParent(roleHigh)

			ret := roleLow.IsGranted(permZongyi)
			So(ret, ShouldBeFalse)
			ret = roleLow.IsGrantInherited(permZongyi)
			So(ret, ShouldBeTrue)
			ret = roleLow.IsGrantInherited(permDianshijv)
			So(ret, ShouldBeTrue)

			fmt.Println("")
			t.Log("roleHigh=", roleHigh.PrettifyRole())
			t.Log("roleMid=", roleMid.PrettifyRole())
			t.Log("roleLow=", roleLow.PrettifyRole())

		})
		Convey("ParentIDs与ParentIDsDeep", func() {
			roleHigh := &Role{ID: 1, Name: "高级编辑"}
			roleMid := &Role{ID: 2, Name: "中级编辑"}
			roleLow := &Role{ID: 3, Name: "初级编辑"}
			roleHigh.Grant(permDianshijv)
			roleMid.Grant(permZongyi)
			roleLow.Grant(permMovie)
			//级联关系roleLow->roleMid->roleHigh
			roleLow.AddParent(roleMid)
			roleMid.AddParent(roleHigh)
			fmt.Println("")
			t.Log("roleLow=", roleLow.PrettifyRole())
			roleIds := roleLow.ParentIDs()
			So(roleIds, ShouldResemble, []uint32{2})
			t.Log("roleLow ParentIDs=", roleIds)
			roleIds = roleLow.ParentIDsDeep()
			So(roleIds, ShouldResemble, []uint32{2, 1})
			t.Log("roleLow ParentIDsDeep=", roleIds)
		})

		Convey("Parents与ParentsDeep", func() {
			roleHigh := &Role{ID: 1, Name: "高级编辑"}
			roleMid := &Role{ID: 2, Name: "中级编辑"}
			roleLow := &Role{ID: 3, Name: "初级编辑"}
			roleHigh.Grant(permDianshijv)
			roleMid.Grant(permZongyi)
			roleLow.Grant(permMovie)
			//级联关系roleLow->roleMid->roleHigh
			roleLow.AddParent(roleMid)
			roleMid.AddParent(roleHigh)
			fmt.Println("")

			roles := roleLow.Parents()
			// 将Role数组转换成一个字符串
			str := strings.Join(funk.Map(roles, func(r *Role) string {
				return fmt.Sprintf("roleID:%v", r.ID)
			}).([]string), ",")
			t.Logf("Parents=%v", str)

			roles = roleLow.ParentsDeep()
			// 将Role数组转换成一个字符串
			str = strings.Join(funk.Map(roles, func(r *Role) string {
				return fmt.Sprintf("roleID:%v", r.ID)
			}).([]string), ",")
			t.Logf("ParentsDeep=%v", str)

		})

		Convey("Permissions与PermissionsDeep", func() {
			roleHigh := &Role{ID: 1, Name: "高级编辑"}
			roleMid := &Role{ID: 2, Name: "中级编辑"}
			roleLow := &Role{ID: 3, Name: "初级编辑"}
			// 高级编辑
			roleHigh.Grant(permDianshijv)
			roleHigh.Grant(permMovie)
			roleHigh.Grant(permZongyi)
			// 中级编辑
			roleMid.Grant(permDianshijv)
			roleMid.Grant(permZongyi)
			// 初级编辑
			roleLow.Grant(permMovie)

			// 级联关系 roleLow->roleMid->roleHigh
			roleLow.AddParent(roleMid)
			roleMid.AddParent(roleHigh)

			ret := roleLow.IsGranted(permZongyi)
			So(ret, ShouldBeFalse)
			ret = roleLow.IsGrantInherited(permZongyi)
			So(ret, ShouldBeTrue)
			ret = roleLow.IsGrantInherited(permDianshijv)
			So(ret, ShouldBeTrue)

			fmt.Println("")
			t.Logf("roleLow.Permissions: %#v", roleLow.Permissions())
			t.Logf("roleLow.PermissionsDeep: %#v", roleLow.PermissionsDeep())
			t.Log(roleLow.PrettifyRole())

		})
	})

}
