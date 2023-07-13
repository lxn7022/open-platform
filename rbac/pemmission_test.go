package rbac

import (
	"fmt"
	"testing"

	// . "github.com/agiledragon/gomonkey"
	. "github.com/smartystreets/goconvey/convey"
)

func TestOperation(t *testing.T) {

	opset := NewOperationSet()
	ret := false

	Convey("TestOperation", t, func() {
		Convey("成功", func() {
			opRead := &Operation{ID: 1, Name: Read}
			opUpdate := &Operation{ID: 2, Name: Update}
			opDelete := &Operation{ID: 3, Name: Delete}
			opCreate := &Operation{ID: 4, Name: Create}

			opset.AddOperation(opRead)
			opset.AddOperation(opUpdate)
			ret = opset.HasOperation(opUpdate)
			So(ret, ShouldBeTrue)
			ret = opset.HasOperation(opDelete)
			So(ret, ShouldBeFalse)
			ret = opset.HasOperation(opCreate)
			So(ret, ShouldBeFalse)

			opset.DelOperation(opUpdate)
			ret = opset.HasOperation(opUpdate)
			So(ret, ShouldBeFalse)

			fmt.Println("\n", "opset=", opset)

		})
	})
}
func TestPermission(t *testing.T) {
	opRead := &Operation{ID: 1, Name: Read}
	opUpdate := &Operation{ID: 2, Name: Update}
	opDelete := &Operation{ID: 3, Name: Delete}
	opCreate := &Operation{ID: 4, Name: Create}

	objDianshijv := &Object{ID: 1, Name: "电视剧频道"}
	objMovie := &Object{ID: 2, Name: "电影频道"}
	objZongyi := &Object{ID: 3, Name: "综艺频道"}

	permChannel := NewPermission(1, "频道权限控制")

	Convey("AddPermission", t, func() {
		Convey("成功", func() {
			ret := false
			permChannel.AddPermission(objDianshijv, opRead)
			permChannel.AddPermission(objDianshijv, opUpdate)
			permChannel.AddPermission(objDianshijv, opDelete)
			permChannel.AddPermission(objDianshijv, opCreate)
			ret = permChannel.HasPermission(objDianshijv, opRead)
			So(ret, ShouldBeTrue)
			ret = permChannel.HasPermission(objMovie, opRead)
			So(ret, ShouldBeFalse)

		})
	})

	Convey("DelPermission", t, func() {
		Convey("成功", func() {
			ret := false
			permChannel.AddPermission(objZongyi, opRead)
			permChannel.AddPermission(objZongyi, opUpdate)
			permChannel.AddPermission(objZongyi, opDelete)
			permChannel.AddPermission(objZongyi, opCreate)
			ret = permChannel.HasPermission(objZongyi, opRead)
			So(ret, ShouldBeTrue)
			permChannel.DelPermission(objZongyi, opRead)
			ret = permChannel.HasPermission(objZongyi, opRead)
			So(ret, ShouldBeFalse)

		})
	})
}
