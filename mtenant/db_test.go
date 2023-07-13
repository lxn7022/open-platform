package mtenant

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDB(t *testing.T) {
	Convey("TenantInfo", t, func() {
		tnInfo := &TenantInfo{}
		tnInfo.SetTenantID("Tencent700")
		tnInfo.SetTenantName("Tencent")
		tnInfo.SetDisplayName("腾讯")
		tnInfo.SetUpdateTime()
		tnInfo.SetCreatTime()
		tnInfo.SetOAuthDBInfo("oauth_db_name:oauth_table_name")
		tnInfo.SetRBACDBInfo("rbac_db_name:rbac_table_name")
		t.Logf("%s", tnInfo.Prettify())
		t.Logf("\n %s,%s,%s \n %v,%v \n %s, %s", tnInfo.GetTenantID(), tnInfo.GetTenantName(), tnInfo.GetDisplayName(),
			tnInfo.GetCreatTime(), tnInfo.GetUpdateTime(),
			tnInfo.GetOAuthDBInfo(), tnInfo.GetRBACDBInfo())

	})

	Convey("TenantDB", t, func() {

		tenantInfo := &TenantInfo{
			TenantID:    "Tencent700",
			TenantName:  "Tencent",
			DisplayName: "腾讯",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			OAuthDBInfo: "oauth_db_name:oauth_table_name",
			RBACDBInfo:  "rbac_db_name:rbac_table_name",
		}

		tnDB := NewBackendTenantDB()
		err := tnDB.Create(tenantInfo)
		So(err, ShouldBeNil)
		tnInfo, err := tnDB.Read("Tencent700")
		So(err, ShouldBeNil)
		err = tnDB.Update(tnInfo)
		So(err, ShouldBeNil)
		err = tnDB.Create(tenantInfo)
		So(err, ShouldBeError)
		err = tnDB.Delete("Tencent600")
		So(err, ShouldBeError)
		err = tnDB.Delete("Tencent700")
		So(err, ShouldBeNil)
		t.Logf("%s", tnInfo.Prettify())
	})
}
