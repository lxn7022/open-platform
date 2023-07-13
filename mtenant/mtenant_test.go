package mtenant

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMTenant(t *testing.T) {
	Convey("MTenant", t, func() {
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
		mTenant := NewMTenant(tnDB)
		tenant, err := mTenant.GetTenant("Tencent700")
		So(err, ShouldBeNil)
		t.Log(tenant.Prettify())

	})

}
