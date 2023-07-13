package mtenant

import (
	"saas/oauth"
	"saas/rbac"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArldzHpUs9ttlAMt7ZKaIVLE1VJLaj3nksRSlvWZ7dZa518cl
oZtVMc3MvbXzMGCuwAvO81FU61s34T5zyYY35EF8UHenZSB1xu4L/9EgbAkR503O
7BRO6UZOuyDNM/t5Fev0FKbR47WM1yQ9k87BWwCsDBNDAvG5fgltApTnsTgAgG7v
ClzKBpme0rh/vUZVhXSBo02b03apqptTkDUqmdXmbTFY0tDcHZJlT51PK21R1Mwj
Zu9+B1Yv9aNogL6JqOP5rcwW+VLRJ0RX+SCePZAu+w4TqBl+uZQJlSzui2K1nuPb
WeNpqatS5MVMK2rjJ3glEtNqnQUScVIL5MWk4QIDAQABAoIBAEd2sUmn/HZ0GELr
JflsChYtTZ8NU2ncnVG5FPc+Ov1Ie4VnrJVCBvoTUgmxu63o87jlHj++5wBSs+Uw
pGXHDsIR1dNmOMfLNnwEuAZ0wsWGMkCONHOxH2ef2kX6fCMCwe+qeLK+burYUJMf
193usnOLIvsQKjfavh5b3sNgJlkN3gpJac+JioRsR1FgI5x3gRBflFvyxVTXulST
TBHSiYgqNglMD7uJ+eWDX+cWuV1H2CakSsGke99BTpdNOwqym77XnQaL6iDKjty+
VSWnKLytwDPxPVQmB70OdrzExEmo0eNqEEIHJ1p9LtSZkCZHpHtYzhTq4i4r7qnK
48CTIsECgYEA4mGmiUmccqGgqhiks5iFqUNmra7jDQxYRrF/xDcyR99g+lxa2k/0
MWQeekks5SI7m2VQqfG3ELrCrhHYNDfnqowsE9mOrkMilirzrrqW8GFxNQi/WZIA
yOEh8R58LdSCcjXSaWHcxq4GZi1rtU+l4Q3NtZ7vI1CQkt3iHFceevsCgYEAxSbK
81BZBbBhl5bJCe1Mqlpxf9U+ezBaKdTXjSoQMelh4Vv8hqwW2/pHf0fJTQczVouS
Le2HIEPphZ6chosv2oYyXzbNyxZad+ebDJ4sOrUGw1hzJ9CJlB6tEOKu6b6G9RNq
6T0tbXMjijPW4DLovItvfc6G5e93Htqz9icgWNMCgYEAo7tM3+7FoIMV2PCJ7vtZ
cNq24NekkENldXvblOb3DtSZJ3q0m0FItJBdGsTiG7dutS3J8aBJb2gkdhGh9eKZ
Q9it6I1pjNAxq7rVFIMPuDxBzMHO49Gdj6yFCAeseNlCn6gdzupg67HiHvSq+i/p
IaUCK2IQQ9J5PkAM0cKQ4RECgYBbzX2RoSdi68f144PHuJULekQBp5WJnXFOq0qX
9C9IXolye/fx6e5XDor+bLoCwUiZkzJFaqaSUq1JyBrQ1703v2dzSLy5RbZowRNE
495qk+MLUYOF1ahKraIfC78xHsQPGLSe2RrvLT8uWodDLNGNAkyvQ10zcreASYyl
IYEBewKBgES2O0KLDwyah4D5aVhoG3epQ2ER/sEJRXxzIP4Cv0AuaArPzEHN9K/J
raiFMV5N3vNAvehPQUW3okgiPQveJ2+H6ZRptTx9gYGiieaDOWQYVZRYbjDiLg9v
3nQPfbN3wlJtKlSsQzcbyTP360zIKAitrbAje1UUZBZ+sQUkQked
-----END RSA PRIVATE KEY-----`

var publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArldzHpUs9ttlAMt7ZKaI
VLE1VJLaj3nksRSlvWZ7dZa518cloZtVMc3MvbXzMGCuwAvO81FU61s34T5zyYY3
5EF8UHenZSB1xu4L/9EgbAkR503O7BRO6UZOuyDNM/t5Fev0FKbR47WM1yQ9k87B
WwCsDBNDAvG5fgltApTnsTgAgG7vClzKBpme0rh/vUZVhXSBo02b03apqptTkDUq
mdXmbTFY0tDcHZJlT51PK21R1MwjZu9+B1Yv9aNogL6JqOP5rcwW+VLRJ0RX+SCe
PZAu+w4TqBl+uZQJlSzui2K1nuPbWeNpqatS5MVMK2rjJ3glEtNqnQUScVIL5MWk
4QIDAQAB
-----END PUBLIC KEY-----`

func Test(t *testing.T) {

	tenant := NewTenant("Tencent", "腾讯", "腾讯",
		oauth.NewBackendMerchantDB(),
		oauth.NewBackendTokenDB())
	t.Log(tenant.Prettify())

	Convey("商户相关操作", t, func() {
		merchant := oauth.NewMerchant("txsp", publicKey)
		merchant.AddApp(&oauth.Application{AppID: "AppID1", AppSecret: "AppID1Secret", Scope: "AppID1Scope", AppName: "AppID1Name"})
		merchant.AddApp(&oauth.Application{AppID: "AppID2", AppSecret: "AppID2Secret", Scope: "AppID2Scope", AppName: "AppID2Name"})

		err := tenant.AddMerchant(merchant)
		So(err, ShouldBeNil)
		err = tenant.AddMerchant(merchant)
		So(err, ShouldBeError)
		t.Log(err)
		ok := tenant.HasMerchant(merchant)
		So(ok, ShouldBeTrue)
		err = tenant.DelMerchant(merchant)
		So(err, ShouldBeNil)
		ok = tenant.HasMerchant(merchant)
		So(ok, ShouldBeFalse)
	})

	Convey("基于OAuth的身份鉴别", t, func() {
		merchant := oauth.NewMerchant("txsp", publicKey)
		merchant.AddApp(&oauth.Application{AppID: "AppID1", AppSecret: "AppID1Secret", Scope: "AppID1Scope", AppName: "AppID1Name"})
		merchant.AddApp(&oauth.Application{AppID: "AppID2", AppSecret: "AppID2Secret", Scope: "AppID2Scope", AppName: "AppID2Name"})
		err := tenant.AddMerchant(merchant)
		So(err, ShouldBeNil)

		mInfo := &oauth.MerchantInfo{MerchantID: "txsp", AppID: "AppID1"}
		targetSign, err := oauth.SignMerchantInfo(privateKey, mInfo)
		So(err, ShouldBeNil)
		accessToken, err := tenant.GetAccessToken("txsp", "AppID1", targetSign)
		So(err, ShouldBeNil)
		t.Log(accessToken)
		err = tenant.VerifyToken("txsp", "AppID1", accessToken)
		So(err, ShouldBeNil)
		accessToken, err = tenant.RefreshToken("txsp", "AppID1", accessToken)
		So(err, ShouldBeNil)
		t.Log(accessToken)
		err = tenant.RevokeToken("txsp", "AppID1", accessToken)
		So(err, ShouldBeNil)
		err = tenant.VerifyToken("txsp", "AppID1", accessToken)
		So(err, ShouldBeError)
		err = tenant.DelMerchant(merchant)
		So(err, ShouldBeNil)
		ok := tenant.HasMerchant(merchant)
		So(ok, ShouldBeFalse)
	})

	Convey("基于RBAC的权限控制", t, func() {
		merchant := oauth.NewMerchant("txsp", publicKey)
		merchant.AddApp(&oauth.Application{AppID: "AppID1", AppSecret: "AppID1Secret", Scope: "AppID1Scope", AppName: "AppID1Name"})
		merchant.AddApp(&oauth.Application{AppID: "AppID2", AppSecret: "AppID2Secret", Scope: "AppID2Scope", AppName: "AppID2Name"})
		err := tenant.AddMerchant(merchant)
		So(err, ShouldBeNil)
		// Operation
		opRead := &rbac.Operation{ID: 1, Name: rbac.Read}
		opUpdate := &rbac.Operation{ID: 2, Name: rbac.Update}
		opDelete := &rbac.Operation{ID: 3, Name: rbac.Delete}
		opCreate := &rbac.Operation{ID: 4, Name: rbac.Create}
		// Object
		objDianshijv := &rbac.Object{ID: 1, Name: "电视剧频道"}
		objMovie := &rbac.Object{ID: 2, Name: "电影频道"}
		objZongyi := &rbac.Object{ID: 3, Name: "综艺频道"}
		// Permission
		permDianshijv := rbac.NewPermission(1, "电视剧-频道权限控制")
		permDianshijv.AddPermission(objDianshijv, opRead)
		permDianshijv.AddPermission(objDianshijv, opUpdate)
		permDianshijv.AddPermission(objDianshijv, opDelete)
		permDianshijv.AddPermission(objDianshijv, opCreate)
		permMovie := rbac.NewPermission(2, "电影-频道权限控制")
		permMovie.AddPermission(objMovie, opRead)
		permZongyi := rbac.NewPermission(3, "综艺-频道权限控制")
		permZongyi.AddPermission(objZongyi, opRead)
		// 构建Role实例 begin
		roleHigh := &rbac.Role{ID: 1, Name: "高级编辑"}
		roleMid := &rbac.Role{ID: 2, Name: "中级编辑"}
		roleLow := &rbac.Role{ID: 3, Name: "初级编辑"}
		// 高级编辑
		roleHigh.Grant(permDianshijv)
		roleHigh.Grant(permMovie)
		roleHigh.Grant(permZongyi)
		// 中级编辑
		roleMid.Grant(permDianshijv)
		roleMid.Grant(permZongyi)
		// 初级编辑
		// roleLow.Grant(permMovie)
		// 级联关系 roleLow->roleMid->roleHigh
		roleLow.AddParent(roleMid)
		roleMid.AddParent(roleHigh)
		// 构建Role实例 end

		err = tenant.Permit("txsp", roleLow, permMovie)
		So(err, ShouldBeNil)
		ok := tenant.IsGranted("txsp", roleLow, permMovie)
		So(ok, ShouldBeTrue)
		ok = tenant.IsGranted("txsp", roleLow, permZongyi)
		So(ok, ShouldBeFalse)
		ok = tenant.IsGrantInherited("txsp", roleLow, permZongyi)
		So(ok, ShouldBeTrue)
		err = tenant.Revoke("txsp", roleLow, permMovie)
		So(err, ShouldBeNil)
		ok = tenant.IsGranted("txsp", roleLow, permMovie)
		So(ok, ShouldBeFalse)
		ok = tenant.IsGrantInherited("txsp", roleLow, permZongyi)
		So(ok, ShouldBeTrue)

	})
}
