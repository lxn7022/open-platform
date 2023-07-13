package oauth

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
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

func TestOAuth(t *testing.T) {

	Convey("SignMerchantInfo&VerifyMerchantInfo", t, func() {

		mInfo := &MerchantInfo{"Tencent", "TXSP"}

		targetSign, err := SignMerchantInfo(privateKey, mInfo)
		So(err, ShouldBeNil)
		assert.NoError(t, err)
		err = VerifyMerchantInfo(publicKey, mInfo, targetSign)
		So(err, ShouldBeNil)
		t.Logf("targetSign:%s", string(targetSign))

	})

	Convey("OAuth", t, func() {

		merchant := NewMerchant("Tencent", publicKey)
		app1 := &Application{"AppID1", "AppID1Secret", "AppID1Scope", "AppID1Name"}
		app2 := &Application{"AppID2", "AppID2Secret", "AppID2Scope", "AppID2Name"}
		ok := merchant.AddApp(app1)
		So(ok, ShouldBeTrue)
		ok = merchant.AddApp(app2)
		So(ok, ShouldBeTrue)

		mdb := NewBackendMerchantDB()
		tdb := NewBackendTokenDB()
		oauth := NewOAuth(mdb, tdb)
		oauth.MerchantDB().Create(merchant)

		mInfo := &MerchantInfo{"Tencent", "AppID1"}
		targetSign, err := SignMerchantInfo(privateKey, mInfo)
		So(err, ShouldBeNil)
		accessToken, err := oauth.GetAccessToken(mInfo, targetSign)
		So(err, ShouldBeNil)
		t.Logf("accessToken:%s", accessToken)
		newAccessToken, err := oauth.RefreshToken(mInfo, accessToken)
		So(err, ShouldBeNil)
		err = oauth.VerifyToken(mInfo, accessToken)
		So(err, ShouldBeError) // 刷新后老accessToken失效
		err = oauth.VerifyToken(mInfo, newAccessToken)
		So(err, ShouldBeNil)
		err = oauth.RevokeToken(mInfo, newAccessToken)
		So(err, ShouldBeNil)
		err = oauth.VerifyToken(mInfo, newAccessToken)
		So(err, ShouldBeError)

	})
}
