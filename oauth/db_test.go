package oauth

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	alphanum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func TestDB(t *testing.T) {

	Convey("BackendMerchantDB", t, func() {
		merchant := NewMerchant("Tencent", alphanum)
		merchant.AddApp(&Application{"AppID1", "AppID1Secret", "AppID1Scope", "AppID1Name"})
		merchant.AddApp(&Application{"AppID2", "AppID2Secret", "AppID2Scope", "AppID2Name"})

		mdb := NewBackendMerchantDB()
		err := mdb.Create(merchant)
		So(err, ShouldBeNil)
		m, err := mdb.Read("Tencent")
		So(err, ShouldBeNil)
		err = mdb.Update(m)
		So(err, ShouldBeNil)
		err = mdb.Create(m)
		So(err, ShouldBeError)
		err = mdb.Delete("Tencent")
		So(err, ShouldBeNil)
		t.Logf("%s", m.Prettify())
	})

	Convey("BackendTokenDB", t, func() {

		tdb := NewBackendTokenDB()
		token, err := tdb.CreateToken("AppID-Tencent", "AppSecret-Tencent")
		accessToken := token.AccessToken
		So(err, ShouldBeNil)
		_, err = tdb.GetToken(accessToken)
		So(err, ShouldBeNil)

		_, err = tdb.RefreshToken(accessToken)
		So(err, ShouldBeNil)
		err = tdb.DeleteToken(accessToken)
		So(err, ShouldBeError) // RefreshToken 之后老的accessToken失效
		t.Logf("%s", token.Prettify())

	})

}

func TestRandomToken(t *testing.T) {

	Convey("RandomToken", t, func() {
		t.Logf("%s %s", RandomToken(), time.Now())
	})

}
