package oauth

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test(t *testing.T) {

	Convey("Merchant", t, func() {

		merchant := NewMerchant("Tencent", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
		pubKey := RandomToken()
		merchant.SetKey(pubKey)
		k := merchant.GetKey()
		So(k, ShouldEqual, pubKey)
		app1 := &Application{"AppID1", "AppID1Secret", "AppID1Scope", "AppID1Name"}
		app2 := &Application{"AppID2", "AppID2Secret", "AppID2Scope", "AppID2Name"}
		err := merchant.AddApp(app1)
		So(err, ShouldBeTrue)
		err = merchant.AddApp(app1)
		So(err, ShouldBeFalse)
		err = merchant.AddApp(app2)
		So(err, ShouldBeTrue)
		t.Logf("%s", merchant.Prettify())
		err = merchant.DelApp(app1)
		So(err, ShouldBeTrue)
		err = merchant.HasApp("AppID1")
		So(err, ShouldBeFalse)
		err = merchant.HasApp("AppID2")
		So(err, ShouldBeTrue)
		app := merchant.GetApp("AppID2")
		So(app, ShouldNotBeNil)
		t.Logf("%+v\n%s", merchant, merchant.Prettify())
	})

}
