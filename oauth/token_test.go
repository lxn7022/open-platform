package oauth

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestToken(t *testing.T) {

	Convey("AccessToken", t, func() {

		token := NewToken()
		accessToken := RandomToken()
		token.SetAccessToken(accessToken)
		So(token.GetAccessToken(), ShouldEqual, accessToken)

		accessCreateAt := time.Now()
		token.SetAccessCreateAt(accessCreateAt)
		So(token.GetAccessCreateAt(), ShouldEqual, accessCreateAt)

		token.SetAccessExpiresIn(TokenExpiry)
		So(token.GetAccessExpiresIn(), ShouldEqual, TokenExpiry)
		t.Logf("%s", token.Prettify())

	})

	Convey("RefreshToken", t, func() {
		token := NewToken()
		refreshToken := RandomToken()
		token.SetRefreshToken(refreshToken)
		So(token.GetRefreshToken(), ShouldEqual, refreshToken)

		refreshCreateAt := time.Now()
		token.SetRefreshCreateAt(refreshCreateAt)
		So(token.GetRefreshCreateAt(), ShouldEqual, refreshCreateAt)

		token.SetRefreshExpiresIn(TokenExpiry)
		So(token.GetRefreshExpiresIn(), ShouldEqual, TokenExpiry)

		t.Logf("%s", token.Prettify())
	})

}
