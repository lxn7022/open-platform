package crypt

import (
	"fmt"
	"strings"
	"testing"

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

func TestRSAEncrypt(t *testing.T) {
	plain := "test crypt"
	result, err := RSAEncrypt([]byte(publicKey), []byte(plain))
	assert.NoError(t, err)

	result2, err := RSADecrypt([]byte(privateKey), result)
	assert.Equal(t, plain, string(result2), "should equal")
	assert.NoError(t, err)
}

func TestRSADecrypt(t *testing.T) {
	plain := "test crypt"
	ciphertext := "nCRc/sN0xd+kPpIdGehVCzE5mL2ZkdsoiEaa3s7nS5MXeEuR8Uzrrv5iU4Nfbh/jCrGBvklBrTqq8GuKDeObbxSPONFH/iCimBvHNenKr+ZAbmDwsOID90o0Acf4tVp3IOQbuA6FmQzvskQA0X6ha6I3M2oFmSb+4UcPyzHML6GNMxgeX81RIBPLPHi0LtcADCJV5fuOYNbAw8ilfKXv8KDzKKhEBb+Yq3gZyRt1bv/RfQB0pDsV5TTs4m7tLe107y3UWim9XqPxHjCYLW3zhmuNYO+p2lB29sriE7GkmEX3PsDAi3D+zEsoUQAfzYrGwfCA7v6H9V3u6fQ36Kg5Gw=="

	result, err := RSADecrypt([]byte(privateKey), b64Decode(ciphertext))
	assert.NoError(t, err)
	assert.Equal(t, plain, string(result), "should equal")
}

func TestGenerateKeyStr(t *testing.T) {
	prikey, pubkey, err := GenerateKeyStr()
	t.Log(prikey)
	t.Log(pubkey)
	assert.Contains(t, prikey, "RSA PRIVATE KEY", "should contains RSA PRIVATE KEY")
	assert.Contains(t, pubkey, "PUBLIC KEY", "should contains PUBLIC KEY")
	assert.NoError(t, err)
}

func TestFormatKeyToMultiline(t *testing.T) {
	toSingle := func(key, keywords string) string {
		key = strings.Replace(key, fmt.Sprintf("-----BEGIN %v KEY-----", keywords), "", 1)
		key = strings.Replace(key, fmt.Sprintf("-----END %v KEY-----", keywords), "", 1)
		return strings.Replace(key, "\n", "", -1)
	}

	prikey, pubkey, _ := GenerateKeyStr()

	key1 := toSingle(pubkey, "PUBLIC")
	fmtKey1 := FormatKeyToMultiline([]byte(key1), false)
	assert.Equal(t, pubkey, string(fmtKey1), "should equal")

	key2 := toSingle(prikey, "RSA PRIVATE")
	fmtKey2 := FormatKeyToMultiline([]byte(key2), true)
	assert.Equal(t, prikey, string(fmtKey2), "should equal")
}
