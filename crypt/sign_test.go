package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignSha1WithRsa(t *testing.T) {
	sign, err := SignSha1WithRsa(privateKey, "hello")
	assert.Greater(t, len(sign), 0, "sign should not be empty")
	assert.NoError(t, err)

	assert.NoError(t, VerifySignSha1WithRsa(publicKey, "hello", sign))
}

func TestSignSha256WithRsa(t *testing.T) {
	sign, err := SignSha256WithRsa(privateKey, "hello")
	assert.Greater(t, len(sign), 0, "sign should not be empty")
	assert.NoError(t, err)

	assert.NoError(t, VerifySignSha256WithRsa(publicKey, "hello", sign))
}

func TestCalcSign(t *testing.T) {
	type args struct {
		data   string
		params *SignParams
	}
	tests := []struct {
		name     string
		args     args
		wantSign string
		wantErr  bool
	}{
		// TODO: Add test cases.
		{"SignMD5", args{"Hello World!", &SignParams{SignMD5, privateKey, "Secret", true, true}}, "", true},
		{"SignHmacMD5", args{"Hello World!", &SignParams{SignHmacMD5, privateKey, "Secret", true, true}}, "", true},
		{"SignHmacSha1", args{"Hello World!", &SignParams{SignHmacSha1, privateKey, "Secret", true, true}}, "", true},
		{"SignSHA1WithRSA", args{"Hello World!", &SignParams{SignSHA1WithRSA, privateKey, "Secret", true, true}}, "", true},
		{"SignSHA256WithRSA", args{"Hello World!", &SignParams{SignSHA256WithRSA, privateKey, "Secret", true, true}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sign, err := CalcSign(tt.args.data, tt.args.params)
			t.Logf("PlainText:%s, CypherText:%v\n", tt.args.data, sign)
			assert.Greater(t, len(sign), 0, "sign should not be empty")
			assert.NoError(t, err)
		})
	}
}
