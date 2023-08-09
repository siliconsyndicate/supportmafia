package auth

import (
	"supportmafia/server/config"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func getTestConfig() *config.TokenAuthConfig {
	c := config.GetConfigFromFile("test")
	return &c.TokenAuthConfig
}

var testTokenAuth = NewTokenAuthentication(getTestConfig(), nil)

func getTestUserClaim() *UserClaim {
	uc := UserClaim{
		ID: primitive.NewObjectID(),
	}
	return &uc
}

func TestTokenAuthentication_SignToken(t *testing.T) {
	type fields struct {
		Config *config.TokenAuthConfig
		User   *UserAuth
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Basic Auth",
			fields: fields{
				Config: getTestConfig(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tAuth := NewTokenAuthentication(tt.fields.Config, nil)
			got, err := tAuth.SignToken(getTestUserClaim())
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenAuthentication.SignToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NotEmpty(t, got)
			assert.NotNil(t, got)
		})
	}
}

func TestTokenAuthentication_VerifyToken(t *testing.T) {
	uc := getTestUserClaim()

	tokenString, _ := testTokenAuth.SignToken(uc)

	testConfigInvalidSignature := getTestConfig()
	testConfigInvalidSignature.JWTSignKey = "abccadnced"

	type args struct {
		tokenString string
	}
	type fields struct {
		Config *config.TokenAuthConfig
		User   *UserAuth
	}
	tests := []struct {
		name          string
		args          args
		fields        fields
		wantErr       bool
		wantErrString string
		wantClaim     Claim
	}{
		{
			name:    "Basic Token Verify",
			wantErr: false,
			args: args{
				tokenString: tokenString,
			},
			fields: fields{
				Config: getTestConfig(),
				User:   &UserAuth{},
			},
			wantClaim: uc,
		},
		{
			name:    "Invalid Token String",
			wantErr: true,
			args: args{
				tokenString: "ZXlKaGJHY2lPaUpJ5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBaQ0k2SWpObE9XUm1NVGcxTFRaa01EUXROREZqTXkwNVl6VmhMVGMzWW1Vd1pEYzNNbVJpTkNJc0luUjVjR1VpT2lKMWMyVnlJbjAuSTZHajBPYzBaYTBzZUVvX2VzX29EZnJmNDE3V1p2bGJJcF9tOTU1Nk9NTQ==",
			},
			fields: fields{
				Config: getTestConfig(),
			},
			wantErrString: "illegal base64 data at input byte 208",
			wantClaim:     nil,
		},
		{
			name:    "Invalid Token Signature",
			wantErr: true,
			args: args{
				tokenString: "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBaQ0k2SWpNNE1qQmhZMk13TFdWbU0ySXRORFExTnkxaFlqUmhMVE13T0Rsall6VXhOV0U0WXlJc0luUjVjR1VpT2lKMWMyVnlJbjAuVEFoS0Vhenh6UjU3T3VZb0FKZVVfeVVKT3ktU0tzSXRBN0FNZlptRG15SQ==",
			},
			fields: fields{
				Config: testConfigInvalidSignature,
			},
			wantErrString: "signature is invalid",
			wantClaim:     nil,
		},
		{
			name:    "Token Expired",
			wantErr: true,
			args: args{
				tokenString: "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBaQ0k2SW1NeVpETmtNMlkwTFRjelpHRXROR001TmkwNE1URmlMVE01TmpGaU5qUmtPVEZtTUNJc0luUjVjR1VpT2lKMWMyVnlJaXdpWlhod0lqb3hOakV3T1RBNU5UTXhmUS5aeU9sVXVSMkhKUzUteFJjcjdfd000dXdmMU90NkdrdmhiYjdpbi0yR3dV",
			},
			fields: fields{
				Config: getTestConfig(),
			},
			wantErrString: "token is expired by",
			wantClaim:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tAuth := &TokenAuthentication{
				Config: tt.fields.Config,
			}
			res, err := tAuth.VerifyToken(tt.args.tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenAuthentication.VerifyToken() error = %v, wantErr %v", err, tt.wantErr)
				assert.Contains(t, tt.wantErrString, err.Error())
			}
			assert.Equal(t, true, res)
		})
	}
}

func TestTokenAuthentication_GetClaimWithTokenString(t *testing.T) {
	uc := getTestUserClaim()
	tokenString, _ := testTokenAuth.SignToken(uc)
	type fields struct {
		Config *config.TokenAuthConfig
	}
	type args struct {
		tokenString string
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   Claim
	}{
		{
			name: "Basic Get Claim",
			fields: fields{
				Config: getTestConfig(),
			},
			want: uc,
			args: args{
				tokenString: tokenString,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tAuth := &TokenAuthentication{
				Config: tt.fields.Config,
			}
			res, err := tAuth.VerifyToken(tt.args.tokenString)
			assert.Nil(t, err)
			assert.Equal(t, true, res)
		})
	}
}
