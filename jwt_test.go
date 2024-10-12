package jwt

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"log"
	"net/http"
	"strings"
	"testing"
)

type SuiteJwt struct {
	suite.Suite
	accessKey  string
	refreshKey string
}

func TestRunJwtSuite(t *testing.T) {
	suite.Run(t, new(SuiteJwt))
}

func (pSelf *SuiteJwt) SetupSuite() {
	pSelf.accessKey = "test_access_key"
	pSelf.refreshKey = "test_refresh_key"
}

func (pSelf *SuiteJwt) Test_GenerateAccessTokenNormal() {
	// given
	var expiresAtAsMinutes int = 1

	// when
	accessToken, err := AccessToken(pSelf.accessKey, expiresAtAsMinutes)

	// then
	assert.NoError(pSelf.T(), err)
	assert.NotEmpty(pSelf.T(), accessToken)
}

func (pSelf *SuiteJwt) Test_GenerateRefreshTokenNormal() {
	// given
	var expiresAtAsHours int = 1

	// when
	refreshToken, err := RefreshToken(pSelf.refreshKey, expiresAtAsHours)

	// then
	assert.NoError(pSelf.T(), err)
	assert.NotEmpty(pSelf.T(), refreshToken)
}

func (pSelf *SuiteJwt) Test_VerifyAccessTokenNormal() {
	// given
	var expiresAtAsMinutes int = 1
	accessToken, err := AccessToken(pSelf.accessKey, expiresAtAsMinutes)
	accessTokenFromClient := "Bearer " + accessToken

	parts := strings.Split(accessTokenFromClient, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Fatal("invalid access token")
		//return http.StatusUnauthorized, "Invalid token"
	}
	seperatedAccessToken := parts[1]

	// when
	httpCode, msg := VerifyToken(pSelf.accessKey, seperatedAccessToken)

	// then
	assert.Empty(pSelf.T(), err)
	assert.Equal(pSelf.T(), "OK", msg)
	assert.Equal(pSelf.T(), http.StatusOK, httpCode)
}

func (pSelf *SuiteJwt) Test_VerifyRefreshTokenNormal() {
	// given
	var expiresAtAsHours int = 1
	refreshToken, err := RefreshToken(pSelf.refreshKey, expiresAtAsHours)

	// when
	httpCode, msg := VerifyToken(pSelf.refreshKey, refreshToken)

	// then
	assert.Empty(pSelf.T(), err)
	assert.Equal(pSelf.T(), "OK", msg)
	assert.Equal(pSelf.T(), http.StatusOK, httpCode)
}

func (pSelf *SuiteJwt) Test_VerifyTokenWithNullKeyError() {
	// when
	httpCode, msg := VerifyToken("", "")

	// then
	assert.Equal(pSelf.T(), "Key is null", msg)
	assert.Equal(pSelf.T(), http.StatusUnauthorized, httpCode)
}

func (pSelf *SuiteJwt) Test_VerifyTokenWithNullTokenError() {
	// when
	httpCode, msg := VerifyToken(pSelf.accessKey, "")

	// then
	assert.Equal(pSelf.T(), "Token is null", msg)
	assert.Equal(pSelf.T(), http.StatusUnauthorized, httpCode)
}

func (pSelf *SuiteJwt) Test_VerifyTokenWithIncorrectKeyError() {
	// given
	var expiresAtAsHours int = 1
	refreshToken, err := RefreshToken(pSelf.refreshKey, expiresAtAsHours)

	// when
	httpCode, msg := VerifyToken("IncorrectKey", refreshToken)

	// then
	assert.Empty(pSelf.T(), err)
	assert.Equal(pSelf.T(), "Token Signature Invalid", msg)
	assert.Equal(pSelf.T(), http.StatusUnauthorized, httpCode)
}

func (pSelf *SuiteJwt) Test_VerifyTokenWithExpiredTokenError() {
	// given
	var expiresAtAsMinutes int = -1
	accessToken, err := AccessToken(pSelf.accessKey, expiresAtAsMinutes)

	// when
	httpCode, msg := VerifyToken(pSelf.accessKey, accessToken)

	// then
	assert.Empty(pSelf.T(), err)
	assert.Equal(pSelf.T(), "Token Expired", msg)
	assert.Equal(pSelf.T(), http.StatusUnauthorized, httpCode)
}

func (pSelf *SuiteJwt) Test_ExtractClaimsNormal() {
	// given
	var expiresAtAsHours int = 1
	refreshToken, err := RefreshToken(pSelf.refreshKey, expiresAtAsHours)

	// when
	refreshTokenClaims, err := ExtractClaims(pSelf.refreshKey, refreshToken)

	// then
	assert.Empty(pSelf.T(), err)
	assert.NotEmpty(pSelf.T(), refreshTokenClaims)
}

func (pSelf *SuiteJwt) Test_ExtractClaimsWithIncorrectKeyError() {
	// given
	var expiresAtAsHours int = 1
	refreshToken, err := RefreshToken(pSelf.refreshKey, expiresAtAsHours)

	// when
	refreshTokenClaims, err := ExtractClaims("IncorrectKey", refreshToken)

	// then
	assert.Error(pSelf.T(), err, "signature is invalid: signature is invalid")
	assert.Empty(pSelf.T(), refreshTokenClaims)
}
