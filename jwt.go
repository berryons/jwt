package jwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

var instance IJwtUtils = new(jwtUtils)

func AccessToken(jwtAccessKey string, expiresAtAsMinutes int) (string, error) {
	return instance.GenerateAccessToken(jwtAccessKey, expiresAtAsMinutes)
}

func RefreshToken(jwtRefreshKey string, expiresAtAsHours int) (string, error) {
	return instance.GenerateRefreshToken(jwtRefreshKey, expiresAtAsHours)
}

func VerifyToken(key, tokenAsString string) (int, string) {
	return instance.VerifyToken(key, tokenAsString)
}

func ExtractClaims(key, tokenAsString string) (*TokenClaims, error) {
	return instance.ExtractClaimsFromToken(key, tokenAsString)
}

type IJwtUtils interface {
	GenerateAccessToken(jwtAccessKey string, expiresAtAsMinutes int) (string, error)
	GenerateRefreshToken(jwtRefreshKey string, expiresAtAsHours int) (string, error)
	VerifyToken(key, tokenAsString string) (int, string)
	ExtractClaimsFromToken(key, tokenAsString string) (*TokenClaims, error)
}

type TokenClaims struct {
	jwt.RegisteredClaims
}

type jwtUtils struct {
}

// GenerateAccessToken - Generate Json Web Token of access.
func (pSelf *jwtUtils) GenerateAccessToken(jwtAccessKey string, expiresAtAsMinutes int) (string, error) {
	claims := TokenClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiresAtAsMinutes) * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	return generateJsonWebToken(jwtAccessKey, claims)
}

// GenerateRefreshToken - Generate Json Web Token of refresh
func (pSelf *jwtUtils) GenerateRefreshToken(jwtRefreshKey string, expiresAtAsHours int) (string, error) {
	claims := TokenClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiresAtAsHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	return generateJsonWebToken(jwtRefreshKey, claims)
}

func generateJsonWebToken(key string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedTokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}

	return signedTokenString, nil
}

// VerifyToken - Verify Json Web Token from token as string
func (pSelf *jwtUtils) VerifyToken(key, tokenAsString string) (int, string) {
	if len(key) <= 0 {
		return http.StatusUnauthorized, "Key is null"
	}

	if len(tokenAsString) <= 0 {
		return http.StatusUnauthorized, "Token is null"
	}

	token, err := jwt.Parse(tokenAsString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(key), nil
	})

	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return http.StatusUnauthorized, "Token Expired"
		}

		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return http.StatusUnauthorized, "Token Signature Invalid"
		}

		return http.StatusUnauthorized, err.Error()
	}

	return http.StatusOK, "OK"

}

// ExtractClaimsFromToken - Extract claims from token as string
func (pSelf *jwtUtils) ExtractClaimsFromToken(key, tokenAsString string) (*TokenClaims, error) {
	claims := &TokenClaims{}

	token, err := jwt.ParseWithClaims(tokenAsString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid Token")
	}

	return claims, nil
}
