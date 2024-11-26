package jwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

type IJwtUtils interface {
	GenerateAccessToken(expiresAtAsMinutes int) (string, error)
	GenerateRefreshToken(expiresAtAsHours int) (string, error)
	VerifyToken(isAccessToken bool, tokenAsString string) (int, string)
	ExtractClaimsFromToken(isAccessToken bool, tokenAsString string) (*TokenClaims, error)
}

type TokenClaims struct {
	jwt.RegisteredClaims
}

type JwtUtils struct {
	accessKey  string
	refreshKey string
}

func (pSelf *JwtUtils) Init(accessKey, refreshKey string) *JwtUtils {
	pSelf.accessKey = accessKey
	pSelf.refreshKey = refreshKey
	return pSelf
}

// GenerateAccessToken - Generate Json Web Token of access.
func (pSelf *JwtUtils) GenerateAccessToken(expiresAtAsMinutes int) (string, error) {
	if pSelf.accessKey == "" {
		return "", fmt.Errorf("access key is empty")
	}

	claims := TokenClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiresAtAsMinutes) * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	return generateJsonWebToken(pSelf.accessKey, claims)
}

// GenerateRefreshToken - Generate Json Web Token of refresh
func (pSelf *JwtUtils) GenerateRefreshToken(expiresAtAsHours int) (string, error) {
	if pSelf.refreshKey == "" {
		return "", fmt.Errorf("refresh key is empty")
	}

	claims := TokenClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiresAtAsHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	return generateJsonWebToken(pSelf.refreshKey, claims)
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
func (pSelf *JwtUtils) VerifyToken(isAccessToken bool, tokenAsString string) (int, string) {
	if (isAccessToken && len(pSelf.accessKey) <= 0) || (!isAccessToken && len(pSelf.refreshKey) <= 0) {
		return http.StatusUnauthorized, "Key is null"
	}

	if len(tokenAsString) <= 0 {
		return http.StatusUnauthorized, "Token is null"
	}

	var key string
	if isAccessToken {
		key = pSelf.accessKey
	} else {
		key = pSelf.refreshKey
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
func (pSelf *JwtUtils) ExtractClaimsFromToken(isAccessToken bool, tokenAsString string) (*TokenClaims, error) {
	if (isAccessToken && len(pSelf.accessKey) <= 0) || (!isAccessToken && len(pSelf.refreshKey) <= 0) {
		return nil, fmt.Errorf("Key is null")
	}

	claims := &TokenClaims{}

	var key string
	if isAccessToken {
		key = pSelf.accessKey
	} else {
		key = pSelf.refreshKey
	}

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
