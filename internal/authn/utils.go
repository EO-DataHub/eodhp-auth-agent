package authn

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidJWT = errors.New("invalid jwt token")
var ErrInvalidClaims = errors.New("invalid claims")
var parser = jwt.NewParser()

// Need to preserve unknown claims through marshalling so implementing jwt.Claims
// interface on map[string]any
type Claims map[string]any

func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if exp, ok := c["exp"].(float64); ok {
		return jwt.NewNumericDate(time.Unix(int64(exp), 0)), nil
	}
	return nil, nil
}

func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	if iat, ok := c["iat"].(float64); ok {
		return jwt.NewNumericDate(time.Unix(int64(iat), 0)), nil
	}
	return nil, nil
}

func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if nbf, ok := c["nbf"].(float64); ok {
		return jwt.NewNumericDate(time.Unix(int64(nbf), 0)), nil
	}
	return nil, nil
}

func (c Claims) GetIssuer() (string, error) {
	if iss, ok := c["iss"].(string); ok {
		return iss, nil
	}
	return "", nil
}

func (c Claims) GetSubject() (string, error) {
	if sub, ok := c["sub"].(string); ok {
		return sub, nil
	}
	return "", nil
}

func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	if aud, ok := c["aud"].([]string); ok {
		return jwt.ClaimStrings(aud), nil
	}
	return nil, nil
}

func CreateJWTToken(claims jwt.Claims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretBytes := []byte(secret)
	signedToken, err := token.SignedString(secretBytes)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ParseClaims(token string, claims jwt.Claims) error {
	// Check if token is JWT by attempting to parse it
	if _, _, err := parser.ParseUnverified(token, claims); err != nil {
		return err
	}
	return nil
}
