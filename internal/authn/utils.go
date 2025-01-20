package authn

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

var ErrInvalidJWT = errors.New("invalid jwt token")
var ErrInvalidClaims = errors.New("invalid claims")

// Need to preserve unknown claims through marshalling so implementing jwt.Claims
// interface on map[string]any
type Claims map[string]any

func (c Claims) Valid() error {
	vErr := new(jwt.ValidationError)
	now := float64(time.Now().Unix())

	if exp, ok := c["exp"].(float64); ok {
		if !verifyExp(exp, now, false) {
			delta := time.Unix(int64(now), 0).Sub(time.Unix(int64(exp), 0))
			vErr.Inner = fmt.Errorf("token is expired by %v", delta)
			vErr.Errors |= jwt.ValidationErrorExpired
		}
	}

	if iss, ok := c["iat"].(float64); ok {
		if !verifyIat(iss, now, false) {
			vErr.Inner = fmt.Errorf("token used before issued")
			vErr.Errors |= jwt.ValidationErrorIssuedAt
		}
	}

	if nbf, ok := c["nbf"].(float64); ok {
		if !verifyNbf(nbf, now, false) {
			vErr.Inner = fmt.Errorf("token is not valid yet")
			vErr.Errors |= jwt.ValidationErrorNotValidYet
		}
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
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
	if t, err := jwt.ParseWithClaims(token, claims, nil); err != nil {
		// Ignore validation errors (no need to check signing of key)
		if _, ok := err.(*jwt.ValidationError); !ok {
			return ErrInvalidJWT
		}

		// Check if token was decoded successfully
		if t == nil {
			// Return an error if the token was not decoded successfully
			return ErrInvalidClaims
		}
	}
	return nil
}

// ----- helpers

func verifyExp(exp, now float64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat, now float64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyNbf(nbf, now float64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}
