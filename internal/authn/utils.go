package authn

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt"
)

func CreateJWTToken(claims Claims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretBytes := []byte(secret)
	signedToken, err := token.SignedString(secretBytes)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ParseClaims(token string) (Claims, error) {
	claims := Claims{}
	// Check if token is JWT by attempting to parse it
	if t, err := jwt.ParseWithClaims(token, claims, nil); err != nil {
		// Ignore validation errors (no need to check signing of key)
		if _, ok := err.(*jwt.ValidationError); !ok {
			return claims, fmt.Errorf("failed to parse jwt token: %w", err)
		}

		// Check if token was decoded successfully
		if t == nil {
			// Return an error if the token was not decoded successfully
			return claims, errors.New("invalid jwt token")
		}
	}
	return claims, nil
}
