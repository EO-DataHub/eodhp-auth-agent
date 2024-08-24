package authn

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt"
)

type Claims struct {
	jwt.StandardClaims
	Username    string `json:"preferred_username"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

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
	if t, err := jwt.ParseWithClaims(token, &claims, nil); err != nil {
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

// Domain host patters are passed in as glob style patterns (e.g.
// *.example.com). This function converts these patterns to regular expressions
// for matching against the request host.
func compileGlobPatterns(patterns []string) []regexp.Regexp {
	compiledPatterns := make([]regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		// Convert wildcard pattern to regular expression
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		compiledPatterns[i] = *regexp.MustCompile(regexPattern)
	}
	return compiledPatterns
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
