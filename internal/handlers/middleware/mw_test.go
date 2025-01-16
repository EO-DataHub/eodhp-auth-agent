package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWTMiddleware_ValidBearerToken_ClaimsPopulated(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(ClaimsKey).(Claims)
		// Test claims
		assert.Equal(t, "abcd-1234", claims.Subject)
		w.WriteHeader(http.StatusOK)
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	jwtToken, err := authn.CreateJWTToken(Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: "abcd-1234",
		},
	}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	mw := JWTMiddleware(next)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
}

func TestProxyAuthRequest_InvalidBearerToken_ClaimsNotPopulated(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(ClaimsKey).(Claims)
		// Test claims
		if claims.Subject == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer invalid-token")

	mw := JWTMiddleware(next)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
}
