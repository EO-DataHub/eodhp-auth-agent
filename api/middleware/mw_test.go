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
		claims := r.Context().Value(ClaimsKey).(authn.Claims)
		// Test claims
		assert.Equal(t, "abcd-1234", claims.Subject)
		assert.Equal(t, "testuser", claims.Username)
		assert.Equal(t, 2, len(claims.RealmAccess.Roles))
		assert.Equal(t, "test_role_1", claims.RealmAccess.Roles[0])
		assert.Equal(t, "test_role_2", claims.RealmAccess.Roles[1])
		w.WriteHeader(http.StatusOK)
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	jwtToken, err := authn.CreateJWTToken(authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: "abcd-1234",
		},
		Username: "testuser",
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{
			Roles: []string{"test_role_1", "test_role_2"},
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
		claims := r.Context().Value(ClaimsKey).(authn.Claims)
		// Test claims
		assert.Equal(t, "", claims.Subject)
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
